//! Run command implementation for rs-stellar-core.
//!
//! The run command starts the node and keeps it synchronized with the network.
//! It handles:
//!
//! - Initial catchup if necessary
//! - Peer connections and message handling
//! - Consensus tracking (or participation for validators)
//! - Ledger close and state updates
//!
//! ## Usage
//!
//! ```text
//! rs-stellar-core run                    # Run as a full node
//! rs-stellar-core run --validator        # Run as a validator
//! rs-stellar-core run --watcher          # Run as a watcher (no catchup)
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::signal;
use tokio::sync::broadcast;

use crate::app::{App, AppState, CatchupTarget};
use crate::config::AppConfig;

/// Node running mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunMode {
    /// Full node: catch up, sync, and track consensus.
    #[default]
    Full,
    /// Validator: participate in consensus.
    Validator,
    /// Watcher: observe only, no catchup.
    Watcher,
}

impl std::fmt::Display for RunMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunMode::Full => write!(f, "full"),
            RunMode::Validator => write!(f, "validator"),
            RunMode::Watcher => write!(f, "watcher"),
        }
    }
}

/// Options for the run command.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Running mode.
    pub mode: RunMode,
    /// Whether to force catchup even if state exists.
    pub force_catchup: bool,
    /// Wait for catchup to complete before starting.
    pub wait_for_sync: bool,
    /// Maximum ledger age before forcing catchup.
    pub max_ledger_age: u32,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            mode: RunMode::Full,
            force_catchup: false,
            wait_for_sync: true,
            max_ledger_age: 300, // ~25 minutes of ledgers
        }
    }
}

impl RunOptions {
    /// Create options for running as a validator.
    pub fn validator() -> Self {
        Self {
            mode: RunMode::Validator,
            ..Default::default()
        }
    }

    /// Create options for running as a watcher.
    pub fn watcher() -> Self {
        Self {
            mode: RunMode::Watcher,
            force_catchup: false,
            wait_for_sync: false,
            ..Default::default()
        }
    }

    /// Set whether to force catchup.
    pub fn with_force_catchup(mut self, force: bool) -> Self {
        self.force_catchup = force;
        self
    }
}

/// Run the node with the given configuration and options.
pub async fn run_node(config: AppConfig, options: RunOptions) -> anyhow::Result<()> {
    tracing::info!(
        mode = %options.mode,
        node_name = %config.node.name,
        network = %config.network.passphrase,
        "Starting rs-stellar-core node"
    );

    // Validate mode-specific requirements
    validate_run_options(&config, &options)?;

    // Store HTTP config before moving config
    let http_enabled = config.http.enabled;
    let http_port = config.http.port;

    // Create the application
    let app = Arc::new(App::new(config).await?);

    // Set up shutdown handling
    let shutdown_app = app.clone();
    let shutdown_handle = tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        tracing::info!("Shutdown signal received");
        shutdown_app.shutdown();
    });

    // Start the HTTP status server if enabled
    let http_handle = if http_enabled {
        let status_server = StatusServer::new(http_port, app.clone());
        Some(tokio::spawn(async move {
            if let Err(e) = status_server.start().await {
                tracing::error!(error = %e, "HTTP status server error");
            }
        }))
    } else {
        None
    };

    // Print startup info
    print_startup_info(&app, &options);

    // Run the main loop
    let result = run_main_loop(app.clone(), options).await;

    // Clean up
    shutdown_handle.abort();
    if let Some(handle) = http_handle {
        handle.abort();
    }

    match result {
        Ok(()) => {
            tracing::info!("Node stopped gracefully");
            Ok(())
        }
        Err(e) => {
            tracing::error!(error = %e, "Node stopped with error");
            Err(e)
        }
    }
}

/// Validate that the options are compatible with the configuration.
fn validate_run_options(config: &AppConfig, options: &RunOptions) -> anyhow::Result<()> {
    if options.mode == RunMode::Validator {
        if !config.node.is_validator {
            anyhow::bail!(
                "Cannot run in validator mode: node is not configured as a validator"
            );
        }
        if config.node.node_seed.is_none() {
            anyhow::bail!("Validators must have a node_seed configured");
        }
    }

    Ok(())
}

/// Print information about the node at startup.
fn print_startup_info(app: &App, options: &RunOptions) {
    let info = app.info();
    println!("rs-stellar-core {}", info.version);
    println!();
    println!("Node: {}", info.node_name);
    println!("Mode: {}", options.mode);
    println!("Public Key: {}", info.public_key);
    println!("Network: {}", info.network_passphrase);
    println!();
}

/// Run the main application loop.
async fn run_main_loop(app: Arc<App>, options: RunOptions) -> anyhow::Result<()> {
    // Check if we need to catch up
    let needs_catchup = check_needs_catchup(&app, &options).await?;

    if needs_catchup {
        if options.mode == RunMode::Watcher {
            tracing::info!("Watcher mode: skipping catchup");
        } else {
            tracing::info!("Node is behind, starting catchup");
            app.catchup(CatchupTarget::Current).await?;
        }
    }

    // Start the main run loop
    tracing::info!("Starting main run loop");
    app.run().await?;

    Ok(())
}

/// Check if the node needs to catch up.
async fn check_needs_catchup(app: &App, options: &RunOptions) -> anyhow::Result<bool> {
    if options.force_catchup {
        return Ok(true);
    }

    // Check current state in database
    // For now, assume we always need catchup if there's no state
    let current_state = app.state().await;
    Ok(current_state == AppState::Initializing)
}

/// Wait for a shutdown signal (Ctrl+C or SIGTERM).
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM");
        }
    }
}

/// Node metrics and status.
#[derive(Debug, Clone, Default)]
pub struct NodeStatus {
    /// Current ledger sequence.
    pub ledger_seq: u32,
    /// Current ledger hash.
    pub ledger_hash: Option<stellar_core_common::Hash256>,
    /// Number of connected peers.
    pub peer_count: usize,
    /// Current consensus state.
    pub consensus_state: String,
    /// Transactions in the pending queue.
    pub pending_tx_count: usize,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// Application state.
    pub state: String,
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Node Status:")?;
        writeln!(f, "  State: {}", self.state)?;
        writeln!(f, "  Ledger: {}", self.ledger_seq)?;
        if let Some(hash) = &self.ledger_hash {
            writeln!(f, "  Ledger Hash: {}", hash)?;
        }
        writeln!(f, "  Peers: {}", self.peer_count)?;
        writeln!(f, "  Consensus: {}", self.consensus_state)?;
        writeln!(f, "  Pending TXs: {}", self.pending_tx_count)?;
        writeln!(f, "  Uptime: {}s", self.uptime_secs)?;
        Ok(())
    }
}

/// Node runner that manages the run lifecycle.
pub struct NodeRunner {
    app: Arc<App>,
    options: RunOptions,
    start_time: std::time::Instant,
    shutdown_tx: broadcast::Sender<()>,
}

impl NodeRunner {
    /// Create a new node runner.
    pub async fn new(config: AppConfig, options: RunOptions) -> anyhow::Result<Self> {
        let app = Arc::new(App::new(config).await?);
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            app,
            options,
            start_time: std::time::Instant::now(),
            shutdown_tx,
        })
    }

    /// Get the application instance.
    pub fn app(&self) -> &Arc<App> {
        &self.app
    }

    /// Get the current node status.
    pub async fn status(&self) -> NodeStatus {
        NodeStatus {
            ledger_seq: 0, // Would query from app
            ledger_hash: None,
            peer_count: 0,
            consensus_state: "tracking".to_string(),
            pending_tx_count: 0,
            uptime_secs: self.start_time.elapsed().as_secs(),
            state: format!("{}", self.app.state().await),
        }
    }

    /// Run the node.
    pub async fn run(&self) -> anyhow::Result<()> {
        run_main_loop(self.app.clone(), self.options.clone()).await
    }

    /// Request shutdown.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
        self.app.shutdown();
    }

    /// Subscribe to shutdown notifications.
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
}

/// Shared state for the HTTP server.
struct ServerState {
    app: Arc<App>,
    start_time: Instant,
}

/// HTTP server for node status and control.
///
/// Provides endpoints for monitoring and interacting with the node:
/// - GET /info - node information
/// - GET /metrics - prometheus-style metrics
/// - GET /peers - connected peers
/// - GET /ledger - current ledger info
/// - POST /tx - submit transactions
pub struct StatusServer {
    port: u16,
    app: Arc<App>,
    start_time: Instant,
}

impl StatusServer {
    /// Create a new status server.
    pub fn new(port: u16, app: Arc<App>) -> Self {
        Self {
            port,
            app,
            start_time: Instant::now(),
        }
    }

    /// Start the server.
    pub async fn start(self) -> anyhow::Result<()> {
        let state = Arc::new(ServerState {
            app: self.app,
            start_time: self.start_time,
        });

        let app = Router::new()
            .route("/", get(root_handler))
            .route("/info", get(info_handler))
            .route("/metrics", get(metrics_handler))
            .route("/peers", get(peers_handler))
            .route("/ledger", get(ledger_handler))
            .route("/tx", post(submit_tx_handler))
            .route("/health", get(health_handler))
            .with_state(state);

        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        tracing::info!(port = self.port, "Starting HTTP status server");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

// ============================================================================
// HTTP Handler Response Types
// ============================================================================

/// Response for the root endpoint.
#[derive(Serialize)]
struct RootResponse {
    name: String,
    version: String,
    endpoints: Vec<String>,
}

/// Response for the /info endpoint.
#[derive(Serialize)]
struct InfoResponse {
    version: String,
    node_name: String,
    public_key: String,
    network_passphrase: String,
    is_validator: bool,
    state: String,
    uptime_secs: u64,
}

/// Response for the /metrics endpoint (Prometheus format).
#[derive(Serialize)]
struct MetricsResponse {
    ledger_seq: u32,
    peer_count: usize,
    pending_transactions: u64,
    uptime_seconds: u64,
    state: String,
    is_validator: bool,
}

/// Response for the /peers endpoint.
#[derive(Serialize)]
struct PeersResponse {
    count: usize,
    peers: Vec<PeerInfo>,
}

/// Information about a connected peer.
#[derive(Serialize)]
struct PeerInfo {
    id: String,
    address: String,
    direction: String,
}

/// Response for the /ledger endpoint.
#[derive(Serialize)]
struct LedgerResponse {
    sequence: u32,
    hash: String,
    close_time: u64,
    protocol_version: u32,
}

/// Request for submitting a transaction.
#[derive(Deserialize)]
struct SubmitTxRequest {
    tx: String, // Base64-encoded XDR transaction envelope
}

/// Response for transaction submission.
#[derive(Serialize)]
struct SubmitTxResponse {
    success: bool,
    hash: Option<String>,
    error: Option<String>,
}

/// Response for the /health endpoint.
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    state: String,
    ledger_seq: u32,
    peer_count: usize,
}

// ============================================================================
// HTTP Handlers
// ============================================================================

async fn root_handler() -> Json<RootResponse> {
    Json(RootResponse {
        name: "rs-stellar-core".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        endpoints: vec![
            "/info".to_string(),
            "/metrics".to_string(),
            "/peers".to_string(),
            "/ledger".to_string(),
            "/tx".to_string(),
            "/health".to_string(),
        ],
    })
}

async fn info_handler(State(state): State<Arc<ServerState>>) -> Json<InfoResponse> {
    let info = state.app.info();
    let app_state = state.app.state().await;
    let uptime = state.start_time.elapsed().as_secs();

    Json(InfoResponse {
        version: info.version,
        node_name: info.node_name,
        public_key: info.public_key,
        network_passphrase: info.network_passphrase,
        is_validator: info.is_validator,
        state: format!("{}", app_state),
        uptime_secs: uptime,
    })
}

async fn metrics_handler(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let app_state = state.app.state().await;
    let uptime = state.start_time.elapsed().as_secs();

    // Get metrics from herder (we don't have direct access, so use available info)
    let metrics = MetricsResponse {
        ledger_seq: 0, // Would need access to current ledger
        peer_count: 0, // Would need access to overlay
        pending_transactions: 0,
        uptime_seconds: uptime,
        state: format!("{}", app_state),
        is_validator: state.app.info().is_validator,
    };

    // Return Prometheus-style text format
    let prometheus_text = format!(
        "# HELP stellar_ledger_sequence Current ledger sequence number\n\
         # TYPE stellar_ledger_sequence gauge\n\
         stellar_ledger_sequence {}\n\
         # HELP stellar_peer_count Number of connected peers\n\
         # TYPE stellar_peer_count gauge\n\
         stellar_peer_count {}\n\
         # HELP stellar_pending_transactions Number of pending transactions\n\
         # TYPE stellar_pending_transactions gauge\n\
         stellar_pending_transactions {}\n\
         # HELP stellar_uptime_seconds Node uptime in seconds\n\
         # TYPE stellar_uptime_seconds counter\n\
         stellar_uptime_seconds {}\n\
         # HELP stellar_is_validator Whether this node is a validator\n\
         # TYPE stellar_is_validator gauge\n\
         stellar_is_validator {}\n",
        metrics.ledger_seq,
        metrics.peer_count,
        metrics.pending_transactions,
        metrics.uptime_seconds,
        if metrics.is_validator { 1 } else { 0 }
    );

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        prometheus_text,
    )
}

async fn peers_handler(State(_state): State<Arc<ServerState>>) -> Json<PeersResponse> {
    // Would need access to overlay manager to get actual peer info
    Json(PeersResponse {
        count: 0,
        peers: vec![],
    })
}

async fn ledger_handler(State(_state): State<Arc<ServerState>>) -> Json<LedgerResponse> {
    // Would need access to ledger manager
    Json(LedgerResponse {
        sequence: 0,
        hash: "0".repeat(64),
        close_time: 0,
        protocol_version: 21,
    })
}

async fn submit_tx_handler(
    State(_state): State<Arc<ServerState>>,
    Json(request): Json<SubmitTxRequest>,
) -> impl IntoResponse {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use stellar_xdr::curr::{ReadXdr, TransactionEnvelope, Limits};

    // Decode and validate the transaction
    let tx_bytes = match STANDARD.decode(&request.tx) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitTxResponse {
                    success: false,
                    hash: None,
                    error: Some(format!("Invalid base64: {}", e)),
                }),
            );
        }
    };

    // Parse the transaction envelope
    let _tx_env = match TransactionEnvelope::from_xdr(&tx_bytes, Limits::none()) {
        Ok(env) => env,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitTxResponse {
                    success: false,
                    hash: None,
                    error: Some(format!("Invalid XDR: {}", e)),
                }),
            );
        }
    };

    // Compute transaction hash
    let hash = stellar_core_common::Hash256::hash(&tx_bytes);

    // Would submit to herder's transaction queue here
    // For now, return success with the hash

    (
        StatusCode::OK,
        Json(SubmitTxResponse {
            success: true,
            hash: Some(hash.to_hex()),
            error: None,
        }),
    )
}

async fn health_handler(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let app_state = state.app.state().await;
    let is_healthy = matches!(app_state, AppState::Synced | AppState::Validating);

    let response = HealthResponse {
        status: if is_healthy { "healthy" } else { "unhealthy" }.to_string(),
        state: format!("{}", app_state),
        ledger_seq: 0,
        peer_count: 0,
    };

    let status = if is_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_mode_display() {
        assert_eq!(format!("{}", RunMode::Full), "full");
        assert_eq!(format!("{}", RunMode::Validator), "validator");
        assert_eq!(format!("{}", RunMode::Watcher), "watcher");
    }

    #[test]
    fn test_run_options_default() {
        let options = RunOptions::default();
        assert_eq!(options.mode, RunMode::Full);
        assert!(!options.force_catchup);
        assert!(options.wait_for_sync);
    }

    #[test]
    fn test_run_options_validator() {
        let options = RunOptions::validator();
        assert_eq!(options.mode, RunMode::Validator);
    }

    #[test]
    fn test_run_options_watcher() {
        let options = RunOptions::watcher();
        assert_eq!(options.mode, RunMode::Watcher);
        assert!(!options.wait_for_sync);
    }

    #[test]
    fn test_node_status_display() {
        let status = NodeStatus {
            ledger_seq: 1000,
            ledger_hash: None,
            peer_count: 5,
            consensus_state: "tracking".to_string(),
            pending_tx_count: 10,
            uptime_secs: 3600,
            state: "Synced".to_string(),
        };

        let display = format!("{}", status);
        assert!(display.contains("Ledger: 1000"));
        assert!(display.contains("Peers: 5"));
        assert!(display.contains("Uptime: 3600s"));
    }
}
