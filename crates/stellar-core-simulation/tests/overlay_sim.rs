use anyhow::Result;
use stellar_core_overlay::OverlayMessage;
use stellar_xdr::curr::StellarMessage;
use tokio::time::{Duration, Instant, timeout};

use stellar_core_simulation::OverlaySimulation;

#[tokio::test]
async fn test_overlay_broadcast_reaches_peers() -> Result<()> {
    let sim = match OverlaySimulation::start(3).await {
        Ok(sim) => sim,
        Err(err) if err.to_string().contains("tcp bind not permitted") => {
            eprintln!("skipping test: tcp bind not permitted in this environment");
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    let mut receivers = sim
        .managers
        .iter()
        .map(|manager| manager.subscribe())
        .collect::<Vec<_>>();

    sim.broadcast_scp(1).await?;

    for (idx, receiver) in receivers.iter_mut().enumerate() {
        if idx == 0 {
            continue;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_scp = false;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match timeout(remaining, receiver.recv()).await {
                Ok(Ok(OverlayMessage { message, .. })) => {
                    if matches!(message, StellarMessage::ScpMessage(_)) {
                        saw_scp = true;
                        break;
                    }
                }
                Ok(Err(_)) => {
                    break;
                }
                Err(_) => {
                    break;
                }
            }
        }
        assert!(saw_scp, "peer {idx} did not receive scp message");
    }

    sim.shutdown().await?;
    Ok(())
}
