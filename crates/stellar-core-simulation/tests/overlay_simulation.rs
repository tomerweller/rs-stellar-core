use anyhow::Result;
use std::time::Duration;

use stellar_core_simulation::OverlaySimulation;

async fn start_or_skip(count: usize) -> Result<Option<OverlaySimulation>> {
    match OverlaySimulation::start(count).await {
        Ok(sim) => Ok(Some(sim)),
        Err(err) if err.to_string().contains("tcp bind not permitted") => {
            eprintln!("skipping test: tcp bind not permitted in this environment");
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

#[tokio::test]
async fn test_overlay_simulation_broadcast() -> Result<()> {
    let Some(sim) = start_or_skip(2).await? else {
        return Ok(());
    };

    tokio::time::sleep(Duration::from_millis(300)).await;
    let stats = sim.managers[0].stats();
    assert!(stats.connected_peers >= 1);

    sim.broadcast_scp(1).await?;
    sim.shutdown().await?;

    Ok(())
}

#[tokio::test]
async fn test_overlay_simulation_peer_counts() -> Result<()> {
    let Some(sim) = start_or_skip(4).await? else {
        return Ok(());
    };

    tokio::time::sleep(Duration::from_millis(300)).await;

    let root_stats = sim.managers[0].stats();
    assert!(root_stats.connected_peers >= 3);

    for idx in 1..sim.managers.len() {
        let stats = sim.managers[idx].stats();
        assert!(stats.connected_peers >= 1, "peer {idx} missing connection");
    }

    sim.shutdown().await?;
    Ok(())
}
