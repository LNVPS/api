use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use lnvps_api_common::{RedisWorkCommander, WorkCommander, WorkJob};

fn redis_url() -> Option<String> {
    std::env::var("LNVPS_TEST_REDIS_URL").ok()
}

async fn kill_other_clients(url: &str) -> Result<()> {
    let client = redis::Client::open(url)?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    let killed: u64 = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("TYPE")
        .arg("normal")
        .arg("SKIPME")
        .arg("yes")
        .query_async(&mut conn)
        .await?;
    if killed == 0 {
        bail!("CLIENT KILL dropped no connections");
    }
    Ok(())
}

async fn recv_trigger(commander: &RedisWorkCommander, deployment_id: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = None;
    while Instant::now() < deadline {
        match commander.recv().await {
            Ok(jobs) => {
                for m in &jobs {
                    commander.ack(&m.id).await?;
                }
                if jobs.iter().any(|m| {
                    matches!(m.job, WorkJob::ReconcileAppDeployment { deployment_id: d } if d == deployment_id)
                }) {
                    return Ok(());
                }
            }
            Err(e) => {
                last_error = Some(e);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    bail!("trigger {deployment_id} never arrived, last error: {last_error:?}")
}

async fn send_trigger(commander: &RedisWorkCommander, deployment_id: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match commander
            .send(WorkJob::ReconcileAppDeployment { deployment_id })
            .await
        {
            Ok(_) => return Ok(()),
            Err(e) if Instant::now() > deadline => return Err(e),
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

#[tokio::test]
async fn a_commander_survives_its_connection_being_killed() -> Result<()> {
    let Some(url) = redis_url() else {
        eprintln!("skipping: LNVPS_TEST_REDIS_URL not set");
        return Ok(());
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let stream = format!("test-reconnect-{nanos}");
    let commander =
        RedisWorkCommander::new_for_stream(&url, &stream, "operator", "consumer-1").await?;
    commander.recv().await?;

    send_trigger(&commander, 1).await?;
    recv_trigger(&commander, 1).await?;

    kill_other_clients(&url).await?;

    send_trigger(&commander, 2).await?;
    recv_trigger(&commander, 2).await?;
    Ok(())
}
