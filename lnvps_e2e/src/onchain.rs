//! Helpers for paying on-chain (regtest) from E2E tests.
//!
//! The `lnd-payer` docker service has a funded on-chain wallet (101 blocks
//! mined to it by `wait-for-lnd.sh`). Tests call [`send_onchain`] to send
//! coins to a receive address derived by the API's `lnd` node, then
//! [`mine_blocks`] so the deposit confirms and the API's on-chain watcher
//! settles the payment.

use anyhow::{Context, ensure};
use serde_json::Value;

/// Name of the payer LND docker-compose service (funded on-chain wallet).
const PAYER_SERVICE: &str = "lnd-payer";

/// Name of the bitcoind docker-compose service (regtest miner).
const BITCOIND_SERVICE: &str = "bitcoind";

/// Docker compose file used by the E2E environment.
///
/// Resolved relative to the workspace root: cargo runs tests with the crate
/// directory as CWD, where a relative path would not resolve.
const COMPOSE_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../docker-compose.e2e.yaml");

/// Run a command inside a docker-compose service container.
async fn exec_in_service(service: &str, args: &[&str]) -> anyhow::Result<std::process::Output> {
    let id_out = tokio::process::Command::new("docker")
        .args(["compose", "-f", COMPOSE_FILE, "ps", "-q", service])
        .output()
        .await?;
    let container_id = String::from_utf8(id_out.stdout)?.trim().to_string();
    ensure!(
        !container_id.is_empty(),
        "Could not find running container for service '{service}'. \
         Is docker-compose.e2e.yaml up?"
    );

    let mut cmd_args = vec!["exec", container_id.as_str()];
    cmd_args.extend_from_slice(args);
    let out = tokio::process::Command::new("docker")
        .args(&cmd_args)
        .output()
        .await?;
    ensure!(
        out.status.success(),
        "docker exec in '{service}' failed (exit {})\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(out)
}

/// Derive a fresh regtest address from the `lnd-payer` wallet — a valid
/// destination for on-chain referral payout tests.
pub async fn new_regtest_address() -> anyhow::Result<String> {
    let out = exec_in_service(
        PAYER_SERVICE,
        &["lncli", "--network=regtest", "newaddress", "p2wkh"],
    )
    .await?;
    let v: Value = serde_json::from_slice(&out.stdout).context("parsing newaddress output")?;
    v["address"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("no address in newaddress output: {v}"))
}

/// Send `amount_sats` on-chain to `address` from the `lnd-payer` wallet.
///
/// Returns the txid. The transaction is only broadcast — call
/// [`mine_blocks`] afterwards so it confirms.
pub async fn send_onchain(address: &str, amount_sats: u64) -> anyhow::Result<String> {
    let amt = amount_sats.to_string();
    let out = exec_in_service(
        PAYER_SERVICE,
        &[
            "lncli",
            "--network=regtest",
            "sendcoins",
            "--addr",
            address,
            "--amt",
            &amt,
        ],
    )
    .await?;
    let v: Value = serde_json::from_slice(&out.stdout).context("parsing sendcoins output")?;
    v["txid"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("no txid in sendcoins output: {v}"))
}

/// Mine `n` regtest blocks (to a throwaway payer address).
pub async fn mine_blocks(n: u32) -> anyhow::Result<()> {
    let out = exec_in_service(
        PAYER_SERVICE,
        &["lncli", "--network=regtest", "newaddress", "p2wkh"],
    )
    .await?;
    let v: Value = serde_json::from_slice(&out.stdout).context("parsing newaddress output")?;
    let addr = v["address"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no address in newaddress output: {v}"))?
        .to_string();

    exec_in_service(
        BITCOIND_SERVICE,
        &[
            "bitcoin-cli",
            "-regtest",
            "-rpcuser=polaruser",
            "-rpcpassword=polarpass",
            "generatetoaddress",
            &n.to_string(),
            &addr,
        ],
    )
    .await?;
    Ok(())
}

/// Extract the on-chain receive address from a VM renew API response.
///
/// The response shape is:
/// ```json
/// { "data": { "data": { "onchain": { "address": "bcrt1..." } } } }
/// ```
pub fn extract_onchain_address(renew_response: &Value) -> anyhow::Result<String> {
    renew_response["data"]["data"]["onchain"]["address"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No on-chain address found in renew response. \
                 Expected data.data.onchain.address to be a string. \
                 Response: {renew_response}"
            )
        })
}
