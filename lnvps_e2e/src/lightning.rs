//! Helpers for paying Lightning invoices from E2E tests.
//!
//! The `lnd-payer` docker service has a funded channel open to the `lnd`
//! service (the API's node).  Tests call [`pay_invoice`] to pay a BOLT11
//! payment request via `lncli` inside that container.

/// Name of the payer LND docker-compose service.
/// Resolved at runtime via `docker compose ps -q lnd-payer`.
const PAYER_SERVICE: &str = "lnd-payer";

/// Docker compose file used by the E2E environment.
const COMPOSE_FILE: &str = "docker-compose.e2e.yaml";

/// Pay a BOLT11 invoice using the `lnd-payer` node.
///
/// Runs `lncli --network=regtest payinvoice --force <bolt11>` inside the
/// `lnd-payer` container.  Returns an error if the container call fails or
/// the payment is rejected.
pub async fn pay_invoice(bolt11: &str) -> anyhow::Result<()> {
    // Resolve the container ID for the payer service.
    let id_out = tokio::process::Command::new("docker")
        .args(["compose", "-f", COMPOSE_FILE, "ps", "-q", PAYER_SERVICE])
        .output()
        .await?;
    let container_id = String::from_utf8(id_out.stdout)?.trim().to_string();
    anyhow::ensure!(
        !container_id.is_empty(),
        "Could not find running container for service '{PAYER_SERVICE}'. \
         Is docker-compose.e2e.yaml up?"
    );

    let out = tokio::process::Command::new("docker")
        .args([
            "exec",
            &container_id,
            "lncli",
            "--network=regtest",
            "payinvoice",
            "--force",
            bolt11,
        ])
        .output()
        .await?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        anyhow::bail!(
            "lncli payinvoice failed (exit {})\nstdout: {stdout}\nstderr: {stderr}",
            out.status
        );
    }
    Ok(())
}

/// Extract the BOLT11 payment request from a VM renew / subscription renew
/// API response body (raw JSON `Value`).
///
/// The response shape is:
/// ```json
/// { "data": { "data": { "lightning": "lnbc..." } } }
/// ```
pub fn extract_bolt11(renew_response: &serde_json::Value) -> anyhow::Result<String> {
    let bolt11 = renew_response["data"]["data"]["lightning"]
        .as_str()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No lightning invoice found in renew response. \
                 Expected data.data.lightning to be a string. \
                 Response: {}",
                renew_response
            )
        })?
        .to_string();
    Ok(bolt11)
}
