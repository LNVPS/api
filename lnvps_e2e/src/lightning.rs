//! Helpers for paying Lightning invoices from E2E tests.
//!
//! The `lnd-payer` docker service has a funded channel open to the `lnd`
//! service (the API's node).  Tests call [`pay_invoice`] to pay a BOLT11
//! payment request via `lncli` inside that container.

/// Name of the payer LND docker-compose service.
/// Resolved at runtime via `docker compose ps -q lnd-payer`.
const PAYER_SERVICE: &str = "lnd-payer";

/// Docker compose file used by the E2E environment.
///
/// Resolved relative to the workspace root: cargo runs tests with the crate
/// directory as CWD, where a relative path would not resolve.
const COMPOSE_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../docker-compose.e2e.yaml");

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

/// Create a BOLT11 invoice on the `lnd-payer` node, for the API's node to pay.
///
/// `amount_msat` of `None` produces an amountless invoice — the shape the
/// refund endpoint has to reject, because it would leave the sum refunded up
/// to the payer.
pub async fn create_invoice(amount_msat: Option<u64>, memo: &str) -> anyhow::Result<String> {
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

    let mut args = vec![
        "exec".to_string(),
        container_id,
        "lncli".to_string(),
        "--network=regtest".to_string(),
        "addinvoice".to_string(),
        format!("--memo={memo}"),
    ];
    if let Some(msat) = amount_msat {
        args.push(format!("--amt_msat={msat}"));
    }

    let out = tokio::process::Command::new("docker")
        .args(&args)
        .output()
        .await?;
    if !out.status.success() {
        anyhow::bail!(
            "lncli addinvoice failed (exit {})\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let body: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    Ok(body["payment_request"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no payment_request in addinvoice output: {body}"))?
        .to_string())
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
