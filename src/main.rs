use std::default;

use log::info;
use proxmox_client::{AuthenticationKind, HttpApiClient, TlsOptions, Token};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    pretty_env_logger::init();

    let addr = "https://10.97.0.234:8006/";
    let url = addr.parse().unwrap();
    let client = proxmox_client::Client::with_options(
        url,
        TlsOptions::Insecure,
        Default::default())?;

    client.set_authentication(AuthenticationKind::Token(Token {
        userid: "root@pam!test-dev".to_string(),
        prefix: "PVEAPIToken".to_string(),
        value: "e2d8d39f-63ce-48f0-a025-b428d29a26e3".to_string(),
    }));

    let rsp = client.get("/api2/json/version").await?;
    let string = String::from_utf8(rsp.body)?;
    info!("Version: {}", string);
    Ok(())
}
