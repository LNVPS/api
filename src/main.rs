use std::default;
use config::{Config, ConfigBuilder};
use log::info;
use proxmox_client::{AuthenticationKind, HttpApiClient, TlsOptions, Token};
use crate::settings::Settings;

mod settings;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    pretty_env_logger::init();

    let config: Settings = Config::builder()
        .add_source("config.toml")
        .build()?.try_deserialize()?;

    let client = proxmox_client::Client::with_options(
        config.server,
        TlsOptions::Insecure,
        Default::default())?;

    client.set_authentication(AuthenticationKind::Token(Token {
        userid: config.token_id.clone(),
        prefix: "PVEAPIToken".to_string(),
        value: config.secret.clone(),
        perl_compat: false,
    }));

    let rsp = client.get("/api2/json/version").await?;
    let string = String::from_utf8(rsp.body)?;
    info!("Version: {}", string);
    Ok(())
}
