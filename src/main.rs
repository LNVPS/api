use config::{Config, File};
use log::info;
use crate::proxmox::{Client, VersionResponse};
use crate::settings::Settings;

mod settings;
mod proxmox;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    pretty_env_logger::init();

    let config: Settings = Config::builder()
        .add_source(File::with_name("config.toml"))
        .build()?.try_deserialize()?;

    let client = Client::new(config.server.parse()?)
        .with_api_token(
            &config.user,
            &config.realm,
            &config.token_id,
            &config.secret,
        );

    let nodes = client.list_nodes().await.expect("Error listing nodes");
    for n in &nodes {
        let vms = client.list_vms(&n.name).await?;
        for vm in &vms {
        }
    }
    Ok(())
}
