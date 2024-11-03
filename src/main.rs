use crate::provisioner::Provisioner;
use crate::settings::Settings;
use config::{Config, File};
use sqlx::MySqlPool;

mod db;
mod provisioner;
mod proxmox;
mod settings;
mod vm;

#[rocket::main]
async fn main() -> Result<(), anyhow::Error> {
    pretty_env_logger::init();

    let config: Settings = Config::builder()
        .add_source(File::with_name("config.toml"))
        .build()?
        .try_deserialize()?;

    let db = MySqlPool::connect(&config.db).await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    let provisioner = Provisioner::new(db.clone());

    Ok(())
}
