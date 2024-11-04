extern crate core;

use crate::cors::CORS;
use crate::provisioner::Provisioner;
use crate::settings::Settings;
use anyhow::Error;
use config::{Config, File};
use log::error;
use rocket::routes;
use sqlx::MySqlPool;

mod api;
mod cors;
mod db;
mod nip98;
mod provisioner;
mod proxmox;
mod settings;
mod vm;

#[rocket::main]
async fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    let config: Settings = Config::builder()
        .add_source(File::with_name("config.toml"))
        .build()?
        .try_deserialize()?;

    let db = MySqlPool::connect(&config.db).await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    let provisioner = Provisioner::new(db);

    if let Err(e) = rocket::build()
        .attach(CORS)
        .manage(provisioner)
        .mount("/", api::routes())
        .launch()
        .await
    {
        error!("{}", e);
    }

    Ok(())
}
