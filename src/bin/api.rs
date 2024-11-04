use anyhow::Error;
use config::{Config, File};
use lnvps::api;
use lnvps::cors::CORS;
use lnvps::provisioner::Provisioner;
use log::error;
use serde::{Deserialize, Serialize};
use sqlx::{Executor, MySqlPool};

#[derive(Debug, Deserialize, Serialize)]
pub struct Settings {
    pub db: String,
}

#[rocket::main]
async fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    let config: Settings = Config::builder()
        .add_source(File::with_name("config.toml"))
        .build()?
        .try_deserialize()?;

    let db = MySqlPool::connect(&config.db).await?;
    sqlx::migrate!().run(&db).await?;
    let provisioner = Provisioner::new(db.clone());
    #[cfg(debug_assertions)]
    {
        let setup_script = include_str!("../../dev_setup.sql");
        db.execute(setup_script).await?;
        provisioner.auto_discover().await?;
    }

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
