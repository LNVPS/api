use anyhow::Error;
use config::{Config, File};
use lnvps::api;
use lnvps::cors::CORS;
use lnvps::provisioner::{LNVpsProvisioner, Provisioner};
use lnvps_db::{LNVpsDb, LNVpsDbMysql};
use log::error;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Settings {
    pub db: String,
}

#[rocket::main]
async fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    let config: Settings = Config::builder()
        .add_source(File::with_name("config.yaml"))
        .build()?
        .try_deserialize()?;

    let db = LNVpsDbMysql::new(&config.db).await?;
    db.migrate().await?;

    let provisioner = LNVpsProvisioner::new(db.clone());
    #[cfg(debug_assertions)]
    {
        let setup_script = include_str!("../../dev_setup.sql");
        db.execute(setup_script).await?;
        provisioner.auto_discover().await?;
    }

    let db: Box<dyn LNVpsDb> = Box::new(db.clone());
    let pv: Box<dyn Provisioner> = Box::new(provisioner);
    if let Err(e) = rocket::build()
        .attach(CORS)
        .manage(db)
        .manage(pv)
        .mount("/", api::routes())
        .launch()
        .await
    {
        error!("{}", e);
    }

    Ok(())
}
