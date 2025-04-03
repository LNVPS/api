mod routes;

use crate::routes::routes;
use anyhow::Result;
use config::{Config, File};
use lnvps_common::CORS;
use lnvps_db::{LNVPSNostrDb, LNVpsDbMysql};
use log::error;
use rocket::http::Method;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Deserialize)]
struct Settings {
    /// Database connection string
    db: String,
    /// Listen address for http server
    listen: Option<String>,
}

#[rocket::main]
async fn main() -> Result<()> {
    env_logger::init();

    let settings: Settings = Config::builder()
        .add_source(File::from(PathBuf::from("config.yaml")))
        .build()?
        .try_deserialize()?;

    // Connect database
    let db = LNVpsDbMysql::new(&settings.db).await?;
    let db: Arc<dyn LNVPSNostrDb> = Arc::new(db);

    let mut config = rocket::Config::default();
    let ip: SocketAddr = match &settings.listen {
        Some(i) => i.parse()?,
        None => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8000),
    };
    config.address = ip.ip();
    config.port = ip.port();

    if let Err(e) = rocket::Rocket::custom(config)
        .manage(db.clone())
        .manage(settings.clone())
        .attach(CORS)
        .mount("/", routes())
        .mount(
            "/",
            vec![rocket::Route::ranked(
                isize::MAX,
                Method::Options,
                "/<catch_all_options_route..>",
                CORS,
            )],
        )
        .launch()
        .await
    {
        error!("{}", e);
    }

    Ok(())
}
