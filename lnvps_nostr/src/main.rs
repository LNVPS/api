use anyhow::Result;
use config::{Config, File};
use lnvps_db::{LNVpsDbMysql, nostr::LNVPSNostrDb};
use log::info;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

mod routes;

#[derive(Clone, Deserialize)]
struct Settings {
    /// Database connection string
    db: String,
    /// Listen address for http server
    listen: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let settings: Settings = Config::builder()
        .add_source(File::from(PathBuf::from("config.yaml")))
        .build()?
        .try_deserialize()?;

    // Connect database
    let db = LNVpsDbMysql::new(&settings.db).await?;
    let db: Arc<dyn LNVPSNostrDb> = Arc::new(db);

    let ip: SocketAddr = match &settings.listen {
        Some(i) => i.parse()?,
        None => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8000),
    };
    let listener = TcpListener::bind(ip).await?;
    info!("Listening on {}", ip);
    let router = routes::routes(db);
    axum::serve(listener, router.layer(CorsLayer::permissive())).await?;

    Ok(())
}
