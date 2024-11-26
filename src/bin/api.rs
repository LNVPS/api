use anyhow::Error;
use config::{Config, File};
use fedimint_tonic_lnd::connect;
use lnvps::api;
use lnvps::cors::CORS;
use lnvps::invoice::InvoiceHandler;
use lnvps::provisioner::lnvps::LNVpsProvisioner;
use lnvps::provisioner::Provisioner;
use lnvps::status::VmStateCache;
use lnvps::worker::{WorkJob, Worker};
use lnvps_db::{LNVpsDb, LNVpsDbMysql};
use log::error;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Deserialize, Serialize)]
pub struct Settings {
    pub listen: Option<String>,
    pub db: String,
    pub lnd: LndConfig,
    pub read_only: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LndConfig {
    pub url: String,
    pub cert: PathBuf,
    pub macaroon: PathBuf,
}

#[rocket::main]
async fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    let settings: Settings = Config::builder()
        .add_source(File::with_name("config.yaml"))
        .build()?
        .try_deserialize()?;

    let db = LNVpsDbMysql::new(&settings.db).await?;
    db.migrate().await?;

    let lnd = connect(settings.lnd.url, settings.lnd.cert, settings.lnd.macaroon).await?;
    let provisioner = LNVpsProvisioner::new(db.clone(), lnd.clone());
    #[cfg(debug_assertions)]
    {
        let setup_script = include_str!("../../dev_setup.sql");
        db.execute(setup_script).await?;
        provisioner.auto_discover().await?;
    }

    let status = VmStateCache::new();
    let mut worker = Worker::new(settings.read_only, db.clone(), lnd.clone(), status.clone());
    let sender = worker.sender();
    tokio::spawn(async move {
        loop {
            if let Err(e) = worker.handle().await {
                error!("worker-error: {}", e);
            }
        }
    });
    let mut handler = InvoiceHandler::new(lnd.clone(), db.clone(), sender.clone());
    tokio::spawn(async move {
        loop {
            if let Err(e) = handler.listen().await {
                error!("invoice-error: {}", e);
            }
        }
    });
    // request work every 30s to check vm status
    let db_clone = db.clone();
    let sender_clone = sender.clone();
    tokio::spawn(async move {
        loop {
            if let Ok(vms) = db_clone.list_vms().await {
                for vm in vms {
                    if let Err(e) = sender_clone.send(WorkJob::CheckVm { vm_id: vm.id }) {
                        error!("failed to send check vm: {}", e);
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });

    let db: Box<dyn LNVpsDb> = Box::new(db.clone());
    let pv: Box<dyn Provisioner> = Box::new(provisioner);

    let mut config = rocket::Config::default();
    let ip: SocketAddr = match &settings.listen {
        Some(i) => i.parse()?,
        None => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8000),
    };
    config.address = ip.ip();
    config.port = ip.port();

    if let Err(e) = rocket::Rocket::custom(config)
        .attach(CORS)
        .manage(db)
        .manage(pv)
        .manage(status)
        .mount("/", api::routes())
        .launch()
        .await
    {
        error!("{}", e);
    }

    Ok(())
}
