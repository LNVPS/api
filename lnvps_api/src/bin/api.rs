use anyhow::Error;
use clap::Parser;
use config::{Config, File};
use lnvps_api::api;
use lnvps_api::data_migration::run_data_migrations;
use lnvps_api::dvm::start_dvms;
use lnvps_api::lightning::get_node;
use lnvps_api::payments::listen_all_payments;
use lnvps_api::settings::Settings;
use lnvps_api_common::VmHistoryLogger;
use lnvps_api::worker::Worker;
use lnvps_api::ExchangeRateService;
use lnvps_api_common::{DefaultRateCache, VmStateCache, WorkJob};
use lnvps_common::CORS;
use lnvps_db::{LNVpsDb, LNVpsDbBase, LNVpsDbMysql};
use log::error;
use nostr::Keys;
use nostr_sdk::Client;
use rocket::http::Method;
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[clap(about, version, author)]
struct Args {
    /// Path to the config file
    #[clap(short, long)]
    config: Option<PathBuf>,

    /// Where to write the log file
    #[clap(long)]
    log: Option<PathBuf>,
}

#[rocket::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

    let args = Args::parse();

    let settings: Settings = Config::builder()
        .add_source(File::from(
            args.config.unwrap_or(PathBuf::from("config.yaml")),
        ))
        .build()?
        .try_deserialize()?;

    // Connect database and migrate
    let db = LNVpsDbMysql::new(&settings.db).await?;
    db.migrate().await?;
    #[cfg(debug_assertions)]
    {
        let setup_script = include_str!("../../dev_setup.sql");
        db.execute(setup_script).await?;
    }
    let db: Arc<dyn LNVpsDb> = Arc::new(db);
    let nostr_client = if let Some(ref c) = settings.nostr {
        let cx = Client::builder().signer(Keys::parse(&c.nsec)?).build();
        for r in &c.relays {
            cx.add_relay(r.clone()).await?;
        }
        cx.connect().await;
        Some(cx)
    } else {
        None
    };

    let exchange: Arc<dyn ExchangeRateService> = Arc::new(DefaultRateCache::default());
    let node = get_node(&settings).await?;

    let status = if let Some(redis_config) = &settings.redis {
        VmStateCache::new_with_redis(redis_config.clone())?
    } else {
        VmStateCache::new()
    };
    let vm_history = Arc::new(VmHistoryLogger::new(db.clone()));
    let provisioner = settings.get_provisioner(db.clone(), node.clone(), exchange.clone());
    provisioner.init().await?;

    // run data migrations
    run_data_migrations(db.clone(), provisioner.clone(), &settings).await?;

    let mut worker = Worker::new(
        db.clone(),
        provisioner.clone(),
        &settings,
        status.clone(),
        nostr_client.clone(),
    )?;
    let sender = worker.sender();
    tokio::spawn(async move {
        loop {
            if let Err(e) = worker.handle().await {
                error!("Worker handler failed: {}", e);
            }
            error!("Worker thread exited!")
        }
    });

    // setup payment handlers
    listen_all_payments(&settings, node.clone(), db.clone(), sender.clone())?;

    // request work every 30s to check vm status
    let sender_clone = sender.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = sender_clone.send(WorkJob::CheckVms) {
                error!("failed to send check vm: {}", e);
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    // refresh rates every 1min
    let rates = exchange.clone();
    tokio::spawn(async move {
        loop {
            match rates.fetch_rates().await {
                Ok(z) => {
                    for r in z {
                        rates.set_rate(r.0, r.1).await;
                    }
                }
                Err(e) => error!("Failed to fetch rates: {}", e),
            }
            tokio::time::sleep(Duration::from_secs(120)).await;
        }
    });

    #[cfg(feature = "nostr-dvm")]
    {
        let nostr_client = nostr_client.unwrap();
        start_dvms(nostr_client.clone(), provisioner.clone());
    }

    // request for host info to be patched
    sender.send(WorkJob::PatchHosts)?;

    let mut config = rocket::Config::default();
    let ip: SocketAddr = match &settings.listen {
        Some(i) => i.parse()?,
        None => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8000),
    };
    config.address = ip.ip();
    config.port = ip.port();

    if let Err(e) = rocket::Rocket::custom(config)
        .manage(db.clone())
        .manage(provisioner.clone())
        .manage(status.clone())
        .manage(exchange.clone())
        .manage(settings.clone())
        .manage(vm_history.clone())
        .manage(sender)
        .mount("/", api::routes())
        .mount(
            "/swagger",
            make_swagger_ui(&SwaggerUIConfig {
                url: "../openapi.json".to_owned(),
                ..Default::default()
            }),
        )
        .attach(CORS)
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
        error!("{:?}", e);
    }

    Ok(())
}
