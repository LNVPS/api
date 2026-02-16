use anyhow::Error;
use clap::{Parser, ValueEnum};
use config::{Config, File};
use lnvps_api::data_migration::run_data_migrations;
use lnvps_api::dvm::start_dvms;
use lnvps_api::payments::listen_all_payments;
use lnvps_api::settings::Settings;
use lnvps_api::worker::Worker;
use lnvps_api_common::VmHistoryLogger;
use lnvps_api_common::{VmStateCache, WorkJob, make_exchange_service};
use std::fmt::{Display, Formatter};

use lnvps_db::{EncryptionContext, LNVpsDb, LNVpsDbBase, LNVpsDbMysql};
use log::{error, info};
use nostr_sdk::{Client, Keys};

use axum::Router;
use lnvps_api::api::*;
use payments_rs::lightning::setup_crypto_provider;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

#[derive(Parser)]
#[clap(about, version, author)]
struct Args {
    /// Path to the config file
    #[clap(short, long)]
    config: Option<PathBuf>,

    /// Where to write the log file
    #[clap(long)]
    log: Option<PathBuf>,

    #[clap(long)]
    mode: Option<Vec<ExecMode>>,
}

#[derive(Clone, ValueEnum, PartialEq)]
enum ExecMode {
    /// Run the worker process
    Worker,

    /// Start the main user facing API
    Api,
}

impl Display for ExecMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecMode::Worker => write!(f, "Worker"),
            ExecMode::Api => write!(f, "Api"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    setup_crypto_provider();

    let args = Args::parse();
    let mut tasks = Vec::new();

    let settings: Settings = Config::builder()
        .add_source(File::from(
            args.config.unwrap_or(PathBuf::from("config.yaml")),
        ))
        .build()?
        .try_deserialize()?;

    // Initialize encryption if configured
    if let Some(ref encryption_config) = settings.encryption {
        EncryptionContext::init_from_file(
            &encryption_config.key_file,
            encryption_config.auto_generate,
        )?;
        info!("Database encryption initialized");
    }

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

    let exchange = make_exchange_service(&settings.redis);
    let node = settings.get_node().await?;

    let status = if let Some(redis_config) = &settings.redis {
        VmStateCache::new_with_redis(redis_config.clone()).await?
    } else {
        VmStateCache::new()
    };
    let vm_history = Arc::new(VmHistoryLogger::new(db.clone()));
    let provisioner = settings.get_provisioner(db.clone(), node.clone(), exchange.clone());
    provisioner.init().await?;

    // run data migrations
    run_data_migrations(db.clone(), provisioner.clone(), &settings).await?;

    let worker = Worker::new(
        db.clone(),
        provisioner.clone(),
        &settings,
        status.clone(),
        nostr_client.clone(),
    )
    .await?;

    let mode = args.mode.unwrap_or(vec![ExecMode::Worker, ExecMode::Api]);

    if mode.contains(&ExecMode::Worker) {
        tasks.push(worker.spawn_job_interval(WorkJob::CheckVms, Duration::from_secs(30)));
        tasks.push(worker.spawn_handler_loop());

        // check all nostr domains every 10 minutes for CNAME entries (enable/disable as needed)
        #[cfg(feature = "nostr-domain")]
        {
            tasks.push(
                worker.spawn_job_interval(WorkJob::CheckNostrDomains, Duration::from_secs(600)),
            );
        }
    }

    // setup payment handlers
    tasks.extend(listen_all_payments(
        &settings,
        node.clone(),
        db.clone(),
        worker.commander(),
    ).await?);

    // refresh rates every 1min
    let rates = exchange.clone();
    tasks.push(tokio::spawn(async move {
        loop {
            match rates.fetch_rates().await {
                Ok(z) => {
                    for r in z {
                        rates.set_rate(r.ticker, r.rate).await;
                    }
                }
                Err(e) => error!("Failed to fetch rates: {}", e),
            }
            tokio::time::sleep(Duration::from_secs(120)).await;
        }
    }));

    #[cfg(feature = "nostr-dvm")]
    {
        let nostr_client = nostr_client.unwrap();
        tasks.push(start_dvms(nostr_client.clone(), provisioner.clone()));
    }

    // request for host info to be patched
    worker.send(WorkJob::PatchHosts).await?;

    if mode.contains(&ExecMode::Api) {
        let ip: SocketAddr = match &settings.listen {
            Some(i) => i.parse()?,
            None => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8000),
        };
        let listener = TcpListener::bind(ip).await?;
        info!("Listening on {}", ip);
        let mut router = Router::new()
            .merge(main_router())
            .merge(contacts_router())
            .merge(webhook_router())
            .merge(subscriptions_router())
        .merge(ip_space_router());

        #[cfg(feature = "openapi")]
        {
            mod openapi {
                include!(concat!(env!("OUT_DIR"), "/openapi.rs"));
            }

            router = router
                .route(
                    "/openapi.json",
                    axum::routing::get(async || {
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            openapi::OPENAPI_JSON,
                        )
                    }),
                )
                .route(
                    "/swagger",
                    axum::routing::get(async move || {
                        axum::response::Html(include_str!("../api/swagger.html"))
                    }),
                );
        }
        #[cfg(feature = "nostr-domain")]
        {
            router = router.merge(nostr_domain_router());
        }
        tasks.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(
                listener,
                router
                    .layer(CorsLayer::very_permissive())
                    .with_state(RouterState {
                        db,
                        state: status,
                        provisioner,
                        history: vm_history,
                        settings,
                        rates: exchange,
                        work_sender: worker.commander(),
                    }),
            )
            .await
            {
                error!("Error while running server: {}", e);
            }
        }));
    }

    for t in tasks {
        t.await?;
    }
    Ok(())
}
