use anyhow::Error;
use clap::{Parser, ValueEnum};
use config::{Config, File};
use lnvps_api::data_migration::run_data_migrations;
use lnvps_api::dvm::start_dvms;
use lnvps_api::payments::listen_all_payments;
use lnvps_api::settings::Settings;
use lnvps_api::worker::Worker;
use lnvps_api_common::{
    ChannelWorkCommander, CountryResolver, MaxmindCountryResolver, RedisWorkCommander,
    VmHistoryLogger, WorkCommander,
};
use lnvps_api_common::{VatClient, VmStateCache, WorkJob, make_exchange_service};
use std::fmt::{Display, Formatter};

use lnvps_db::{EncryptionContext, LNVpsDb, LNVpsDbBase, LNVpsDbMysql};
use log::{error, info, warn};
use nostr_sdk::{Client, Keys};

use axum::Router;
use lnvps_api::api::*;
use lnvps_api::subscription::SubscriptionHandler;
use payments_rs::lightning::setup_crypto_provider;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket};
use tower_http::cors::CorsLayer;

#[derive(Parser)]
#[clap(about, version, author)]
struct Args {
    /// Path to one or more config files. Files are layered in order, so values
    /// in later files override earlier ones. Defaults to `config.yaml` when no
    /// paths are given.
    #[clap(short, long)]
    config: Vec<PathBuf>,

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

    let settings: Settings = {
        let mut builder = Config::builder();
        if args.config.is_empty() {
            builder = builder.add_source(File::from(PathBuf::from("config.yaml")));
        } else {
            // Explicit files are layered in order; later files override earlier.
            for path in &args.config {
                builder = builder.add_source(File::from(path.clone()));
            }
        }
        builder.build()?.try_deserialize()?
    };

    // Email verification gates VM ordering, but it can only be delivered over
    // SMTP. When SMTP is unconfigured the verification requirement is skipped so
    // ordering still works — warn so the operator knows this is in effect.
    if settings.smtp.is_none() {
        warn!(
            "SMTP is not configured: email verification is disabled and VM ordering will not require a verified email"
        );
    }

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
    if std::env::var("LNVPS_NO_DEV_SETUP").is_err() {
        let setup_script = include_str!("../../dev_setup.sql");
        db.execute(setup_script).await?;
        info!("Executed dev_setup.sql");
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

    // Optional IP -> country geolocation for VAT place-of-supply evidence.
    let geoip: Option<Arc<dyn CountryResolver>> = match &settings.geoip_database {
        Some(path) => match MaxmindCountryResolver::open(path) {
            Ok(r) => {
                info!("Loaded GeoIP database from {}", path.display());
                Some(Arc::new(r))
            }
            Err(e) => {
                error!("Failed to load GeoIP database {}: {}", path.display(), e);
                None
            }
        },
        None => None,
    };

    let status = if let Some(redis_config) = &settings.redis {
        VmStateCache::new_with_redis(redis_config.clone()).await?
    } else {
        VmStateCache::new()
    };
    let vm_history = VmHistoryLogger::new(db.clone());

    let work_commander: Arc<dyn WorkCommander> = if let Some(redis_config) = &settings.redis {
        Arc::new(RedisWorkCommander::new(&redis_config.url, "workers", "api-worker").await?)
    } else {
        Arc::new(ChannelWorkCommander::new())
    };

    // One shared VAT rate cache for the whole process. It is populated now and
    // refreshed periodically; the same instance is handed to the subscription
    // handler (and thus every PricingEngine clone) so rate updates are visible
    // everywhere without restarting. Until the first successful refresh no rates
    // are known and tax falls back to 0%.
    let vat = VatClient::new();
    match vat.refresh_rates().await {
        Ok(n) => info!("Loaded {} VAT rates", n),
        Err(e) => warn!(
            "Failed to load VAT rates (tax will be 0% until refreshed): {}",
            e
        ),
    }
    tasks.push(tokio::spawn({
        let vat = vat.clone();
        async move {
            loop {
                // Refresh once a day - standard rates change rarely.
                tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
                match vat.refresh_rates().await {
                    Ok(n) => info!("Refreshed {} VAT rates", n),
                    Err(e) => error!("Failed to refresh VAT rates: {}", e),
                }
            }
        }
    }));

    let sub_handler = SubscriptionHandler::new(
        settings.clone(),
        db.clone(),
        node.clone(),
        exchange.clone(),
        vat.clone(),
        work_commander.clone(),
        status.clone(),
    )?;
    sub_handler.vm_provisioner().init().await?;

    let worker = Worker::new(
        db.clone(),
        work_commander.clone(),
        sub_handler.clone(),
        node.clone(),
        &settings,
        status.clone(),
        nostr_client.clone(),
    )
    .await?;
    let mode = args.mode.unwrap_or(vec![ExecMode::Worker, ExecMode::Api]);

    if mode.contains(&ExecMode::Worker) {
        // Data migrations touch hosts, ARP tables, DNS, etc. — worker concerns only.
        run_data_migrations(db.clone(), sub_handler.vm_provisioner(), &settings).await?;

        tasks.push(worker.spawn_job_interval(WorkJob::CheckVms, Duration::from_secs(30)));
        tasks.push(worker.spawn_job_interval(WorkJob::CheckSubscriptions, Duration::from_secs(30)));
        // Refresh cached router tunnel/BGP session/route state + traffic every 60s
        tasks.push(worker.spawn_job_interval(WorkJob::SyncRouterState, Duration::from_secs(60)));
        // Automated referral payouts are opt-in (config-gated); run hourly.
        if settings.referral.is_some() {
            tasks.push(
                worker
                    .spawn_job_interval(WorkJob::ProcessReferralPayouts, Duration::from_secs(3600)),
            );
        }
        tasks.push(worker.spawn_handler_loop());

        // check all nostr domains every 10 minutes for CNAME entries (enable/disable as needed)
        #[cfg(feature = "nostr-domain")]
        {
            tasks.push(
                worker.spawn_job_interval(WorkJob::CheckNostrDomains, Duration::from_secs(600)),
            );
        }

        // check vms now to get current state
        worker.send(WorkJob::CheckVms).await?;
    }

    // Payment settlement handlers run in API mode only.
    //
    // This is deliberate, not just to avoid double-processing when API and
    // worker are separate processes:
    //   * Revolut / Stripe / Bitvora settle via HTTP webhooks. The
    //     `/api/v1/webhook/*` endpoints hand messages to the payment handlers
    //     over an IN-PROCESS broadcast (`payments_rs::webhook::WEBHOOK_BRIDGE`),
    //     so the handler MUST live in the same process as the HTTP listener.
    //   * The LND invoice subscription is a direct node stream; running it in
    //     the single API process keeps settlement in one place.
    // Settlement itself only marks payments paid and enqueues jobs
    // (`SpawnVm`, `ProcessVmUpgrade`, ...); the worker performs the actual
    // provisioning. NOTE: if you scale the API tier to multiple replicas while
    // using LND, each replica opens its own invoice subscription — run a single
    // API replica (or move LND settlement to the worker) to avoid double work.
    if mode.contains(&ExecMode::Api) {
        tasks.extend(
            listen_all_payments(&settings, node.clone(), db.clone(), sub_handler.clone()).await?,
        );
    }

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

    // DVMs subscribe to Nostr job requests to place VM orders — a single-consumer
    // background listener (like the Telegram poller), so run it in the singleton
    // worker to avoid duplicate order handling when the API tier is scaled out.
    #[cfg(feature = "nostr-dvm")]
    if mode.contains(&ExecMode::Worker) {
        if let Some(nostr_client) = &nostr_client {
            tasks.push(start_dvms(nostr_client.clone(), sub_handler.clone()));
        } else {
            warn!("nostr-dvm feature is enabled but no nostr config is set; skipping DVMs");
        }
    }

    // request for host info to be patched
    worker.send(WorkJob::PatchHosts).await?;

    // Telegram bot poller completes account linking. `getUpdates` allows only a
    // SINGLE consumer per bot token, so it must run in exactly one process.
    // It runs in the worker (the singleton tier, co-located with notification
    // SENDING via the SendNotification job) so the API tier can be scaled to
    // multiple replicas without every replica opening a conflicting poller.
    if mode.contains(&ExecMode::Worker)
        && let Some(tg) = &settings.telegram
    {
        let bot = lnvps_api::notifications::TelegramBot::new(
            tg.token.clone(),
            reqwest::Client::new(),
            db.clone(),
        );
        tasks.push(tokio::spawn(async move {
            if let Err(e) = bot.run().await {
                error!("Telegram bot poller exited: {}", e);
            }
        }));
    }

    if mode.contains(&ExecMode::Api) {
        let ip: SocketAddr = match &settings.listen {
            Some(i) => i.parse()?,
            None => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8000),
        };
        let listener = bind_address(ip).await?;
        info!("Listening on {}", ip);
        let mut router = Router::new()
            .merge(docs_router())
            .merge(main_router())
            .merge(contacts_router())
            .merge(webhook_router())
            .merge(subscriptions_router())
            .merge(ip_space_router())
            .merge(referral_router())
            .merge(legal_router());

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
                        sub_handler,
                        history: vm_history,
                        settings,
                        rates: exchange,
                        work_sender: worker.commander(),
                        geoip: geoip.clone(),
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

async fn bind_address(address: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(1024)
}
