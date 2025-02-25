use anyhow::Error;
use clap::Parser;
use config::{Config, File};
use fedimint_tonic_lnd::connect;
use lnvps::api;
use lnvps::cors::CORS;
use lnvps::exchange::ExchangeRateCache;
use lnvps::invoice::InvoiceHandler;
use lnvps::provisioner::Provisioner;
use lnvps::settings::Settings;
use lnvps::status::VmStateCache;
use lnvps::worker::{WorkJob, Worker};
use lnvps_db::{LNVpsDb, LNVpsDbMysql};
use log::error;
use nostr::Keys;
use nostr_sdk::Client;
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Parser)]
#[clap(about, version, author)]
struct Args {
    #[clap(short, long)]
    config: Option<String>,
}

#[rocket::main]
async fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    let args = Args::parse();
    let settings: Settings = Config::builder()
        .add_source(File::with_name(
            &args.config.unwrap_or("config.yaml".to_string()),
        ))
        .build()?
        .try_deserialize()?;

    let db = LNVpsDbMysql::new(&settings.db).await?;
    db.migrate().await?;

    let exchange = ExchangeRateCache::new();
    let lnd = connect(
        settings.lnd.url.clone(),
        settings.lnd.cert.clone(),
        settings.lnd.macaroon.clone(),
    )
    .await?;
    #[cfg(debug_assertions)]
    {
        let setup_script = include_str!("../../dev_setup.sql");
        db.execute(setup_script).await?;
    }

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
    let router = settings.router.as_ref().map(|r| r.get_router());
    let status = VmStateCache::new();
    let worker_provisioner =
        settings
            .provisioner
            .get_provisioner(db.clone(), router, lnd.clone(), exchange.clone());
    worker_provisioner.init().await?;

    let mut worker = Worker::new(
        db.clone(),
        worker_provisioner,
        &settings,
        status.clone(),
        nostr_client.clone(),
    );
    let sender = worker.sender();

    // send a startup notification
    if let Some(admin) = &settings.smtp.and_then(|s| s.admin) {
        sender.send(WorkJob::SendNotification {
            title: Some("Startup".to_string()),
            message: "System is starting!".to_string(),
            user_id: *admin,
        })?;
    }

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
            sleep(Duration::from_secs(5)).await;
        }
    });
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
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    let router = settings.router.as_ref().map(|r| r.get_router());
    let provisioner =
        settings
            .provisioner
            .get_provisioner(db.clone(), router, lnd.clone(), exchange.clone());

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
        .manage(exchange)
        .manage(sender)
        .mount("/", api::routes())
        .mount(
            "/swagger",
            make_swagger_ui(&SwaggerUIConfig {
                url: "../openapi.json".to_owned(),
                ..Default::default()
            }),
        )
        .launch()
        .await
    {
        error!("{}", e);
    }

    Ok(())
}
