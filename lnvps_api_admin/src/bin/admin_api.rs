use anyhow::Error;
use clap::Parser;
use config::{Config, File};
use lnvps_api_admin::admin;
use lnvps_api_admin::settings::Settings;
use lnvps_api_common::{VmStateCache, WorkCommander};
use lnvps_common::CORS;
use lnvps_db::{EncryptionContext, LNVpsDb, LNVpsDbMysql};
use log::{error, info};
use rocket::http::Method;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

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
    let db: Arc<dyn LNVpsDb> = Arc::new(db);

    // Initialize VM state cache
    let vm_state_cache = if let Some(redis_config) = &settings.redis {
        VmStateCache::new_with_redis(redis_config.clone())?
    } else {
        VmStateCache::new()
    };

    // Initialize WorkCommander for job distribution (publisher mode)
    let work_commander = if let Some(redis_config) = &settings.redis {
        Some(WorkCommander::new_publisher(&redis_config.url)?)
    } else {
        None
    };

    let mut config = rocket::Config::default();
    let ip: SocketAddr = match &settings.listen {
        Some(i) => i.parse()?,
        None => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8001),
    };
    info!("Starting api server on {}", ip);
    config.address = ip.ip();
    config.port = ip.port();

    if let Err(e) = rocket::Rocket::custom(config)
        .manage(db.clone())
        .manage(settings.clone())
        .manage(vm_state_cache.clone())
        .manage(work_commander)
        .mount("/", admin::admin_routes())
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
