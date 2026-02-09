use anyhow::{Error, bail};
use async_trait::async_trait;
use clap::Parser;
use config::{Config, File};
use lnvps_api_admin::admin::admin_router;
use lnvps_api_admin::settings::Settings;
use lnvps_api_common::{
    RedisWorkCommander, RedisWorkFeedback, VmStateCache, WorkCommander, WorkJob, WorkJobMessage,
    make_exchange_service,
};
use lnvps_db::{EncryptionContext, LNVpsDb, LNVpsDbMysql};
use log::info;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
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
}

#[tokio::main]
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
        VmStateCache::new_with_redis(redis_config.clone()).await?
    } else {
        VmStateCache::new()
    };

    // Initialize WorkCommander for job distribution (publisher mode)
    let work_commander: Arc<dyn WorkCommander> = if let Some(redis_config) = &settings.redis {
        Arc::new(RedisWorkCommander::new_publisher(&redis_config.url).await?)
    } else {
        Arc::new(NeverWorkCommander)
    };

    let feedback = if let Some(redis_config) = &settings.redis {
        Some(RedisWorkFeedback::new(&redis_config.url).await?)
    } else {
        None
    };

    // Initialize exchange rate service
    let exchange = make_exchange_service(&settings.redis);
    let ip: SocketAddr = match &settings.listen {
        Some(i) => i.parse()?,
        None => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8001),
    };
    let listener = TcpListener::bind(ip).await?;
    info!("Listening on {}", ip);
    let router = admin_router(
        db.clone(),
        work_commander,
        vm_state_cache,
        exchange,
        feedback,
    );
    axum::serve(listener, router.layer(CorsLayer::very_permissive())).await?;

    Ok(())
}

struct NeverWorkCommander;

#[async_trait]
impl WorkCommander for NeverWorkCommander {
    async fn send(&self, _job: WorkJob) -> anyhow::Result<String> {
        bail!("Work commander not configured, not possible to send work jobs")
    }

    async fn recv(&self) -> anyhow::Result<Vec<WorkJobMessage>> {
        bail!("Work commander not configured, not possible to send work jobs")
    }

    async fn ack(&self, _id: &str) -> anyhow::Result<()> {
        Ok(())
    }
}
