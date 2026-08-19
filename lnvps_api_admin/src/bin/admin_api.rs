use anyhow::{Error, bail};
use async_trait::async_trait;
use clap::Parser;
use config::{Config, File};
use lnvps_api_admin::admin::admin_router;
use lnvps_api_admin::settings::Settings;
use lnvps_api_common::{
    RateLimiter, RedisWorkCommander, RedisWorkFeedback, VatClient, VmStateCache, WorkCommander,
    WorkJob, WorkJobMessage, handle_panic, make_exchange_service, nip98_payload_middleware,
    rate_limit_middleware,
};
use lnvps_db::{EncryptionContext, LNVpsDb, LNVpsDbBase, LNVpsDbMysql};
use log::{info, warn};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::net::TcpSocket;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowHeaders, Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;

/// CORS layer for the admin API.
///
/// Auth is carried in the `Authorization` header (NIP-98 / JWT), never cookies,
/// so credentials are NOT needed. Returning `Access-Control-Allow-Origin: *`
/// (rather than reflecting the origin like `very_permissive`) keeps Tor/Brave
/// working, which send `Origin: null` on cross-site requests — a `null`
/// allow-origin plus allow-credentials is rejected by browsers. Headers are
/// mirrored because a literal `*` does not cover `Authorization`.
fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(AllowHeaders::mirror_request())
        .expose_headers(Any)
}

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

    // This API is reachable only by authenticated admins, for whom the
    // underlying error is the useful part of a 500. The default is sanitised
    // and the public API must leave it that way: `lnvps_api_common` is compiled
    // once for both binaries, so this cannot be a compile-time choice.
    lnvps_api_common::set_verbose_internal_errors(true);

    let args = Args::parse();

    let settings: Settings = Config::builder()
        .add_source(File::from(
            args.config.unwrap_or(PathBuf::from("config.yaml")),
        ))
        .build()?
        .try_deserialize()?;

    // Initialize encryption: prefer the environment variable, otherwise fall
    // back to the key file configured in settings.
    if let Ok(hex_key) = std::env::var(lnvps_api_admin::settings::ENCRYPTION_KEY_ENV) {
        EncryptionContext::init_from_hex(&hex_key)?;
        info!("Database encryption initialized from environment");
    } else if let Some(ref encryption_config) = settings.encryption {
        EncryptionContext::init_from_file(
            &encryption_config.key_file,
            encryption_config.auto_generate,
        )?;
        info!("Database encryption initialized from key file");
    }

    // Connect database and migrate
    let db = LNVpsDbMysql::new(&settings.db).await?;
    db.migrate().await?;
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

    // EU VAT rates, refreshed daily, mirroring the public API. The admin API
    // reports the rate a user would be charged, and an empty table reports 0%
    // for every country — which reads as "this customer pays no VAT" rather
    // than "nothing is loaded". A failure here is logged, not fatal: every other
    // admin endpoint works without it, and the one that needs it says so.
    let vat = VatClient::new();
    match vat.refresh_rates().await {
        Ok(n) => info!("Loaded {} VAT rates", n),
        Err(e) => warn!(
            "Failed to load VAT rates (tax determination will report unavailable): {}",
            e
        ),
    }
    tokio::spawn({
        let vat = vat.clone();
        async move {
            loop {
                // Standard rates change rarely; daily is what the public API does.
                tokio::time::sleep(std::time::Duration::from_secs(24 * 60 * 60)).await;
                match vat.refresh_rates().await {
                    Ok(n) => info!("Refreshed {} VAT rates", n),
                    Err(e) => log::error!("Failed to refresh VAT rates: {}", e),
                }
            }
        }
    });
    let ip: SocketAddr = match &settings.listen {
        Some(i) => i.parse()?,
        None => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8001),
    };
    let listener = bind_address(ip).await?;
    info!("Listening on {}", ip);
    let router = admin_router(
        db.clone(),
        work_commander,
        vm_state_cache,
        exchange,
        feedback,
        // A misconfigured key is fatal at startup rather than at the first call
        // to a node: an admin API that starts and then cannot reach any node is
        // a much harder failure to read.
        match &settings.nostr {
            Some(config) => Some(config.control()?),
            None => None,
        },
        vat,
    );

    // Same cross-cutting stack as the public API. The admin surface previously
    // had none of it: no rate limiting in front of NIP-98 verification, and no
    // framing/MIME/referrer protection on the HTML it serves. Remember that the
    // LAST layer added is the OUTERMOST, so requests flow bottom-to-top.
    let app = router
        .layer(axum::middleware::from_fn(nip98_payload_middleware))
        .layer(axum::middleware::from_fn_with_state(
            RateLimiter::default().with_config(&settings.rate_limit),
            rate_limit_middleware,
        ))
        .layer(CatchPanicLayer::custom(handle_panic))
        .layer(cors_layer())
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::CONTENT_SECURITY_POLICY,
            axum::http::HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
        ));

    // `into_make_service_with_connect_info` gives the rate limiter a peer-address
    // fallback when a request arrives without forwarding headers.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn bind_address(address: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(1024)
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
