use anyhow::{Context, Result};
use clap::Parser;
use config::{Config, File};
use lnvps_api::gateway_import::{
    CONFIRM_ENV, FsCredentials, GatewayRowSpec, HttpGatewayAdmin, ImportOptions, confirm_apply,
    import_providers, next_steps, render_report,
};
use lnvps_api::settings::Settings;
use lnvps_db::{EncryptionContext, LNVpsDb, LNVpsDbMysql};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[clap(about = "Import payment_method_config rows as providers of the LNVPS gateway project")]
struct Args {
    #[clap(short, long)]
    config: Vec<PathBuf>,

    #[clap(long)]
    gateway_url: Option<String>,

    #[clap(long)]
    admin_token: Option<String>,

    #[clap(long)]
    tenant: u64,

    #[clap(long)]
    company_id: Option<u64>,

    #[clap(long)]
    apply: bool,

    #[clap(long)]
    create_gateway_row: bool,

    #[clap(long)]
    gateway_api_key: Option<String>,

    #[clap(long)]
    webhook_secret: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    confirm_apply(args.apply, std::env::var(CONFIRM_ENV).ok().as_deref())?;
    let admin_token = args
        .admin_token
        .clone()
        .or_else(|| std::env::var("GATEWAY_ADMIN_TOKEN").ok())
        .context("pass --admin-token or set GATEWAY_ADMIN_TOKEN")?;
    let args_gateway_url = args
        .gateway_url
        .clone()
        .or_else(|| std::env::var("GATEWAY_URL").ok());

    let settings: Settings = {
        let mut builder = Config::builder();
        if args.config.is_empty() {
            builder = builder.add_source(File::from(PathBuf::from("config.yaml")));
        } else {
            for path in &args.config {
                builder = builder.add_source(File::from(path.clone()));
            }
        }
        builder.build()?.try_deserialize()?
    };

    if let Ok(hex_key) = std::env::var(lnvps_api::settings::ENCRYPTION_KEY_ENV) {
        EncryptionContext::init_from_hex(&hex_key)?;
    } else if let Some(ref encryption_config) = settings.encryption {
        EncryptionContext::init_from_file(
            &encryption_config.key_file,
            encryption_config.auto_generate,
        )?;
    }

    let gateway_url = args_gateway_url
        .or_else(|| settings.gateway.as_ref().map(|g| g.url.clone()))
        .context("pass --gateway-url or set the gateway section in the config")?;

    let db: Arc<dyn LNVpsDb> = Arc::new(LNVpsDbMysql::new(&settings.db).await?);
    let gateway_row = if args.create_gateway_row {
        let api_key = args
            .gateway_api_key
            .clone()
            .or_else(|| std::env::var("GATEWAY_API_KEY").ok())
            .context("pass --gateway-api-key or set GATEWAY_API_KEY")?;
        let webhook_secret = args
            .webhook_secret
            .clone()
            .or_else(|| std::env::var("GATEWAY_WEBHOOK_SECRET").ok())
            .context("pass --webhook-secret or set GATEWAY_WEBHOOK_SECRET")?;
        Some(GatewayRowSpec {
            url: gateway_url.clone(),
            api_key,
            webhook_secret,
        })
    } else {
        None
    };
    let admin = HttpGatewayAdmin::new(&gateway_url, &admin_token);
    let report = import_providers(
        &db,
        &admin,
        &FsCredentials,
        &ImportOptions {
            tenant: args.tenant,
            apply: args.apply,
            company_id: args.company_id,
            gateway_row,
        },
    )
    .await?;
    print!("{}", render_report(&report));
    if args.apply {
        print!("{}", next_steps(&report, &gateway_url));
    }
    if !args.apply {
        println!("Nothing was changed. Re-run with --apply to create the providers.");
    }
    Ok(())
}
