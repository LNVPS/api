use anyhow::{Context, Result};
use clap::Parser;
use config::{Config, File};
use lnvps_api::key_rotation::rotate_all;
use lnvps_api::settings::Settings;
use lnvps_db::{EncryptionContext, LNVpsDb, LNVpsDbMysql};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(about = "Re-encrypt every encrypted column under LNVPS_ENCRYPTION_KEY")]
struct Args {
    #[arg(long)]
    config: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let mut builder = Config::builder();
    if args.config.is_empty() {
        builder = builder.add_source(File::from(PathBuf::from("config.yaml")));
    } else {
        for path in &args.config {
            builder = builder.add_source(File::from(path.clone()));
        }
    }
    let settings: Settings = builder.build()?.try_deserialize()?;

    let new_key = std::env::var(lnvps_api::settings::ENCRYPTION_KEY_ENV)
        .context("LNVPS_ENCRYPTION_KEY must hold the new key")?;
    let previous = lnvps_db::encryption::previous_keys_from_env();
    EncryptionContext::init_from_hex_with_previous(&new_key, &previous)?;
    let ctx = EncryptionContext::get()?;

    let db: Arc<dyn LNVpsDb> = Arc::new(LNVpsDbMysql::new(&settings.db).await?);
    let changed = rotate_all(db.as_ref(), ctx).await?;
    println!(
        "re-encrypted {changed} values under key id {}; the previous keys can now be removed",
        ctx.key_id()
    );
    Ok(())
}
