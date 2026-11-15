use anyhow::{Result, bail};
use clap::Parser;
use config::{Config, File};
use lnvps_api::settings::Settings;
use lnvps_db::audit::verify_chain;
use lnvps_db::{LNVpsDb, LNVpsDbMysql};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(about = "Verify the audit_log hash chain; exits non-zero on tampering")]
struct Args {
    #[arg(long)]
    config: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
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
    let db: Arc<dyn LNVpsDb> = Arc::new(LNVpsDbMysql::new(&settings.db).await?);

    let mut head = None;
    let mut entries = 0u64;
    loop {
        let after = head
            .as_ref()
            .map(|h: &lnvps_db::audit::ChainHead| h.last_id)
            .unwrap_or(0);
        let batch = db.audit_range(after, 1000).await?;
        if batch.is_empty() {
            break;
        }
        match verify_chain(&batch, head.as_ref()) {
            Ok(h) => {
                entries += batch.len() as u64;
                head = Some(h);
            }
            Err(e) => bail!("audit log verification failed after {entries} entries: {e}"),
        }
    }
    println!(
        "audit log intact: {entries} entries, head {}",
        head.map(|h| h.last_hash).unwrap_or_default()
    );
    Ok(())
}
