use anyhow::Result;
use log::info;
use std::path::PathBuf;
use std::sync::Arc;

use lnvps_agent::agent::SupportAgent;
use lnvps_agent::conversation::JsonFileStore;
use lnvps_agent::settings::{ENCRYPTION_KEY_ENV, Settings};
use lnvps_db::{EncryptionContext, LNVpsDb, LNVpsDbMysql};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    let settings = Settings::load()?;
    info!("LNVPS support agent starting...");
    info!("OpenAI URL: {}", settings.openai.base_url);
    info!("Model: {}", settings.openai.model);

    // Encrypted columns (a user's email, SSH key material, saved payment
    // instruments) are unreadable without this, and the failure would surface
    // as a confusing per-tool error rather than at startup.
    if let Ok(hex_key) = std::env::var(ENCRYPTION_KEY_ENV) {
        EncryptionContext::init_from_hex(&hex_key)?;
        info!("Database encryption initialized from environment");
    } else if let Some(ref encryption) = settings.encryption {
        EncryptionContext::init_from_file(&encryption.key_file, encryption.auto_generate)?;
        info!("Database encryption initialized from key file");
    } else {
        info!("No encryption key configured — encrypted columns will not be readable");
    }

    // Connect read-only: the agent is not the owner of this schema and must
    // never migrate it. A version skew is the API's problem to fix, and a
    // migration run from a support process would be a very bad surprise.
    let db: Arc<dyn LNVpsDb> = Arc::new(LNVpsDbMysql::new(&settings.db).await?);
    info!("Database connected");

    let history_path = settings
        .conversation_history_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("conversation_history"));
    info!("Conversation history: {}", history_path.display());

    let store = Arc::new(JsonFileStore::new(history_path).await?);
    let agent = SupportAgent::new(db, settings.clone(), store);

    let mut handles = Vec::new();

    if let Some(ref kind1_cfg) = settings.kind1 {
        info!(
            "Starting kind1 Nostr support channel: relays={:?}, mentions={:?}",
            kind1_cfg.relays, kind1_cfg.mention_pubkeys
        );
        let channel = Box::new(
            lnvps_agent::channel::kind1::Kind1SupportChannel::new(
                kind1_cfg.clone(),
                &settings.nsec,
            )
            .await?,
        );
        let agent = agent.clone();
        handles.push(tokio::spawn(async move {
            agent.run_loop(channel).await;
        }));
    }

    if let Some(ref email_cfg) = settings.email {
        info!(
            "Starting email support channel: {} / {}",
            email_cfg.imap_server, email_cfg.imap_username
        );
        let channel = Box::new(lnvps_agent::channel::email::EmailSupportChannel::new(
            email_cfg.clone(),
        ));
        let agent = agent.clone();
        handles.push(tokio::spawn(async move {
            agent.run_loop(channel).await;
        }));
    }

    if handles.is_empty() {
        info!("No support channel configured — exiting.");
        return Ok(());
    }

    for handle in handles {
        if let Err(e) = handle.await {
            return Err(anyhow::anyhow!("Channel panicked: {}", e));
        }
    }

    Ok(())
}
