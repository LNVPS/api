use anyhow::Result;
use log::info;
use std::path::PathBuf;
use std::sync::Arc;

use lnvps_agent::agent::SupportAgent;
use lnvps_agent::api_client::ApiClient;
use lnvps_agent::conversation::JsonFileStore;
use lnvps_agent::settings::Settings;

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
    info!("Admin API URL: {}", settings.admin_api_url);
    info!("OpenAI URL: {}", settings.openai.base_url);
    info!("Model: {}", settings.openai.model);

    let history_path = settings
        .conversation_history_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("conversation_history"));
    info!("Conversation history: {}", history_path.display());

    let store = Arc::new(JsonFileStore::new(history_path).await?);
    let api_client = Arc::new(ApiClient::new(&settings)?);
    let agent = SupportAgent::new(api_client.clone(), settings.clone(), store);

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
