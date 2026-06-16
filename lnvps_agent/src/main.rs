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

    let config_path = std::env::var("LNVPS_AGENT_CONFIG").ok().map(PathBuf::from);

    let settings = Settings::load(config_path)?;
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
        agent.run_loop(channel).await;
    } else if let Some(ref email_cfg) = settings.email {
        info!(
            "Starting email support channel: {} / {}",
            email_cfg.imap_server, email_cfg.imap_username
        );
        let channel = Box::new(lnvps_agent::channel::email::EmailSupportChannel::new(
            email_cfg.clone(),
        ));
        agent.run_loop(channel).await;
    } else {
        info!("No support channel configured — exiting.");
    }

    Ok(())
}
