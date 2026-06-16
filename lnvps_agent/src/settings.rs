use anyhow::{Result, anyhow};
use config::Config;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    /// Listen address for the agent HTTP server
    pub listen: Option<String>,

    /// Base URL of the LNVPS admin API
    pub admin_api_url: String,

    /// Base URL of the LNVPS user API
    pub user_api_url: String,

    /// Nsec key (bech32 `nsec1...`) used to sign NIP-98 auth events and for Nostr channel operations.
    /// Fresh tokens are generated per API call — no stale pre-encoded event needed.
    pub nsec: String,

    /// OpenAI-compatible API configuration
    pub openai: OpenAiConfig,

    /// Support agent system prompt (optional override)
    pub system_prompt: Option<String>,

    /// Email channel configuration (IMAP polling + SMTP replies)
    pub email: Option<EmailConfig>,

    /// Kind 1 Nostr channel configuration (mention-based support via kind 1 replies)
    pub kind1: Option<Kind1Config>,

    /// Path to conversation history storage directory
    pub conversation_history_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EmailConfig {
    /// IMAP server host:port (e.g., "imap.gmail.com:993")
    pub imap_server: String,
    /// IMAP username / login
    pub imap_username: String,
    /// IMAP password or app-specific password
    pub imap_password: String,
    /// IMAP mailbox to watch (e.g., "INBOX")
    pub imap_mailbox: Option<String>,

    /// SMTP server host:port (e.g., "smtp.gmail.com:587")
    pub smtp_server: String,
    /// SMTP username
    pub smtp_username: String,
    /// SMTP password
    pub smtp_password: String,
    /// From address for replies (e.g., "support@lnvps.io")
    pub smtp_from: String,
    /// Custom from name (e.g., "LNVPS Support")
    pub smtp_from_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Kind1Config {
    /// Nostr relays to connect to (e.g., ["wss://relay.damus.io"])
    pub relays: Vec<String>,

    /// Hex pubkey(s) of accounts whose mentions trigger support responses.
    /// When set, only mentions of these pubkeys are processed.
    /// If empty/omitted, mentions of the bot's own pubkey (derived from the
    /// top-level nsec) are used.
    pub mention_pubkeys: Option<Vec<String>>,

    /// Poll interval in seconds between checking for new mentions
    pub poll_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct OpenAiConfig {
    /// Base URL of the OpenAI-compatible API (e.g., http://localhost:11434/v1 for Ollama)
    pub base_url: String,

    /// API key (not needed for Ollama but required by some providers)
    pub api_key: Option<String>,

    /// Model name to use (e.g., "llama3.2", "gpt-4o")
    pub model: String,

    /// Max tokens for the response
    pub max_tokens: Option<u32>,
}

impl Settings {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let builder = Config::builder();

        // Default configuration
        let builder = builder
            .set_default("listen", "0.0.0.0:8080")?
            .set_default("openai.max_tokens", 2048u32)?;

        #[cfg(debug_assertions)]
        let builder = {
            let default_path = std::env::current_dir()?.join("settings.yaml");
            if default_path.exists() {
                builder.add_source(config::File::from(default_path).required(false))
            } else {
                builder
            }
        };

        // Load from explicit path
        let builder = if let Some(p) = path {
            builder.add_source(config::File::from(p).required(true))
        } else {
            builder
        };

        let config = builder
            .add_source(
                config::Environment::with_prefix("LNVPS_AGENT")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        let settings: Settings = config.try_deserialize()?;
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> Result<()> {
        if self.admin_api_url.is_empty() {
            return Err(anyhow!("admin_api_url must not be empty"));
        }
        if self.nsec.is_empty() {
            return Err(anyhow!("nsec must not be empty"));
        }
        if self.openai.base_url.is_empty() {
            return Err(anyhow!("openai.base_url must not be empty"));
        }
        if self.openai.model.is_empty() {
            return Err(anyhow!("openai.model must not be empty"));
        }
        Ok(())
    }
}
