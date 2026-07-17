//! NIP-17 (Nostr private DM) notification channel.

use super::{Notification, NotificationChannel};
use async_trait::async_trait;
use lnvps_api_common::retry::OpError;
use lnvps_db::{AccountType, User};
use nostr_sdk::{Client, EventBuilder, PublicKey};

/// Delivers notifications as NIP-17 private direct messages over Nostr.
pub struct Nip17Channel {
    client: Client,
}

impl Nip17Channel {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl NotificationChannel for Nip17Channel {
    fn name(&self) -> &'static str {
        "nip17"
    }

    fn wants(&self, user: &User) -> bool {
        // Only native Nostr accounts have a real key to DM. OAuth accounts store
        // a synthetic `pubkey` that is not a valid Nostr key, so never attempt
        // NIP-17 for them even if the flag were somehow set.
        user.contact_nip17 && user.account_type == AccountType::Nostr
    }

    async fn send(
        &self,
        user: &User,
        notification: &Notification,
    ) -> Result<(), OpError<anyhow::Error>> {
        let sig = self
            .client
            .signer()
            .await
            .map_err(|e| OpError::Transient(e.into()))?;
        let pubkey = PublicKey::from_slice(&user.pubkey).map_err(|e| OpError::Fatal(e.into()))?;
        let ev = EventBuilder::private_msg(&sig, pubkey, notification.message.clone(), None)
            .await
            .map_err(|e| OpError::Transient(e.into()))?;
        self.client
            .send_event(&ev)
            .await
            .map_err(|e| OpError::Transient(e.into()))?;
        Ok(())
    }
}
