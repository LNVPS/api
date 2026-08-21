//! Resolving a channel's sender identity to an LNVPS customer.
//!
//! This is the single place resolution happens; channels never look a sender up
//! themselves. It reads the database directly, like every other lookup the
//! agent makes.
//!
//! An unknown sender resolves to [`Requester::Anonymous`] rather than creating
//! an account: `upsert_user` would mint a row for every stranger who mentions
//! the bot on a public relay, and an account conjured from an unverified email
//! address in a `From:` header would be worse than useless — it would be an
//! authorisation decision made from a forgeable header.

use std::sync::Arc;

use anyhow::Result;
use lnvps_db::{LNVpsDb, User, email_hash};
use serde_json::json;

use crate::identity::{Requester, SenderIdentity};

/// Resolve a sender identity against the database.
///
/// Never fails for an unknown sender: "not a customer" is an ordinary outcome
/// that selects the public tool set, not an error to report to the sender.
pub async fn resolve(db: &Arc<dyn LNVpsDb>, sender: &SenderIdentity) -> Result<Requester> {
    let user = match sender {
        // Matched on the indexed hash, so the plaintext address is never used
        // as a lookup key.
        SenderIdentity::Email(email) => db
            .admin_find_user_by_email_hash(&email_hash(email))
            .await
            .ok()
            .flatten()
            .map(|info| info.user_info),
        SenderIdentity::Pubkey(pubkey) => match hex::decode(pubkey) {
            Ok(bytes) => db.get_user_by_pubkey(&bytes).await.ok(),
            Err(_) => {
                log::warn!("Sender pubkey {} is not hex — treating as public", pubkey);
                None
            }
        },
        // A guest session id identifies no account by construction, so there is
        // nothing to look up.
        SenderIdentity::Guest(_) => None,
    };

    let Some(user) = user else {
        log::info!("{} is not an LNVPS customer — general", sender.as_str());
        return Ok(Requester::Anonymous);
    };
    Ok(Requester::Customer {
        user_id: user.id,
        account: account_context(&user),
    })
}

/// The account fields rendered into the customer prompt.
///
/// Hand-built for the same reason every tool projection is: the `User` record
/// carries email/Telegram/WhatsApp verification tokens, and this value is
/// pasted verbatim into the model's system prompt.
fn account_context(user: &User) -> serde_json::Value {
    json!({
        "id": user.id,
        "pubkey": hex::encode(&user.pubkey),
        "email": user.email.as_str(),
        "email_verified": user.email_verified,
        "country_code": user.country_code,
        "created": user.created,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;

    async fn db_with_user() -> (Arc<MockDb>, Arc<dyn LNVpsDb>) {
        let mock = Arc::new(MockDb::default());
        {
            let mut users = mock.users.lock().await;
            users.insert(
                1,
                User {
                    id: 1,
                    pubkey: vec![0xab; 32],
                    email: "bob@example.com".into(),
                    email_verified: true,
                    email_verify_token: "SECRET-EMAIL-TOKEN".to_string(),
                    ..Default::default()
                },
            );
        }
        let dyn_db: Arc<dyn LNVpsDb> = mock.clone();
        (mock, dyn_db)
    }

    #[tokio::test]
    async fn resolves_a_customer_by_pubkey() {
        let (_mock, db) = db_with_user().await;
        let requester = resolve(&db, &SenderIdentity::Pubkey("ab".repeat(32)))
            .await
            .unwrap();
        assert_eq!(requester.user_id(), Some(1));
    }

    #[tokio::test]
    async fn resolves_a_customer_by_email() {
        let (_mock, db) = db_with_user().await;
        let requester = resolve(&db, &SenderIdentity::Email("BOB@example.com".to_string()))
            .await
            .unwrap();
        // Address matching is case-insensitive, via the hash.
        assert_eq!(requester.user_id(), Some(1));
    }

    /// An unknown sender must not become an account: a `From:` header is
    /// forgeable, and a public relay mention is not a signup.
    #[tokio::test]
    async fn an_unknown_sender_is_anonymous_and_creates_nothing() {
        let (mock, db) = db_with_user().await;
        let before = mock.users.lock().await.len();

        for sender in [
            SenderIdentity::Email("stranger@example.com".to_string()),
            SenderIdentity::Pubkey("cd".repeat(32)),
            SenderIdentity::Guest("session-id".to_string()),
            // A malformed pubkey is a miss, not a panic or a lookup by garbage.
            SenderIdentity::Pubkey("not-hex".to_string()),
        ] {
            let requester = resolve(&db, &sender).await.unwrap();
            assert!(
                requester.user_id().is_none(),
                "{sender:?} must be anonymous"
            );
        }
        assert_eq!(mock.users.lock().await.len(), before, "created a user");
    }

    /// The account context is pasted into the system prompt verbatim, so it
    /// must never carry a verification token.
    #[tokio::test]
    async fn account_context_omits_verification_secrets() {
        let (_mock, db) = db_with_user().await;
        let requester = resolve(&db, &SenderIdentity::Pubkey("ab".repeat(32)))
            .await
            .unwrap();
        let Requester::Customer { account, .. } = requester else {
            panic!("expected a customer");
        };
        let rendered = account.to_string();
        assert!(rendered.contains("bob@example.com"));
        for secret in ["SECRET-EMAIL-TOKEN", "email_verify_token"] {
            assert!(!rendered.contains(secret), "leaked {secret}");
        }
    }
}
