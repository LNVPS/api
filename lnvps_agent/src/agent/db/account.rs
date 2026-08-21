//! Account tools: the customer's own record, SSH keys and saved payment
//! methods.
//!
//! The redaction rules live with the projections they apply to: verification
//! tokens, encrypted key material and processor references never leave this
//! module, and the tests below fail on the field *names* too, so a future
//! struct change cannot reintroduce them quietly.

use anyhow::Result;
use serde_json::{Value, json};

use super::DbToolExecutor;

impl DbToolExecutor {
    /// The customer's own account, with verification tokens stripped.
    pub(super) async fn account(&self) -> Result<Value> {
        let user = self.db.get_user(self.require_user()?).await?;
        Ok(json!({
            "id": user.id,
            "pubkey": hex::encode(&user.pubkey),
            "account_type": user.account_type.to_string(),
            "created": user.created,
            "email": user.email.as_str(),
            "email_verified": user.email_verified,
            "country_code": user.country_code,
            "billing_name": user.billing_name,
            "billing_city": user.billing_city,
            "billing_state": user.billing_state,
            "billing_postcode": user.billing_postcode,
            "billing_tax_id": user.billing_tax_id,
            "contact_email": user.contact_email,
            "contact_nip17": user.contact_nip17,
            "contact_telegram": user.contact_telegram,
            "contact_whatsapp": user.contact_whatsapp,
            "telegram_linked": user.telegram_chat_id.is_some(),
            "whatsapp_number": user.whatsapp_number,
            "whatsapp_verified": user.whatsapp_verified,
        }))
    }

    /// SSH keys by name only. The key material is stored encrypted and is not
    /// needed to answer "which key is on my VM", which is what is asked.
    pub(super) async fn ssh_keys(&self) -> Result<Value> {
        Ok(Value::Array(
            self.db
                .list_user_ssh_key(self.require_user()?)
                .await?
                .into_iter()
                .map(|k| json!({ "id": k.id, "name": k.name, "created": k.created }))
                .collect(),
        ))
    }

    /// Saved payment methods, by brand and last four digits only — the stored
    /// processor references are encrypted and never leave the database.
    pub(super) async fn payment_methods(&self) -> Result<Value> {
        Ok(Value::Array(
            self.db
                .list_user_payment_methods(self.require_user()?, None)
                .await?
                .into_iter()
                .map(|pm| {
                    json!({
                        "id": pm.id,
                        "provider": pm.provider,
                        "name": pm.name,
                        "card_brand": pm.card_brand,
                        "card_last_four": pm.card_last_four,
                        "expires": match (pm.exp_month, pm.exp_year) {
                            (Some(m), Some(y)) => Some(format!("{:02}/{}", m, y)),
                            _ => None,
                        },
                        "is_default": pm.is_default,
                        "enabled": pm.enabled,
                        "created": pm.created,
                    })
                })
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::DbToolExecutor;
    use crate::agent::ToolExecutor;
    use lnvps_api_common::MockDb;
    use lnvps_db::LNVpsDb;
    use std::sync::Arc;

    /// The account projection must never carry verification secrets.
    #[tokio::test]
    pub(super) async fn account_projection_omits_secrets() {
        let db = Arc::new(MockDb::default());
        let user_id = {
            let mut users = db.users.lock().await;
            let id = 1u64;
            users.insert(
                id,
                lnvps_db::User {
                    id,
                    pubkey: vec![0xab; 32],
                    email: "bob@example.com".into(),
                    email_verify_token: "SECRET-EMAIL-TOKEN".to_string(),
                    telegram_link_token: Some("SECRET-TG-TOKEN".to_string()),
                    whatsapp_verify_code: Some("SECRET-WA-CODE".to_string()),
                    ..Default::default()
                },
            );
            id
        };
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        let exec = DbToolExecutor::new(dyn_db, user_id);

        let out = exec.execute("get_my_account", "{}").await.unwrap();
        assert!(out.contains("bob@example.com"), "own email is fine to show");
        for secret in ["SECRET-EMAIL-TOKEN", "SECRET-TG-TOKEN", "SECRET-WA-CODE"] {
            assert!(!out.contains(secret), "leaked {secret}");
        }
        // Field names must not appear either, so a future struct change can't
        // silently reintroduce them.
        for field in [
            "email_verify_token",
            "telegram_link_token",
            "whatsapp_verify_code",
        ] {
            assert!(!out.contains(field), "leaked field {field}");
        }
    }

    /// Key material is stored encrypted and answers no support question; the
    /// name is what identifies a key to a customer.
    #[tokio::test]
    async fn ssh_keys_are_listed_by_name_only() {
        let db = Arc::new(MockDb::default());
        db.user_ssh_keys.lock().await.insert(
            1,
            lnvps_db::UserSshKey {
                id: 1,
                name: "laptop".to_string(),
                user_id: 1,
                created: chrono::Utc::now(),
                key_data: "ssh-ed25519 SECRET-KEY-BLOB".to_string().into(),
            },
        );
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        let exec = DbToolExecutor::new(dyn_db, 1);

        let out = exec.execute("list_my_ssh_keys", "{}").await.unwrap();
        assert!(out.contains("laptop"));
        for leaked in ["SECRET-KEY-BLOB", "key_data"] {
            assert!(!out.contains(leaked), "leaked {leaked}");
        }
    }

    /// Enough to answer "why did my renewal fail" — and no more: the stored
    /// processor references are encrypted and must not be echoed.
    #[tokio::test]
    async fn payment_methods_show_only_card_identifiers() {
        let db = Arc::new(MockDb::default());
        db.user_payment_methods.lock().await.insert(
            1,
            lnvps_db::UserPaymentMethod {
                id: 1,
                user_id: 1,
                created: chrono::Utc::now(),
                provider: "revolut".to_string(),
                name: Some("Personal".to_string()),
                external_customer_id: Some("SECRET-CUSTOMER".to_string().into()),
                external_id: "SECRET-INSTRUMENT".to_string().into(),
                card_brand: Some("visa".to_string()),
                card_last_four: Some("4242".to_string()),
                exp_month: Some(3),
                exp_year: Some(2027),
                is_default: true,
                enabled: true,
            },
        );
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        let exec = DbToolExecutor::new(dyn_db, 1);

        let out = exec.execute("list_my_payment_methods", "{}").await.unwrap();
        assert!(out.contains("4242"));
        assert!(out.contains("\"expires\": \"03/2027\""), "{out}");
        for leaked in [
            "SECRET-CUSTOMER",
            "SECRET-INSTRUMENT",
            "external_id",
            "external_customer_id",
        ] {
            assert!(!out.contains(leaked), "leaked {leaked}");
        }
    }
}
