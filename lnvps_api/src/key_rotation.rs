use anyhow::Result;
use lnvps_db::{EncryptionContext, LNVpsDb};

pub const ENCRYPTED_COLUMNS: &[(&str, &str, &str)] = &[
    ("users", "id", "email"),
    ("users", "id", "billing_name"),
    ("users", "id", "billing_address_1"),
    ("users", "id", "billing_address_2"),
    ("users", "id", "billing_city"),
    ("users", "id", "billing_state"),
    ("users", "id", "billing_postcode"),
    ("users", "id", "billing_tax_id"),
    ("user_ssh_key", "id", "key_data"),
    ("user_payment_method", "id", "external_id"),
    ("user_payment_method", "id", "external_customer_id"),
    ("vm_host", "id", "api_token"),
    ("vm_host", "id", "ssh_key"),
    ("router", "id", "token"),
    ("dns_server", "id", "token"),
    ("tunnel_pool", "id", "private_key"),
    ("ip_provider", "id", "token"),
    ("onchain_address_owner", "id", "address"),
    ("subscription_payment", "hex(id)", "external_data"),
    ("app_deployment", "id", "config"),
    ("agent_message", "id", "content"),
];

const BATCH: u64 = 500;

pub fn reencrypt(ctx: &EncryptionContext, value: &str) -> Result<Option<String>> {
    if EncryptionContext::is_encrypted(value) {
        ctx.rotate(value)
    } else {
        Ok(Some(ctx.encrypt(value)?))
    }
}

pub async fn rotate_all(db: &dyn LNVpsDb, ctx: &EncryptionContext) -> Result<u64> {
    let current_prefix = format!("ENC1:{}:", ctx.key_id());
    let transform = |v: &str| reencrypt(ctx, v);
    let mut total = 0;
    for (table, id_expr, column) in ENCRYPTED_COLUMNS {
        loop {
            let changed = db
                .transform_column_batch(table, id_expr, column, &current_prefix, BATCH, &transform)
                .await?;
            total += changed;
            if changed == 0 {
                break;
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(byte: u8, previous: &[u8]) -> EncryptionContext {
        let previous: Vec<[u8; 32]> = previous.iter().map(|b| [*b; 32]).collect();
        EncryptionContext::from_raw_keys([byte; 32], &previous)
    }

    #[test]
    fn old_key_values_move_to_the_new_key() {
        let old = ctx(1, &[]);
        let new = ctx(2, &[1]);
        let stored = old.encrypt("DE123456789").unwrap();
        let moved = reencrypt(&new, &stored).unwrap().unwrap();
        assert!(moved.starts_with(&format!("ENC1:{}:", new.key_id())));
        assert_eq!(new.decrypt(&moved).unwrap(), "DE123456789");
    }

    #[test]
    fn plaintext_pii_is_encrypted() {
        let new = ctx(2, &[]);
        let moved = reencrypt(&new, "12 High Street").unwrap().unwrap();
        assert!(EncryptionContext::is_encrypted(&moved));
        assert_eq!(new.decrypt(&moved).unwrap(), "12 High Street");
    }

    #[test]
    fn a_value_under_an_unknown_key_is_an_error_not_a_silent_skip() {
        let old = ctx(1, &[]);
        let new = ctx(2, &[]);
        let stored = old.encrypt("x").unwrap();
        assert!(reencrypt(&new, &stored).is_err());
    }

    #[test]
    fn already_current_values_are_left_alone() {
        let new = ctx(2, &[]);
        let stored = new.encrypt("x").unwrap();
        assert_eq!(reencrypt(&new, &stored).unwrap(), None);
    }
}
