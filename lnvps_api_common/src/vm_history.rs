use anyhow::Result;
use chrono::Utc;
use lnvps_db::{LNVpsDb, Vm, VmHistory, VmHistoryActionType};
use payments_rs::currency::{Currency, CurrencyAmount};
use serde_json::{Value, json};
use std::str::FromStr;
use std::sync::Arc;

fn serialize_json_to_bytes(value: Option<Value>) -> Option<Vec<u8>> {
    value.and_then(|v| serde_json::to_vec(&v).ok())
}

#[derive(Clone)]
pub struct VmHistoryLogger {
    db: Arc<dyn LNVpsDb>,
}

impl VmHistoryLogger {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }

    pub async fn log_vm_created(
        &self,
        vm: &Vm,
        initiated_by_user: Option<u64>,
        metadata: Option<Value>,
    ) -> Result<()> {
        let vm_state = json!({
            "host_id": vm.host_id,
            "user_id": vm.user_id,
            "image_id": vm.image_id,
            "template_id": vm.template_id,
            "custom_template_id": vm.custom_template_id,
            "ssh_key_id": vm.ssh_key_id,
            "created": vm.created,
            "expires": vm.expires,
            "disk_id": vm.disk_id,
            "mac_address": vm.mac_address,
            "ref_code": vm.ref_code
        });

        let history = VmHistory {
            id: 0, // Will be set by database
            vm_id: vm.id,
            action_type: VmHistoryActionType::Created,
            timestamp: Utc::now(),
            initiated_by_user,
            previous_state: None,
            new_state: serialize_json_to_bytes(Some(vm_state)),
            metadata: serialize_json_to_bytes(metadata),
            description: Some(format!("VM {} was created", vm.id)),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn log_vm_started(
        &self,
        vm_id: u64,
        initiated_by_user: Option<u64>,
        metadata: Option<Value>,
    ) -> Result<()> {
        let history = VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::Started,
            timestamp: Utc::now(),
            initiated_by_user,
            previous_state: None,
            new_state: None,
            metadata: serialize_json_to_bytes(metadata),
            description: Some(format!("VM {} was started", vm_id)),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn log_vm_stopped(
        &self,
        vm_id: u64,
        initiated_by_user: Option<u64>,
        metadata: Option<Value>,
    ) -> Result<()> {
        let history = VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::Stopped,
            timestamp: Utc::now(),
            initiated_by_user,
            previous_state: None,
            new_state: None,
            metadata: serialize_json_to_bytes(metadata),
            description: Some(format!("VM {} was stopped", vm_id)),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn log_vm_restarted(
        &self,
        vm_id: u64,
        initiated_by_user: Option<u64>,
        metadata: Option<Value>,
    ) -> Result<()> {
        let history = VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::Restarted,
            timestamp: Utc::now(),
            initiated_by_user,
            previous_state: None,
            new_state: None,
            metadata: serialize_json_to_bytes(metadata),
            description: Some(format!("VM {} was restarted", vm_id)),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn log_vm_deleted(
        &self,
        vm_id: u64,
        initiated_by_user: Option<u64>,
        reason: Option<&str>,
        metadata: Option<Value>,
    ) -> Result<()> {
        let description = match reason {
            Some(r) => format!("VM {} was deleted: {}", vm_id, r),
            None => format!("VM {} was deleted", vm_id),
        };

        let history = VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::Deleted,
            timestamp: Utc::now(),
            initiated_by_user,
            previous_state: None,
            new_state: None,
            metadata: serialize_json_to_bytes(metadata),
            description: Some(description),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn log_vm_expired(&self, vm_id: u64, metadata: Option<Value>) -> Result<()> {
        let history = VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::Expired,
            timestamp: Utc::now(),
            initiated_by_user: None, // System action
            previous_state: None,
            new_state: None,
            metadata: serialize_json_to_bytes(metadata),
            description: Some(format!("VM {} expired", vm_id)),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn log_vm_renewed(
        &self,
        vm_id: u64,
        initiated_by_user: Option<u64>,
        old_expires: chrono::DateTime<Utc>,
        new_expires: chrono::DateTime<Utc>,
        payment_amount: Option<u64>,
        payment_currency: Option<&str>,
        metadata: Option<Value>,
    ) -> Result<()> {
        let mut meta = metadata.unwrap_or_else(|| json!({}));
        if let Some(amount) = payment_amount {
            meta["payment_amount"] = json!(amount);
        }
        if let Some(currency) = payment_currency {
            meta["payment_currency"] = json!(currency);
        }

        let history = VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::Renewed,
            timestamp: Utc::now(),
            initiated_by_user,
            previous_state: serialize_json_to_bytes(Some(json!({"expires": old_expires}))),
            new_state: serialize_json_to_bytes(Some(json!({"expires": new_expires}))),
            metadata: serialize_json_to_bytes(Some(meta)),
            description: Some(format!(
                "VM {} was renewed until {}",
                vm_id,
                new_expires.format("%Y-%m-%d %H:%M UTC")
            )),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn log_vm_extended(
        &self,
        vm_id: u64,
        initiated_by_user: Option<u64>,
        old_expires: chrono::DateTime<Utc>,
        new_expires: chrono::DateTime<Utc>,
        days_extended: u32,
        reason: Option<String>,
        metadata: Option<Value>,
    ) -> Result<()> {
        let mut meta = metadata.unwrap_or_else(|| json!({}));
        meta["days_extended"] = json!(days_extended);
        meta["admin_action"] = json!(true);
        if let Some(r) = &reason {
            meta["reason"] = json!(r);
        }

        let description = match reason {
            Some(r) => format!(
                "VM {} was extended by {} days until {} - Reason: {}",
                vm_id,
                days_extended,
                new_expires.format("%Y-%m-%d %H:%M UTC"),
                r
            ),
            None => format!(
                "VM {} was extended by {} days until {}",
                vm_id,
                days_extended,
                new_expires.format("%Y-%m-%d %H:%M UTC")
            ),
        };

        let history = VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::Renewed,
            timestamp: Utc::now(),
            initiated_by_user,
            previous_state: serialize_json_to_bytes(Some(json!({"expires": old_expires}))),
            new_state: serialize_json_to_bytes(Some(json!({"expires": new_expires}))),
            metadata: serialize_json_to_bytes(Some(meta)),
            description: Some(description),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn log_vm_reinstalled(
        &self,
        vm_id: u64,
        initiated_by_user: Option<u64>,
        old_image_id: u64,
        new_image_id: u64,
        metadata: Option<Value>,
    ) -> Result<()> {
        let history = VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::Reinstalled,
            timestamp: Utc::now(),
            initiated_by_user,
            previous_state: serialize_json_to_bytes(Some(json!({"image_id": old_image_id}))),
            new_state: serialize_json_to_bytes(Some(json!({"image_id": new_image_id}))),
            metadata: serialize_json_to_bytes(metadata),
            description: Some(format!("VM {} was reinstalled with new image", vm_id)),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn log_vm_state_changed(
        &self,
        vm_id: u64,
        old_state: &str,
        new_state: &str,
        metadata: Option<Value>,
    ) -> Result<()> {
        let history = VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::StateChanged,
            timestamp: Utc::now(),
            initiated_by_user: None, // System action
            previous_state: serialize_json_to_bytes(Some(json!({"state": old_state}))),
            new_state: serialize_json_to_bytes(Some(json!({"state": new_state}))),
            metadata: serialize_json_to_bytes(metadata),
            description: Some(format!(
                "VM {} state changed from {} to {}",
                vm_id, old_state, new_state
            )),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn log_vm_payment_received(
        &self,
        vm_id: u64,
        payment_amount: u64,
        payment_currency: &str,
        time_added_seconds: u64,
        metadata: Option<Value>,
    ) -> Result<()> {
        let mut meta = metadata.unwrap_or_else(|| json!({}));
        meta["payment_amount"] = json!(payment_amount);
        meta["payment_currency"] = json!(payment_currency);
        meta["time_added_seconds"] = json!(time_added_seconds);

        let currency = Currency::from_str(payment_currency).unwrap_or(Currency::BTC);
        let formatted_amount = CurrencyAmount::from_u64(currency, payment_amount);

        let history = VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::PaymentReceived,
            timestamp: Utc::now(),
            initiated_by_user: None, // Payment is usually external
            previous_state: None,
            new_state: None,
            metadata: serialize_json_to_bytes(Some(meta)),
            description: Some(format!(
                "VM {} received payment of {} ({} seconds added)",
                vm_id, formatted_amount, time_added_seconds
            )),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn log_vm_configuration_changed(
        &self,
        vm_id: u64,
        initiated_by_user: Option<u64>,
        old_vm: &Vm,
        new_vm: &Vm,
        metadata: Option<Value>,
    ) -> Result<()> {
        let previous_state = json!({
            "host_id": old_vm.host_id,
            "image_id": old_vm.image_id,
            "template_id": old_vm.template_id,
            "custom_template_id": old_vm.custom_template_id,
            "ssh_key_id": old_vm.ssh_key_id,
            "expires": old_vm.expires,
            "disk_id": old_vm.disk_id,
            "mac_address": old_vm.mac_address
        });

        let new_state = json!({
            "host_id": new_vm.host_id,
            "image_id": new_vm.image_id,
            "template_id": new_vm.template_id,
            "custom_template_id": new_vm.custom_template_id,
            "ssh_key_id": new_vm.ssh_key_id,
            "expires": new_vm.expires,
            "disk_id": new_vm.disk_id,
            "mac_address": new_vm.mac_address
        });

        let history = VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::ConfigurationChanged,
            timestamp: Utc::now(),
            initiated_by_user,
            previous_state: serialize_json_to_bytes(Some(previous_state)),
            new_state: serialize_json_to_bytes(Some(new_state)),
            metadata: serialize_json_to_bytes(metadata),
            description: Some(format!("VM {} configuration was changed", vm_id)),
        };

        self.db.insert_vm_history(&history).await?;
        Ok(())
    }

    pub async fn get_vm_history(&self, vm_id: u64) -> Result<Vec<VmHistory>> {
        Ok(self.db.list_vm_history(vm_id).await?)
    }

    pub async fn get_vm_history_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<VmHistory>> {
        Ok(self
            .db
            .list_vm_history_paginated(vm_id, limit, offset)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockDb;
    use std::sync::Arc;

    fn make_logger() -> VmHistoryLogger {
        let db = Arc::new(MockDb::empty());
        VmHistoryLogger::new(db)
    }

    /// Regression test for d88e153: log_vm_payment_received must format the payment amount
    /// using CurrencyAmount::Display rather than printing the raw u64 integer.
    /// Before the fix the description was "VM 1 received payment of 1000 BTC (3600 seconds added)"
    /// (raw integer). After the fix it is "VM 1 received payment of BTC 0.00000001 (3600 seconds added)".
    #[tokio::test]
    async fn test_payment_received_description_uses_formatted_amount() {
        let logger = make_logger();
        // 1000 milli-satoshis in BTC currency
        logger
            .log_vm_payment_received(1, 1000, "BTC", 3600, None)
            .await
            .unwrap();

        let db = logger.db.clone();
        let history = db.list_vm_history(1).await.unwrap();
        assert_eq!(history.len(), 1);
        let description = history[0].description.as_deref().unwrap_or("");
        // The description must NOT contain the raw bare integer "1000 BTC"
        // (which would indicate CurrencyAmount formatting was not used).
        assert!(
            !description.contains("1000 BTC"),
            "description should not contain raw integer amount '1000 BTC', got: {description}"
        );
        // CurrencyAmount::Display for 1000 millisats produces "BTC 0.00000001"
        assert!(
            description.contains("BTC 0.00000001"),
            "description should contain formatted amount 'BTC 0.00000001', got: {description}"
        );
    }

    #[tokio::test]
    async fn test_serialize_json_to_bytes_some_value() {
        let val = serde_json::json!({"key": "value"});
        let result = serialize_json_to_bytes(Some(val.clone()));
        assert!(result.is_some());
        let decoded: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(decoded, val);
    }

    #[tokio::test]
    async fn test_serialize_json_to_bytes_none() {
        let result = serialize_json_to_bytes(None);
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_log_vm_created() {
        let logger = make_logger();
        let vm = lnvps_db::Vm {
            id: 42,
            host_id: 0,
            user_id: 0,
            image_id: 0,
            template_id: None,
            custom_template_id: None,
            ssh_key_id: 0,
            created: chrono::Utc::now(),
            expires: chrono::Utc::now(),
            disk_id: 0,
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            deleted: false,
            ref_code: None,
            auto_renewal_enabled: false,
        };
        logger.log_vm_created(&vm, Some(1), None).await.unwrap();
        let history = logger.db.list_vm_history(42).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].action_type.to_string(), "created");
        assert!(history[0].description.as_deref().unwrap_or("").contains("42"));
    }

    #[tokio::test]
    async fn test_log_vm_started() {
        let logger = make_logger();
        logger.log_vm_started(7, None, None).await.unwrap();
        let history = logger.db.list_vm_history(7).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].action_type.to_string(), "started");
    }

    #[tokio::test]
    async fn test_log_vm_stopped() {
        let logger = make_logger();
        logger.log_vm_stopped(8, None, None).await.unwrap();
        let history = logger.db.list_vm_history(8).await.unwrap();
        assert_eq!(history[0].action_type.to_string(), "stopped");
    }

    #[tokio::test]
    async fn test_log_vm_restarted() {
        let logger = make_logger();
        logger.log_vm_restarted(9, None, None).await.unwrap();
        let history = logger.db.list_vm_history(9).await.unwrap();
        assert_eq!(history[0].action_type.to_string(), "restarted");
    }

    #[tokio::test]
    async fn test_log_vm_deleted_with_reason() {
        let logger = make_logger();
        logger
            .log_vm_deleted(10, None, Some("test reason"), None)
            .await
            .unwrap();
        let history = logger.db.list_vm_history(10).await.unwrap();
        assert_eq!(history[0].action_type.to_string(), "deleted");
        assert!(history[0]
            .description
            .as_deref()
            .unwrap_or("")
            .contains("test reason"));
    }

    #[tokio::test]
    async fn test_log_vm_deleted_without_reason() {
        let logger = make_logger();
        logger.log_vm_deleted(11, None, None, None).await.unwrap();
        let history = logger.db.list_vm_history(11).await.unwrap();
        assert_eq!(history[0].action_type.to_string(), "deleted");
    }

    #[tokio::test]
    async fn test_log_vm_expired() {
        let logger = make_logger();
        logger.log_vm_expired(12, None).await.unwrap();
        let history = logger.db.list_vm_history(12).await.unwrap();
        assert_eq!(history[0].action_type.to_string(), "expired");
    }

    #[tokio::test]
    async fn test_log_vm_renewed() {
        let logger = make_logger();
        let old = chrono::Utc::now();
        let new = old + chrono::TimeDelta::days(30);
        logger
            .log_vm_renewed(13, None, old, new, Some(1000), Some("BTC"), None)
            .await
            .unwrap();
        let history = logger.db.list_vm_history(13).await.unwrap();
        assert_eq!(history[0].action_type.to_string(), "renewed");
        assert!(history[0].new_state.is_some());
        assert!(history[0].previous_state.is_some());
        // metadata should include payment_amount
        let meta_bytes = history[0].metadata.as_ref().unwrap();
        let meta: serde_json::Value = serde_json::from_slice(meta_bytes).unwrap();
        assert_eq!(meta["payment_amount"], 1000);
        assert_eq!(meta["payment_currency"], "BTC");
    }

    #[tokio::test]
    async fn test_log_vm_extended_with_reason() {
        let logger = make_logger();
        let old = chrono::Utc::now();
        let new = old + chrono::TimeDelta::days(7);
        logger
            .log_vm_extended(14, Some(99), old, new, 7, Some("admin gift".to_string()), None)
            .await
            .unwrap();
        let history = logger.db.list_vm_history(14).await.unwrap();
        assert_eq!(history[0].action_type.to_string(), "renewed");
        assert!(history[0]
            .description
            .as_deref()
            .unwrap_or("")
            .contains("admin gift"));
        let meta: serde_json::Value =
            serde_json::from_slice(history[0].metadata.as_ref().unwrap()).unwrap();
        assert_eq!(meta["days_extended"], 7);
        assert_eq!(meta["admin_action"], true);
    }

    #[tokio::test]
    async fn test_log_vm_extended_without_reason() {
        let logger = make_logger();
        let old = chrono::Utc::now();
        let new = old + chrono::TimeDelta::days(3);
        logger
            .log_vm_extended(15, None, old, new, 3, None, None)
            .await
            .unwrap();
        let history = logger.db.list_vm_history(15).await.unwrap();
        assert_eq!(history[0].action_type.to_string(), "renewed");
    }

    #[tokio::test]
    async fn test_log_vm_reinstalled() {
        let logger = make_logger();
        logger
            .log_vm_reinstalled(16, Some(5), 1, 2, None)
            .await
            .unwrap();
        let history = logger.db.list_vm_history(16).await.unwrap();
        assert_eq!(history[0].action_type.to_string(), "reinstalled");
        let prev: serde_json::Value =
            serde_json::from_slice(history[0].previous_state.as_ref().unwrap()).unwrap();
        let next: serde_json::Value =
            serde_json::from_slice(history[0].new_state.as_ref().unwrap()).unwrap();
        assert_eq!(prev["image_id"], 1);
        assert_eq!(next["image_id"], 2);
    }

    #[tokio::test]
    async fn test_log_vm_state_changed() {
        let logger = make_logger();
        logger
            .log_vm_state_changed(17, "running", "stopped", None)
            .await
            .unwrap();
        let history = logger.db.list_vm_history(17).await.unwrap();
        assert_eq!(history[0].action_type.to_string(), "state_changed");
        let desc = history[0].description.as_deref().unwrap_or("");
        assert!(desc.contains("running") && desc.contains("stopped"));
    }

    #[tokio::test]
    async fn test_log_vm_configuration_changed() {
        let logger = make_logger();
        let now = chrono::Utc::now();
        let old_vm = lnvps_db::Vm {
            id: 18,
            host_id: 1,
            user_id: 1,
            image_id: 1,
            template_id: Some(1),
            custom_template_id: None,
            ssh_key_id: 1,
            created: now,
            expires: now,
            disk_id: 1,
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            deleted: false,
            ref_code: None,
            auto_renewal_enabled: false,
        };
        let mut new_vm = old_vm.clone();
        new_vm.image_id = 2;
        logger
            .log_vm_configuration_changed(18, Some(1), &old_vm, &new_vm, None)
            .await
            .unwrap();
        let history = logger.db.list_vm_history(18).await.unwrap();
        assert_eq!(history[0].action_type.to_string(), "configuration_changed");
    }

    #[tokio::test]
    async fn test_get_vm_history() {
        let logger = make_logger();
        logger.log_vm_started(20, None, None).await.unwrap();
        logger.log_vm_stopped(20, None, None).await.unwrap();
        let history = logger.get_vm_history(20).await.unwrap();
        assert_eq!(history.len(), 2);
    }

    #[tokio::test]
    async fn test_get_vm_history_paginated() {
        let logger = make_logger();
        for _ in 0..5 {
            logger.log_vm_started(21, None, None).await.unwrap();
        }
        let page = logger.get_vm_history_paginated(21, 2, 0).await.unwrap();
        assert_eq!(page.len(), 2);
        let page2 = logger.get_vm_history_paginated(21, 2, 2).await.unwrap();
        assert_eq!(page2.len(), 2);
        let page3 = logger.get_vm_history_paginated(21, 2, 4).await.unwrap();
        assert_eq!(page3.len(), 1);
    }
}
