use anyhow::Result;
use chrono::Utc;
use lnvps_db::{LNVpsDb, Vm, VmHistory, VmHistoryActionType};
use serde_json::{Value, json};
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
                "VM {} received payment of {} {} ({} seconds added)",
                vm_id, payment_amount, payment_currency, time_added_seconds
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
        self.db.list_vm_history(vm_id).await
    }

    pub async fn get_vm_history_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<VmHistory>> {
        self.db
            .list_vm_history_paginated(vm_id, limit, offset)
            .await
    }
}
