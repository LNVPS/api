//! Startup backfill: migrate VMs and vm_payment records into the subscription system.
//!
//! This runs unconditionally at app startup, immediately after schema migrations and
//! BEFORE `run_data_migrations` (which calls `list_vms()` and would fail to decode the
//! non-nullable `vm.subscription_line_item_id` if any VM were still unlinked).
//!
//! Phase 1 — Subscription backfill: for every VM (including deleted) without a
//!   `subscription_line_item_id`, create a subscription + line item and link the VM.
//!   The VM's existing `expires` and `auto_renewal_enabled` are copied onto the
//!   subscription so billing/renewal enforcement continues seamlessly.
//!
//! Phase 2 — Payment backfill: copy every `vm_payment` row that has not yet been
//!   copied into `subscription_payment`, preserving all fields.
//!
//! Both phases are idempotent: VMs already linked and payments already copied are skipped.
use anyhow::{Context, Result, bail};
use chrono::Utc;
use lnvps_db::{
    IntervalType, LNVpsDb, LNVpsDbMysql, Subscription, SubscriptionLineItem,
    SubscriptionPaymentType, SubscriptionType, VmForMigration, VmPaymentRaw,
};
use log::{info, warn};
use std::sync::Arc;

/// Compute interval-to-seconds matching PricingEngine::cost_plan_interval_to_seconds.
fn interval_to_seconds(interval_type: IntervalType, interval_amount: u64) -> i64 {
    let base = match interval_type {
        IntervalType::Day => 86_400i64,
        IntervalType::Month => 2_592_000i64, // 30 days
        IntervalType::Year => 31_536_000i64, // 365 days
    };
    base * interval_amount as i64
}

/// Run the VM → subscription backfill. Safe to call on every startup (idempotent).
pub async fn run_vm_subscription_backfill(db_impl: Arc<LNVpsDbMysql>) -> Result<()> {
    let db: Arc<dyn LNVpsDb> = db_impl.clone();

    // Phase 1: create subscriptions for all VMs (including deleted)
    let vm_ids = db_impl
        .list_vm_ids_without_subscription()
        .await
        .context("Failed to list VMs needing subscription")?;

    if !vm_ids.is_empty() {
        info!(
            "VM subscription backfill — Phase 1: {} VMs need a subscription",
            vm_ids.len()
        );
    }

    let mut sub_migrated = 0usize;
    let mut sub_errored = 0usize;
    for vm_id in &vm_ids {
        match migrate_vm_subscription(db_impl.clone(), db.clone(), *vm_id).await {
            Ok(()) => sub_migrated += 1,
            Err(e) => {
                warn!("Phase 1: Failed to migrate VM {}: {:#}", vm_id, e);
                sub_errored += 1;
            }
        }
    }
    if !vm_ids.is_empty() {
        info!(
            "VM subscription backfill — Phase 1 complete: {} subscriptions created, {} errors",
            sub_migrated, sub_errored
        );
    }

    // Phase 2: backfill vm_payment → subscription_payment
    let payment_vm_ids = db_impl
        .list_vm_ids_with_uncopied_payments()
        .await
        .context("Failed to list VMs with uncopied payments")?;

    if !payment_vm_ids.is_empty() {
        info!(
            "VM subscription backfill — Phase 2: {} VMs have vm_payment records to backfill",
            payment_vm_ids.len()
        );
    }

    let mut pay_migrated = 0usize;
    let mut pay_errored = 0usize;
    for vm_id in &payment_vm_ids {
        match migrate_vm_payments(db_impl.clone(), db.clone(), *vm_id).await {
            Ok(n) => pay_migrated += n,
            Err(e) => {
                warn!("Phase 2: Failed to migrate payments for VM {}: {:#}", vm_id, e);
                pay_errored += 1;
            }
        }
    }
    if !payment_vm_ids.is_empty() {
        info!(
            "VM subscription backfill — Phase 2 complete: {} payments backfilled, {} VM errors",
            pay_migrated, pay_errored
        );
    }

    if sub_errored > 0 || pay_errored > 0 {
        bail!(
            "VM subscription backfill incomplete: {} subscription errors, {} payment VM errors (see warnings above)",
            sub_errored,
            pay_errored
        );
    }

    Ok(())
}

// ─── Phase 1: subscription creation ─────────────────────────────────────────

async fn migrate_vm_subscription(
    db_impl: Arc<LNVpsDbMysql>,
    db: Arc<dyn LNVpsDb>,
    vm_id: u64,
) -> Result<()> {
    let vm: VmForMigration = db_impl
        .get_vm_for_migration(vm_id)
        .await
        .context("Failed to get VM")?;

    let company_id = db
        .get_vm_company_id(vm_id)
        .await
        .context("Failed to get company id for VM")?;
    let company = db
        .get_company(company_id)
        .await
        .context("Failed to get company")?;
    let currency = company.base_currency.clone();

    let (interval_amount, interval_type, line_item_amount, description) =
        if let Some(template_id) = vm.template_id {
            let template = db
                .get_vm_template(template_id)
                .await
                .context("Failed to get VM template")?;
            let cost_plan = db
                .get_cost_plan(template.cost_plan_id)
                .await
                .context("Failed to get cost plan")?;
            let desc = format!("{} (VM {})", template.name, vm_id);
            (
                cost_plan.interval_amount,
                cost_plan.interval_type,
                cost_plan.amount,
                desc,
            )
        } else if vm.custom_template_id.is_some() {
            let desc = format!("Custom VM {}", vm_id);
            (1u64, IntervalType::Month, 0u64, desc)
        } else {
            bail!("VM {} has neither template_id nor custom_template_id", vm_id);
        };

    let time_value = interval_to_seconds(interval_type, interval_amount);
    info!(
        "Phase 1: VM {} → subscription ({} {}, time_value={}s, amount={})",
        vm_id,
        interval_amount,
        match interval_type {
            IntervalType::Day => "day(s)",
            IntervalType::Month => "month(s)",
            IntervalType::Year => "year(s)",
        },
        time_value,
        line_item_amount,
    );

    // Deleted VMs should have inactive subscriptions — they are no longer running.
    let is_active = !vm.deleted;

    let subscription = Subscription {
        id: 0,
        user_id: vm.user_id,
        company_id,
        name: format!("VM {} Subscription", vm_id),
        description: Some(description.clone()),
        created: Utc::now(),
        // Preserve the VM's existing billing expiry so renewal/suspension/auto-renewal
        // enforcement continues seamlessly. The legacy vm.expires column is the source
        // of truth pre-migration and is dropped only at finalization.
        expires: Some(vm.expires),
        is_active,
        is_setup: true,
        currency,
        interval_amount,
        interval_type,
        setup_fee: 0,
        // Preserve the VM's auto-renewal preference so NWC auto-renewal keeps working.
        auto_renewal_enabled: vm.auto_renewal_enabled,
        external_id: None,
    };
    let line_item = SubscriptionLineItem {
        id: 0,
        subscription_id: 0,
        subscription_type: SubscriptionType::Vps,
        name: description,
        description: None,
        amount: line_item_amount,
        setup_amount: 0,
        configuration: None,
    };

    let (_sub_id, line_item_ids) = db
        .insert_subscription_with_line_items(&subscription, vec![line_item])
        .await
        .context("Failed to insert subscription")?;
    let subscription_line_item_id = line_item_ids[0];

    db_impl
        .set_vm_subscription_line_item(vm_id, subscription_line_item_id)
        .await
        .context("Failed to link VM to subscription")?;

    Ok(())
}

// ─── Phase 2: payment backfill ───────────────────────────────────────────────

async fn migrate_vm_payments(
    db_impl: Arc<LNVpsDbMysql>,
    db: Arc<dyn LNVpsDb>,
    vm_id: u64,
) -> Result<usize> {
    // Get the subscription_line_item_id (must exist after Phase 1)
    let vm: VmForMigration = db_impl
        .get_vm_for_migration(vm_id)
        .await
        .context("Failed to get VM")?;

    let subscription_line_item_id = vm
        .subscription_line_item_id
        .filter(|&id| id != 0)
        .with_context(|| format!("VM {} has no subscription_line_item_id", vm_id))?;

    let subscription_id = db
        .get_subscription_by_line_item_id(subscription_line_item_id)
        .await?
        .id;

    // Load all vm_payment rows for this VM (raw — external_data not decrypted)
    let vm_payments: Vec<VmPaymentRaw> = db_impl
        .list_vm_payments_for_migration(vm_id)
        .await
        .context("Failed to list vm_payments")?;

    // Idempotency check: find already-copied ids via raw query to avoid decryption.
    let existing_ids: std::collections::HashSet<Vec<u8>> = db_impl
        .list_subscription_payment_ids_for_subscription(subscription_id)
        .await
        .context("Failed to list existing subscription payment ids")?
        .into_iter()
        .collect();

    let mut copied = 0usize;

    for vp in &vm_payments {
        // Idempotency: skip if a subscription_payment with the same id already exists
        if existing_ids.contains(&vp.id) {
            continue;
        }

        let payment_type = match vp.payment_type {
            lnvps_db::PaymentType::Renewal => SubscriptionPaymentType::Renewal,
            lnvps_db::PaymentType::Upgrade => SubscriptionPaymentType::Upgrade,
        };

        // Parse upgrade_params string → serde_json::Value for metadata
        let metadata: Option<serde_json::Value> = vp
            .upgrade_params
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());

        // time_value: VmPaymentRaw has u64 (0 = none), SubscriptionPayment has Option<u64>
        let time_value = if vp.time_value > 0 {
            Some(vp.time_value)
        } else {
            None
        };

        let payment_type_u16 = payment_type as u16;
        let metadata_str: Option<String> = metadata.as_ref().map(|v| v.to_string());

        db_impl
            .insert_subscription_payment_raw(
                vp,
                subscription_id,
                vm.user_id,
                payment_type_u16,
                time_value,
                metadata_str.as_deref(),
            )
            .await
            .with_context(|| {
                format!(
                    "Failed to insert subscription_payment for vm_payment {}",
                    hex::encode(&vp.id)
                )
            })?;
        copied += 1;
    }

    Ok(copied)
}
