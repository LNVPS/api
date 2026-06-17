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
use lnvps_api_common::PricingEngine;
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

/// Billing details resolved for a VM from its template or custom pricing.
struct VmBilling {
    currency: String,
    interval_amount: u64,
    interval_type: IntervalType,
    line_item_amount: u64,
    description: String,
}

/// Resolve a VM's billing details (currency, interval, recurring amount, description) so they
/// match what the live provisioning paths set, ensuring the admin UI shows the correct cost:
///   - standard template: subscription.currency = cost_plan.currency, amount = cost_plan.amount
///   - custom template:   subscription.currency = pricing.currency,   amount = computed cost
///
/// Shared by the initial backfill and the one-time repair pass so both produce identical values.
async fn resolve_vm_billing(db: &Arc<dyn LNVpsDb>, vm: &VmForMigration) -> Result<VmBilling> {
    if let Some(template_id) = vm.template_id {
        let template = db
            .get_vm_template(template_id)
            .await
            .context("Failed to get VM template")?;
        let cost_plan = db
            .get_cost_plan(template.cost_plan_id)
            .await
            .context("Failed to get cost plan")?;
        Ok(VmBilling {
            currency: cost_plan.currency,
            interval_amount: cost_plan.interval_amount,
            interval_type: cost_plan.interval_type,
            line_item_amount: cost_plan.amount,
            description: format!("{} (VM {})", template.name, vm.id),
        })
    } else if let Some(custom_template_id) = vm.custom_template_id {
        // Custom VMs are always billed monthly; the amount is computed from the custom
        // pricing (CPU/memory/disk/IPs) just like update_line_item_cost_for_custom_vm.
        let custom_template = db
            .get_custom_vm_template(custom_template_id)
            .await
            .context("Failed to get custom VM template")?;
        let price = PricingEngine::get_custom_vm_cost_amount(db, vm.id, &custom_template)
            .await
            .context("Failed to compute custom VM cost")?;
        Ok(VmBilling {
            currency: price.currency.to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            line_item_amount: price.total(),
            description: format!("Custom VM {}", vm.id),
        })
    } else {
        bail!(
            "VM {} has neither template_id nor custom_template_id",
            vm.id
        );
    }
}

/// Run the VM → subscription backfill. Safe to call on every startup (idempotent).
pub async fn run_vm_subscription_backfill(db_impl: Arc<LNVpsDbMysql>) -> Result<()> {
    let db: Arc<dyn LNVpsDb> = db_impl.clone();

    // Phase 0: repair subscriptions written by earlier (buggy) backfill revisions.
    // Idempotent — performs no writes once every already-migrated row is correct.
    let linked_vm_ids = db_impl
        .list_vm_ids_with_subscription()
        .await
        .context("Failed to list VMs with subscription for repair")?;
    let mut repaired = 0usize;
    let mut repair_errored = 0usize;
    for vm_id in &linked_vm_ids {
        match repair_migrated_vm_subscription(db_impl.clone(), db.clone(), *vm_id).await {
            Ok(true) => repaired += 1,
            Ok(false) => {}
            Err(e) => {
                warn!("Phase 0: Failed to repair VM {}: {:#}", vm_id, e);
                repair_errored += 1;
            }
        }
    }
    if repaired > 0 || repair_errored > 0 {
        info!(
            "VM subscription backfill — Phase 0 complete: {} subscriptions repaired, {} errors",
            repaired, repair_errored
        );
    }

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
                warn!(
                    "Phase 2: Failed to migrate payments for VM {}: {:#}",
                    vm_id, e
                );
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

    if repair_errored > 0 || sub_errored > 0 || pay_errored > 0 {
        bail!(
            "VM subscription backfill incomplete: {} repair errors, {} subscription errors, {} payment VM errors (see warnings above)",
            repair_errored,
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

    let billing = resolve_vm_billing(&db, &vm).await?;
    let VmBilling {
        currency,
        interval_amount,
        interval_type,
        line_item_amount,
        description,
    } = billing;

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
    let subscription = build_subscription_for_vm(
        &vm,
        company_id,
        currency,
        interval_amount,
        interval_type,
        &description,
    );
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

/// Build the `Subscription` row for a VM during backfill.
///
/// Pure mapping (no DB access) so it can be unit-tested. The key invariants:
/// - `created` is copied from the VM's original creation date (NOT `Utc::now()`), because the
///   subscription is now the source of truth for the VM's "created" timestamp in the API.
/// - `expires` and `auto_renewal_enabled` are copied from the VM so billing/renewal continue.
/// - `is_setup` mirrors the legacy "has this VM ever been paid" signal: pre-migration, a
///   never-paid VM had `expires == created` and `check_vms` deleted it after 1h. The new
///   `check_vms` uses `subscription.is_setup` for that decision, so we must NOT blindly set
///   `is_setup = true` — a VM that was still unpaid at migration time would then look paid and
///   never be cleaned up. `expires > created` means at least one payment advanced the expiry.
/// - Deleted VMs get an inactive subscription — they are no longer running.
fn build_subscription_for_vm(
    vm: &VmForMigration,
    company_id: u64,
    currency: String,
    interval_amount: u64,
    interval_type: IntervalType,
    description: &str,
) -> Subscription {
    // A pre-migration VM was "set up" (paid at least once) iff its expiry was advanced past
    // its creation time. Never-paid VMs had expires == created and must stay !is_setup so the
    // worker's unpaid-VM cleanup continues to apply to them after migration. A NULL expires
    // means the VM was created by the new (post-migration) path and has no legacy expiry to
    // copy — treat it as not-yet-set-up with no subscription expiry.
    let is_setup = vm.expires.map(|e| e > vm.created).unwrap_or(false);
    Subscription {
        id: 0,
        user_id: vm.user_id,
        company_id,
        name: format!("VM {} Subscription", vm.id),
        description: Some(description.to_string()),
        // Preserve the VM's original creation date so the subscription (now the source of
        // truth for the VM's "created" timestamp in the API) reflects when the VM was
        // actually ordered, not when the migration ran.
        created: vm.created,
        // Preserve the VM's existing billing expiry so renewal/suspension/auto-renewal
        // enforcement continues seamlessly. The legacy vm.expires column is the source of
        // truth pre-migration and is dropped only at finalization.
        expires: vm.expires,
        // An unpaid VM (never set up) must not be marked active.
        is_active: !vm.deleted && is_setup,
        is_setup,
        currency,
        interval_amount,
        interval_type,
        setup_fee: 0,
        // Preserve the VM's auto-renewal preference so NWC auto-renewal keeps working.
        auto_renewal_enabled: vm.auto_renewal_enabled,
        external_id: None,
    }
}

// ─── Phase 0: repair already-migrated subscriptions ──────────────────────────

/// Repair subscriptions created by earlier (buggy) backfill revisions.
///
/// Earlier revisions wrote several fields incorrectly for already-linked VMs:
///   - `subscription.created` was stamped with the migration time instead of `vm.created`
///   - custom-VM line items got `amount = 0` (showing $0 in the admin UI)
///   - `subscription.currency` used the company base currency instead of the cost-plan /
///     pricing currency
///   - `is_setup`/`is_active` were forced true even for never-paid VMs
///
/// This pass re-derives the correct values and updates the subscription + line item only when
/// they actually differ. It is idempotent: once every row is correct it performs no writes.
async fn repair_migrated_vm_subscription(
    db_impl: Arc<LNVpsDbMysql>,
    db: Arc<dyn LNVpsDb>,
    vm_id: u64,
) -> Result<bool> {
    let vm: VmForMigration = db_impl
        .get_vm_for_migration(vm_id)
        .await
        .context("Failed to get VM")?;

    let line_item_id = match vm.subscription_line_item_id.filter(|&id| id != 0) {
        Some(id) => id,
        None => return Ok(false), // not migrated yet; Phase 1 will handle it
    };

    // A NULL legacy expires means this VM was provisioned by the new (post-migration) path,
    // so its subscription was created correctly and there is no legacy data to back-derive
    // created/is_setup from. The buggy revisions this pass repairs only ever ran against
    // pre-migration VMs (which always have a non-NULL legacy expires), so skip these.
    let Some(legacy_expires) = vm.expires else {
        return Ok(false);
    };

    let mut subscription = db
        .get_subscription_by_line_item_id(line_item_id)
        .await
        .context("Failed to get subscription for VM")?;
    let mut line_item = db
        .get_subscription_line_item(line_item_id)
        .await
        .context("Failed to get subscription line item")?;

    let billing = resolve_vm_billing(&db, &vm).await?;
    let is_setup = legacy_expires > vm.created;
    let want_created = vm.created;
    let want_active = !vm.deleted && is_setup;

    let mut changed = false;
    if subscription.created != want_created {
        subscription.created = want_created;
        changed = true;
    }
    if subscription.currency != billing.currency {
        subscription.currency = billing.currency.clone();
        changed = true;
    }
    if subscription.interval_amount != billing.interval_amount {
        subscription.interval_amount = billing.interval_amount;
        changed = true;
    }
    if subscription.interval_type != billing.interval_type {
        subscription.interval_type = billing.interval_type;
        changed = true;
    }
    if subscription.is_setup != is_setup {
        subscription.is_setup = is_setup;
        changed = true;
    }
    if subscription.is_active != want_active {
        subscription.is_active = want_active;
        changed = true;
    }

    if changed {
        db.update_subscription(&subscription)
            .await
            .context("Failed to update subscription during repair")?;
    }

    if line_item.amount != billing.line_item_amount {
        line_item.amount = billing.line_item_amount;
        db.update_subscription_line_item(&line_item)
            .await
            .context("Failed to update line item during repair")?;
        changed = true;
    }

    if changed {
        info!(
            "Phase 0: repaired VM {} subscription (created={}, currency={}, amount={}, is_setup={})",
            vm_id, want_created, billing.currency, billing.line_item_amount, is_setup
        );
    }

    Ok(changed)
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn vm_for_migration(created: chrono::DateTime<Utc>, deleted: bool) -> VmForMigration {
        // Paid VM: expiry advanced well past creation.
        vm_with_expires(
            created,
            Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap(),
            deleted,
        )
    }

    fn vm_with_expires(
        created: chrono::DateTime<Utc>,
        expires: chrono::DateTime<Utc>,
        deleted: bool,
    ) -> VmForMigration {
        VmForMigration {
            id: 42,
            user_id: 7,
            template_id: Some(1),
            custom_template_id: None,
            created,
            expires: Some(expires),
            auto_renewal_enabled: true,
            subscription_line_item_id: None,
            deleted,
        }
    }

    /// Regression: the backfill must preserve the VM's original creation date on the
    /// subscription, not stamp it with the migration time (was `Utc::now()`).
    #[test]
    fn build_subscription_preserves_vm_created() {
        let vm_created = Utc.with_ymd_and_hms(2025, 1, 15, 12, 30, 0).unwrap();
        let vm = vm_for_migration(vm_created, false);

        let sub = build_subscription_for_vm(
            &vm,
            3,
            "EUR".to_string(),
            1,
            IntervalType::Month,
            "Test (VM 42)",
        );

        assert_eq!(
            sub.created, vm_created,
            "subscription.created must equal vm.created"
        );
        assert_ne!(sub.created, Utc::now());
        // Other preserved fields
        assert_eq!(sub.expires, vm.expires);
        assert_eq!(sub.auto_renewal_enabled, vm.auto_renewal_enabled);
        assert_eq!(sub.user_id, vm.user_id);
        assert_eq!(sub.company_id, 3);
        assert_eq!(sub.currency, "EUR");
        assert!(
            sub.is_active,
            "non-deleted VM must have an active subscription"
        );
        assert!(sub.is_setup);
    }

    /// Deleted VMs must map to inactive subscriptions.
    #[test]
    fn build_subscription_deleted_vm_is_inactive() {
        let vm = vm_for_migration(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(), true);
        let sub = build_subscription_for_vm(&vm, 1, "USD".to_string(), 1, IntervalType::Month, "x");
        assert!(
            !sub.is_active,
            "deleted VM must have an inactive subscription"
        );
    }

    /// Regression: a VM that was still unpaid at migration time (legacy `expires == created`)
    /// must NOT be marked `is_setup`/`is_active`, otherwise the worker's unpaid-VM cleanup
    /// (which now keys off `subscription.is_setup`) would never delete it.
    #[test]
    fn build_subscription_unpaid_vm_is_not_setup() {
        let t = Utc.with_ymd_and_hms(2026, 6, 17, 10, 0, 0).unwrap();
        let vm = vm_with_expires(t, t, false); // expires == created => never paid
        let sub = build_subscription_for_vm(&vm, 1, "EUR".to_string(), 1, IntervalType::Month, "x");
        assert!(!sub.is_setup, "never-paid VM must not be is_setup");
        assert!(!sub.is_active, "never-paid VM must not be active");
    }

    /// A paid VM (expiry advanced past creation) must be `is_setup` and active.
    #[test]
    fn build_subscription_paid_vm_is_setup() {
        let created = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2025, 2, 1, 0, 0, 0).unwrap();
        let vm = vm_with_expires(created, expires, false);
        let sub = build_subscription_for_vm(&vm, 1, "EUR".to_string(), 1, IntervalType::Month, "x");
        assert!(sub.is_setup, "paid VM must be is_setup");
        assert!(sub.is_active, "paid non-deleted VM must be active");
    }

    /// Regression: a VM with a NULL legacy expires (provisioned by the new path) must not
    /// panic/error and must produce a not-setup subscription with no expiry.
    #[test]
    fn build_subscription_null_expires_is_not_setup() {
        let created = Utc.with_ymd_and_hms(2026, 6, 17, 10, 0, 0).unwrap();
        let mut vm = vm_with_expires(created, created, false);
        vm.expires = None;
        let sub = build_subscription_for_vm(&vm, 1, "EUR".to_string(), 1, IntervalType::Month, "x");
        assert_eq!(sub.expires, None, "NULL legacy expires => no subscription expiry");
        assert!(!sub.is_setup, "NULL-expires VM must not be is_setup");
        assert!(!sub.is_active);
    }
}
