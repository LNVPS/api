/// Data migration tool: migrate VMs to the subscription payment system.
///
/// Phase 1 — Subscription backfill:
///   For every VM (including deleted) that does not yet have a subscription_line_item_id:
///   - Standard VMs (template_id set): create a subscription from the cost plan interval/amount.
///   - Custom VMs (custom_template_id set): create a subscription with 1-Month interval.
///   - VMs with neither: skip with a warning.
///
/// Phase 2 — Payment backfill:
///   For every vm_payment that has not yet been copied to subscription_payment:
///   - Look up the VM's subscription_line_item_id (set in Phase 1).
///   - Insert a matching subscription_payment row preserving all fields.
///   - PaymentType::Renewal → SubscriptionPaymentType::Renewal
///   - PaymentType::Upgrade → SubscriptionPaymentType::Upgrade
///   - upgrade_params JSON string → metadata serde_json::Value
///
/// Both phases are idempotent. Use --dry-run to preview without writing.
use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::Parser;
use config::{Config, File};
use lnvps_api_admin::settings::Settings;
use lnvps_db::{
    EncryptionContext, IntervalType, LNVpsDb, LNVpsDbBase, LNVpsDbMysql, Subscription,
    SubscriptionLineItem, SubscriptionPaymentType, SubscriptionType, VmForMigration, VmPaymentRaw,
};
use log::{info, warn};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[clap(
    about = "Migrate VMs and vm_payment records to the subscription payment system",
    version,
    author
)]
struct Args {
    /// Path to the config file
    #[clap(short, long)]
    config: Option<PathBuf>,

    /// Preview changes without writing to the database
    #[clap(long)]
    dry_run: bool,
}

/// Compute interval-to-seconds matching PricingEngine::cost_plan_interval_to_seconds.
fn interval_to_seconds(interval_type: IntervalType, interval_amount: u64) -> i64 {
    let base = match interval_type {
        IntervalType::Day => 86_400i64,
        IntervalType::Month => 2_592_000i64, // 30 days
        IntervalType::Year => 31_536_000i64, // 365 days
    };
    base * interval_amount as i64
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    let settings: Settings = Config::builder()
        .add_source(File::from(
            args.config.unwrap_or(PathBuf::from("config.yaml")),
        ))
        .build()?
        .try_deserialize()?;

    if let Some(ref encryption_config) = settings.encryption {
        EncryptionContext::init_from_file(
            &encryption_config.key_file,
            encryption_config.auto_generate,
        )?;
        info!("Database encryption initialized");
    }

    let db_impl = LNVpsDbMysql::new(&settings.db).await?;
    db_impl.migrate().await?;
    let db_impl = Arc::new(db_impl);
    let db: Arc<dyn LNVpsDb> = db_impl.clone();

    if args.dry_run {
        info!("*** DRY RUN MODE — no changes will be written ***");
    }

    // Phase 1: create subscriptions for all VMs (including deleted)
    let vm_ids = db_impl
        .list_vm_ids_without_subscription()
        .await
        .context("Failed to list VMs needing subscription")?;
    info!("Phase 1: {} VMs need a subscription", vm_ids.len());

    let mut sub_migrated = 0usize;
    let mut sub_errored = 0usize;
    for vm_id in &vm_ids {
        match migrate_vm_subscription(db_impl.clone(), db.clone(), *vm_id, args.dry_run).await {
            Ok(()) => sub_migrated += 1,
            Err(e) => {
                warn!("Phase 1: Failed to migrate VM {}: {:#}", vm_id, e);
                sub_errored += 1;
            }
        }
    }
    info!(
        "Phase 1 complete: {} subscriptions created, {} errors",
        sub_migrated, sub_errored
    );

    // Phase 2: backfill vm_payment → subscription_payment
    let payment_vm_ids = db_impl
        .list_vm_ids_with_uncopied_payments()
        .await
        .context("Failed to list VMs with uncopied payments")?;
    info!(
        "Phase 2: {} VMs have vm_payment records to backfill",
        payment_vm_ids.len()
    );

    let mut pay_migrated = 0usize;
    let mut pay_errored = 0usize;
    for vm_id in &payment_vm_ids {
        match migrate_vm_payments(db_impl.clone(), db.clone(), *vm_id, args.dry_run).await {
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
    info!(
        "Phase 2 complete: {} payments backfilled, {} VM errors",
        pay_migrated, pay_errored
    );

    if sub_errored > 0 || pay_errored > 0 {
        bail!(
            "{} subscription errors, {} payment VM errors (see warnings above)",
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
    dry_run: bool,
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
            bail!(
                "VM {} has neither template_id nor custom_template_id",
                vm_id
            );
        };

    let time_value = interval_to_seconds(interval_type, interval_amount);
    info!(
        "{} VM {} → subscription ({} {}, time_value={}s, amount={})",
        if dry_run { "[DRY RUN]" } else { "Phase 1:" },
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

    if dry_run {
        return Ok(());
    }

    // Deleted VMs should have inactive subscriptions — they are no longer running.
    let is_active = !vm.deleted;

    let subscription = Subscription {
        id: 0,
        user_id: vm.user_id,
        company_id,
        name: format!("VM {} Subscription", vm_id),
        description: Some(description.clone()),
        created: Utc::now(),
        expires: None, // vm.expires column removed; set manually after migration if needed
        is_active,
        is_setup: true,
        currency,
        interval_amount,
        interval_type,
        setup_fee: 0,
        auto_renewal_enabled: false,
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

    info!(
        "Phase 1: VM {} → subscription line item {}",
        vm_id, subscription_line_item_id
    );
    Ok(())
}

// ─── Phase 2: payment backfill ───────────────────────────────────────────────

async fn migrate_vm_payments(
    db_impl: Arc<LNVpsDbMysql>,
    db: Arc<dyn LNVpsDb>,
    vm_id: u64,
    dry_run: bool,
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

    let subscription_id = db.get_subscription_by_line_item_id(subscription_line_item_id).await?.id;

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
        let metadata = vp
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
        let metadata_str: Option<String> =
            metadata.as_ref().map(|v: &serde_json::Value| v.to_string());

        if dry_run {
            info!(
                "[DRY RUN] VM {} payment {} → subscription_payment (paid={}, amount={} {})",
                vm_id,
                hex::encode(&vp.id),
                vp.is_paid,
                vp.amount,
                vp.currency
            );
        } else {
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
            info!(
                "Phase 2: VM {} payment {} → subscription_payment",
                vm_id,
                hex::encode(&vp.id)
            );
        }
        copied += 1;
    }

    Ok(copied)
}
