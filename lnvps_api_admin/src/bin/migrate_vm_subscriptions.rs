/// Data migration tool: migrate VMs to the subscription payment system.
///
/// For each active, non-deleted VM that doesn't yet have a `subscription_id`:
///   - Standard VMs (template_id set): create a subscription from the cost plan interval/amount.
///   - Custom VMs (custom_template_id set): create a subscription with 1-Month interval.
///   - VMs with neither: skip with a warning.
///
/// The migration is idempotent: VMs that already have a subscription_id are skipped.
/// Use --dry-run to preview what would be done without writing to the database.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::Parser;
use config::{Config, File};
use lnvps_api_admin::settings::Settings;
use lnvps_db::{
    EncryptionContext, IntervalType, LNVpsDb, LNVpsDbBase, LNVpsDbMysql, Subscription,
    SubscriptionLineItem, SubscriptionType,
};
use log::{info, warn};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[clap(
    about = "Migrate VMs to the subscription payment system",
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
    let db: Arc<dyn LNVpsDb> = Arc::new(db_impl);

    if args.dry_run {
        info!("*** DRY RUN MODE — no changes will be written ***");
    }

    run_migration(db, args.dry_run).await
}

async fn run_migration(db: Arc<dyn LNVpsDb>, dry_run: bool) -> Result<()> {
    let vms = db.list_vms().await.context("Failed to list VMs")?;

    let mut migrated = 0usize;
    let mut skipped = 0usize;
    let mut errored = 0usize;

    for vm in &vms {
        // Skip deleted VMs
        if vm.deleted {
            skipped += 1;
            continue;
        }
        // Skip VMs already linked to a subscription
        if vm.subscription_id.is_some() {
            skipped += 1;
            continue;
        }

        match migrate_vm(db.clone(), vm.id, dry_run).await {
            Ok(()) => migrated += 1,
            Err(e) => {
                warn!("Failed to migrate VM {}: {:#}", vm.id, e);
                errored += 1;
            }
        }
    }

    info!(
        "Migration complete: {} migrated, {} skipped, {} errors",
        migrated, skipped, errored
    );

    if errored > 0 {
        bail!("{} VMs could not be migrated (see warnings above)", errored);
    }

    Ok(())
}

async fn migrate_vm(db: Arc<dyn LNVpsDb>, vm_id: u64, dry_run: bool) -> Result<()> {
    let vm = db.get_vm(vm_id).await.context("Failed to get VM")?;

    // Determine currency and company
    let company_id = db
        .get_vm_company_id(vm_id)
        .await
        .context("Failed to get company id for VM")?;
    let company = db
        .get_company(company_id)
        .await
        .context("Failed to get company")?;
    let currency = company.base_currency.clone();

    // Determine interval and line item amount based on pricing type
    let (interval_amount, interval_type, line_item_amount, description) =
        if let Some(template_id) = vm.template_id {
            // Standard VM: get cost plan from template
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
            // Custom VM: always billed monthly; amount computed from pricing
            let desc = format!("Custom VM {}", vm_id);
            (1u64, IntervalType::Month, 0u64, desc)
        } else {
            bail!(
                "VM {} has neither template_id nor custom_template_id — skipping",
                vm_id
            );
        };

    let time_value = interval_to_seconds(interval_type, interval_amount);

    info!(
        "{} VM {} → subscription ({} {} {:?}, time_value={}s, amount={})",
        if dry_run { "[DRY RUN]" } else { "Migrating" },
        vm_id,
        interval_amount,
        match interval_type {
            IntervalType::Day => "day(s)",
            IntervalType::Month => "month(s)",
            IntervalType::Year => "year(s)",
        },
        currency,
        time_value,
        line_item_amount,
    );

    if dry_run {
        return Ok(());
    }

    let subscription = Subscription {
        id: 0,
        user_id: vm.user_id,
        company_id,
        name: format!("VM {} Subscription", vm_id),
        description: Some(description.clone()),
        created: Utc::now(),
        expires: Some(vm.expires),
        is_active: true,
        currency: currency.clone(),
        interval_amount,
        interval_type,
        setup_fee: 0,
        auto_renewal_enabled: vm.auto_renewal_enabled,
        external_id: None,
    };

    let line_item = SubscriptionLineItem {
        id: 0,
        subscription_id: 0, // filled by insert_subscription_with_line_items
        subscription_type: SubscriptionType::VmRenewal,
        name: description,
        description: None,
        amount: line_item_amount,
        setup_amount: 0,
        configuration: None,
    };

    let subscription_id = db
        .insert_subscription_with_line_items(&subscription, vec![line_item])
        .await
        .context("Failed to insert subscription")?;

    // Link the VM to the new subscription
    let mut updated_vm = vm;
    updated_vm.subscription_id = Some(subscription_id);
    db.update_vm(&updated_vm)
        .await
        .context("Failed to update VM with subscription_id")?;

    info!(
        "VM {} → subscription {} (time_value={}s)",
        vm_id, subscription_id, time_value
    );

    Ok(())
}
