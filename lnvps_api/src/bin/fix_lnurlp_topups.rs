//! One-shot admin tool to re-credit LNURL-pay ("topup") payments that were
//! applied to the wrong VM.
//!
//! ## Background
//!
//! Before PR #152 the LNURL-pay callback `v1_renew_vm_lnurlp(vm_id)` called
//! `renew_amount(vm_line.subscription_id, ...)` instead of `renew_amount(vm_id, ...)`.
//! Inside `price_to_payment_with_type` that value is treated as a **VM id**, so a
//! payment scanned for one VM was credited to whichever VM's `id` happened to equal
//! the intended VM's `subscription_id`, and the paid `time_value` extended the wrong
//! subscription's expiry.
//!
//! ## Detection
//!
//! Normal subscription renewals use the invoice memo `"Subscription renewal: {name}"`,
//! while LNURL-pay topups use `"VM renewal {N} to {expiry}"`. The memo is stored in the
//! BOLT11 payment request (`subscription_payment.external_data`), so we can read it back
//! in-process without talking to the Lightning node.
//!
//! For every affected (pre-fix) topup, the number `N` in the memo is the value that was
//! mis-passed as the VM id — i.e. the **intended VM's subscription id**. The correct
//! subscription to credit is therefore exactly `N`, and the intended VM is
//! `get_vm_by_subscription(N)`.
//!
//! ## Why the `--before` cutoff matters
//!
//! After the fix, the same memo carries a real VM id rather than a subscription id, so
//! post-fix topups must NOT be re-pointed. We therefore only consider payments created
//! before the fix went live. The default cutoff is the PR #152 merge date; override it
//! with `--before` to match the actual production deploy time.
//!
//! ## Actions
//!
//! For each affected paid Lightning topup created before the cutoff:
//!   * re-point `payment.subscription_id` to the intended subscription `N`
//!   * extend subscription `N`'s expiry by the payment's `time_value`
//!     (`GREATEST(expires, now) + time_value`, matching `subscription_payment_paid`)
//!
//! The wrongly-credited subscription is intentionally left untouched (its extra time is
//! not clawed back). VMs that are deleted or whose subscription has already expired are
//! skipped.
//!
//! Runs as a dry-run by default; pass `--apply` to persist changes.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use config::{Config, File};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use lnvps_api::settings::Settings;
use lnvps_db::{
    EncryptionContext, LNVpsDb, LNVpsDbMysql, PaymentMethod, SubscriptionPayment,
};
use log::{info, warn};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

/// Default cutoff: the merge date of PR #152 (the fix). Only payments created
/// strictly before this instant are considered. Override with `--before` to
/// match the real production deploy time.
const DEFAULT_BEFORE: &str = "2026-07-03T00:00:00Z";

#[derive(Parser)]
#[clap(about, version, author)]
struct Args {
    /// Path to one or more config files (layered in order, later overrides earlier).
    /// Defaults to `config.yaml`.
    #[clap(short, long)]
    config: Vec<PathBuf>,

    /// Only consider payments created strictly before this RFC3339 timestamp.
    /// Defaults to the PR #152 merge date.
    #[clap(long, default_value = DEFAULT_BEFORE)]
    before: String,

    /// Persist changes. Without this flag the tool only reports what it would do.
    #[clap(long)]
    apply: bool,
}

/// Parse an LNURLp topup memo of the form `"VM renewal {N} to {expiry}"`,
/// returning `N` (the intended subscription id). Returns `None` for any other
/// memo (e.g. normal subscription renewals or description-hash invoices).
fn parse_topup_memo(memo: &str) -> Option<u64> {
    let rest = memo.strip_prefix("VM renewal ")?;
    let (num, _) = rest.split_once(" to ")?;
    num.trim().parse::<u64>().ok()
}

/// Extract the plaintext description from a stored BOLT11 payment request.
fn bolt11_memo(pr: &str) -> Option<String> {
    let invoice = Bolt11Invoice::from_str(pr).ok()?;
    match invoice.description() {
        Bolt11InvoiceDescriptionRef::Direct(d) => Some(d.to_string()),
        // Description-hash invoices don't carry the plaintext memo.
        Bolt11InvoiceDescriptionRef::Hash(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_topup_memo() {
        // Real format: format!("VM renewal {vm_id} to {}", p.new_expiry)
        assert_eq!(
            parse_topup_memo("VM renewal 42 to 2026-08-01 00:00:00 UTC"),
            Some(42)
        );
        assert_eq!(parse_topup_memo("VM renewal 1 to whenever"), Some(1));
    }

    #[test]
    fn ignores_non_topup_memos() {
        assert_eq!(parse_topup_memo("Subscription renewal: my-sub"), None);
        assert_eq!(parse_topup_memo("VM upgrade 7"), None);
        assert_eq!(parse_topup_memo("VM renewal xyz to now"), None);
        assert_eq!(parse_topup_memo("VM renewal 42"), None); // no " to "
        assert_eq!(parse_topup_memo(""), None);
    }

    #[test]
    fn rejects_invalid_bolt11() {
        assert_eq!(bolt11_memo("not-a-bolt11"), None);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    let before: DateTime<Utc> = DateTime::parse_from_rfc3339(&args.before)
        .context("invalid --before timestamp (expected RFC3339)")?
        .with_timezone(&Utc);

    let settings: Settings = {
        let mut builder = Config::builder();
        if args.config.is_empty() {
            builder = builder.add_source(File::from(PathBuf::from("config.yaml")));
        } else {
            for path in &args.config {
                builder = builder.add_source(File::from(path.clone()));
            }
        }
        builder.build()?.try_deserialize()?
    };

    if let Some(ref encryption_config) = settings.encryption {
        EncryptionContext::init_from_file(
            &encryption_config.key_file,
            encryption_config.auto_generate,
        )?;
        info!("Database encryption initialized");
    }

    let db = LNVpsDbMysql::new(&settings.db).await?;
    let db: Arc<dyn LNVpsDb> = Arc::new(db);

    info!(
        "Scanning LNURLp topups created before {} ({} mode)",
        before,
        if args.apply { "APPLY" } else { "DRY-RUN" }
    );

    let now = Utc::now();
    let mut scanned = 0usize;
    let mut topups = 0usize;
    let mut fixed = 0usize;
    let mut skipped = 0usize;

    let subscriptions = db.list_subscriptions().await?;
    for sub in &subscriptions {
        let payments = db.list_subscription_payments(sub.id).await?;
        for payment in payments {
            scanned += 1;

            // Only paid Lightning topups created before the fix are candidates.
            if !payment.is_paid
                || payment.payment_method != PaymentMethod::Lightning
                || payment.created >= before
            {
                continue;
            }

            let memo = match bolt11_memo(payment.external_data.as_str()) {
                Some(m) => m,
                None => continue,
            };
            let intended_sub_id = match parse_topup_memo(&memo) {
                Some(n) => n,
                None => continue, // not an LNURLp topup memo
            };
            topups += 1;

            // Already credited to the right subscription (happens when the
            // intended VM's id equals its subscription id): nothing to do.
            if payment.subscription_id == intended_sub_id {
                continue;
            }

            if let Err(e) = plan_and_apply(
                db.as_ref(),
                &payment,
                intended_sub_id,
                now,
                args.apply,
                &mut fixed,
                &mut skipped,
            )
            .await
            {
                warn!(
                    "payment {} (memo {:?}): {}",
                    hex::encode(&payment.id),
                    memo,
                    e
                );
                skipped += 1;
            }
        }
    }

    info!(
        "Done. scanned={} topups={} {}={} skipped={}",
        scanned,
        topups,
        if args.apply { "fixed" } else { "would-fix" },
        fixed,
        skipped
    );
    if !args.apply && fixed > 0 {
        info!("Dry-run only — re-run with --apply to persist these changes.");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn plan_and_apply(
    db: &dyn LNVpsDb,
    payment: &SubscriptionPayment,
    intended_sub_id: u64,
    now: DateTime<Utc>,
    apply: bool,
    fixed: &mut usize,
    skipped: &mut usize,
) -> Result<()> {
    // The intended subscription must exist and own a live VM.
    let mut intended_sub = db
        .get_subscription(intended_sub_id)
        .await
        .with_context(|| format!("intended subscription {intended_sub_id} not found"))?;

    let vm = db
        .get_vm_by_subscription(intended_sub_id)
        .await
        .with_context(|| format!("no VM for subscription {intended_sub_id}"))?;

    // Skip VMs that are gone or whose subscription already lapsed.
    if vm.deleted {
        info!(
            "skip payment {}: intended VM {} is deleted",
            hex::encode(&payment.id),
            vm.id
        );
        *skipped += 1;
        return Ok(());
    }
    if let Some(exp) = intended_sub.expires
        && exp < now
    {
        info!(
            "skip payment {}: intended subscription {} already expired at {}",
            hex::encode(&payment.id),
            intended_sub_id,
            exp
        );
        *skipped += 1;
        return Ok(());
    }

    let time_value = payment.time_value.unwrap_or(0);
    let new_expiry = intended_sub
        .expires
        .map(|e| e.max(now))
        .unwrap_or(now)
        + chrono::Duration::seconds(time_value as i64);

    info!(
        "FIX payment {}: subscription {} -> {} (VM {}), +{}s expiry {} -> {}",
        hex::encode(&payment.id),
        payment.subscription_id,
        intended_sub_id,
        vm.id,
        time_value,
        intended_sub
            .expires
            .map(|e| e.to_rfc3339())
            .unwrap_or_else(|| "none".into()),
        new_expiry.to_rfc3339(),
    );

    if apply {
        // Re-point first so the operation is idempotent: a re-run sees the
        // corrected subscription_id and skips, avoiding a double extension.
        let mut updated = payment.clone();
        updated.subscription_id = intended_sub_id;
        db.update_subscription_payment(&updated).await?;

        intended_sub.expires = Some(new_expiry);
        intended_sub.is_active = true;
        intended_sub.is_setup = true;
        db.update_subscription(&intended_sub).await?;
    }

    *fixed += 1;
    Ok(())
}
