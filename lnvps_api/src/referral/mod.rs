//! Automated referral commission payouts.
//!
//! Referrers accrue commission (a percentage of each referred VM's first
//! payment; see the pricing/DB layer). This module turns that accrued **BTC**
//! commission into outgoing Lightning payments, independently of the
//! subscription/billing machinery.
//!
//! Fiat-settled commission can also be paid automatically: the balance is
//! quoted against BTC at send time and transferred as sats, recorded with both
//! sides and the rate used. Automated payouts are opt-in — each kind is
//! disabled entirely when its minimum threshold is not configured.

use crate::fee_estimate::FeeEstimator;
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use lnvps_api_common::{
    ExchangeRateService, KeyValueStore, Ticker, TickerRate, WorkCommander, WorkJob,
};
use lnvps_db::{LNVpsDb, Referral, ReferralPayout, ReferralPayoutMode};
use log::{debug, info, warn};
use payments_rs::currency::{Currency, CurrencyAmount};
use payments_rs::lightning::{LightningNode, PayInvoiceRequest};
use payments_rs::onchain::{OnChainProvider, SendCoinsRequest, SendOutput};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

/// The effective payout threshold (in msat) for a referrer: the larger of the
/// system minimum and the referrer's own chosen `payout_threshold` (sats), so a
/// referrer can raise — but never lower — the bar to avoid many tiny payouts.
fn effective_min_msat(referral: &Referral, system_min_msat: u64) -> u64 {
    match referral.payout_threshold {
        Some(sats) => sats.saturating_mul(1000).max(system_min_msat),
        None => system_min_msat,
    }
}

/// The payable referral commission (millisats) for one balance: `owed_msat` is
/// what this balance holds, `total_msat` is everything the referrer is owed
/// valued in millisats across every currency, and the threshold is judged on
/// the latter.
///
/// A referrer is owed the sum of their balances, not each one separately: with
/// the threshold applied per currency, someone holding a little BTC and a
/// little EUR is never paid either, however large the two are together. The
/// floor exists to stop dust payments, so it belongs on the run as a whole.
///
/// Returns `None` below the threshold, or when the balance rounds to zero whole
/// sats — Bitcoin settles whole sats, so a sub-sat remainder stays owed for a
/// later payout.
fn payable_from_total(owed_msat: u64, total_msat: u64, min_msat: u64) -> Option<u64> {
    if total_msat < min_msat {
        return None;
    }
    let pay_msat = (owed_msat / 1000) * 1000;
    if pay_msat == 0 { None } else { Some(pay_msat) }
}

/// Value `owed` units of `currency` in millisats at `rate`.
fn quoted_msat(currency: &str, owed: u64, rate: TickerRate) -> Result<u64> {
    let settled_currency = Currency::from_str(currency)
        .map_err(|_| anyhow!("unsupported payout currency {}", currency))?;
    Ok(rate
        .convert(CurrencyAmount::from_u64(settled_currency, owed))?
        .value())
}

/// Most sats one converted payout may send.
///
/// The quote comes from a cache with no age on it, so a stale or wrong feed
/// value passes every sanity check and multiplies what leaves the node — and a
/// Lightning payment does not come back. A commission payout is small; anything
/// above this is a rate to distrust, so the balance is left to accrue for a
/// human to look at rather than sent.
const MAX_CONVERTED_PAYOUT_MSAT: u64 = 1_000_000_000;

/// A converted payout refused because the quote values it above
/// [`MAX_CONVERTED_PAYOUT_MSAT`].
///
/// Typed rather than a bare message so a caller can tell "the rate is not to be
/// trusted" apart from every other reason a payout did not happen, and tell an
/// operator about it once.
#[derive(Debug)]
struct RefusedOverCeiling {
    currency: String,
    owed: u64,
    pay_msat: u64,
}

impl std::fmt::Display for RefusedOverCeiling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "converted payout of {} msat for {} {} exceeds the {} msat ceiling; check the rate",
            self.pay_msat, self.owed, self.currency, MAX_CONVERTED_PAYOUT_MSAT
        )
    }
}

impl std::error::Error for RefusedOverCeiling {}

/// Build the payout row for a fiat-settled balance paid as sats, or `None` when
/// the converted balance is below the threshold. Errors when it is above the
/// per-payout ceiling.
///
/// `total_msat` is the referrer's whole outstanding balance valued in millisats
/// (see [`payable_from_total`]); it is the figure the threshold is judged on,
/// while `owed` is what this row settles.
///
/// The row is reserved unpaid: `amount`/`currency` are what it discharges,
/// `sent_amount` is what leaves the wallet, and `rate` is the quote both were
/// taken at. The settled amount is derived **back** from the rounded-to-sats
/// transfer, so the sub-sat remainder Lightning cannot send stays owed instead
/// of being written off.
fn converted_payout(
    referral: &Referral,
    currency: &str,
    owed: u64,
    rate: TickerRate,
    total_msat: u64,
    min_msat: u64,
) -> Result<Option<ReferralPayout>> {
    let quoted_msat = quoted_msat(currency, owed, rate)?;
    let Some(pay_msat) = payable_from_total(quoted_msat, total_msat, min_msat) else {
        return Ok(None);
    };
    if pay_msat > MAX_CONVERTED_PAYOUT_MSAT {
        return Err(RefusedOverCeiling {
            currency: currency.to_uppercase(),
            owed,
            pay_msat,
        }
        .into());
    }
    let settled_amount = rate.convert(CurrencyAmount::millisats(pay_msat))?.value();
    if settled_amount == 0 {
        return Ok(None);
    }
    Ok(Some(ReferralPayout {
        referral_id: referral.id,
        amount: settled_amount,
        currency: currency.to_uppercase(),
        sent_amount: pay_msat,
        sent_currency: Currency::BTC.to_string(),
        rate: rate.rate,
        rate_collected: Some(Utc::now()),
        created: Utc::now(),
        mode: referral.mode,
        ..Default::default()
    }))
}

/// Amount already reserved or paid against a referrer's balance in `currency`,
/// in that currency's smallest unit.
///
/// A payout nets in the currency it settles, not the currency it sent: a EUR
/// commission sent as BTC discharges EUR and must leave the BTC balance alone,
/// or the referrer is charged twice for one transfer. The referrer bears the
/// fee, so it is debited alongside the amount.
fn settled_in(payouts: &[ReferralPayout], currency: &str) -> u64 {
    payouts
        .iter()
        .filter(|p| p.currency.eq_ignore_ascii_case(currency))
        .map(|p| p.amount.saturating_add(p.fee))
        .sum()
}

/// Commission earned per settled currency, excluding BTC (which the BTC passes
/// own). Keys are upper-cased so `eur` and `EUR` are one balance.
fn earned_by_fiat_currency(usage: &[lnvps_db::ReferralCostUsage]) -> BTreeMap<String, u64> {
    let mut earned: BTreeMap<String, u64> = BTreeMap::new();
    for u in usage
        .iter()
        .filter(|u| !u.currency.eq_ignore_ascii_case("BTC"))
    {
        *earned.entry(u.currency.to_uppercase()).or_default() += u.commission();
    }
    earned
}

/// Split `total_fee` across payouts in proportion to their `amounts`, returning
/// one fee per entry (in order). Any rounding remainder is added to the largest
/// payout so the shares sum to exactly `total_fee`.
fn split_fee_proportional(amounts: &[u64], total_fee: u64) -> Vec<u64> {
    let sum: u128 = amounts.iter().map(|a| *a as u128).sum();
    if sum == 0 || total_fee == 0 {
        return vec![0; amounts.len()];
    }
    let mut shares: Vec<u64> = amounts
        .iter()
        .map(|a| ((*a as u128 * total_fee as u128) / sum) as u64)
        .collect();
    let assigned: u64 = shares.iter().sum();
    let remainder = total_fee.saturating_sub(assigned);
    if remainder > 0 {
        if let Some((idx, _)) = amounts.iter().enumerate().max_by_key(|(_, a)| **a) {
            shares[idx] += remainder;
        }
    }
    shares
}

/// Decode a hex-encoded raw transaction. Returns `None` if it can't be parsed.
fn decode_tx(raw_tx_hex: &str) -> Option<bitcoin::Transaction> {
    let bytes = hex::decode(raw_tx_hex.trim()).ok()?;
    bitcoin::consensus::encode::deserialize(&bytes).ok()
}

/// Find the output index (`vout`) in `tx` that pays `address`.
///
/// Matches on the output **script**, computed from the address, so it works
/// regardless of the network the address string is encoded for (a mainnet and a
/// regtest address for the same witness program share a script_pubkey).
fn vout_for_address(tx: &bitcoin::Transaction, address: &str) -> Option<u32> {
    use std::str::FromStr;
    let script = bitcoin::Address::from_str(address.trim())
        .ok()?
        .assume_checked()
        .script_pubkey();
    tx.output
        .iter()
        .position(|o| o.script_pubkey == script)
        .map(|i| i as u32)
}

/// One payout in an on-chain batch: the reserved row, where it is paid, and the
/// quote it was converted at (`None` when it settles the BTC balance directly).
struct BatchRow {
    referral: Referral,
    address: String,
    payout: ReferralPayout,
    rate: Option<TickerRate>,
}

/// Pays referrers their accrued BTC commission over Lightning or on-chain.
#[derive(Clone)]
pub struct ReferralPayoutHandler {
    db: Arc<dyn LNVpsDb>,
    node: Arc<dyn LightningNode>,
    tx: Arc<dyn WorkCommander>,
    /// Minimum accrued BTC commission (millisats) before a Lightning payout is
    /// attempted. `None` disables automated Lightning payouts.
    min_payout_msat: Option<u64>,
    /// On-chain provider used to pay [`ReferralPayoutMode::OnChain`] referrers.
    /// `None` (or a `None` threshold) disables automated on-chain payouts.
    onchain: Option<Arc<dyn OnChainProvider>>,
    /// Minimum accrued BTC commission (millisats) before an on-chain payout is
    /// attempted. Separate from (and typically higher than) the Lightning
    /// minimum because on-chain payouts compete with mempool fees.
    min_onchain_payout_msat: Option<u64>,
    /// Maximum next-block fee rate (sat/vByte) tolerated for on-chain payouts;
    /// batches are deferred when the current rate exceeds this.
    max_onchain_fee_per_vbyte: u64,
    /// Source of the current on-chain fee-rate estimate (mockable).
    fee_estimator: Arc<dyn FeeEstimator>,
    /// Rate source used to quote a fiat-settled balance against BTC at send
    /// time.
    exchange: Arc<dyn ExchangeRateService>,
    /// Minimum fiat-settled commission, valued in millisats at the quote, before
    /// an automated converted payout is attempted. `None` disables automated
    /// fiat payouts; the balance still accrues for manual payout.
    min_fiat_payout_msat: Option<u64>,
    /// Remembers which balances are currently refused over the ceiling, so an
    /// operator hears about a refusal once instead of on every pass.
    kv: Arc<dyn KeyValueStore>,
}

impl ReferralPayoutHandler {
    /// Create a handler. `min_payout_sats` of `None` disables automated
    /// Lightning payouts; `onchain`/`min_onchain_payout_sats` of `None` disables
    /// automated on-chain payouts. In all cases commission still accrues and can
    /// be paid manually by admins.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Arc<dyn LNVpsDb>,
        node: Arc<dyn LightningNode>,
        tx: Arc<dyn WorkCommander>,
        min_payout_sats: Option<u64>,
        onchain: Option<Arc<dyn OnChainProvider>>,
        min_onchain_payout_sats: Option<u64>,
        max_onchain_fee_per_vbyte: u64,
        fee_estimator: Arc<dyn FeeEstimator>,
        exchange: Arc<dyn ExchangeRateService>,
        min_fiat_payout_sats: Option<u64>,
        kv: Arc<dyn KeyValueStore>,
    ) -> Self {
        Self {
            db,
            node,
            tx,
            min_payout_msat: min_payout_sats.map(|s| s.saturating_mul(1000)),
            onchain,
            min_onchain_payout_msat: min_onchain_payout_sats.map(|s| s.saturating_mul(1000)),
            max_onchain_fee_per_vbyte,
            fee_estimator,
            exchange,
            min_fiat_payout_msat: min_fiat_payout_sats.map(|s| s.saturating_mul(1000)),
            kv,
        }
    }

    /// Key holding whether one referrer's balance in `currency` is currently
    /// refused over the ceiling.
    ///
    /// Without redis configured this state lives in memory, so a restart
    /// re-alerts on a standing refusal.
    fn refusal_key(referral_id: u64, currency: &str) -> String {
        format!(
            "referral:payout-refused:{}:{}",
            referral_id,
            currency.to_uppercase()
        )
    }

    /// Tell admins a payout was refused, but only on the transition into the
    /// refused state: the balance is re-evaluated every pass, so notifying on
    /// the state itself would notify forever.
    async fn note_refusal(&self, referral: &Referral, refusal: &RefusedOverCeiling) {
        let key = Self::refusal_key(referral.id, &refusal.currency);
        match self.kv.get(&key).await {
            Ok(Some(v)) if v == b"1" => return,
            Ok(_) => {}
            // Notify anyway when the state is unknown: a duplicate alert is
            // cheaper than a refusal nobody hears about.
            Err(e) => warn!(
                "Failed to read refusal state for code {}: {}",
                referral.code, e
            ),
        }
        let _ = self
            .tx
            .send(WorkJob::SendAdminNotification {
                title: Some("Referral payout refused".to_string()),
                message: format!(
                    "A referral payout for code {} was refused: {}.\n\
                     Either the {} rate is wrong, or the referrer is legitimately owed \
                     more than the ceiling and needs paying by hand. The balance keeps \
                     accruing and nothing left the wallet.",
                    referral.code, refusal, refusal.currency
                ),
            })
            .await;
        if let Err(e) = self.kv.store(&key, b"1").await {
            warn!(
                "Failed to record refusal state for code {}: {}",
                referral.code, e
            );
        }
    }

    /// Forget a refusal once the balance pays, so a later one is reported again.
    async fn clear_refusal(&self, referral_id: u64, currency: &str) {
        let key = Self::refusal_key(referral_id, currency);
        if let Err(e) = self.kv.store(&key, b"0").await {
            warn!(
                "Failed to clear refusal state for referral {}: {}",
                referral_id, e
            );
        }
    }

    /// Tell admins when a conversion was refused over the ceiling.
    async fn note_refusal_over_ceiling(&self, referral: &Referral, e: &anyhow::Error) {
        if let Some(refusal) = e.downcast_ref::<RefusedOverCeiling>() {
            self.note_refusal(referral, refusal).await;
        }
    }

    /// Process automated payouts for every enrolled referrer. Per-referrer
    /// failures are logged and do not abort the batch.
    ///
    /// Lightning/NWC referrers are paid individually; on-chain referrers are
    /// **batched into a single send-many transaction** (see
    /// [`Self::process_onchain_batch`]) so one transaction (and one fee) covers
    /// every eligible on-chain payout in the run.
    pub async fn process_payouts(&self) -> Result<()> {
        let referrals = self.db.list_all_referrals().await?;

        // Lightning / NWC payouts, one payment each.
        if let Some(min_msat) = self.min_payout_msat {
            debug!(
                "Processing Lightning referral payouts for {} referrers (min {} msat)",
                referrals.len(),
                min_msat
            );
            for referral in &referrals {
                // On-chain referrers are handled by the batched pass below.
                if referral.mode == ReferralPayoutMode::OnChain {
                    continue;
                }
                if let Err(e) = self.process_one(referral, min_msat).await {
                    warn!("Referral payout failed for code {}: {}", referral.code, e);
                }
            }
        }

        // Fiat-settled balances of Lightning/NWC referrers, converted at the
        // current rate and sent as sats. On-chain referrers' fiat balances are
        // settled by the batch below.
        if let Some(min_fiat_msat) = self.min_fiat_payout_msat {
            for referral in &referrals {
                if let Err(e) = self.process_fiat(referral, min_fiat_msat).await {
                    warn!(
                        "Converted referral payout failed for code {}: {}",
                        referral.code, e
                    );
                }
            }
        }

        // On-chain payouts (BTC and fiat balances), batched into one transaction.
        if let (Some(onchain), Some(min_onchain_msat)) =
            (self.onchain.as_ref(), self.min_onchain_payout_msat)
        {
            if let Err(e) = self
                .process_onchain_batch(onchain.as_ref(), &referrals, min_onchain_msat)
                .await
            {
                warn!("On-chain referral payout batch failed: {}", e);
            }
        }

        Ok(())
    }

    /// Pay every eligible [`ReferralPayoutMode::OnChain`] referrer in a **single
    /// send-many transaction**, settling both their BTC and their fiat balances.
    ///
    /// Each referrer's owed BTC commission is computed exactly as for Lightning
    /// (earned minus already paid/reserved, cleared against the on-chain
    /// threshold and rounded to whole sats). Every eligible payout is reserved
    /// (unpaid) up-front so a crash or concurrent run cannot double-pay, then a
    /// single transaction pays them all. On success the shared `txid` is
    /// recorded on every payout row; on failure all reservations are released so
    /// the balances retry next run.
    ///
    /// The network fee is **charged to the referrers**: after the batch
    /// confirms, the transaction fee is split across the batch in proportion to
    /// each payout and debited from the referrer's balance (see
    /// [`Self::payable_onchain_msat`]). Before broadcasting, the current
    /// next-block fee rate is fetched from mempool.space and the batch is
    /// deferred if it exceeds the configured cap, so payouts wait for cheaper
    /// fees.
    async fn process_onchain_batch(
        &self,
        onchain: &dyn OnChainProvider,
        referrals: &[Referral],
        min_onchain_msat: u64,
    ) -> Result<()> {
        // 1. Select eligible on-chain referrers and their payable amount.
        let mut eligible: Vec<(Referral, String, u64)> = Vec::new();
        let mut fiat: Vec<(Referral, String, String, u64, u64)> = Vec::new();
        for referral in referrals {
            if referral.mode != ReferralPayoutMode::OnChain {
                continue;
            }
            let Some(address) = referral
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                debug!(
                    "Skipping on-chain payout for code {}: no payout address",
                    referral.code
                );
                continue;
            };
            // The threshold is judged on everything this referrer is owed, so
            // the total is computed once and shared by both balances.
            let with_fiat = self.min_fiat_payout_msat.is_some();
            let total_msat = match self.total_owed_msat(referral, true, with_fiat).await {
                Ok(total) => total,
                Err(e) => {
                    warn!(
                        "Failed to value the on-chain balance for code {}: {}",
                        referral.code, e
                    );
                    continue;
                }
            };
            match self
                .payable_onchain_msat(referral, min_onchain_msat, total_msat)
                .await
            {
                Ok(Some(pay_msat)) => {
                    eligible.push((referral.clone(), address.to_string(), pay_msat))
                }
                Ok(None) => {}
                Err(e) => warn!(
                    "Failed to compute on-chain payout for code {}: {}",
                    referral.code, e
                ),
            }
            if with_fiat {
                match self.owed_fiat(referral).await {
                    Ok(owed) => fiat.extend(owed.into_iter().map(|(currency, amount)| {
                        (
                            referral.clone(),
                            address.to_string(),
                            currency,
                            amount,
                            total_msat,
                        )
                    })),
                    Err(e) => warn!(
                        "Failed to compute fiat on-chain balance for code {}: {}",
                        referral.code, e
                    ),
                }
            }
        }
        if eligible.is_empty() && fiat.is_empty() {
            return Ok(());
        }
        self.send_batch(onchain, eligible, fiat, min_onchain_msat)
            .await
    }

    /// Current BTC quote for `currency`, rejected when the feed returns
    /// something that cannot be a price.
    async fn quote(&self, currency: &str) -> Result<TickerRate> {
        let ticker = Ticker::btc_rate(currency)?;
        let rate = self
            .exchange
            .get_rate(ticker)
            .await
            .ok_or_else(|| anyhow!("no {} rate available", ticker))?;
        if !(rate.is_finite() && rate > 0.0) {
            bail!("unusable {} rate {}", ticker, rate);
        }
        Ok(TickerRate { ticker, rate })
    }

    /// Outstanding fiat-settled commission per currency for one referrer, in
    /// each currency's smallest unit. Balances below the threshold are kept —
    /// the threshold applies to the converted amount, which is only known once
    /// the batch is quoted.
    async fn owed_fiat(&self, referral: &Referral) -> Result<Vec<(String, u64)>> {
        let usage = self.db.list_referral_usage(&referral.code).await?;
        let earned = earned_by_fiat_currency(&usage);
        if earned.is_empty() {
            return Ok(Vec::new());
        }
        let payouts = self.db.list_referral_payouts(referral.id).await?;
        Ok(earned
            .into_iter()
            .filter_map(|(currency, earned_amount)| {
                let owed = earned_amount.saturating_sub(settled_in(&payouts, &currency));
                (owed > 0).then_some((currency, owed))
            })
            .collect())
    }

    /// Outstanding BTC-settled commission (millisats) for one referrer: earned
    /// minus every existing (paid + reserved) BTC payout.
    async fn owed_btc_msat(&self, referral: &Referral) -> Result<u64> {
        let usage = self.db.list_referral_usage(&referral.code).await?;
        let earned_msat: u64 = usage
            .iter()
            .filter(|u| u.currency.eq_ignore_ascii_case("BTC"))
            .map(|u| u.commission())
            .sum();
        let existing = settled_in(&self.db.list_referral_payouts(referral.id).await?, "BTC");
        Ok(earned_msat.saturating_sub(existing))
    }

    /// Everything a referrer is owed, valued in millisats: the BTC balance plus
    /// every fiat balance quoted against BTC at the current rate.
    ///
    /// This is the figure the payout threshold is judged on, so that several
    /// small balances that together clear the floor are paid instead of
    /// accruing forever. Only the kinds actually payable in this pass are
    /// counted (`include_btc`/`include_fiat`), so a balance that cannot leave
    /// the wallet does not unlock one that can. A currency whose rate cannot be
    /// quoted is left out rather than guessed at.
    async fn total_owed_msat(
        &self,
        referral: &Referral,
        include_btc: bool,
        include_fiat: bool,
    ) -> Result<u64> {
        let mut total = if include_btc {
            self.owed_btc_msat(referral).await?
        } else {
            0
        };
        if include_fiat {
            for (currency, owed) in self.owed_fiat(referral).await? {
                let quoted = match self.quote(&currency).await {
                    Ok(rate) => quoted_msat(&currency, owed, rate),
                    Err(e) => Err(e),
                };
                match quoted {
                    Ok(msat) => total = total.saturating_add(msat),
                    Err(e) => warn!(
                        "Excluding {} balance from the payout total for code {}: {}",
                        currency, referral.code, e
                    ),
                }
            }
        }
        Ok(total)
    }

    /// Reserve, broadcast (single send-many) and record a batch of on-chain
    /// payouts. Split from selection so it can be tested with hand-built lists.
    /// `eligible` entries are `(referrer, address, pay_msat)` against the BTC
    /// balance; `fiat` entries are `(referrer, address, currency, owed,
    /// total_msat)` against a fiat-settled balance, where `total_msat` is that
    /// referrer's whole outstanding balance the threshold is judged on.
    ///
    /// The current next-block fee rate is obtained from the fee estimator; if it
    /// exceeds the configured cap the whole batch is **deferred** (returns `Ok`
    /// without reserving or sending) so payouts wait for cheaper fees. Otherwise
    /// the batch is broadcast at that rate.
    ///
    /// Fiat balances are quoted here rather than at selection time so the rate
    /// carried on the row is the one the transaction was actually built at, and
    /// so the fee — charged in sats — converts back at that same quote.
    async fn send_batch(
        &self,
        onchain: &dyn OnChainProvider,
        eligible: Vec<(Referral, String, u64)>,
        fiat: Vec<(Referral, String, String, u64, u64)>,
        min_onchain_msat: u64,
    ) -> Result<()> {
        // Check the current next-block fee rate; defer the whole batch if fees
        // are too high so we wait for cheaper conditions.
        let sat_per_vbyte = self
            .fee_estimator
            .next_block_fee_rate()
            .await
            .context("estimating next-block on-chain fee rate")?;
        if sat_per_vbyte > self.max_onchain_fee_per_vbyte {
            info!(
                "Deferring on-chain referral payouts: next-block fee {} sat/vB exceeds cap {} sat/vB",
                sat_per_vbyte, self.max_onchain_fee_per_vbyte
            );
            return Ok(());
        }

        // 1. Build every row the batch will pay: BTC balances as they stand,
        //    fiat balances converted at one quote per currency taken now.
        let mut rows: Vec<BatchRow> = eligible
            .into_iter()
            .map(|(referral, address, pay_msat)| BatchRow {
                payout: ReferralPayout {
                    referral_id: referral.id,
                    amount: pay_msat,
                    currency: "BTC".to_string(),
                    created: Utc::now(),
                    mode: ReferralPayoutMode::OnChain,
                    ..Default::default()
                }
                .unconverted(),
                referral,
                address,
                rate: None,
            })
            .collect();

        let mut quotes: BTreeMap<String, TickerRate> = BTreeMap::new();
        for (referral, address, currency, owed, total_msat) in fiat {
            let rate = match quotes.get(&currency) {
                Some(rate) => *rate,
                None => match self.quote(&currency).await {
                    Ok(rate) => *quotes.entry(currency.clone()).or_insert(rate),
                    Err(e) => {
                        warn!("Skipping {} on-chain payout: {}", currency, e);
                        continue;
                    }
                },
            };
            // A fiat balance leaving on-chain has to clear both floors: the
            // on-chain one is sized for mempool fees, the fiat one is what an
            // operator set for converted payouts.
            let min_msat = min_onchain_msat.max(self.min_fiat_payout_msat.unwrap_or(0));
            let converted = converted_payout(
                &referral,
                &currency,
                owed,
                rate,
                total_msat,
                effective_min_msat(&referral, min_msat),
            );
            if let Err(e) = &converted {
                self.note_refusal_over_ceiling(&referral, e).await;
            }
            match converted {
                Ok(Some(payout)) => rows.push(BatchRow {
                    referral,
                    address,
                    payout,
                    rate: Some(rate),
                }),
                Ok(None) => {}
                Err(e) => warn!(
                    "Skipping converted on-chain payout for code {}: {}",
                    referral.code, e
                ),
            }
        }
        if rows.is_empty() {
            return Ok(());
        }

        // 2. Reserve every payout (unpaid) before sending, so a crash between
        //    the broadcast and the DB update cannot double-pay next run.
        for row in rows.iter_mut() {
            row.payout.id = self.db.insert_referral_payout(&row.payout).await?;
        }

        // 3. Broadcast a single send-many transaction paying every referrer at
        //    the chosen fee rate.
        let req = Self::payout_batch_request(&rows, sat_per_vbyte);
        let total_msat: u64 = rows.iter().map(|r| r.payout.sent_amount).sum();
        match onchain.send_coins(req).await {
            Ok(resp) => {
                info!(
                    "Broadcast on-chain referral payout batch {} ({} payouts, {} sats)",
                    resp.txid,
                    rows.len(),
                    total_msat / 1000
                );
                // Decode the raw transaction once so each payout can record its
                // exact outpoint (txid:vout) and so we can size the fee from the
                // real transaction weight.
                let decoded = resp.raw_tx.as_deref().and_then(decode_tx);
                // Total on-chain fee = chosen rate × the transaction's vsize
                // (this is exactly what the wallet pays at `sat_per_vbyte`).
                // Prefer the backend-reported fee when present.
                let total_fee_msat = resp
                    .fee
                    .map(|f| f.value())
                    .or_else(|| {
                        decoded
                            .as_ref()
                            .map(|tx| sat_per_vbyte.saturating_mul(tx.vsize() as u64) * 1000)
                    })
                    .unwrap_or(0);
                // Split the fee across the batch in proportion to what each row
                // sends, which is the only side the fee is denominated in.
                let amounts: Vec<u64> = rows.iter().map(|r| r.payout.sent_amount).collect();
                let fee_shares = split_fee_proportional(&amounts, total_fee_msat);

                // 4. Mark every reserved payout paid with its outpoint and fee.
                for (mut row, sent_fee_msat) in rows.into_iter().zip(fee_shares) {
                    let outpoint = match decoded
                        .as_ref()
                        .and_then(|tx| vout_for_address(tx, &row.address))
                    {
                        Some(vout) => format!("{}:{}", resp.txid, vout),
                        // Fall back to the bare txid if the tx couldn't be
                        // decoded or the output wasn't found.
                        None => resp.txid.clone(),
                    };
                    let sent_msat = row.payout.sent_amount;
                    row.payout.is_paid = true;
                    row.payout.output = Some(outpoint.clone());
                    row.payout.sent_fee = sent_fee_msat;
                    // The fee is incurred in sats; it is charged to the referrer
                    // against the balance this row settles, so it is carried
                    // over at the quote the row was built at rather than at
                    // whatever the rate is when it is read.
                    row.payout.fee = match row.rate {
                        Some(rate) => match rate
                            .convert(CurrencyAmount::millisats(sent_fee_msat))
                            .map(|a| a.value())
                        {
                            Ok(fee) => fee,
                            Err(e) => {
                                warn!("Failed to convert fee for payout {}: {}", row.payout.id, e);
                                0
                            }
                        },
                        None => sent_fee_msat,
                    };
                    if let Err(e) = self.db.update_referral_payout(&row.payout).await {
                        warn!(
                            "Broadcast payout {} but failed to mark it paid: {}",
                            row.payout.id, e
                        );
                    }
                    if row.rate.is_some() {
                        self.clear_refusal(row.referral.id, &row.payout.currency)
                            .await;
                    }
                    let _ = self
                        .tx
                        .send(WorkJob::SendNotification {
                            user_id: row.referral.user_id,
                            message: match row.rate {
                                // Name the balance each line settles: one
                                // transaction can pay a referrer's BTC and fiat
                                // balances, and two bare sat figures against one
                                // outpoint read like a double payment.
                                Some(rate) => format!(
                                    "You've been paid {} in referral commission on-chain \
                                     as {} sats ({}, minus {} sats fee).",
                                    CurrencyAmount::from_u64(rate.ticker.1, row.payout.amount),
                                    sent_msat / 1000,
                                    outpoint,
                                    sent_fee_msat / 1000
                                ),
                                None => format!(
                                    "You've been paid {} sats in referral commission on-chain \
                                     ({}, minus {} sats fee).",
                                    sent_msat / 1000,
                                    outpoint,
                                    sent_fee_msat / 1000
                                ),
                            },
                            title: Some("Referral payout".to_string()),
                        })
                        .await;
                }
                Ok(())
            }
            Err(e) => {
                // Release all reservations so the balances retry next run.
                for row in rows {
                    if let Err(del) = self.db.delete_referral_payout(row.payout.id).await {
                        warn!(
                            "Failed to release reserved on-chain payout {} after send error: {}",
                            row.payout.id, del
                        );
                    }
                }
                Err(anyhow!("send_coins failed: {}", e))
            }
        }
    }

    /// Build the single send-many request paying every row at `sat_per_vbyte`.
    ///
    /// Rows are summed per address: a referrer owed both a BTC and a fiat
    /// balance is two rows against one payout address, and paying it twice would
    /// buy a second output and a second share of the fee for nothing.
    fn payout_batch_request(rows: &[BatchRow], sat_per_vbyte: u64) -> SendCoinsRequest {
        let mut outputs: Vec<(String, u64)> = Vec::new();
        for row in rows {
            match outputs.iter_mut().find(|(addr, _)| *addr == row.address) {
                Some((_, msat)) => *msat = msat.saturating_add(row.payout.sent_amount),
                None => outputs.push((row.address.clone(), row.payout.sent_amount)),
            }
        }
        SendCoinsRequest {
            outputs: outputs
                .into_iter()
                .map(|(address, pay_msat)| SendOutput {
                    address,
                    amount: CurrencyAmount::millisats(pay_msat),
                })
                .collect(),
            sat_per_vbyte: Some(sat_per_vbyte),
            target_conf: None,
            label: Some("LNVPS referral payouts".to_string()),
        }
    }

    /// Compute a single on-chain referrer's payable BTC commission (millisats),
    /// or `None` when below the threshold. Mirrors the Lightning accounting:
    /// earned minus every existing (paid + reserved) BTC payout.
    async fn payable_onchain_msat(
        &self,
        referral: &Referral,
        min_onchain_msat: u64,
        total_msat: u64,
    ) -> Result<Option<u64>> {
        Ok(payable_from_total(
            self.owed_btc_msat(referral).await?,
            total_msat,
            effective_min_msat(referral, min_onchain_msat),
        ))
    }

    /// Accrue and pay a single referrer's owed BTC commission, if it clears the
    /// threshold. Reserves the payout before paying so a crash or concurrent run
    /// cannot double-pay; the reservation is deleted if the payment fails.
    async fn process_one(&self, referral: &Referral, min_msat: u64) -> Result<()> {
        // Earned BTC commission minus what is already paid AND reserved, so an
        // in-flight reservation is never paid twice.
        let owed_msat = self.owed_btc_msat(referral).await?;

        // The threshold is judged on everything owed, including fiat balances
        // payable in this run, so small balances in several currencies are not
        // each held below the floor forever.
        let total_msat = self
            .total_owed_msat(referral, true, self.min_fiat_payout_msat.is_some())
            .await?;

        let Some(pay_msat) = payable_from_total(
            owed_msat,
            total_msat,
            effective_min_msat(referral, min_msat),
        ) else {
            return Ok(());
        };

        // Reserve first (unpaid) so the amount is not double-paid next cycle.
        let mut payout = ReferralPayout {
            id: 0,
            referral_id: referral.id,
            amount: pay_msat,
            fee: 0,
            currency: "BTC".to_string(),
            created: Utc::now(),
            is_paid: false,
            mode: referral.mode,
            output: None,
            pre_image: None,
            ..Default::default()
        }
        .unconverted();
        let payout_id = self.db.insert_referral_payout(&payout).await?;
        payout.id = payout_id;

        match self.pay_commission(referral, pay_msat).await {
            Ok((bolt11, pre_image, fee_msat)) => {
                payout.is_paid = true;
                // `output` is the paid BOLT11 invoice for Lightning payouts.
                payout.output = Some(bolt11);
                payout.pre_image = pre_image;
                // Charge the referrer the routing fee we paid. Settled and sent
                // are both BTC here, so the fee is the same figure on each side.
                payout.fee = fee_msat;
                payout.sent_fee = fee_msat;
                self.db.update_referral_payout(&payout).await?;
                info!(
                    "Paid referral commission {} msat (fee {} msat) to code {} (payout {})",
                    pay_msat, fee_msat, referral.code, payout_id
                );
                let _ = self
                    .tx
                    .send(WorkJob::SendNotification {
                        user_id: referral.user_id,
                        message: format!(
                            "You've been paid {} sats in referral commission (minus {} sats fee).",
                            pay_msat / 1000,
                            fee_msat / 1000
                        ),
                        title: Some("Referral payout".to_string()),
                    })
                    .await;
                Ok(())
            }
            Err(e) => {
                // Release the reservation so the balance can be retried later.
                if let Err(del) = self.db.delete_referral_payout(payout_id).await {
                    warn!(
                        "Failed to release reserved payout {} after payment error: {}",
                        payout_id, del
                    );
                }
                Err(e)
            }
        }
    }

    /// Pay a referrer's fiat-settled commission by converting it to sats at the
    /// current rate.
    ///
    /// The balance nets in the currency it was earned in, so the payout row
    /// settles that currency (`amount`) while recording what actually left the
    /// wallet (`sent_amount`, always BTC) and the rate the two were quoted at.
    /// Reconciling later must not depend on a price feed still being reachable.
    ///
    /// Lightning and NWC referrers only: an on-chain referrer's fiat balance is
    /// settled by the batch instead (see [`Self::send_batch`]), so it is quoted
    /// once for the transaction that pays it.
    async fn process_fiat(&self, referral: &Referral, min_fiat_msat: u64) -> Result<()> {
        if referral.mode == ReferralPayoutMode::OnChain {
            return Ok(());
        }
        // Everything owed, judged once: the threshold is a floor on the run,
        // not on each currency, so a referrer holding several small balances is
        // paid rather than held below it in every one of them.
        let total_msat = self
            .total_owed_msat(referral, self.min_payout_msat.is_some(), true)
            .await?;
        for (currency, owed) in self.owed_fiat(referral).await? {
            if let Err(e) = self
                .pay_converted(referral, &currency, owed, total_msat, min_fiat_msat)
                .await
            {
                warn!(
                    "Converted {} payout failed for code {}: {}",
                    currency, referral.code, e
                );
            }
        }
        Ok(())
    }

    /// Quote `owed` in `currency` against BTC and, if the result clears the
    /// threshold, pay it as sats and record both sides.
    async fn pay_converted(
        &self,
        referral: &Referral,
        currency: &str,
        owed: u64,
        total_msat: u64,
        min_fiat_msat: u64,
    ) -> Result<()> {
        let rate = self.quote(currency).await?;

        let converted = converted_payout(
            referral,
            currency,
            owed,
            rate,
            total_msat,
            effective_min_msat(referral, min_fiat_msat),
        );
        if let Err(e) = &converted {
            self.note_refusal_over_ceiling(referral, e).await;
        }

        let Some(mut payout) = converted? else {
            return Ok(());
        };
        let pay_msat = payout.sent_amount;
        let settled_amount = payout.amount;

        let payout_id = self.db.insert_referral_payout(&payout).await?;
        payout.id = payout_id;

        match self.pay_commission(referral, pay_msat).await {
            Ok((bolt11, pre_image, fee_msat)) => {
                payout.is_paid = true;
                payout.output = Some(bolt11);
                payout.pre_image = pre_image;
                // The fee is incurred in sats; it is charged to the referrer
                // against a fiat balance, so it is carried over at the same
                // quote rather than at whatever the rate is when it is read.
                payout.sent_fee = fee_msat;
                payout.fee = rate.convert(CurrencyAmount::millisats(fee_msat))?.value();
                self.db.update_referral_payout(&payout).await?;
                info!(
                    "Paid referral commission {} {} as {} msat (fee {} msat) to code {} (payout {})",
                    settled_amount, currency, pay_msat, fee_msat, referral.code, payout_id
                );
                self.clear_refusal(referral.id, currency).await;
                let _ = self
                    .tx
                    .send(WorkJob::SendNotification {
                        user_id: referral.user_id,
                        message: format!(
                            "You've been paid {} sats in referral commission (minus {} sats fee).",
                            pay_msat / 1000,
                            fee_msat / 1000
                        ),
                        title: Some("Referral payout".to_string()),
                    })
                    .await;
                Ok(())
            }
            Err(e) => {
                if let Err(del) = self.db.delete_referral_payout(payout_id).await {
                    warn!(
                        "Failed to release reserved payout {} after payment error: {}",
                        payout_id, del
                    );
                }
                Err(e)
            }
        }
    }

    /// Resolve a BOLT11 invoice for `amount_msat` from the referrer's chosen
    /// payout method and pay it from our node. Returns `(bolt11, preimage,
    /// routing_fee_msat)`.
    async fn pay_commission(
        &self,
        referral: &Referral,
        amount_msat: u64,
    ) -> Result<(String, Option<Vec<u8>>, u64)> {
        let bolt11 = match referral.mode {
            ReferralPayoutMode::LightningAddress => {
                let addr = referral
                    .address
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow!("no lightning address configured"))?;
                self.lnurl_pay_invoice(addr, amount_msat).await?
            }
            ReferralPayoutMode::Nwc => {
                #[cfg(feature = "nostr-nwc")]
                {
                    self.nwc_make_invoice(referral.user_id, amount_msat).await?
                }
                #[cfg(not(feature = "nostr-nwc"))]
                {
                    bail!("NWC payouts are not supported by this build");
                }
            }
            ReferralPayoutMode::AccountCredit => {
                bail!("account credit payouts are not implemented");
            }
            ReferralPayoutMode::OnChain => {
                // On-chain referrers are paid by the batched send-many pass, not
                // this per-referrer Lightning path.
                bail!("on-chain payouts are handled by the batch, not pay_commission");
            }
        };

        let resp = self
            .node
            .pay_invoice(PayInvoiceRequest {
                invoice: bolt11.clone(),
                timeout_seconds: Some(60),
            })
            .await?;
        let pre_image = resp
            .payment_preimage
            .and_then(|h| hex::decode(h.trim()).ok());
        Ok((bolt11, pre_image, resp.fee_msat))
    }

    /// Fetch a BOLT11 invoice for `amount_msat` from a Lightning address via
    /// LNURL-pay.
    async fn lnurl_pay_invoice(&self, address: &str, amount_msat: u64) -> Result<String> {
        use lnurl::LnUrlResponse;
        use lnurl::lightning_address::LightningAddress;

        let ln_addr = LightningAddress::from_str(address)
            .map_err(|_| anyhow!("invalid lightning address"))?;
        let client = lnurl::Builder::default()
            .build_async()
            .map_err(|e| anyhow!("lnurl client: {}", e))?;
        let resp = client
            .make_request(&ln_addr.lnurlp_url())
            .await
            .map_err(|e| anyhow!("lnurl request failed: {}", e))?;
        let pay = match resp {
            LnUrlResponse::LnUrlPayResponse(p) => p,
            _ => bail!("lightning address did not return an LNURL-pay response"),
        };
        let invoice = client
            .get_invoice(&pay, amount_msat, None, Some("LNVPS referral payout"))
            .await
            .map_err(|e| anyhow!("failed to fetch LNURL invoice: {}", e))?;
        Ok(invoice.pr)
    }

    /// Create a BOLT11 invoice for `amount_msat` on the referrer's wallet via
    /// their saved NWC connection, so our node can pay it out.
    #[cfg(feature = "nostr-nwc")]
    async fn nwc_make_invoice(&self, user_id: u64, amount_msat: u64) -> Result<String> {
        use nostr_sdk::prelude::*;

        let nwc_method = self
            .db
            .list_user_payment_methods(user_id, Some("nwc"))
            .await?
            .into_iter()
            .find(|m| m.enabled)
            .ok_or_else(|| anyhow!("no enabled NWC payment method"))?;
        let nwc_string: String = nwc_method.external_id.clone().into();
        let nwc_uri = NostrWalletConnectUri::from_str(&nwc_string)
            .context("Invalid NWC connection string")?;
        let client = nwc::NostrWalletConnect::new(nwc_uri);
        let rsp = client
            .make_invoice(MakeInvoiceRequest {
                amount: amount_msat,
                description: Some("LNVPS referral payout".to_string()),
                description_hash: None,
                expiry: None,
            })
            .await?;
        Ok(rsp.invoice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::MockOnChainProvider;
    use lnvps_api_common::{ChannelWorkCommander, InMemoryKeyValueStore, MockDb};
    use lnvps_db::Referral;

    /// A deterministic, checksum-valid regtest P2WPKH address for tests.
    fn regtest_addr(byte: u8) -> String {
        let program = bitcoin::WitnessProgram::new(bitcoin::WitnessVersion::V0, &[byte; 20])
            .expect("valid v0 witness program");
        bitcoin::Address::from_witness_program(program, bitcoin::KnownHrp::Regtest).to_string()
    }

    fn referrer(id: u64, code: &str) -> Referral {
        Referral {
            id,
            user_id: id,
            code: code.to_string(),
            address: Some(regtest_addr(id as u8)),
            mode: ReferralPayoutMode::OnChain,
            referral_rate: None,
            payout_threshold: None,
            created: Utc::now(),
        }
    }

    /// A test handler with the given on-chain provider and a fixed fee
    /// estimate (sat/vByte). The fee cap is 50, so `feerate <= 50` broadcasts
    /// and `> 50` defers.
    fn handler_with_feerate(
        db: Arc<dyn LNVpsDb>,
        onchain: Arc<dyn OnChainProvider>,
        feerate: u64,
    ) -> ReferralPayoutHandler {
        ReferralPayoutHandler::new(
            db,
            Arc::new(crate::mocks::MockNode::default()),
            Arc::new(ChannelWorkCommander::new()),
            None,
            Some(onchain),
            Some(1000),
            50,
            Arc::new(crate::fee_estimate::FixedFeeEstimator(feerate)),
            Arc::new(lnvps_api_common::MockExchangeRate::default()),
            None,
            Arc::new(InMemoryKeyValueStore::new()),
        )
    }

    fn handler(db: Arc<dyn LNVpsDb>, onchain: Arc<dyn OnChainProvider>) -> ReferralPayoutHandler {
        handler_with_feerate(db, onchain, 10)
    }

    #[test]
    fn test_split_fee_proportional() {
        // Proportional split; remainder to the largest.
        let shares = split_fee_proportional(&[2_000_000, 1_000_000], 300);
        assert_eq!(shares, vec![200, 100], "split in proportion to amount");
        assert_eq!(shares.iter().sum::<u64>(), 300, "shares sum to the fee");
        // Rounding remainder is absorbed by the largest payout.
        let shares = split_fee_proportional(&[2_000_000, 1_000_000], 301);
        assert_eq!(shares.iter().sum::<u64>(), 301);
        assert_eq!(shares[0], 201, "largest payout takes the remainder");
        // Zero fee / zero amounts.
        assert_eq!(split_fee_proportional(&[1, 2], 0), vec![0, 0]);
        assert_eq!(split_fee_proportional(&[0, 0], 100), vec![0, 0]);
    }

    /// [`converted_payout`] for a referrer who owes nothing else: the total the
    /// threshold is judged on is what this one balance is worth.
    fn converted_payout_alone(
        referral: &Referral,
        currency: &str,
        owed: u64,
        rate: TickerRate,
        min_msat: u64,
    ) -> Result<Option<ReferralPayout>> {
        let total = quoted_msat(currency, owed, rate).unwrap_or(0);
        converted_payout(referral, currency, owed, rate, total, min_msat)
    }

    fn eur_rate(rate: f32) -> TickerRate {
        TickerRate {
            ticker: Ticker::btc_rate("EUR").unwrap(),
            rate,
        }
    }

    /// A converted payout settles the currency it was earned in and sends BTC,
    /// carrying the quote both sides were taken at. The settled amount comes
    /// back from the rounded-to-sats transfer, so the sub-sat remainder stays
    /// owed rather than being discharged for free.
    #[test]
    fn converted_payout_records_both_sides_at_one_quote() {
        // €12.34 owed at 100,000 EUR/BTC = 12_340_000 msat exactly.
        let p = converted_payout_alone(
            &referrer(1, "AAA"),
            "eur",
            1_234,
            eur_rate(100_000.0),
            1_000,
        )
        .unwrap()
        .expect("above threshold");
        assert_eq!(
            p.currency, "EUR",
            "settles the earned currency, upper-cased"
        );
        assert_eq!(p.amount, 1_234);
        assert_eq!(p.sent_currency, "BTC");
        assert_eq!(p.sent_amount, 12_340_000);
        assert_eq!(p.rate, 100_000.0);
        assert!(p.rate_collected.is_some(), "a quote happened");
        assert!(!p.is_paid, "reserved, not paid");
        assert_eq!((p.fee, p.sent_fee), (0, 0), "fee is known only once paid");

        // A balance whose value does not land on a whole sat discharges only
        // what the rounded transfer is worth.
        let p =
            converted_payout_alone(&referrer(1, "AAA"), "EUR", 1_001, eur_rate(90_000.0), 1_000)
                .unwrap()
                .expect("above threshold");
        assert_eq!(p.sent_amount % 1_000, 0, "whole sats only");
        assert!(
            p.amount <= 1_001,
            "settled {} must not exceed the owed 1001",
            p.amount
        );
    }

    /// The threshold is judged on the converted value, and a referrer's own
    /// higher threshold still applies.
    #[test]
    fn converted_payout_respects_the_threshold() {
        // €0.10 at 100,000 EUR/BTC = 100_000 msat, below a 1_000_000 msat floor.
        assert!(
            converted_payout_alone(
                &referrer(1, "AAA"),
                "EUR",
                10,
                eur_rate(100_000.0),
                1_000_000
            )
            .unwrap()
            .is_none()
        );
        // The same balance clears a floor it is above.
        assert!(
            converted_payout_alone(&referrer(1, "AAA"), "EUR", 10, eur_rate(100_000.0), 1_000)
                .unwrap()
                .is_some()
        );
        // A currency with no scale on either side is refused rather than paid
        // at a guessed rate.
        assert!(
            converted_payout_alone(
                &referrer(1, "AAA"),
                "XYZ",
                1_000,
                eur_rate(100_000.0),
                1_000
            )
            .is_err()
        );
        // Above the per-payout ceiling — €2000 at 100k is 0.02 BTC — the payout
        // is refused rather than sent: a rate that far out is the likelier
        // explanation, and a Lightning payment does not come back.
        assert!(
            converted_payout_alone(
                &referrer(1, "AAA"),
                "EUR",
                200_000,
                eur_rate(100_000.0),
                1_000
            )
            .is_err(),
            "a payout above the ceiling is refused, not sent"
        );
    }

    /// Commission is grouped per settled currency, case-insensitively, and BTC
    /// is left to the BTC passes.
    #[test]
    fn fiat_balances_group_per_currency() {
        let usage = |currency: &str, amount: u64| lnvps_db::ReferralCostUsage {
            vm_id: 1,
            ref_code: "AAA".to_string(),
            created: Utc::now(),
            amount,
            currency: currency.to_string(),
            rate: 1.0,
            base_currency: "EUR".to_string(),
            effective_rate: 10.0,
        };
        let earned = earned_by_fiat_currency(&[
            usage("EUR", 1_000),
            usage("eur", 500),
            usage("USD", 2_000),
            usage("BTC", 1_000_000),
        ]);
        assert_eq!(earned.get("EUR"), Some(&150), "10% of 1500, one balance");
        assert_eq!(earned.get("USD"), Some(&200));
        assert!(!earned.contains_key("BTC"), "BTC is not a fiat balance");
    }

    /// Netting follows the currency a payout settles, never the one it sent,
    /// and the fee is debited with the amount. A payout that sent another
    /// currency must not discharge that currency's balance too, or the referrer
    /// is paid twice for one transfer.
    #[test]
    fn settled_in_nets_per_currency() {
        let eur_sent_as_btc = ReferralPayout {
            amount: 1_000,
            fee: 7,
            currency: "EUR".to_string(),
            sent_amount: 12_000_000,
            sent_fee: 84_000,
            sent_currency: "BTC".to_string(),
            rate: 90_000.0,
            rate_collected: Some(Utc::now()),
            ..Default::default()
        };
        let btc_sent_as_eur = ReferralPayout {
            amount: 500_000,
            currency: "btc".to_string(),
            sent_amount: 430,
            sent_currency: "EUR".to_string(),
            ..Default::default()
        };
        let usd = ReferralPayout {
            amount: 500,
            currency: "usd".to_string(),
            ..Default::default()
        };
        let all = [eur_sent_as_btc, btc_sent_as_eur, usd];
        assert_eq!(
            settled_in(&all, "EUR"),
            1_007,
            "amount + fee, EUR rows only"
        );
        assert_eq!(settled_in(&all, "USD"), 500);
        assert_eq!(
            settled_in(&all, "BTC"),
            500_000,
            "the BTC commission stays debited whatever left the wallet"
        );
    }

    /// Seed a mock DB with one referrer whose single referred VM paid `amount`
    /// in `currency`, at a 10% commission. Returns the persisted referrer.
    async fn fiat_referrer(db: &MockDb, currency: &str, amount: u64, base: Referral) -> Referral {
        use lnvps_db::LNVpsDbBase;

        db.companies.lock().await.get_mut(&1).unwrap().referral_rate = 10.0;
        let referral = base;
        let id = db.insert_referral(&referral).await.unwrap();
        add_referred_payment(db, 1, &referral.code, currency, amount).await;

        Referral { id, ..referral }
    }

    /// Add a referred VM (`id`) under `code` whose first — and only — payment
    /// was `amount` in `currency`, so a referrer can be given a balance in more
    /// than one currency.
    async fn add_referred_payment(db: &MockDb, id: u64, code: &str, currency: &str, amount: u64) {
        use lnvps_db::{
            EncryptedString, PaymentMethod, SubscriptionLineItem, SubscriptionPayment,
            SubscriptionPaymentType, SubscriptionType,
        };

        db.vms.lock().await.insert(
            id,
            lnvps_db::Vm {
                id,
                subscription_line_item_id: id,
                ref_code: Some(code.to_string()),
                ..MockDb::mock_vm()
            },
        );
        db.subscription_line_items.lock().await.insert(
            id,
            SubscriptionLineItem {
                id,
                subscription_id: id,
                subscription_type: SubscriptionType::Vps,
                name: "vm".to_string(),
                description: None,
                amount,
                setup_amount: 0,
                configuration: None,
            },
        );
        db.subscription_payments
            .lock()
            .await
            .push(SubscriptionPayment {
                id: vec![id as u8; 32],
                subscription_id: id,
                user_id: 1,
                created: Utc::now(),
                expires: Utc::now(),
                amount,
                currency: currency.to_string(),
                payment_method: PaymentMethod::Revolut,
                payment_type: SubscriptionPaymentType::Purchase,
                external_data: EncryptedString::from("test"),
                external_id: None,
                is_paid: true,
                rate: 1.0,
                time_value: Some(2_592_000),
                metadata: None,
                tax: 0,
                processing_fee: 0,
                paid_at: Some(Utc::now()),
                tax_rate: None,
                tax_country_code: None,
                tax_treatment: None,
                tax_evidence: None,
                tax_breakdown: None,
                refunded_payment_id: None,
                renewal_source: None,
            });
    }

    fn fiat_handler(
        db: Arc<dyn LNVpsDb>,
        exchange: Arc<dyn ExchangeRateService>,
    ) -> ReferralPayoutHandler {
        fiat_handler_with(
            db,
            exchange,
            Arc::new(ChannelWorkCommander::new()),
            Arc::new(InMemoryKeyValueStore::new()),
        )
    }

    /// A Lightning fiat handler whose work queue and refusal state the test
    /// can inspect.
    fn fiat_handler_with(
        db: Arc<dyn LNVpsDb>,
        exchange: Arc<dyn ExchangeRateService>,
        tx: Arc<ChannelWorkCommander>,
        kv: Arc<dyn KeyValueStore>,
    ) -> ReferralPayoutHandler {
        ReferralPayoutHandler::new(
            db,
            Arc::new(crate::mocks::MockNode::default()),
            tx,
            None,
            None,
            None,
            50,
            Arc::new(crate::fee_estimate::FixedFeeEstimator(10)),
            exchange,
            Some(1),
            kv,
        )
    }

    /// A payment that fails leaves no reservation behind — the balance has to
    /// survive to be retried — and a balance already discharged by an existing
    /// payout is not paid again.
    #[tokio::test]
    async fn fiat_payouts_release_on_failure_and_net_once_settled() {
        let db = Arc::new(MockDb::default());
        let referral = fiat_referrer(
            &db,
            "EUR",
            10_000,
            Referral {
                mode: ReferralPayoutMode::LightningAddress,
                address: Some("payouts@example.invalid".to_string()),
                ..referrer(0, "FIAT")
            },
        )
        .await;
        let exchange = Arc::new(lnvps_api_common::MockExchangeRate::default());
        exchange
            .set_rate(Ticker::btc_rate("EUR").unwrap(), 100_000.0)
            .await;
        let db: Arc<dyn LNVpsDb> = db;
        let h = fiat_handler(db.clone(), exchange);

        // €100 paid at 10% = €10 owed. The lightning address does not resolve,
        // so the payment fails and the reservation must be gone.
        h.process_fiat(&referral, 1_000).await.unwrap();
        assert!(
            db.list_referral_payouts(referral.id)
                .await
                .unwrap()
                .is_empty(),
            "a failed payment must not leave a reservation holding the balance"
        );

        // Record the payout out of band; the balance is now discharged and the
        // next pass must not pay it a second time.
        db.insert_referral_payout(&ReferralPayout {
            referral_id: referral.id,
            amount: 1_000,
            currency: "EUR".to_string(),
            sent_amount: 10_000_000,
            sent_currency: "BTC".to_string(),
            rate: 100_000.0,
            rate_collected: Some(Utc::now()),
            is_paid: true,
            ..Default::default()
        })
        .await
        .unwrap();

        h.process_fiat(&referral, 1_000).await.unwrap();
        assert_eq!(
            db.list_referral_payouts(referral.id).await.unwrap().len(),
            1,
            "a settled balance is not paid twice"
        );
    }

    /// A refusal over the ceiling reaches an operator once, not once a pass:
    /// the balance is re-evaluated on every run, so notifying on the state
    /// rather than the transition into it would notify forever.
    #[tokio::test]
    async fn a_refused_payout_notifies_admins_once() {
        let db = Arc::new(MockDb::default());
        let referral = fiat_referrer(
            &db,
            "EUR",
            10_000,
            Referral {
                mode: ReferralPayoutMode::LightningAddress,
                address: Some("payouts@example.invalid".to_string()),
                ..referrer(0, "FIAT")
            },
        )
        .await;
        // €10 owed at 100 EUR/BTC is 0.1 BTC — ten times the ceiling, which is
        // what a broken rate feed looks like.
        let exchange = eur_exchange(100.0).await;
        let db: Arc<dyn LNVpsDb> = db;
        let tx = Arc::new(ChannelWorkCommander::new());
        let kv: Arc<dyn KeyValueStore> = Arc::new(InMemoryKeyValueStore::new());
        let h = fiat_handler_with(db.clone(), exchange, tx.clone(), kv.clone());

        h.process_fiat(&referral, 1_000).await.unwrap();

        let jobs = tx.recv().await.unwrap();
        assert_eq!(jobs.len(), 1, "one job: {:?}", jobs);
        let WorkJob::SendAdminNotification { message, title } = &jobs[0].job else {
            panic!("expected an admin notification, got {:?}", jobs[0].job);
        };
        assert_eq!(title.as_deref(), Some("Referral payout refused"));
        assert!(
            message.contains(&referral.code),
            "names the code: {message}"
        );
        assert!(message.contains("ceiling"), "{message}");
        assert!(
            db.list_referral_payouts(referral.id)
                .await
                .unwrap()
                .is_empty(),
            "a refused payout reserves nothing"
        );

        // Same balance, same refusal: the operator has already been told.
        h.process_fiat(&referral, 1_000).await.unwrap();
        // `recv` waits for a job rather than reporting an empty queue, so the
        // absence of a second notification can only be observed as a timeout.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), tx.recv())
                .await
                .is_err(),
            "a standing refusal must not notify every pass"
        );
    }

    /// Once the balance pays, the refusal is forgotten, so the next one is
    /// reported instead of being swallowed as a repeat.
    #[tokio::test]
    async fn a_paid_balance_clears_the_refusal() {
        let db = Arc::new(MockDb::default());
        let referral = fiat_referrer(
            &db,
            "EUR",
            10_000,
            Referral {
                mode: ReferralPayoutMode::LightningAddress,
                address: Some("payouts@example.invalid".to_string()),
                ..referrer(0, "FIAT")
            },
        )
        .await;
        let db: Arc<dyn LNVpsDb> = db;
        let kv: Arc<dyn KeyValueStore> = Arc::new(InMemoryKeyValueStore::new());
        let key = ReferralPayoutHandler::refusal_key(referral.id, "EUR");
        kv.store(&key, b"1").await.unwrap();

        let tx = Arc::new(ChannelWorkCommander::new());
        let h = fiat_handler_with(
            db.clone(),
            eur_exchange(100.0).await,
            tx.clone(),
            kv.clone(),
        );
        h.clear_refusal(referral.id, "EUR").await;

        h.process_fiat(&referral, 1_000).await.unwrap();
        let jobs = tx.recv().await.unwrap();
        assert_eq!(
            jobs.len(),
            1,
            "a refusal after the state was cleared is reported again: {:?}",
            jobs
        );
    }

    /// A row paying `pay_msat` to `address` against the BTC balance.
    fn btc_row(referral: Referral, address: &str, pay_msat: u64) -> BatchRow {
        BatchRow {
            payout: ReferralPayout {
                referral_id: referral.id,
                amount: pay_msat,
                currency: "BTC".to_string(),
                mode: ReferralPayoutMode::OnChain,
                ..Default::default()
            }
            .unconverted(),
            referral,
            address: address.to_string(),
            rate: None,
        }
    }

    /// A handler that pays on-chain and has fiat payouts enabled.
    fn onchain_fiat_handler(
        db: Arc<dyn LNVpsDb>,
        onchain: Arc<dyn OnChainProvider>,
        exchange: Arc<dyn ExchangeRateService>,
        tx: Arc<ChannelWorkCommander>,
        min_fiat_sats: u64,
    ) -> ReferralPayoutHandler {
        ReferralPayoutHandler::new(
            db,
            Arc::new(crate::mocks::MockNode::default()),
            tx,
            None,
            Some(onchain),
            Some(1),
            50,
            Arc::new(crate::fee_estimate::FixedFeeEstimator(10)),
            exchange,
            Some(min_fiat_sats),
            Arc::new(InMemoryKeyValueStore::new()),
        )
    }

    async fn eur_exchange(rate: f32) -> Arc<lnvps_api_common::MockExchangeRate> {
        let exchange = Arc::new(lnvps_api_common::MockExchangeRate::default());
        exchange
            .set_rate(Ticker::btc_rate("EUR").unwrap(), rate)
            .await;
        exchange
    }

    /// A fiat balance owed to an on-chain referrer is settled by the batch: the
    /// row records what it discharges (EUR) against what left the wallet (sats)
    /// at the quote the transaction was built at, the fee is carried over at
    /// that same quote, and the discharged balance is not paid again.
    #[tokio::test]
    async fn onchain_fiat_balance_settles_in_the_batch_once() {
        let db = Arc::new(MockDb::default());
        let addr = regtest_addr(9);
        let referral = fiat_referrer(
            &db,
            "EUR",
            10_000,
            Referral {
                mode: ReferralPayoutMode::OnChain,
                address: Some(addr.clone()),
                ..referrer(0, "FIAT")
            },
        )
        .await;
        let exchange = eur_exchange(100_000.0).await;
        let onchain = Arc::new(MockOnChainProvider::default());
        let db: Arc<dyn LNVpsDb> = db;
        let tx = Arc::new(ChannelWorkCommander::new());
        let h = onchain_fiat_handler(db.clone(), onchain.clone(), exchange, tx.clone(), 1);

        h.process_payouts().await.unwrap();

        // One transaction, one output: the referrer has no BTC balance.
        let sends = onchain.sends.lock().await;
        assert_eq!(sends.len(), 1, "one batch transaction");
        assert_eq!(sends[0].outputs.len(), 1);
        assert_eq!(sends[0].outputs[0].address, addr);
        drop(sends);

        let payouts = db.list_referral_payouts(referral.id).await.unwrap();
        assert_eq!(payouts.len(), 1, "one payout for the EUR balance");
        let p = &payouts[0];
        assert!(p.is_paid, "paid");
        assert_eq!(p.mode, ReferralPayoutMode::OnChain);
        assert_eq!(p.currency, "EUR", "settles the EUR balance");
        assert_eq!(p.sent_currency, "BTC", "sats left the wallet");
        // 10% of €100 is €10; at 100k EUR/BTC that is 10_000 sats.
        assert_eq!(p.sent_amount, 10_000_000);
        assert_eq!(p.amount, 1_000);
        assert_eq!(p.rate, 100_000.0, "the quote is recorded on the row");
        assert!(p.rate_collected.is_some());
        assert!(
            p.output.as_deref().unwrap().ends_with(":0"),
            "records its outpoint in the batch tx"
        );

        // The fee is charged in sats and carried into EUR at the same quote.
        assert!(p.sent_fee > 0, "the referrer bears the on-chain fee");
        let rate = TickerRate {
            ticker: Ticker::btc_rate("EUR").unwrap(),
            rate: 100_000.0,
        };
        assert_eq!(
            p.fee,
            rate.convert(CurrencyAmount::millisats(p.sent_fee))
                .unwrap()
                .value(),
            "fee converted at the row's own quote, not a later one"
        );

        // The notification names the balance it settles: one transaction can pay
        // a referrer's BTC and fiat balances, and two bare sat figures against
        // one outpoint read like a double payment.
        let jobs = tx.recv().await.unwrap();
        let WorkJob::SendNotification { message, .. } = &jobs[0].job else {
            panic!("expected a notification, got {:?}", jobs[0].job);
        };
        assert!(
            message.contains("EUR 10.00"),
            "notification names the settled balance: {message}"
        );

        // The balance is discharged (amount + fee), so a second pass pays nothing.
        h.process_payouts().await.unwrap();
        assert_eq!(
            db.list_referral_payouts(referral.id).await.unwrap().len(),
            1,
            "a settled fiat balance is not paid twice"
        );
        assert_eq!(
            onchain.sends.lock().await.len(),
            1,
            "no second transaction broadcast"
        );
    }

    /// `min-fiat-payout-sats` floors the on-chain rows too: it is not merely an
    /// on/off switch for a referrer paid on-chain.
    #[tokio::test]
    async fn onchain_fiat_respects_the_fiat_minimum() {
        let db = Arc::new(MockDb::default());
        let referral = fiat_referrer(
            &db,
            "EUR",
            10_000,
            Referral {
                mode: ReferralPayoutMode::OnChain,
                address: Some(regtest_addr(9)),
                ..referrer(0, "FIAT")
            },
        )
        .await;
        let onchain = Arc::new(MockOnChainProvider::default());
        let db: Arc<dyn LNVpsDb> = db;
        // €10 is 10_000 sats at this quote, below a 20_000 sat fiat minimum.
        let h = onchain_fiat_handler(
            db.clone(),
            onchain.clone(),
            eur_exchange(100_000.0).await,
            Arc::new(ChannelWorkCommander::new()),
            20_000,
        );

        h.process_payouts().await.unwrap();

        assert!(
            onchain.sends.lock().await.is_empty(),
            "a balance below the fiat minimum is not sent"
        );
        assert!(
            db.list_referral_payouts(referral.id)
                .await
                .unwrap()
                .is_empty(),
            "and nothing is reserved"
        );
    }

    /// Regression: the threshold is a floor on everything a referrer is owed,
    /// not on each currency separately.
    ///
    /// A referrer holding 10,000 sats of BTC commission and €10 (another 10,000
    /// sats at the quote) used to be paid neither under a 15,000 sat floor,
    /// because each balance was judged alone — and never would be, however many
    /// currencies stacked up. Together they are 20,000 sats, over the floor, so
    /// both are settled.
    #[tokio::test]
    async fn test_payout_threshold_counts_every_currency() {
        let db = Arc::new(MockDb::default());
        // VM 1: €100 paid → €10 commission → 10,000 sats at 100,000 EUR/BTC.
        let referral = fiat_referrer(
            &db,
            "EUR",
            10_000,
            Referral {
                mode: ReferralPayoutMode::OnChain,
                address: Some(regtest_addr(9)),
                ..referrer(0, "FIAT")
            },
        )
        .await;
        // VM 2: 0.1 BTC paid → 10,000 sats commission.
        add_referred_payment(&db, 2, "FIAT", "BTC", 100_000_000).await;

        let onchain = Arc::new(MockOnChainProvider::default());
        let db: Arc<dyn LNVpsDb> = db;
        // Both floors are 15,000 sats: neither balance clears one on its own.
        let h = ReferralPayoutHandler::new(
            db.clone(),
            Arc::new(crate::mocks::MockNode::default()),
            Arc::new(ChannelWorkCommander::new()),
            None,
            Some(onchain.clone()),
            Some(15_000),
            50,
            Arc::new(crate::fee_estimate::FixedFeeEstimator(10)),
            eur_exchange(100_000.0).await,
            Some(15_000),
            Arc::new(InMemoryKeyValueStore::new()),
        );

        h.process_payouts().await.unwrap();

        let payouts = db.list_referral_payouts(referral.id).await.unwrap();
        assert_eq!(
            payouts.len(),
            2,
            "both balances settle once they clear the floor together, got {payouts:?}"
        );
        let btc = payouts
            .iter()
            .find(|p| p.currency == "BTC")
            .expect("the BTC balance is paid");
        assert_eq!(btc.amount, 10_000_000, "10,000 sats of BTC commission");
        let eur = payouts
            .iter()
            .find(|p| p.currency == "EUR")
            .expect("the EUR balance is paid");
        assert_eq!(eur.amount, 1_000, "€10 discharged");
        assert_eq!(eur.sent_amount, 10_000_000, "sent as 10,000 sats");
        // One transaction pays the referrer both balances in a single output.
        let sends = onchain.sends.lock().await;
        assert_eq!(sends.len(), 1, "one batched transaction");
        assert_eq!(sends[0].outputs.len(), 1, "one output for one referrer");
        assert_eq!(sends[0].outputs[0].amount.value(), 20_000_000);
    }

    /// A referrer owed in two currencies is one output, not two: paying the same
    /// address twice buys a second output and a second share of the fee.
    #[test]
    fn test_payout_batch_request_sums_rows_sharing_an_address() {
        let rows = vec![
            btc_row(referrer(1, "AAA"), "bcrt1qa", 2_000_000),
            BatchRow {
                payout: ReferralPayout {
                    referral_id: 1,
                    amount: 1_000,
                    currency: "EUR".to_string(),
                    sent_amount: 500_000,
                    sent_currency: "BTC".to_string(),
                    rate: 100_000.0,
                    mode: ReferralPayoutMode::OnChain,
                    ..Default::default()
                },
                referral: referrer(1, "AAA"),
                address: "bcrt1qa".to_string(),
                rate: None,
            },
        ];
        let req = ReferralPayoutHandler::payout_batch_request(&rows, 12);
        assert_eq!(req.outputs.len(), 1, "one output per address");
        assert_eq!(req.outputs[0].amount.value(), 2_500_000, "amounts summed");
    }

    #[test]
    fn test_payout_batch_request_one_output_per_referrer() {
        let eligible = vec![
            btc_row(referrer(1, "AAA"), "bcrt1qa", 2_000_000),
            btc_row(referrer(2, "BBB"), "bcrt1qb", 1_500_000),
        ];
        let req = ReferralPayoutHandler::payout_batch_request(&eligible, 12);
        assert_eq!(req.outputs.len(), 2, "one output per referrer");
        assert_eq!(req.sat_per_vbyte, Some(12), "fee rate is passed through");
        assert_eq!(
            req.total_msat(),
            3_500_000,
            "outputs sum to the batch total"
        );
        assert_eq!(req.outputs[0].address, "bcrt1qa");
        assert_eq!(req.outputs[0].amount.value(), 2_000_000);
        assert_eq!(req.outputs[1].address, "bcrt1qb");
    }

    #[tokio::test]
    async fn test_send_batch_single_tx_shared_txid_all_paid() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        // Two referrers must be persisted so their payout rows FK-resolve.
        let ra = db.insert_referral(&referrer(0, "AAA")).await.unwrap();
        let rb = db.insert_referral(&referrer(0, "BBB")).await.unwrap();
        let onchain = Arc::new(MockOnChainProvider::default());
        let h = handler(db.clone(), onchain.clone());

        let addr_a = regtest_addr(1);
        let addr_b = regtest_addr(2);
        let eligible = vec![
            (
                Referral {
                    id: ra,
                    ..referrer(ra, "AAA")
                },
                addr_a.clone(),
                2_000_000,
            ),
            (
                Referral {
                    id: rb,
                    ..referrer(rb, "BBB")
                },
                addr_b.clone(),
                1_500_000,
            ),
        ];
        h.send_batch(onchain.as_ref(), eligible, vec![], 1_000)
            .await
            .unwrap();

        // Exactly ONE on-chain transaction was broadcast for the whole batch.
        let sends = onchain.sends.lock().await;
        assert_eq!(sends.len(), 1, "all referrers batched into a single tx");
        assert_eq!(sends[0].outputs.len(), 2);
        drop(sends);

        // Both payout rows are paid and record an outpoint sharing the batch
        // txid but with the distinct vout of each referrer's output.
        let pa = db.list_referral_payouts(ra).await.unwrap();
        let pb = db.list_referral_payouts(rb).await.unwrap();
        assert_eq!(pa.len(), 1);
        assert_eq!(pb.len(), 1);
        assert!(pa[0].is_paid && pb[0].is_paid, "both marked paid");
        assert_eq!(pa[0].amount, 2_000_000);
        assert_eq!(pb[0].amount, 1_500_000);

        let oa = pa[0].output.as_deref().expect("output set");
        let ob = pb[0].output.as_deref().expect("output set");
        assert_eq!(pa[0].mode, ReferralPayoutMode::OnChain);
        assert_eq!(pb[0].mode, ReferralPayoutMode::OnChain);
        let (txa, va) = oa.rsplit_once(':').expect("txid:vout");
        let (txb, vb) = ob.rsplit_once(':').expect("txid:vout");
        assert_eq!(txa, txb, "both rows share the batch transaction id");
        assert_eq!(va, "0", "referrer A is the first output");
        assert_eq!(vb, "1", "referrer B is the second output");

        // The on-chain fee was charged to the referrers (split by amount) — the
        // larger payout bears the larger share.
        assert!(pa[0].fee > 0 && pb[0].fee > 0, "fee charged to both");
        assert!(
            pa[0].fee >= pb[0].fee,
            "larger payout bears >= fee ({} vs {})",
            pa[0].fee,
            pb[0].fee
        );
    }

    #[tokio::test]
    async fn test_send_batch_defers_when_fee_rate_too_high() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let ra = db.insert_referral(&referrer(0, "AAA")).await.unwrap();
        let onchain = Arc::new(MockOnChainProvider::default());
        // Fee estimate 100 sat/vB exceeds the handler's 50 cap.
        let h = handler_with_feerate(db.clone(), onchain.clone(), 100);

        let eligible = vec![(
            Referral {
                id: ra,
                ..referrer(ra, "AAA")
            },
            regtest_addr(1),
            2_000_000,
        )];
        h.send_batch(onchain.as_ref(), eligible, vec![], 1_000)
            .await
            .unwrap();

        // Nothing was broadcast and no payout was reserved/recorded.
        assert!(onchain.sends.lock().await.is_empty(), "no tx broadcast");
        assert!(
            db.list_referral_payouts(ra).await.unwrap().is_empty(),
            "no payout reserved when deferred"
        );
    }

    /// A provider whose `send_coins` always fails, to test reservation rollback.
    #[derive(Default)]
    struct FailingOnChain;

    #[async_trait::async_trait]
    impl OnChainProvider for FailingOnChain {
        async fn new_address(
            &self,
            _req: payments_rs::onchain::NewAddressRequest,
        ) -> anyhow::Result<payments_rs::onchain::NewAddressResponse> {
            anyhow::bail!("not supported")
        }
        async fn subscribe_payments(
            &self,
            _from: Option<payments_rs::onchain::PaymentCursor>,
        ) -> anyhow::Result<
            std::pin::Pin<
                Box<dyn futures::Stream<Item = payments_rs::onchain::ChainPaymentUpdate> + Send>,
            >,
        > {
            anyhow::bail!("not supported")
        }
        async fn send_coins(
            &self,
            _req: SendCoinsRequest,
        ) -> anyhow::Result<payments_rs::onchain::SendCoinsResponse> {
            anyhow::bail!("node offline")
        }
    }

    #[tokio::test]
    async fn test_send_batch_releases_reservations_on_failure() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let ra = db.insert_referral(&referrer(0, "AAA")).await.unwrap();
        let onchain = Arc::new(FailingOnChain);
        let h = onchain_fiat_handler(
            db.clone(),
            onchain.clone(),
            eur_exchange(100_000.0).await,
            Arc::new(ChannelWorkCommander::new()),
            1,
        );

        let referral = Referral {
            id: ra,
            ..referrer(ra, "AAA")
        };
        let eligible = vec![(referral.clone(), regtest_addr(1), 2_000_000)];
        // A fiat row rides the same batch: its reservation must be released too.
        let fiat = vec![(
            referral,
            regtest_addr(1),
            "EUR".to_string(),
            1_000,
            10_000_000,
        )];
        let res = h.send_batch(onchain.as_ref(), eligible, fiat, 1_000).await;
        assert!(res.is_err(), "send failure propagates");
        // The reserved payouts were released so the balances retry next run.
        let payouts = db.list_referral_payouts(ra).await.unwrap();
        assert!(
            payouts.is_empty(),
            "reservations released on send failure, got {payouts:?}"
        );
    }

    #[test]
    fn test_payable_from_total_rounding_and_floor() {
        // Below threshold -> None
        assert_eq!(payable_from_total(500_000, 500_000, 1_000_000), None);
        // At threshold, whole sats -> pays full amount
        assert_eq!(
            payable_from_total(1_000_000, 1_000_000, 1_000_000),
            Some(1_000_000)
        );
        // Sub-sat remainder dropped (1_234_567 msat -> 1_234_000 msat)
        assert_eq!(
            payable_from_total(1_234_567, 1_234_567, 1_000_000),
            Some(1_234_000)
        );
        // Owed below a tiny threshold that rounds to zero whole sats -> None
        assert_eq!(payable_from_total(999, 999, 1), None);
    }

    /// The floor is judged on everything owed, while the payout is only what
    /// this balance holds — so balances that are each too small to pay are
    /// still paid when they add up.
    #[test]
    fn test_payable_from_total() {
        // This balance alone is under the floor, but the referrer is not.
        assert_eq!(
            payable_from_total(500_000, 1_200_000, 1_000_000),
            Some(500_000),
            "a small balance rides on the referrer's total"
        );
        // The total is still what the floor is judged on.
        assert_eq!(payable_from_total(500_000, 900_000, 1_000_000), None);
        // Sub-sat balances still cannot be sent, however large the total.
        assert_eq!(payable_from_total(999, 10_000_000, 1_000_000), None);
        // And what is paid is rounded down to whole sats.
        assert_eq!(
            payable_from_total(1_500, 10_000_000, 1_000_000),
            Some(1_000)
        );
    }

    #[test]
    fn test_effective_min_msat() {
        let system_min = 1_000 * 1000; // 1000 sats in msat

        // No user threshold -> system minimum is used.
        let mut r = referrer(1, "AAA");
        r.payout_threshold = None;
        assert_eq!(effective_min_msat(&r, system_min), system_min);

        // A higher user threshold raises the bar.
        r.payout_threshold = Some(50_000);
        assert_eq!(effective_min_msat(&r, system_min), 50_000 * 1000);

        // A user threshold below the system minimum can never lower it.
        r.payout_threshold = Some(100);
        assert_eq!(effective_min_msat(&r, system_min), system_min);

        // Equal to the system minimum -> system minimum.
        r.payout_threshold = Some(1_000);
        assert_eq!(effective_min_msat(&r, system_min), system_min);
    }
}
