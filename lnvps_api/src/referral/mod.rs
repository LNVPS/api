//! Automated referral commission payouts.
//!
//! Referrers accrue commission (a percentage of each referred VM's first
//! payment; see the pricing/DB layer). This module turns that accrued **BTC**
//! commission into outgoing Lightning payments, independently of the
//! subscription/billing machinery.
//!
//! Non-BTC (fiat) commission is never auto-paid here — Lightning settles in
//! sats — and is left to accrue for manual admin payout. Automated payouts are
//! opt-in: when no minimum threshold is configured they are disabled entirely.

use crate::fee_estimate::FeeEstimator;
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use lnvps_api_common::{WorkCommander, WorkJob};
use lnvps_db::{LNVpsDb, Referral, ReferralPayout, ReferralPayoutMode};
use log::{debug, info, warn};
use payments_rs::currency::CurrencyAmount;
use payments_rs::lightning::{LightningNode, PayInvoiceRequest};
use payments_rs::onchain::{OnChainProvider, SendCoinsRequest, SendOutput};
use std::str::FromStr;
use std::sync::Arc;

/// Compute the payable BTC referral commission (in millisats) from the earned
/// and already-reserved/paid amounts and the minimum threshold.
///
/// Returns `None` when the outstanding balance is below `min_msat` or rounds to
/// zero whole sats. Lightning settles whole sats, so any sub-sat remainder is
/// dropped and stays owed for a later payout.
fn payable_referral_msat(earned_msat: u64, existing_msat: u64, min_msat: u64) -> Option<u64> {
    let owed = earned_msat.saturating_sub(existing_msat);
    if owed < min_msat {
        return None;
    }
    let pay_msat = (owed / 1000) * 1000;
    if pay_msat == 0 { None } else { Some(pay_msat) }
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

        // On-chain payouts, batched into a single transaction.
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
    /// send-many transaction**.
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
            match self.payable_onchain_msat(referral, min_onchain_msat).await {
                Ok(Some(pay_msat)) => {
                    eligible.push((referral.clone(), address.to_string(), pay_msat))
                }
                Ok(None) => {}
                Err(e) => warn!(
                    "Failed to compute on-chain payout for code {}: {}",
                    referral.code, e
                ),
            }
        }
        if eligible.is_empty() {
            return Ok(());
        }
        self.send_batch(onchain, eligible).await
    }

    /// Reserve, broadcast (single send-many) and record a batch of on-chain
    /// payouts. Split from selection so it can be tested with a hand-built
    /// `eligible` list. Each entry is `(referrer, address, pay_msat)`.
    ///
    /// The current next-block fee rate is obtained from the fee estimator; if it
    /// exceeds the configured cap the whole batch is **deferred** (returns `Ok`
    /// without reserving or sending) so payouts wait for cheaper fees. Otherwise
    /// the batch is broadcast at that rate.
    async fn send_batch(
        &self,
        onchain: &dyn OnChainProvider,
        eligible: Vec<(Referral, String, u64)>,
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

        // 1. Reserve every payout (unpaid) before sending, so a crash between
        //    the broadcast and the DB update cannot double-pay next run.
        let mut reserved: Vec<(u64, Referral, String, u64)> = Vec::new();
        for (referral, addr, pay_msat) in &eligible {
            let payout = ReferralPayout {
                id: 0,
                referral_id: referral.id,
                amount: *pay_msat,
                fee: 0,
                currency: "BTC".to_string(),
                created: Utc::now(),
                is_paid: false,
                invoice: None,
                pre_image: None,
                outpoint: None,
            };
            let payout_id = self.db.insert_referral_payout(&payout).await?;
            reserved.push((payout_id, referral.clone(), addr.clone(), *pay_msat));
        }

        // 2. Broadcast a single send-many transaction paying every referrer at
        //    the chosen fee rate.
        let req = Self::payout_batch_request(&eligible, sat_per_vbyte);
        let total_msat: u64 = eligible.iter().map(|(_, _, m)| *m).sum();
        match onchain.send_coins(req).await {
            Ok(resp) => {
                info!(
                    "Broadcast on-chain referral payout batch {} ({} referrers, {} sats)",
                    resp.txid,
                    reserved.len(),
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
                // Split the fee across referrers in proportion to their payout.
                let amounts: Vec<u64> = reserved.iter().map(|(_, _, _, m)| *m).collect();
                let fee_shares = split_fee_proportional(&amounts, total_fee_msat);

                // 3. Mark every reserved payout paid with its outpoint and fee.
                for ((payout_id, referral, address, pay_msat), fee_msat) in
                    reserved.into_iter().zip(fee_shares)
                {
                    let outpoint = match decoded
                        .as_ref()
                        .and_then(|tx| vout_for_address(tx, &address))
                    {
                        Some(vout) => format!("{}:{}", resp.txid, vout),
                        // Fall back to the bare txid if the tx couldn't be
                        // decoded or the output wasn't found.
                        None => resp.txid.clone(),
                    };
                    let payout = ReferralPayout {
                        id: payout_id,
                        referral_id: referral.id,
                        amount: pay_msat,
                        fee: fee_msat,
                        currency: "BTC".to_string(),
                        created: Utc::now(),
                        is_paid: true,
                        invoice: None,
                        pre_image: None,
                        outpoint: Some(outpoint.clone()),
                    };
                    if let Err(e) = self.db.update_referral_payout(&payout).await {
                        warn!(
                            "Broadcast payout {} but failed to mark it paid: {}",
                            payout_id, e
                        );
                    }
                    let _ = self
                        .tx
                        .send(WorkJob::SendNotification {
                            user_id: referral.user_id,
                            message: format!(
                                "You've been paid {} sats in referral commission on-chain \
                                 ({}, minus {} sats fee).",
                                pay_msat / 1000,
                                outpoint,
                                fee_msat / 1000
                            ),
                            title: Some("Referral payout".to_string()),
                        })
                        .await;
                }
                Ok(())
            }
            Err(e) => {
                // Release all reservations so the balances retry next run.
                for (payout_id, _referral, _address, _pay_msat) in reserved {
                    if let Err(del) = self.db.delete_referral_payout(payout_id).await {
                        warn!(
                            "Failed to release reserved on-chain payout {} after send error: {}",
                            payout_id, del
                        );
                    }
                }
                Err(anyhow!("send_coins failed: {}", e))
            }
        }
    }

    /// Build the single send-many request paying every eligible referrer at
    /// `sat_per_vbyte`. Each entry is `(referrer, address, pay_msat)`.
    fn payout_batch_request(
        eligible: &[(Referral, String, u64)],
        sat_per_vbyte: u64,
    ) -> SendCoinsRequest {
        SendCoinsRequest {
            outputs: eligible
                .iter()
                .map(|(_r, address, pay_msat)| SendOutput {
                    address: address.clone(),
                    amount: CurrencyAmount::millisats(*pay_msat),
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
    ) -> Result<Option<u64>> {
        let usage = self.db.list_referral_usage(&referral.code).await?;
        let earned_msat: u64 = usage
            .iter()
            .filter(|u| u.currency.eq_ignore_ascii_case("BTC"))
            .map(|u| u.commission())
            .sum();
        // The referrer bears fees, so debit amount + fee from their balance.
        let existing: u64 = self
            .db
            .list_referral_payouts(referral.id)
            .await?
            .iter()
            .filter(|p| p.currency.eq_ignore_ascii_case("BTC"))
            .map(|p| p.amount.saturating_add(p.fee))
            .sum();
        Ok(payable_referral_msat(
            earned_msat,
            existing,
            min_onchain_msat,
        ))
    }

    /// Accrue and pay a single referrer's owed BTC commission, if it clears the
    /// threshold. Reserves the payout before paying so a crash or concurrent run
    /// cannot double-pay; the reservation is deleted if the payment fails.
    async fn process_one(&self, referral: &Referral, min_msat: u64) -> Result<()> {
        // Earned BTC commission (millisats) across all first payments.
        let usage = self.db.list_referral_usage(&referral.code).await?;
        let earned_msat: u64 = usage
            .iter()
            .filter(|u| u.currency.eq_ignore_ascii_case("BTC"))
            .map(|u| u.commission())
            .sum();

        // Subtract every existing BTC payout record (paid AND reserved) so an
        // in-flight reservation is never paid twice. The referrer bears fees, so
        // debit amount + fee.
        let existing: u64 = self
            .db
            .list_referral_payouts(referral.id)
            .await?
            .iter()
            .filter(|p| p.currency.eq_ignore_ascii_case("BTC"))
            .map(|p| p.amount.saturating_add(p.fee))
            .sum();

        let Some(pay_msat) = payable_referral_msat(earned_msat, existing, min_msat) else {
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
            invoice: None,
            pre_image: None,
            outpoint: None,
        };
        let payout_id = self.db.insert_referral_payout(&payout).await?;
        payout.id = payout_id;

        match self.pay_commission(referral, pay_msat).await {
            Ok((bolt11, pre_image, fee_msat)) => {
                payout.is_paid = true;
                payout.invoice = Some(bolt11);
                payout.pre_image = pre_image;
                // Charge the referrer the routing fee we paid.
                payout.fee = fee_msat;
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
    use lnvps_api_common::{ChannelWorkCommander, MockDb};
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

    #[test]
    fn test_payout_batch_request_one_output_per_referrer() {
        let eligible = vec![
            (referrer(1, "AAA"), "bcrt1qa".to_string(), 2_000_000),
            (referrer(2, "BBB"), "bcrt1qb".to_string(), 1_500_000),
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
        h.send_batch(onchain.as_ref(), eligible).await.unwrap();

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

        let oa = pa[0].outpoint.as_deref().expect("outpoint set");
        let ob = pb[0].outpoint.as_deref().expect("outpoint set");
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
        h.send_batch(onchain.as_ref(), eligible).await.unwrap();

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
        let h = handler(db.clone(), onchain.clone());

        let eligible = vec![(
            Referral {
                id: ra,
                ..referrer(ra, "AAA")
            },
            regtest_addr(1),
            2_000_000,
        )];
        let res = h.send_batch(onchain.as_ref(), eligible).await;
        assert!(res.is_err(), "send failure propagates");
        // The reserved payout was released so the balance retries next run.
        let payouts = db.list_referral_payouts(ra).await.unwrap();
        assert!(
            payouts.is_empty(),
            "reservation released on send failure, got {payouts:?}"
        );
    }

    #[test]
    fn test_payable_referral_msat() {
        // Below threshold -> None
        assert_eq!(payable_referral_msat(500_000, 0, 1_000_000), None);
        // At threshold, whole sats -> pays full amount
        assert_eq!(
            payable_referral_msat(1_000_000, 0, 1_000_000),
            Some(1_000_000)
        );
        // Existing payouts subtracted; remainder below threshold -> None
        assert_eq!(payable_referral_msat(1_500_000, 1_000_000, 1_000_000), None);
        // Sub-sat remainder dropped (1_234_567 msat -> 1_234_000 msat)
        assert_eq!(
            payable_referral_msat(1_234_567, 0, 1_000_000),
            Some(1_234_000)
        );
        // Owed below a tiny threshold that rounds to zero whole sats -> None
        assert_eq!(payable_referral_msat(999, 0, 1), None);
    }
}
