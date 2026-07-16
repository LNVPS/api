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

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use lnvps_api_common::{WorkCommander, WorkJob};
use lnvps_db::{LNVpsDb, Referral, ReferralPayout, ReferralPayoutMode};
use log::{debug, info, warn};
use payments_rs::lightning::{LightningNode, PayInvoiceRequest};
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

/// Pays referrers their accrued BTC commission over Lightning.
#[derive(Clone)]
pub struct ReferralPayoutHandler {
    db: Arc<dyn LNVpsDb>,
    node: Arc<dyn LightningNode>,
    tx: Arc<dyn WorkCommander>,
    /// Minimum accrued BTC commission (millisats) before a payout is attempted.
    /// `None` disables automated payouts.
    min_payout_msat: Option<u64>,
}

impl ReferralPayoutHandler {
    /// Create a handler. `min_payout_sats` of `None` disables automated payouts;
    /// commission still accrues and can be paid manually by admins.
    pub fn new(
        db: Arc<dyn LNVpsDb>,
        node: Arc<dyn LightningNode>,
        tx: Arc<dyn WorkCommander>,
        min_payout_sats: Option<u64>,
    ) -> Self {
        Self {
            db,
            node,
            tx,
            min_payout_msat: min_payout_sats.map(|s| s.saturating_mul(1000)),
        }
    }

    /// Process automated payouts for every enrolled referrer. Per-referrer
    /// failures are logged and do not abort the batch.
    pub async fn process_payouts(&self) -> Result<()> {
        let Some(min_msat) = self.min_payout_msat else {
            return Ok(());
        };
        let referrals = self.db.list_all_referrals().await?;
        debug!(
            "Processing referral payouts for {} referrers (min {} msat)",
            referrals.len(),
            min_msat
        );
        for referral in referrals {
            if let Err(e) = self.process_one(&referral, min_msat).await {
                warn!("Referral payout failed for code {}: {}", referral.code, e);
            }
        }
        Ok(())
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
        // in-flight reservation is never paid twice.
        let existing: u64 = self
            .db
            .list_referral_payouts(referral.id)
            .await?
            .iter()
            .filter(|p| p.currency.eq_ignore_ascii_case("BTC"))
            .map(|p| p.amount)
            .sum();

        let Some(pay_msat) = payable_referral_msat(earned_msat, existing, min_msat) else {
            return Ok(());
        };

        // Reserve first (unpaid) so the amount is not double-paid next cycle.
        let mut payout = ReferralPayout {
            id: 0,
            referral_id: referral.id,
            amount: pay_msat,
            currency: "BTC".to_string(),
            created: Utc::now(),
            is_paid: false,
            invoice: None,
            pre_image: None,
        };
        let payout_id = self.db.insert_referral_payout(&payout).await?;
        payout.id = payout_id;

        match self.pay_commission(referral, pay_msat).await {
            Ok((bolt11, pre_image)) => {
                payout.is_paid = true;
                payout.invoice = Some(bolt11);
                payout.pre_image = pre_image;
                self.db.update_referral_payout(&payout).await?;
                info!(
                    "Paid referral commission {} msat to code {} (payout {})",
                    pay_msat, referral.code, payout_id
                );
                let _ = self
                    .tx
                    .send(WorkJob::SendNotification {
                        user_id: referral.user_id,
                        message: format!(
                            "You've been paid {} sats in referral commission.",
                            pay_msat / 1000
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
    /// payout method and pay it from our node. Returns `(bolt11, preimage)`.
    async fn pay_commission(
        &self,
        referral: &Referral,
        amount_msat: u64,
    ) -> Result<(String, Option<Vec<u8>>)> {
        let bolt11 = match referral.mode {
            ReferralPayoutMode::LightningAddress => {
                let addr = referral
                    .lightning_address
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
        Ok((bolt11, pre_image))
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
    use super::payable_referral_msat;

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
