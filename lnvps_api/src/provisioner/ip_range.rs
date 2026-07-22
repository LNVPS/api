//! IP-range allocation and LIR registry fulfilment.
//!
//! Carves concrete CIDRs out of `available_ip_space` blocks, records them as
//! `ip_range_subscription` rows, and — when a registry / RPKI provider is
//! configured — creates the LIR objects that let a customer announce the space:
//!
//! * an IRR `route`/`route6` object (via [`RegistryProvider`]); and
//! * an RPKI ROA authorising the customer's origin ASN over the prefix (via
//!   [`RpkiProvider`]).
//!
//! This is the domain layer; [`crate::subscription::IpRangeLineItemHandler`] is
//! the thin subscription-lifecycle adapter that delegates here (mirroring how
//! `VmLineItemHandler` delegates to [`crate::provisioner::VmProvisioner`]).

use anyhow::{Context, Result, anyhow, bail};
use ipnetwork::IpNetwork;
use lnvps_api_common::{
    RegistryProvider, RoaDefinition, RouteObject, RpkiProvider, WorkCommander, WorkJob,
};
use lnvps_db::{
    AvailableIpSpace, IpRangeSubscription, LNVpsDb, SubscriptionLineItem, SubscriptionPayment,
};
use log::{info, warn};
use serde::Deserialize;
use serde_json::json;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// Immutable configuration persisted on the subscription line item at order
/// time. Ongoing mutable state (the origin ASN) lives on the
/// `ip_range_subscription` assignment row instead, not here.
#[derive(Debug, Deserialize)]
struct IpRangeLineItemConfig {
    available_ip_space_id: u64,
    prefix_size: u8,
}

/// Allocates IP ranges and reconciles their LIR registry objects.
#[derive(Clone)]
pub struct IpRangeProvisioner {
    db: Arc<dyn LNVpsDb>,
    tx: Arc<dyn WorkCommander>,
    registry: Option<Arc<dyn RegistryProvider>>,
    rpki: Option<Arc<dyn RpkiProvider>>,
}

impl IpRangeProvisioner {
    pub fn new(db: Arc<dyn LNVpsDb>, tx: Arc<dyn WorkCommander>) -> Self {
        Self {
            db,
            tx,
            registry: None,
            rpki: None,
        }
    }

    /// Attach registry / RPKI providers for LIR object fulfilment.
    pub fn with_providers(
        mut self,
        registry: Option<Arc<dyn RegistryProvider>>,
        rpki: Option<Arc<dyn RpkiProvider>>,
    ) -> Self {
        self.registry = registry;
        self.rpki = rpki;
        self
    }

    /// Fulfil an IP-range line item after a payment completed.
    ///
    /// Idempotent: a line item that already has an active allocation is treated
    /// as a renewal and left untouched; an expired line item's previous
    /// allocation is reactivated when its CIDR is still free; otherwise a fresh
    /// CIDR is carved out. The origin ASN is configured by the customer (see
    /// [`Self::configure_origin_asn`]), so no registry objects are created for
    /// fresh allocations here.
    ///
    /// `CheckSubscriptions` is dispatched on **every** outcome — including
    /// fulfilment failure — because the payment is already committed as paid by
    /// the caller and the worker must reconcile subscription state regardless.
    pub async fn allocate_on_payment(
        &self,
        line_item_id: u64,
        payment: &SubscriptionPayment,
    ) -> Result<()> {
        let res = self.fulfil_on_payment(line_item_id, payment).await;
        if let Err(e) = self.tx.send(WorkJob::CheckSubscriptions).await {
            warn!(
                "Failed to dispatch CheckSubscriptions for line item {}: {}",
                line_item_id, e
            );
        }
        res
    }

    /// The fulfilment logic behind [`Self::allocate_on_payment`].
    async fn fulfil_on_payment(
        &self,
        line_item_id: u64,
        payment: &SubscriptionPayment,
    ) -> Result<()> {
        let li = self.db.get_subscription_line_item(line_item_id).await?;

        let existing = self
            .db
            .list_ip_range_subscriptions_by_line_item(li.id)
            .await?;
        // An active allocation already exists → this is a plain renewal.
        if existing.iter().any(|s| s.is_active) {
            return Ok(());
        }

        // Expired-then-renewed: prefer giving the customer their previous
        // CIDR back over carving a new one.
        if let Some(prev) = existing.into_iter().max_by_key(|s| s.created)
            && self.try_reactivate(prev).await?
        {
            return Ok(());
        }

        self.allocate_fresh(&li, payment).await
    }

    /// Reactivate a previously-deactivated allocation if its CIDR is still
    /// free in the space. Re-creates registry objects (route object / ROA) for
    /// the allocation's configured origin ASN, if any. Returns `false` when
    /// the CIDR was re-allocated to someone else (or is unparsable) and a
    /// fresh allocation should be made instead.
    async fn try_reactivate(&self, mut prev: IpRangeSubscription) -> Result<bool> {
        let cidr: IpNetwork = match prev.cidr.parse() {
            Ok(c) => c,
            Err(_) => return Ok(false),
        };
        let (active, _) = self
            .db
            .list_ip_range_subscriptions_by_space_paginated(
                prev.available_ip_space_id,
                None,
                Some(true),
                100_000,
                0,
            )
            .await?;
        let (ps, pe) = net_bounds(&cidr);
        let clash = active
            .iter()
            .filter_map(|s| s.cidr.parse::<IpNetwork>().ok())
            .filter(|t| t.is_ipv4() == cidr.is_ipv4())
            .any(|t| {
                let (ts, te) = net_bounds(&t);
                ps <= te && ts <= pe
            });
        if clash {
            info!(
                "Previous allocation {} for line item {} is no longer free — allocating fresh",
                prev.cidr, prev.subscription_line_item_id
            );
            return Ok(false);
        }
        prev.is_active = true;
        prev.ended_at = None;
        self.db.update_ip_range_subscription(&prev).await?;
        info!(
            "Reactivated allocation {} for line item {}",
            prev.cidr, prev.subscription_line_item_id
        );
        // Re-create registry objects for the configured origin ASN (no-op
        // when none is set; they were torn down on deactivation).
        let space = self
            .db
            .get_available_ip_space(prev.available_ip_space_id)
            .await?;
        self.fulfil_registry(&space, &mut prev).await?;
        Ok(true)
    }

    /// Carve a fresh CIDR out of the line item's configured IP space.
    async fn allocate_fresh(
        &self,
        li: &SubscriptionLineItem,
        payment: &SubscriptionPayment,
    ) -> Result<()> {
        let cfg: IpRangeLineItemConfig = match &li.configuration {
            Some(v) => serde_json::from_value(v.clone())
                .with_context(|| format!("parse config for line item {}", li.id))?,
            None => bail!("IP range line item {} has no configuration", li.id),
        };

        let space = self
            .db
            .get_available_ip_space(cfg.available_ip_space_id)
            .await?;
        let block: IpNetwork = space
            .cidr
            .parse()
            .with_context(|| format!("invalid CIDR on ip space {}: {}", space.id, space.cidr))?;

        // Gather active allocations already carved out of this block.
        let (taken_subs, _) = self
            .db
            .list_ip_range_subscriptions_by_space_paginated(space.id, None, Some(true), 100_000, 0)
            .await?;
        let taken: Vec<IpNetwork> = taken_subs
            .iter()
            .filter_map(|s| s.cidr.parse().ok())
            .collect();

        let cidr = allocate_subnet(&block, cfg.prefix_size, &taken).with_context(|| {
            format!(
                "no free /{} subnet available in {}",
                cfg.prefix_size, space.cidr
            )
        })?;
        info!(
            "Allocated {} to subscription {} (line item {})",
            cidr, payment.subscription_id, li.id
        );

        let ips = IpRangeSubscription {
            id: 0,
            subscription_line_item_id: li.id,
            available_ip_space_id: space.id,
            created: chrono::Utc::now(),
            cidr: cidr.to_string(),
            // Origin ASN is configured by the customer after allocation; the
            // route object / ROA are created then (see `configure_origin_asn`).
            origin_asn: None,
            is_active: true,
            started_at: chrono::Utc::now(),
            ended_at: None,
            metadata: None,
        };
        self.db.insert_ip_range_subscription(&ips).await?;
        Ok(())
    }

    /// Set (or change/clear) the origin ASN on an allocation and reconcile its
    /// registry objects: objects for the previous ASN are removed, then new ones
    /// are created for `new_asn`. This is the mutable, post-allocation path a
    /// customer uses to re-home their space to a different ASN.
    pub async fn configure_origin_asn(&self, ip_sub_id: u64, new_asn: Option<u32>) -> Result<()> {
        let mut ips = self.db.get_ip_range_subscription(ip_sub_id).await?;
        if ips.origin_asn == new_asn {
            return Ok(());
        }
        // Tear down objects for the previous ASN, if any.
        self.teardown_registry(&ips).await;

        let space = self
            .db
            .get_available_ip_space(ips.available_ip_space_id)
            .await?;
        ips.origin_asn = new_asn;
        ips.metadata = None;
        // Persist the new ASN first (covers the cleared / no-provider cases).
        self.db.update_ip_range_subscription(&ips).await?;
        // Create objects for the new ASN (no-op when cleared to None).
        self.fulfil_registry(&space, &mut ips).await?;
        Ok(())
    }

    /// Deactivate all active allocations for a line item, tearing down their
    /// registry objects first. Called on subscription expiry.
    pub async fn deactivate_line_item(&self, line_item: &SubscriptionLineItem) -> Result<()> {
        let ip_subs = self
            .db
            .list_ip_range_subscriptions_by_line_item(line_item.id)
            .await?;
        for mut ips in ip_subs {
            if ips.is_active {
                self.teardown_registry(&ips).await;
                ips.is_active = false;
                ips.ended_at = Some(chrono::Utc::now());
                if let Err(e) = self.db.update_ip_range_subscription(&ips).await {
                    warn!(
                        "Failed to deactivate ip_range_subscription {}: {}",
                        ips.id, e
                    );
                }
            }
        }
        Ok(())
    }

    /// The `mnt-by` maintainer to own the created route object, taken from the
    /// space's `metadata.maintainer` (or `mnt_by`). `None` if unset.
    fn space_maintainer(space: &AvailableIpSpace) -> Option<String> {
        let meta = space.metadata.as_ref()?;
        meta.get("maintainer")
            .or_else(|| meta.get("mnt_by"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Create the IRR route object + RPKI ROA for an allocation whose origin ASN
    /// is set, persisting their references onto the `ip_range_subscription`
    /// metadata. A no-op when `ips.origin_asn` is `None`. Mutates and saves the
    /// row.
    async fn fulfil_registry(
        &self,
        space: &AvailableIpSpace,
        ips: &mut IpRangeSubscription,
    ) -> Result<()> {
        let Some(origin_asn) = ips.origin_asn else {
            // No origin ASN configured — nothing to authorise yet.
            return Ok(());
        };
        let cidr: IpNetwork = ips
            .cidr
            .parse()
            .with_context(|| format!("invalid CIDR on ip_range_subscription {}", ips.id))?;
        let mut meta = serde_json::Map::new();

        // route/route6 object.
        if let Some(reg) = &self.registry {
            if let Some(maintainer) = Self::space_maintainer(space) {
                let obj = RouteObject {
                    prefix: cidr,
                    origin_asn,
                    description: format!(
                        "LNVPS subscription line item {}",
                        ips.subscription_line_item_id
                    ),
                    maintainer: maintainer.clone(),
                };
                let r = reg
                    .create_route_object(&obj)
                    .await
                    .map_err(|e| anyhow!("create route object: {}", e))?;
                meta.insert("route_object_ref".to_string(), json!(r.0));
                meta.insert("maintainer".to_string(), json!(maintainer));
            } else {
                warn!(
                    "No maintainer on ip space {} — skipping route object for {}",
                    space.id, cidr
                );
            }
        }

        // RPKI ROA.
        if let Some(rpki) = &self.rpki {
            let roa = RoaDefinition {
                origin_asn,
                prefix: cidr,
                max_length: None,
            };
            rpki.add_roa(&roa)
                .await
                .map_err(|e| anyhow!("add roa: {}", e))?;
            meta.insert(
                "roa_max_length".to_string(),
                json!(roa.effective_max_length()),
            );
        }

        ips.metadata = Some(serde_json::Value::Object(meta));
        self.db.update_ip_range_subscription(ips).await?;
        Ok(())
    }

    /// Remove any registry objects previously created for an allocation.
    async fn teardown_registry(&self, ips: &IpRangeSubscription) {
        let Some(meta) = ips.metadata.as_ref() else {
            return;
        };
        let cidr: Option<IpNetwork> = ips.cidr.parse().ok();
        let (Some(origin_asn), Some(cidr)) = (ips.origin_asn, cidr) else {
            return;
        };

        if let (Some(reg), Some(mnt)) = (
            &self.registry,
            meta.get("maintainer").and_then(|v| v.as_str()),
        ) && meta.get("route_object_ref").is_some()
        {
            let obj = RouteObject {
                prefix: cidr,
                origin_asn,
                description: String::new(),
                maintainer: mnt.to_string(),
            };
            if let Err(e) = reg.delete_route_object(&obj).await {
                warn!("Failed to delete route object for {}: {}", ips.cidr, e);
            }
        }

        if let Some(rpki) = &self.rpki
            && let Some(max_length) = meta.get("roa_max_length").and_then(|v| v.as_u64())
        {
            let roa = RoaDefinition {
                origin_asn,
                prefix: cidr,
                max_length: Some(max_length as u8),
            };
            if let Err(e) = rpki.remove_roa(&roa).await {
                warn!("Failed to remove ROA for {}: {}", ips.cidr, e);
            }
        }
    }
}

// ===========================================================================
// CIDR sub-allocation
// ===========================================================================

/// Inclusive numeric bounds `[start, end]` of a CIDR (both families widened to
/// `u128`).
fn net_bounds(n: &IpNetwork) -> (u128, u128) {
    match n {
        IpNetwork::V4(v4) => {
            let base = u32::from(v4.network()) as u128;
            let size = 1u128 << (32 - v4.prefix() as u32);
            (base, base + size - 1)
        }
        IpNetwork::V6(v6) => {
            let base = u128::from(v6.network());
            let host_bits = 128 - v6.prefix() as u32;
            if host_bits >= 128 {
                (0, u128::MAX)
            } else {
                (base, base + (1u128 << host_bits) - 1)
            }
        }
    }
}

/// Build a CIDR from a numeric network address, prefix, and family.
fn make_net(start: u128, prefix: u8, v4: bool) -> Option<IpNetwork> {
    if v4 {
        IpNetwork::new(std::net::IpAddr::V4(Ipv4Addr::from(start as u32)), prefix).ok()
    } else {
        IpNetwork::new(std::net::IpAddr::V6(Ipv6Addr::from(start)), prefix).ok()
    }
}

/// Find the first sub-prefix of length `target_len` inside `block` that does
/// not overlap any CIDR in `taken`. Returns `None` if the parameters are
/// invalid (wrong family / bad length) or the block is fully allocated.
///
/// Runs in time proportional to the number of `taken` allocations, not the size
/// of the address space: it walks candidates in order and jumps past occupied
/// ranges, so a mostly-empty block is served from its first free slot instantly.
pub fn allocate_subnet(
    block: &IpNetwork,
    target_len: u8,
    taken: &[IpNetwork],
) -> Option<IpNetwork> {
    let v4 = block.is_ipv4();
    let max_bits: u32 = if v4 { 32 } else { 128 };
    if (target_len as u32) < block.prefix() as u32 || target_len as u32 > max_bits {
        return None;
    }
    let host_bits = max_bits - target_len as u32;
    if host_bits >= 128 {
        return None;
    }
    let size = 1u128 << host_bits;
    let (block_start, block_end) = net_bounds(block);

    // Only same-family allocations can overlap; sort by start for the walk.
    let mut taken_bounds: Vec<(u128, u128)> = taken
        .iter()
        .filter(|t| t.is_ipv4() == v4)
        .map(net_bounds)
        .collect();
    taken_bounds.sort_unstable();

    let mut cur = block_start;
    loop {
        if cur > block_end {
            return None;
        }
        let cand_end = cur.checked_add(size - 1)?;
        if cand_end > block_end {
            return None;
        }
        // Does the candidate overlap any taken range?
        if let Some((_, te)) = taken_bounds
            .iter()
            .find(|(ts, te)| cur <= *te && *ts <= cand_end)
        {
            // Jump to the next size-aligned slot after the occupied range.
            let after = te.checked_add(1)?;
            let aligned = (after + size - 1) & !(size - 1);
            cur = if aligned <= cur { cur + size } else { aligned };
        } else {
            return make_net(cur, target_len, v4);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use lnvps_api_common::{ChannelWorkCommander, MockDb, RegistryRef};
    use lnvps_db::{LNVpsDbBase, PaymentMethod, SubscriptionPaymentType, SubscriptionType};
    use std::sync::Mutex as StdMutex;

    fn net(s: &str) -> IpNetwork {
        s.parse().unwrap()
    }

    #[test]
    fn test_allocate_first_free_v4() {
        let block = net("192.0.2.0/24");
        assert_eq!(
            allocate_subnet(&block, 26, &[]).unwrap(),
            net("192.0.2.0/26")
        );
    }

    #[test]
    fn test_allocate_skips_taken_v4() {
        let block = net("192.0.2.0/24");
        let taken = [net("192.0.2.0/26"), net("192.0.2.64/26")];
        assert_eq!(
            allocate_subnet(&block, 26, &taken).unwrap(),
            net("192.0.2.128/26")
        );
    }

    #[test]
    fn test_allocate_partial_overlap_jump() {
        let block = net("10.0.0.0/22");
        let taken = [net("10.0.1.0/24")];
        assert_eq!(
            allocate_subnet(&block, 24, &taken).unwrap(),
            net("10.0.0.0/24")
        );
        let taken = [net("10.0.0.0/24"), net("10.0.1.0/24")];
        assert_eq!(
            allocate_subnet(&block, 24, &taken).unwrap(),
            net("10.0.2.0/24")
        );
    }

    #[test]
    fn test_allocate_full_block_none() {
        let block = net("192.0.2.0/25");
        let taken = [net("192.0.2.0/26"), net("192.0.2.64/26")];
        assert!(allocate_subnet(&block, 26, &taken).is_none());
    }

    #[test]
    fn test_allocate_v6() {
        let block = net("2001:db8::/32");
        assert_eq!(
            allocate_subnet(&block, 48, &[]).unwrap(),
            net("2001:db8::/48")
        );
        let taken = [net("2001:db8::/48")];
        assert_eq!(
            allocate_subnet(&block, 48, &taken).unwrap(),
            net("2001:db8:1::/48")
        );
    }

    #[test]
    fn test_allocate_invalid_params() {
        let block = net("192.0.2.0/24");
        assert!(allocate_subnet(&block, 23, &[]).is_none());
        assert!(allocate_subnet(&block, 33, &[]).is_none());
        assert_eq!(
            allocate_subnet(&block, 26, &[net("2001:db8::/48")]).unwrap(),
            net("192.0.2.0/26")
        );
    }

    #[test]
    fn test_space_maintainer_reads_metadata() {
        let mut space = sample_space();
        space.metadata = None;
        assert_eq!(IpRangeProvisioner::space_maintainer(&space), None);
        space.metadata = Some(json!({ "maintainer": "LNVPS-MNT" }));
        assert_eq!(
            IpRangeProvisioner::space_maintainer(&space).as_deref(),
            Some("LNVPS-MNT")
        );
        space.metadata = Some(json!({ "mnt_by": "ALT-MNT" }));
        assert_eq!(
            IpRangeProvisioner::space_maintainer(&space).as_deref(),
            Some("ALT-MNT")
        );
    }

    // ---- Fulfilment integration (mock DB + capturing providers) ----

    #[derive(Default)]
    struct CapturingRegistry {
        created: StdMutex<Vec<RouteObject>>,
        deleted: StdMutex<Vec<RouteObject>>,
    }

    #[async_trait]
    impl RegistryProvider for CapturingRegistry {
        async fn create_route_object(
            &self,
            obj: &RouteObject,
        ) -> lnvps_api_common::retry::OpResult<RegistryRef> {
            self.created.lock().unwrap().push(obj.clone());
            Ok(RegistryRef(obj.primary_key()))
        }
        async fn delete_route_object(
            &self,
            obj: &RouteObject,
        ) -> lnvps_api_common::retry::OpResult<()> {
            self.deleted.lock().unwrap().push(obj.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct CapturingRpki {
        added: StdMutex<Vec<RoaDefinition>>,
        removed: StdMutex<Vec<RoaDefinition>>,
    }

    #[async_trait]
    impl RpkiProvider for CapturingRpki {
        async fn add_roa(&self, roa: &RoaDefinition) -> lnvps_api_common::retry::OpResult<()> {
            self.added.lock().unwrap().push(roa.clone());
            Ok(())
        }
        async fn remove_roa(&self, roa: &RoaDefinition) -> lnvps_api_common::retry::OpResult<()> {
            self.removed.lock().unwrap().push(roa.clone());
            Ok(())
        }
        async fn list_roas(&self) -> lnvps_api_common::retry::OpResult<Vec<RoaDefinition>> {
            Ok(vec![])
        }
    }

    fn sample_space() -> AvailableIpSpace {
        AvailableIpSpace {
            id: 10,
            company_id: 1,
            cidr: "192.0.2.0/24".to_string(),
            min_prefix_size: 28,
            max_prefix_size: 24,
            created: chrono::Utc::now(),
            updated: chrono::Utc::now(),
            registry: lnvps_db::InternetRegistry::RIPE,
            external_id: None,
            is_available: true,
            is_reserved: false,
            metadata: Some(json!({ "maintainer": "LNVPS-MNT" })),
        }
    }

    /// Seed the available IP space + an IP-range line item. The origin ASN is
    /// deliberately NOT part of the (immutable) line-item config — it is set on
    /// the assignment row later via `configure_origin_asn`.
    async fn seed_line_item(db: &MockDb) -> u64 {
        db.insert_available_ip_space(&sample_space()).await.unwrap();
        let cfg = json!({ "available_ip_space_id": 10, "prefix_size": 26 });
        let li = SubscriptionLineItem {
            id: 500,
            subscription_id: 1,
            subscription_type: SubscriptionType::IpRange,
            name: "IP Range".to_string(),
            description: None,
            amount: 1000,
            setup_amount: 0,
            configuration: Some(cfg),
        };
        db.subscription_line_items
            .lock()
            .await
            .insert(li.id, li.clone());
        li.id
    }

    fn payment(sub_id: u64) -> SubscriptionPayment {
        SubscriptionPayment {
            id: vec![1u8; 32],
            subscription_id: sub_id,
            user_id: 1,
            created: chrono::Utc::now(),
            expires: chrono::Utc::now(),
            amount: 1000,
            currency: "EUR".to_string(),
            payment_method: PaymentMethod::Lightning,
            payment_type: SubscriptionPaymentType::Purchase,
            external_data: "{}".to_string().into(),
            external_id: None,
            is_paid: true,
            rate: 1.0,
            time_value: None,
            metadata: None,
            tax: 0,
            processing_fee: 0,
            paid_at: None,
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
        }
    }

    fn provisioner(
        db: Arc<MockDb>,
        reg: Option<Arc<CapturingRegistry>>,
        rpki: Option<Arc<CapturingRpki>>,
    ) -> IpRangeProvisioner {
        IpRangeProvisioner::new(db, Arc::new(ChannelWorkCommander::default())).with_providers(
            reg.map(|r| r as Arc<dyn RegistryProvider>),
            rpki.map(|r| r as Arc<dyn RpkiProvider>),
        )
    }

    #[tokio::test]
    async fn test_allocate_then_configure_fulfils() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let li_id = seed_line_item(&db).await;
        let reg = Arc::new(CapturingRegistry::default());
        let rpki = Arc::new(CapturingRpki::default());
        let prov = provisioner(db.clone(), Some(reg.clone()), Some(rpki.clone()));

        // Payment only allocates the CIDR — no ASN yet, so no registry objects.
        prov.allocate_on_payment(li_id, &payment(1)).await?;
        let subs = db.list_ip_range_subscriptions_by_line_item(li_id).await?;
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].cidr, "192.0.2.0/26");
        assert!(subs[0].is_active);
        assert_eq!(subs[0].origin_asn, None);
        assert!(reg.created.lock().unwrap().is_empty());
        assert!(rpki.added.lock().unwrap().is_empty());

        // Customer configures their origin ASN → registry objects created.
        prov.configure_origin_asn(subs[0].id, Some(3333)).await?;
        let subs = db.list_ip_range_subscriptions_by_line_item(li_id).await?;
        assert_eq!(subs[0].origin_asn, Some(3333));
        assert_eq!(reg.created.lock().unwrap().len(), 1);
        assert_eq!(reg.created.lock().unwrap()[0].origin_asn, 3333);
        assert_eq!(rpki.added.lock().unwrap().len(), 1);
        assert_eq!(rpki.added.lock().unwrap()[0].prefix, net("192.0.2.0/26"));
        let meta = subs[0].metadata.as_ref().unwrap();
        assert_eq!(meta.get("route_object_ref").unwrap(), "192.0.2.0/26AS3333");
        Ok(())
    }

    #[tokio::test]
    async fn test_configure_origin_asn_rehome_replaces_objects() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let li_id = seed_line_item(&db).await;
        let reg = Arc::new(CapturingRegistry::default());
        let rpki = Arc::new(CapturingRpki::default());
        let prov = provisioner(db.clone(), Some(reg.clone()), Some(rpki.clone()));

        prov.allocate_on_payment(li_id, &payment(1)).await?;
        let id = db.list_ip_range_subscriptions_by_line_item(li_id).await?[0].id;

        prov.configure_origin_asn(id, Some(3333)).await?;
        prov.configure_origin_asn(id, Some(64500)).await?;

        assert_eq!(reg.deleted.lock().unwrap().len(), 1);
        assert_eq!(reg.deleted.lock().unwrap()[0].origin_asn, 3333);
        assert_eq!(reg.created.lock().unwrap().len(), 2);
        assert_eq!(reg.created.lock().unwrap()[1].origin_asn, 64500);
        assert_eq!(rpki.removed.lock().unwrap().len(), 1);

        let subs = db.list_ip_range_subscriptions_by_line_item(li_id).await?;
        assert_eq!(subs[0].origin_asn, Some(64500));

        // Setting the same ASN again is a no-op.
        prov.configure_origin_asn(id, Some(64500)).await?;
        assert_eq!(reg.created.lock().unwrap().len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn test_allocate_idempotent_on_renewal() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let li_id = seed_line_item(&db).await;
        let prov = provisioner(db.clone(), None, None);

        prov.allocate_on_payment(li_id, &payment(1)).await?;
        prov.allocate_on_payment(li_id, &payment(1)).await?; // renewal

        let subs = db.list_ip_range_subscriptions_by_line_item(li_id).await?;
        assert_eq!(subs.len(), 1, "renewal must not allocate a second range");
        Ok(())
    }

    #[tokio::test]
    async fn test_deactivate_line_item_tears_down() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let li_id = seed_line_item(&db).await;
        let reg = Arc::new(CapturingRegistry::default());
        let rpki = Arc::new(CapturingRpki::default());
        let prov = provisioner(db.clone(), Some(reg.clone()), Some(rpki.clone()));

        prov.allocate_on_payment(li_id, &payment(1)).await?;
        let id = db.list_ip_range_subscriptions_by_line_item(li_id).await?[0].id;
        prov.configure_origin_asn(id, Some(3333)).await?;

        let li = db.get_subscription_line_item(li_id).await?;
        prov.deactivate_line_item(&li).await?;

        let subs = db.list_ip_range_subscriptions_by_line_item(li_id).await?;
        assert!(!subs[0].is_active);
        assert_eq!(reg.deleted.lock().unwrap().len(), 1);
        assert_eq!(rpki.removed.lock().unwrap().len(), 1);
        Ok(())
    }

    /// Bounded receive so a missing dispatch fails the test instead of
    /// hanging the suite.
    async fn recv_timeout(
        tx: &ChannelWorkCommander,
    ) -> Result<Vec<lnvps_api_common::WorkJobMessage>> {
        tokio::time::timeout(std::time::Duration::from_secs(5), tx.recv())
            .await
            .map_err(|_| anyhow::anyhow!("no work job dispatched within 5s"))?
    }

    /// Regression (suite hang): `allocate_on_payment` must dispatch
    /// `CheckSubscriptions` on **every** outcome — fresh allocation, plain
    /// renewal and fulfilment failure — because the payment is already
    /// committed as paid by the caller. After c97d2f8 only the fresh-allocation
    /// path dispatched, hanging `test_complete_non_vm_renewal_dispatches_check_subscriptions`.
    #[tokio::test]
    async fn test_allocate_on_payment_always_dispatches_check_subscriptions() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let li_id = seed_line_item(&db).await;
        let tx = Arc::new(ChannelWorkCommander::default());
        let prov = IpRangeProvisioner::new(db.clone(), tx.clone());

        // Fresh allocation dispatches.
        prov.allocate_on_payment(li_id, &payment(1)).await?;
        let jobs = recv_timeout(&tx).await?;
        assert!(matches!(jobs[0].job, WorkJob::CheckSubscriptions));

        // Plain renewal (active allocation exists) dispatches.
        prov.allocate_on_payment(li_id, &payment(1)).await?;
        let jobs = recv_timeout(&tx).await?;
        assert!(matches!(jobs[0].job, WorkJob::CheckSubscriptions));

        // Fulfilment failure (no configuration) still dispatches.
        let li2 = SubscriptionLineItem {
            id: 501,
            subscription_id: 1,
            subscription_type: SubscriptionType::IpRange,
            name: "no config".to_string(),
            description: None,
            amount: 1000,
            setup_amount: 0,
            configuration: None,
        };
        db.subscription_line_items
            .lock()
            .await
            .insert(li2.id, li2.clone());
        assert!(prov.allocate_on_payment(li2.id, &payment(1)).await.is_err());
        let jobs = recv_timeout(&tx).await?;
        assert!(matches!(jobs[0].job, WorkJob::CheckSubscriptions));
        Ok(())
    }

    /// An expired line item that renews gets its previous CIDR **reactivated**
    /// (same row, same subnet) and its registry objects re-created — not a new
    /// subnet carved out.
    #[tokio::test]
    async fn test_renewal_reactivates_previous_allocation() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let li_id = seed_line_item(&db).await;
        let reg = Arc::new(CapturingRegistry::default());
        let rpki = Arc::new(CapturingRpki::default());
        let prov = provisioner(db.clone(), Some(reg.clone()), Some(rpki.clone()));

        prov.allocate_on_payment(li_id, &payment(1)).await?;
        let id = db.list_ip_range_subscriptions_by_line_item(li_id).await?[0].id;
        prov.configure_origin_asn(id, Some(3333)).await?;

        // Expire → deactivated, registry objects torn down.
        let li = db.get_subscription_line_item(li_id).await?;
        prov.deactivate_line_item(&li).await?;

        // Renewal payment reactivates the same allocation.
        prov.allocate_on_payment(li_id, &payment(1)).await?;
        let subs = db.list_ip_range_subscriptions_by_line_item(li_id).await?;
        assert_eq!(subs.len(), 1, "must reuse the existing row, not add one");
        assert!(subs[0].is_active);
        assert!(subs[0].ended_at.is_none());
        assert_eq!(subs[0].cidr, "192.0.2.0/26");
        assert_eq!(subs[0].origin_asn, Some(3333));
        // Registry objects re-created for the configured ASN.
        assert_eq!(reg.created.lock().unwrap().len(), 2);
        assert_eq!(rpki.added.lock().unwrap().len(), 2);
        Ok(())
    }

    /// If the previous CIDR was re-allocated to another customer while the
    /// line item was expired, renewal falls back to carving a fresh subnet.
    #[tokio::test]
    async fn test_renewal_allocates_fresh_when_previous_cidr_taken() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let li_id = seed_line_item(&db).await;
        let prov = provisioner(db.clone(), None, None);

        prov.allocate_on_payment(li_id, &payment(1)).await?;
        let li = db.get_subscription_line_item(li_id).await?;
        prov.deactivate_line_item(&li).await?;

        // Another line item takes the freed 192.0.2.0/26.
        let li2 = SubscriptionLineItem {
            id: 501,
            configuration: li.configuration.clone(),
            ..li.clone()
        };
        db.subscription_line_items
            .lock()
            .await
            .insert(li2.id, li2.clone());
        prov.allocate_on_payment(li2.id, &payment(2)).await?;
        assert_eq!(
            db.list_ip_range_subscriptions_by_line_item(li2.id).await?[0].cidr,
            "192.0.2.0/26"
        );

        // Renewing the original line item must NOT steal the CIDR back.
        prov.allocate_on_payment(li_id, &payment(1)).await?;
        let subs = db.list_ip_range_subscriptions_by_line_item(li_id).await?;
        let active: Vec<_> = subs.iter().filter(|s| s.is_active).collect();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].cidr, "192.0.2.64/26");
        Ok(())
    }
}
