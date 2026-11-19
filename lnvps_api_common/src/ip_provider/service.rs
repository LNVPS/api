use crate::ip_provider::{
    IpOrderSpec, IpProvider as IpProviderClient, MockIpProvider, OvhIpProvider,
    ProviderOrderStatus, free_ip4, in_flight_orders, month_start, order_supply, region_rule,
    vm_ip4_needed, waiting_ip4,
};
use crate::retry::OpError;
use crate::{NetworkProvisioner, WorkCommander, WorkJob};
use anyhow::{Result, bail};
use chrono::Utc;
use lnvps_db::{
    IpOrder, IpOrderState, IpProvider, IpProviderKind, IpProviderRegion, IpRange,
    IpRangeAllocationMode, LNVpsDb, Vm, VmIpWait,
};
use log::{error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct IpProviderEntry {
    pub config: IpProvider,
    pub provider: Arc<dyn IpProviderClient>,
}

pub type ProviderBuilder = Arc<dyn Fn(&IpProvider) -> Arc<dyn IpProviderClient> + Send + Sync>;

pub fn default_provider_builder() -> ProviderBuilder {
    Arc::new(|c: &IpProvider| -> Arc<dyn IpProviderClient> {
        match c.kind {
            IpProviderKind::Ovh => Arc::new(OvhIpProvider::new(
                &c.name,
                &c.url,
                c.token.as_str(),
                &c.subsidiary,
                &c.rir.to_lowercase(),
            )),
            IpProviderKind::Mock => Arc::new(MockIpProvider::new(&c.name, 0)),
        }
    })
}

#[derive(Debug, Clone)]
pub struct NewIpOrder {
    pub provider: String,
    pub region_id: u64,
    pub country: Option<String>,
    pub destination: Option<String>,
    pub prefix_len: u16,
    pub quantity: u32,
    pub idempotency_key: Option<String>,
    pub auto: bool,
    pub requested_by: Option<u64>,
}

pub async fn create_ip_order(db: &dyn LNVpsDb, req: NewIpOrder) -> Result<(IpOrder, bool)> {
    if req.quantity == 0 {
        bail!("quantity must be at least 1");
    }
    if req.prefix_len != 32 && req.quantity != 1 {
        bail!("address blocks are ordered one at a time");
    }
    if let Some(key) = &req.idempotency_key {
        if let Some(existing) = db.get_ip_order_by_key(key).await? {
            return Ok((existing, false));
        }
    }
    let (open, _) = db
        .list_ip_orders(None, Some(req.region_id), 1000, 0)
        .await?;
    if let Some(existing) = open.into_iter().find(|o| {
        o.state.is_in_flight()
            && o.provider == req.provider
            && o.country == req.country
            && o.destination == req.destination
            && o.prefix_len == req.prefix_len
            && o.quantity == req.quantity
    }) {
        return Ok((existing, false));
    }
    db.get_host_region(req.region_id).await?;
    let mut order = IpOrder {
        provider: req.provider,
        region_id: req.region_id,
        idempotency_key: req.idempotency_key,
        country: req.country,
        destination: req.destination,
        prefix_len: req.prefix_len,
        quantity: req.quantity,
        state: IpOrderState::AwaitingApproval,
        auto: req.auto,
        requested_by: req.requested_by,
        created: Utc::now(),
        ..Default::default()
    };
    order.id = db.insert_ip_order(&order).await?;
    db.insert_ip_order_audit(order.id, "requested", None, req.requested_by)
        .await?;
    Ok((order, true))
}

pub async fn approve_ip_order(db: &dyn LNVpsDb, id: u64, admin_user_id: u64) -> Result<IpOrder> {
    if !db
        .transition_ip_order(id, IpOrderState::AwaitingApproval, IpOrderState::Approved)
        .await?
    {
        let order = db.get_ip_order(id).await?;
        bail!(
            "order {} is {}, only awaiting_approval orders can be approved",
            id,
            order.state
        );
    }
    let mut order = db.get_ip_order(id).await?;
    order.approved_by = Some(admin_user_id);
    order.approved_at = Some(Utc::now());
    db.update_ip_order(&order).await?;
    db.insert_ip_order_audit(id, "approved", None, Some(admin_user_id))
        .await?;
    Ok(order)
}

pub async fn reject_ip_order(db: &dyn LNVpsDb, id: u64, admin_user_id: u64) -> Result<IpOrder> {
    if !db
        .transition_ip_order(id, IpOrderState::AwaitingApproval, IpOrderState::Rejected)
        .await?
    {
        let order = db.get_ip_order(id).await?;
        bail!(
            "order {} is {}, only awaiting_approval orders can be rejected",
            id,
            order.state
        );
    }
    db.insert_ip_order_audit(id, "rejected", None, Some(admin_user_id))
        .await?;
    Ok(db.get_ip_order(id).await?)
}

pub struct IpOrderService {
    db: Arc<dyn LNVpsDb>,
    commander: Arc<dyn WorkCommander>,
    builder: ProviderBuilder,
    gate: Mutex<()>,
}

impl IpOrderService {
    pub fn new(db: Arc<dyn LNVpsDb>, commander: Arc<dyn WorkCommander>) -> Self {
        Self::with_builder(db, commander, default_provider_builder())
    }

    pub fn with_builder(
        db: Arc<dyn LNVpsDb>,
        commander: Arc<dyn WorkCommander>,
        builder: ProviderBuilder,
    ) -> Self {
        Self {
            db,
            commander,
            builder,
            gate: Mutex::new(()),
        }
    }

    async fn entry(&self, name: &str) -> Result<Option<IpProviderEntry>> {
        Ok(self.db.get_ip_provider_by_name(name).await?.map(|config| {
            let provider = (self.builder)(&config);
            IpProviderEntry { config, provider }
        }))
    }

    async fn notify(&self, title: &str, message: String) {
        if let Err(e) = self
            .commander
            .send(WorkJob::SendAdminNotification {
                message,
                title: Some(title.to_string()),
            })
            .await
        {
            warn!("Failed to queue ip order notification: {}", e);
        }
    }

    async fn audit(&self, order: &IpOrder, event: &str, detail: Option<&str>) {
        if let Err(e) = self
            .db
            .insert_ip_order_audit(order.id, event, detail, None)
            .await
        {
            error!("Failed to write ip order audit for {}: {}", order.id, e);
        }
    }

    async fn fail(&self, order: &mut IpOrder, reason: &str) -> Result<()> {
        order.state = IpOrderState::Failed;
        order.error = Some(reason.to_string());
        self.db.update_ip_order(order).await?;
        self.audit(order, "failed", Some(reason)).await;
        self.notify(
            "IP order failed",
            format!(
                "IP order #{} ({} /{} x{}) failed: {}",
                order.id, order.provider, order.prefix_len, order.quantity, reason
            ),
        )
        .await;
        Ok(())
    }

    fn spec(order: &IpOrder) -> IpOrderSpec {
        IpOrderSpec {
            country: order.country.clone(),
            destination: order.destination.clone(),
            prefix_len: order.prefix_len,
            quantity: order.quantity,
        }
    }

    pub async fn process_order(&self, id: u64) -> Result<()> {
        let _gate = self.gate.lock().await;
        let mut order = self.db.get_ip_order(id).await?;
        match order.state {
            IpOrderState::AwaitingApproval => self.review(&mut order).await,
            IpOrderState::Approved => self.place(&mut order).await,
            IpOrderState::Ordering => {
                if order.provider_order_id.is_none() {
                    warn!("IP order {} is ordering with no provider id", order.id);
                }
                Ok(())
            }
            IpOrderState::Ordered => self.poll(&mut order).await,
            _ => Ok(()),
        }
    }

    async fn review(&self, order: &mut IpOrder) -> Result<()> {
        let Some(entry) = self.entry(&order.provider).await? else {
            return self
                .fail(order, &format!("unknown ip provider '{}'", order.provider))
                .await;
        };
        if !entry.config.enabled {
            return self
                .fail(
                    order,
                    &format!("ip provider '{}' is disabled", order.provider),
                )
                .await;
        }
        let estimate = match entry.provider.quote(&Self::spec(order)).await {
            Ok(q) => Some(q),
            Err(e) => {
                warn!("Quote for ip order {} failed: {}", order.id, e);
                None
            }
        };
        if let Some(q) = &estimate {
            order.cost = q.cost;
            order.currency = q.currency.clone();
            self.db.update_ip_order(order).await?;
        }
        if entry.config.approval_required {
            let cost = estimate
                .map(|q| format!("{} {}", q.cost, q.currency))
                .unwrap_or_else(|| "unknown".to_string());
            self.audit(order, "awaiting_approval", Some(&cost)).await;
            self.notify(
                "IP order needs approval",
                format!(
                    "IP order #{} ({} /{} x{} in region {}) is waiting for approval. Estimated cost {}.",
                    order.id, order.provider, order.prefix_len, order.quantity, order.region_id, cost
                ),
            )
            .await;
            return Ok(());
        }
        if self
            .db
            .transition_ip_order(
                order.id,
                IpOrderState::AwaitingApproval,
                IpOrderState::Approved,
            )
            .await?
        {
            order.state = IpOrderState::Approved;
            self.audit(order, "auto_approved", None).await;
            return self.place(order).await;
        }
        Ok(())
    }

    async fn place(&self, order: &mut IpOrder) -> Result<()> {
        let Some(entry) = self.entry(&order.provider).await? else {
            return self
                .fail(order, &format!("unknown ip provider '{}'", order.provider))
                .await;
        };
        let cfg = &entry.config;
        if !cfg.enabled {
            return self
                .fail(
                    order,
                    &format!("ip provider '{}' is disabled", order.provider),
                )
                .await;
        }
        if cfg.gateway.is_empty() {
            return self
                .fail(
                    order,
                    "no gateway configured for the provider, cannot register the range",
                )
                .await;
        }
        let quote = match entry.provider.quote(&Self::spec(order)).await {
            Ok(q) => q,
            Err(OpError::Transient(e)) => {
                warn!("Quote for ip order {} failed, will retry: {}", order.id, e);
                return Ok(());
            }
            Err(OpError::Fatal(e)) => return self.fail(order, &format!("quote failed: {e}")).await,
        };
        if quote.currency != cfg.currency {
            return self
                .fail(
                    order,
                    &format!(
                        "quoted in {} but the spend cap is in {}",
                        quote.currency, cfg.currency
                    ),
                )
                .await;
        }
        let spent = self
            .db
            .sum_ip_order_cost_since(month_start(Utc::now()), &cfg.currency)
            .await?;
        if spent.saturating_add(quote.cost) > cfg.monthly_spend_cap {
            return self
                .fail(
                    order,
                    &format!(
                        "monthly spend cap exceeded: {} spent + {} quoted > cap {} {}",
                        spent, quote.cost, cfg.monthly_spend_cap, cfg.currency
                    ),
                )
                .await;
        }
        order.cost = quote.cost;
        order.currency = quote.currency.clone();
        self.db.update_ip_order(order).await?;
        if !self
            .db
            .transition_ip_order(order.id, IpOrderState::Approved, IpOrderState::Ordering)
            .await?
        {
            return Ok(());
        }
        order.state = IpOrderState::Ordering;
        self.audit(
            order,
            "ordering",
            Some(&format!("{} {}", quote.cost, quote.currency)),
        )
        .await;
        let max_cost = cfg.monthly_spend_cap - spent;
        match entry.provider.order(&Self::spec(order), max_cost).await {
            Ok(placed) => {
                order.provider_order_id = Some(placed.provider_order_id.clone());
                order.cost = placed.cost;
                order.currency = placed.currency.clone();
                order.ordered_at = Some(Utc::now());
                order.state = IpOrderState::Ordered;
                self.db.update_ip_order(order).await?;
                self.audit(order, "ordered", Some(&placed.provider_order_id))
                    .await;
                self.notify(
                    "IP order placed",
                    format!(
                        "IP order #{} placed with {} (order {}), cost {} {}.",
                        order.id,
                        order.provider,
                        placed.provider_order_id,
                        placed.cost,
                        placed.currency
                    ),
                )
                .await;
                Ok(())
            }
            Err(OpError::Transient(e)) => {
                warn!(
                    "Ordering for ip order {} failed before purchase, will retry: {}",
                    order.id, e
                );
                self.db
                    .transition_ip_order(order.id, IpOrderState::Ordering, IpOrderState::Approved)
                    .await?;
                Ok(())
            }
            Err(OpError::Fatal(e)) => {
                self.fail(
                    order,
                    &format!("{e}. Verify with the provider that no order was placed."),
                )
                .await
            }
        }
    }

    async fn poll(&self, order: &mut IpOrder) -> Result<()> {
        let Some(entry) = self.entry(&order.provider).await? else {
            return Ok(());
        };
        let Some(provider_order_id) = order.provider_order_id.clone() else {
            return Ok(());
        };
        let status = match entry.provider.order_status(&provider_order_id).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Polling ip order {} failed: {}", order.id, e);
                return Ok(());
            }
        };
        match status {
            ProviderOrderStatus::Pending => Ok(()),
            ProviderOrderStatus::Failed(reason) => self.fail(order, &reason).await,
            ProviderOrderStatus::Delivered(ips) => {
                if ips.is_empty() {
                    order.error = Some("delivered but no addresses were found yet".to_string());
                    self.db.update_ip_order(order).await?;
                    return Ok(());
                }
                let mut registered = vec![];
                for ip in &ips {
                    let range = self.register_range(order, &entry, &ip.cidr).await?;
                    registered.push(range.cidr);
                }
                order.state = IpOrderState::Delivered;
                order.delivered_at = Some(Utc::now());
                order.error = None;
                self.db.update_ip_order(order).await?;
                self.audit(order, "delivered", Some(&registered.join(",")))
                    .await;
                self.notify(
                    "IP order delivered",
                    format!(
                        "IP order #{} delivered: {} registered in region {}.",
                        order.id,
                        registered.join(", "),
                        order.region_id
                    ),
                )
                .await;
                Ok(())
            }
        }
    }

    async fn register_range(
        &self,
        order: &IpOrder,
        entry: &IpProviderEntry,
        cidr: &str,
    ) -> Result<IpRange> {
        let range = match self.db.get_ip_range_by_cidr(cidr).await? {
            Some(r) => r,
            None => {
                let mut r = IpRange {
                    cidr: cidr.to_string(),
                    gateway: entry.config.gateway.clone(),
                    enabled: entry.config.enable_ranges_on_delivery,
                    region_id: order.region_id,
                    access_policy_id: entry.config.access_policy_id,
                    allocation_mode: IpRangeAllocationMode::Sequential,
                    use_full_range: cidr.ends_with("/32"),
                    ..Default::default()
                };
                r.id = self.db.insert_ip_range(&r).await?;
                r
            }
        };
        let linked = self
            .db
            .list_ip_order_ranges_for_order(order.id)
            .await?
            .into_iter()
            .any(|l| l.ip_range_id == range.id);
        if !linked {
            self.db
                .insert_ip_order_range(order.id, range.id, cidr)
                .await?;
        }
        Ok(range)
    }

    pub async fn release_range(&self, ip_range_id: u64, actor: Option<u64>) -> Result<()> {
        let _gate = self.gate.lock().await;
        let link = self
            .db
            .get_ip_order_range_by_range(ip_range_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("range {ip_range_id} was not bought from a provider"))?;
        if link.released_at.is_some() {
            return Ok(());
        }
        let order = self.db.get_ip_order(link.ip_order_id).await?;
        let Some(entry) = self.entry(&order.provider).await? else {
            bail!("unknown ip provider '{}'", order.provider);
        };
        if !entry.config.enabled {
            bail!("ip provider '{}' is disabled", order.provider);
        }
        let range = self.db.get_ip_range(ip_range_id).await?;
        let allocated = self.db.list_vm_ip_assignments_in_range(ip_range_id).await?;
        if !allocated.is_empty() {
            bail!(
                "range {} has {} allocated IP(s), refusing to release it",
                range.cidr,
                allocated.len()
            );
        }
        self.db.set_ip_range_enabled(ip_range_id, false).await?;
        let allocated = self.db.list_vm_ip_assignments_in_range(ip_range_id).await?;
        if !allocated.is_empty() {
            self.db
                .set_ip_range_enabled(ip_range_id, range.enabled)
                .await?;
            bail!(
                "range {} gained {} allocated IP(s) while releasing, refusing",
                range.cidr,
                allocated.len()
            );
        }
        if let Err(e) = entry.provider.release(&link.cidr).await {
            self.db
                .set_ip_range_enabled(ip_range_id, range.enabled)
                .await?;
            self.db
                .insert_ip_order_audit(order.id, "release_failed", Some(&e.to_string()), actor)
                .await?;
            bail!("provider refused to release {}: {}", link.cidr, e);
        }
        self.db.mark_ip_order_range_released(link.id).await?;
        self.db
            .insert_ip_order_audit(order.id, "released", Some(&link.cidr), actor)
            .await?;
        info!("Released {} ({})", link.cidr, order.provider);
        self.notify(
            "IP range released",
            format!("Released {} back to {}.", link.cidr, order.provider),
        )
        .await;
        Ok(())
    }

    pub async fn free_addresses(&self, region_id: u64) -> Result<u64> {
        free_ip4(self.db.as_ref(), region_id).await
    }

    pub async fn sweep(&self) -> Result<()> {
        for state in [IpOrderState::Approved, IpOrderState::Ordered] {
            let (orders, _) = self.db.list_ip_orders(Some(state), None, 1000, 0).await?;
            for o in orders {
                if let Err(e) = self.process_order(o.id).await {
                    error!("Failed to process ip order {}: {}", o.id, e);
                }
            }
        }
        self.serve_waiting_vms().await?;
        self.top_up().await
    }

    pub async fn top_up(&self) -> Result<()> {
        let day = Utc::now().format("%Y-%m-%d");
        for config in self.db.list_ip_providers().await? {
            if !config.enabled {
                continue;
            }
            let rules = self
                .db
                .list_ip_provider_regions(Some(config.id), None)
                .await?;
            for region in rules.into_iter().filter(|r| r.enabled) {
                let Some(threshold) = region.auto_threshold else {
                    continue;
                };
                if self.free_addresses(region.region_id).await? >= threshold {
                    continue;
                }
                let (order, created) = create_ip_order(
                    self.db.as_ref(),
                    NewIpOrder {
                        provider: config.name.clone(),
                        region_id: region.region_id,
                        country: region.country.clone(),
                        destination: region.destination.clone(),
                        prefix_len: region.prefix_len,
                        quantity: region.quantity,
                        idempotency_key: Some(format!(
                            "auto:{}:{}:{}",
                            config.name, region.region_id, day
                        )),
                        auto: true,
                        requested_by: None,
                    },
                )
                .await?;
                if created {
                    self.audit(
                        &order,
                        "auto_top_up",
                        Some(&format!("below {threshold} free")),
                    )
                    .await;
                    self.process_order(order.id).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn gate_vm(&self, vm: &Vm) -> Result<bool> {
        let ip4 = vm_ip4_needed(self.db.as_ref(), vm).await?;
        if ip4 == 0 {
            return Ok(true);
        }
        if !self.db.list_vm_ip_assignments(vm.id).await?.is_empty() {
            return Ok(true);
        }
        let existing = self.db.get_vm_ip_wait(vm.id).await?;
        if existing.as_ref().is_some_and(|w| w.released) {
            return Ok(true);
        }
        let region_id = self.db.get_host(vm.host_id).await?.region_id;
        let waits = self.db.list_vm_ip_waits(Some(region_id)).await?;
        let older = waiting_ip4(&waits, existing.as_ref());
        let free = free_ip4(self.db.as_ref(), region_id).await?;
        if free >= older + ip4 as u64 {
            if existing.is_some() {
                self.db.delete_vm_ip_wait(vm.id).await?;
            }
            return Ok(true);
        }
        if existing.is_none() {
            self.db
                .insert_vm_ip_wait(&VmIpWait {
                    id: 0,
                    vm_id: vm.id,
                    region_id,
                    ip4_needed: ip4,
                    ip_order_id: None,
                    released: false,
                    created: Utc::now(),
                })
                .await?;
            self.notify(
                "VM waiting for an IP",
                format!(
                    "VM #{} (user {}) is waiting for an IP address in region {}.",
                    vm.id, vm.user_id, region_id
                ),
            )
            .await;
            self.tell_user(
                vm.user_id,
                format!("[VM{}] Waiting for an IP address", vm.id),
                format!(
                    "Your VM #{} is paid and queued. This region is out of IP addresses, so we are \
                     ordering more. Delivery may take longer than usual, and you will be told when \
                     your VM is ready.",
                    vm.id
                ),
            )
            .await;
        }
        self.ensure_region_capacity(region_id).await?;
        Ok(false)
    }

    async fn tell_user(&self, user_id: u64, title: String, message: String) {
        if let Err(e) = self
            .commander
            .send(WorkJob::SendNotification {
                user_id,
                message,
                title: Some(title),
            })
            .await
        {
            warn!("Failed to queue notification for user {}: {}", user_id, e);
        }
    }

    pub async fn ensure_region_capacity(&self, region_id: u64) -> Result<Option<IpOrder>> {
        let created = {
            let _gate = self.gate.lock().await;
            self.create_demand_order(region_id).await?
        };
        if let Some(o) = &created {
            self.process_order(o.id).await?;
        }
        Ok(created)
    }

    async fn create_demand_order(&self, region_id: u64) -> Result<Option<IpOrder>> {
        let waits = self.db.list_vm_ip_waits(Some(region_id)).await?;
        let pending: Vec<&VmIpWait> = waits.iter().filter(|w| !w.released).collect();
        if pending.is_empty() {
            return Ok(None);
        }
        let Some((provider, rule)) = region_rule(self.db.as_ref(), region_id).await? else {
            return Ok(None);
        };
        let oldest = pending
            .iter()
            .map(|w| w.created)
            .min()
            .unwrap_or_else(Utc::now);
        let (history, _) = self
            .db
            .list_ip_orders(None, Some(region_id), 1000, 0)
            .await?;
        if history.iter().any(|o| {
            o.provider == provider.name
                && o.created >= oldest
                && matches!(o.state, IpOrderState::Failed | IpOrderState::Rejected)
        }) {
            return Ok(None);
        }
        let free = free_ip4(self.db.as_ref(), region_id).await?;
        let demand: u64 = pending.iter().map(|w| w.ip4_needed as u64).sum();
        let in_flight = in_flight_orders(self.db.as_ref(), region_id, &provider.name).await?;
        let supply: u64 = in_flight.iter().map(order_supply).sum();
        if free + supply >= demand {
            self.link_waits(&pending, in_flight.first()).await?;
            return Ok(None);
        }
        let shortfall = demand - free - supply;
        if let Some(open) = in_flight
            .iter()
            .find(|o| o.state == IpOrderState::AwaitingApproval)
        {
            if rule.prefix_len == 32 {
                let wanted = (open.quantity as u64 + shortfall).min(u32::MAX as u64) as u32;
                if self.db.grow_ip_order_quantity(open.id, wanted).await? {
                    self.audit(open, "grown", Some(&format!("quantity now {wanted}")))
                        .await;
                }
            }
            self.link_waits(&pending, Some(open)).await?;
            return Ok(None);
        }
        if !in_flight.is_empty() {
            self.link_waits(&pending, in_flight.first()).await?;
            return Ok(None);
        }
        let quantity = if rule.prefix_len == 32 {
            shortfall.max(rule.quantity as u64).min(u32::MAX as u64) as u32
        } else {
            1
        };
        let (order, created) = create_ip_order(
            self.db.as_ref(),
            NewIpOrder {
                provider: provider.name.clone(),
                region_id,
                country: rule.country.clone(),
                destination: rule.destination.clone(),
                prefix_len: rule.prefix_len,
                quantity,
                idempotency_key: Some(format!(
                    "demand:{}:{}:{}",
                    provider.name,
                    region_id,
                    Utc::now().format("%Y-%m-%d-%H")
                )),
                auto: true,
                requested_by: None,
            },
        )
        .await?;
        if !created {
            return Ok(None);
        }
        self.audit(
            &order,
            "demand",
            Some(&format!("{} VM(s) waiting for an IP", pending.len())),
        )
        .await;
        self.link_waits(&pending, Some(&order)).await?;
        Ok(Some(order))
    }

    async fn link_waits(&self, waits: &[&VmIpWait], order: Option<&IpOrder>) -> Result<()> {
        let Some(order) = order else {
            return Ok(());
        };
        for w in waits.iter().filter(|w| w.ip_order_id != Some(order.id)) {
            self.db
                .set_vm_ip_wait_order(w.vm_id, Some(order.id))
                .await?;
        }
        Ok(())
    }

    pub async fn serve_waiting_vms(&self) -> Result<()> {
        let all = self.db.list_vm_ip_waits(None).await?;
        let mut regions: Vec<u64> = all.iter().map(|w| w.region_id).collect();
        regions.sort();
        regions.dedup();
        for region_id in regions {
            let waits = self.db.list_vm_ip_waits(Some(region_id)).await?;
            let mut free = free_ip4(self.db.as_ref(), region_id).await?;
            for w in waits.iter().filter(|w| !w.released) {
                if free < w.ip4_needed as u64 {
                    break;
                }
                free -= w.ip4_needed as u64;
                self.db.set_vm_ip_wait_released(w.vm_id, true).await?;
                self.commander
                    .send(WorkJob::SpawnVm { vm_id: w.vm_id })
                    .await?;
                if let Ok(vm) = self.db.get_vm(w.vm_id).await {
                    self.tell_user(
                        vm.user_id,
                        format!("[VM{}] IP address ready", vm.id),
                        format!(
                            "An IP address is now available and your VM #{} is being provisioned.",
                            vm.id
                        ),
                    )
                    .await;
                }
            }
            if let Err(e) = self.ensure_region_capacity(region_id).await {
                error!("Failed to order capacity for region {}: {}", region_id, e);
            }
            self.refund_stale_waits(region_id).await?;
        }
        Ok(())
    }

    async fn refund_stale_waits(&self, region_id: u64) -> Result<()> {
        let rules = self
            .db
            .list_ip_provider_regions(None, Some(region_id))
            .await?;
        let hours = rules
            .iter()
            .map(|r| r.wait_refund_hours)
            .filter(|h| *h > 0)
            .min();
        let Some(hours) = hours else {
            return Ok(());
        };
        let cutoff = Utc::now() - chrono::Duration::hours(hours as i64);
        let (orders, _) = self
            .db
            .list_ip_orders(None, Some(region_id), 1000, 0)
            .await?;
        if orders.iter().any(|o| o.state.is_in_flight()) {
            return Ok(());
        }
        for w in self.db.list_vm_ip_waits(Some(region_id)).await? {
            if w.released || w.created > cutoff {
                continue;
            }
            self.commander
                .send(WorkJob::DeleteVm {
                    vm_id: w.vm_id,
                    reason: Some(format!(
                        "No IP address could be supplied within {hours} hours; refunded"
                    )),
                    admin_user_id: None,
                    purge: false,
                    by_owner: true,
                })
                .await?;
            self.db.delete_vm_ip_wait(w.vm_id).await?;
            self.notify(
                "Waiting VM refunded",
                format!(
                    "VM #{} waited more than {hours}h for an IP in region {region_id} with no order in flight, and was deleted and refunded to credit.",
                    w.vm_id
                ),
            )
            .await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_provider::OwnedIp;
    use crate::{ChannelWorkCommander, MockDb};
    use lnvps_db::{LNVpsDbBase, VmIpAssignment};

    fn config(approval_required: bool, cap: u64) -> IpProvider {
        IpProvider {
            id: 0,
            name: "mock".to_string(),
            kind: IpProviderKind::Mock,
            enabled: true,
            url: String::new(),
            token: "".into(),
            subsidiary: "IE".to_string(),
            rir: "ripe".to_string(),
            gateway: "203.0.113.254".to_string(),
            access_policy_id: None,
            approval_required,
            monthly_spend_cap: cap,
            currency: "EUR".to_string(),
            enable_ranges_on_delivery: true,
        }
    }

    fn rule(threshold: u64, country: Option<&str>) -> IpProviderRegion {
        IpProviderRegion {
            id: 0,
            provider_id: 1,
            region_id: 1,
            country: country.map(|c| c.to_string()),
            destination: None,
            prefix_len: 32,
            quantity: 1,
            auto_threshold: Some(threshold),
            enabled: true,
            ..Default::default()
        }
    }

    struct Fixture {
        db: Arc<MockDb>,
        mock: MockIpProvider,
        service: IpOrderService,
    }

    async fn fixture_with(cfg: IpProvider) -> Fixture {
        fixture_with_rules(cfg, vec![]).await
    }

    async fn fixture_with_rules(cfg: IpProvider, rules: Vec<IpProviderRegion>) -> Fixture {
        let db = Arc::new(MockDb::default());
        db.insert_ip_provider(&cfg).await.unwrap();
        for r in rules {
            db.insert_ip_provider_region(&r).await.unwrap();
        }
        let mock = MockIpProvider::new("mock", 200);
        let shared = mock.clone();
        let service = IpOrderService::with_builder(
            db.clone(),
            Arc::new(ChannelWorkCommander::new()),
            Arc::new(move |_| Arc::new(shared.clone())),
        );
        Fixture { db, mock, service }
    }

    fn request(key: Option<&str>) -> NewIpOrder {
        NewIpOrder {
            provider: "mock".to_string(),
            region_id: 1,
            country: Some("IE".to_string()),
            destination: None,
            prefix_len: 32,
            quantity: 1,
            idempotency_key: key.map(|k| k.to_string()),
            auto: false,
            requested_by: Some(1),
        }
    }

    async fn deliver(f: &Fixture, cidr: &str) {
        *f.mock.status.lock().await = ProviderOrderStatus::Delivered(vec![OwnedIp {
            cidr: cidr.to_string(),
            country: Some("IE".to_string()),
            routed_to: None,
        }]);
    }

    #[tokio::test]
    async fn order_requires_approval_before_any_money_moves() {
        let f = fixture_with(config(true, 10_000)).await;
        let (order, created) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        assert!(created);
        f.service.process_order(order.id).await.unwrap();
        f.service.process_order(order.id).await.unwrap();
        let o = f.db.get_ip_order(order.id).await.unwrap();
        assert_eq!(o.state, IpOrderState::AwaitingApproval);
        assert_eq!(f.mock.orders_placed(), 0);
        assert_eq!(o.cost, 200);
    }

    #[tokio::test]
    async fn approved_order_is_placed_once() {
        let f = fixture_with(config(true, 10_000)).await;
        let (order, _) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        f.service.process_order(order.id).await.unwrap();
        approve_ip_order(f.db.as_ref(), order.id, 7).await.unwrap();
        f.service.process_order(order.id).await.unwrap();
        f.service.process_order(order.id).await.unwrap();
        let o = f.db.get_ip_order(order.id).await.unwrap();
        assert_eq!(o.state, IpOrderState::Ordered);
        assert_eq!(o.approved_by, Some(7));
        assert_eq!(o.provider_order_id.as_deref(), Some("mock-1"));
        assert_eq!(f.mock.orders_placed(), 1);
    }

    #[tokio::test]
    async fn rejected_order_is_never_placed() {
        let f = fixture_with(config(true, 10_000)).await;
        let (order, _) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        reject_ip_order(f.db.as_ref(), order.id, 7).await.unwrap();
        assert!(approve_ip_order(f.db.as_ref(), order.id, 7).await.is_err());
        f.service.process_order(order.id).await.unwrap();
        assert_eq!(f.mock.orders_placed(), 0);
    }

    #[tokio::test]
    async fn approval_cannot_be_given_twice() {
        let f = fixture_with(config(true, 10_000)).await;
        let (order, _) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        approve_ip_order(f.db.as_ref(), order.id, 7).await.unwrap();
        assert!(approve_ip_order(f.db.as_ref(), order.id, 8).await.is_err());
    }

    #[tokio::test]
    async fn delivery_polling_registers_the_range() {
        let f = fixture_with(config(false, 10_000)).await;
        let (order, _) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        f.service.process_order(order.id).await.unwrap();
        assert_eq!(
            f.db.get_ip_order(order.id).await.unwrap().state,
            IpOrderState::Ordered
        );
        f.service.process_order(order.id).await.unwrap();
        assert_eq!(
            f.db.get_ip_order(order.id).await.unwrap().state,
            IpOrderState::Ordered
        );
        deliver(&f, "203.0.113.5/32").await;
        f.service.process_order(order.id).await.unwrap();
        f.service.process_order(order.id).await.unwrap();
        let o = f.db.get_ip_order(order.id).await.unwrap();
        assert_eq!(o.state, IpOrderState::Delivered);
        assert!(o.delivered_at.is_some());
        let range =
            f.db.get_ip_range_by_cidr("203.0.113.5/32")
                .await
                .unwrap()
                .unwrap();
        assert_eq!(range.region_id, 1);
        assert_eq!(range.gateway, "203.0.113.254");
        assert!(range.enabled);
        let links = f.db.list_ip_order_ranges_for_order(order.id).await.unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].ip_range_id, range.id);
        let events: Vec<String> =
            f.db.list_ip_order_audit(order.id)
                .await
                .unwrap()
                .into_iter()
                .map(|a| a.event)
                .collect();
        for e in [
            "requested",
            "auto_approved",
            "ordering",
            "ordered",
            "delivered",
        ] {
            assert!(events.contains(&e.to_string()), "missing {e} in {events:?}");
        }
    }

    #[tokio::test]
    async fn provider_cancelled_order_fails() {
        let f = fixture_with(config(false, 10_000)).await;
        let (order, _) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        f.service.process_order(order.id).await.unwrap();
        *f.mock.status.lock().await = ProviderOrderStatus::Failed("cancelled".to_string());
        f.service.process_order(order.id).await.unwrap();
        let o = f.db.get_ip_order(order.id).await.unwrap();
        assert_eq!(o.state, IpOrderState::Failed);
        assert_eq!(o.error.as_deref(), Some("cancelled"));
    }

    #[tokio::test]
    async fn retried_request_does_not_double_buy() {
        let f = fixture_with(config(false, 10_000)).await;
        let (a, created_a) = create_ip_order(f.db.as_ref(), request(Some("k1")))
            .await
            .unwrap();
        let (b, created_b) = create_ip_order(f.db.as_ref(), request(Some("k1")))
            .await
            .unwrap();
        assert!(created_a);
        assert!(!created_b);
        assert_eq!(a.id, b.id);
        f.service.process_order(a.id).await.unwrap();
        f.service.process_order(b.id).await.unwrap();
        assert_eq!(f.mock.orders_placed(), 1);
    }

    #[tokio::test]
    async fn identical_in_flight_request_is_reused_without_a_key() {
        let f = fixture_with(config(false, 10_000)).await;
        let (a, _) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        let (b, created) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        assert!(!created);
        assert_eq!(a.id, b.id);
    }

    #[tokio::test]
    async fn finished_order_does_not_block_a_new_request() {
        let f = fixture_with(config(false, 10_000)).await;
        let (a, _) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        f.service.process_order(a.id).await.unwrap();
        deliver(&f, "203.0.113.5/32").await;
        f.service.process_order(a.id).await.unwrap();
        let (b, created) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        assert!(created);
        assert_ne!(a.id, b.id);
    }

    #[tokio::test]
    async fn spend_cap_refuses_the_order() {
        let f = fixture_with(config(false, 300)).await;
        let (a, _) = create_ip_order(f.db.as_ref(), request(Some("a")))
            .await
            .unwrap();
        f.service.process_order(a.id).await.unwrap();
        assert_eq!(f.mock.orders_placed(), 1);
        let mut second = request(Some("b"));
        second.country = Some("FR".to_string());
        let (b, _) = create_ip_order(f.db.as_ref(), second).await.unwrap();
        f.service.process_order(b.id).await.unwrap();
        let o = f.db.get_ip_order(b.id).await.unwrap();
        assert_eq!(o.state, IpOrderState::Failed);
        assert!(o.error.unwrap().contains("spend cap"));
        assert_eq!(f.mock.orders_placed(), 1);
    }

    #[tokio::test]
    async fn disabled_provider_never_orders() {
        let mut cfg = config(false, 10_000);
        cfg.enabled = false;
        let f = fixture_with(cfg).await;
        let (order, _) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        f.service.process_order(order.id).await.unwrap();
        assert_eq!(
            f.db.get_ip_order(order.id).await.unwrap().state,
            IpOrderState::Failed
        );
        assert_eq!(f.mock.orders_placed(), 0);
    }

    #[tokio::test]
    async fn provider_failure_marks_order_failed() {
        let f = fixture_with(config(false, 10_000)).await;
        *f.mock.fail_order.lock().await = Some("boom".to_string());
        let (order, _) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        f.service.process_order(order.id).await.unwrap();
        let o = f.db.get_ip_order(order.id).await.unwrap();
        assert_eq!(o.state, IpOrderState::Failed);
        assert!(o.error.unwrap().contains("boom"));
    }

    async fn delivered_range(f: &Fixture) -> u64 {
        let (order, _) = create_ip_order(f.db.as_ref(), request(None)).await.unwrap();
        f.service.process_order(order.id).await.unwrap();
        deliver(f, "203.0.113.5/32").await;
        f.service.process_order(order.id).await.unwrap();
        f.db.get_ip_range_by_cidr("203.0.113.5/32")
            .await
            .unwrap()
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn release_terminates_an_unused_range() {
        let f = fixture_with(config(false, 10_000)).await;
        let range_id = delivered_range(&f).await;
        f.service.release_range(range_id, Some(1)).await.unwrap();
        assert_eq!(*f.mock.release_calls.lock().await, vec!["203.0.113.5/32"]);
        assert!(!f.db.get_ip_range(range_id).await.unwrap().enabled);
        f.service.release_range(range_id, Some(1)).await.unwrap();
        assert_eq!(f.mock.release_calls.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn release_is_refused_while_ips_are_allocated() {
        let f = fixture_with(config(false, 10_000)).await;
        let range_id = delivered_range(&f).await;
        f.db.ip_assignments.lock().await.insert(
            1,
            VmIpAssignment {
                id: 1,
                vm_id: 1,
                ip_range_id: range_id,
                ip: "203.0.113.5".to_string(),
                ..Default::default()
            },
        );
        let err = f
            .service
            .release_range(range_id, Some(1))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("allocated"));
        assert!(f.mock.release_calls.lock().await.is_empty());
        assert!(f.db.get_ip_range(range_id).await.unwrap().enabled);
    }

    #[tokio::test]
    async fn release_is_refused_for_ranges_not_bought() {
        let f = fixture_with(config(false, 10_000)).await;
        assert!(f.service.release_range(1, None).await.is_err());
        assert!(f.mock.release_calls.lock().await.is_empty());
    }

    #[tokio::test]
    async fn top_up_orders_once_per_day_when_below_threshold() {
        let f = fixture_with_rules(config(false, 10_000), vec![rule(1_000_000, Some("IE"))]).await;
        f.service.top_up().await.unwrap();
        f.service.top_up().await.unwrap();
        assert_eq!(f.mock.orders_placed(), 1);
        let (orders, _) = f.db.list_ip_orders(None, None, 10, 0).await.unwrap();
        assert_eq!(orders.len(), 1);
        assert!(orders[0].auto);
    }

    #[tokio::test]
    async fn top_up_orders_the_rule_quantity() {
        let mut r = rule(1_000_000, None);
        r.quantity = 3;
        let f = fixture_with_rules(config(true, 10_000), vec![r]).await;
        f.service.top_up().await.unwrap();
        let (orders, _) = f.db.list_ip_orders(None, None, 10, 0).await.unwrap();
        assert_eq!(orders[0].quantity, 3);
    }

    #[tokio::test]
    async fn top_up_waits_for_approval_by_default() {
        let f = fixture_with_rules(config(true, 10_000), vec![rule(1_000_000, None)]).await;
        f.service.top_up().await.unwrap();
        assert_eq!(f.mock.orders_placed(), 0);
        let (orders, _) = f.db.list_ip_orders(None, None, 10, 0).await.unwrap();
        assert_eq!(orders[0].state, IpOrderState::AwaitingApproval);
    }

    #[tokio::test]
    async fn top_up_skips_regions_with_enough_free_addresses() {
        let f = fixture_with_rules(config(false, 10_000), vec![rule(1, None)]).await;
        f.service.top_up().await.unwrap();
        assert_eq!(f.mock.orders_placed(), 0);
    }

    #[tokio::test]
    async fn top_up_does_nothing_for_a_disabled_provider() {
        let mut cfg = config(false, 10_000);
        cfg.enabled = false;
        let f = fixture_with_rules(cfg, vec![rule(1_000_000, None)]).await;
        f.service.top_up().await.unwrap();
        let (orders, _) = f.db.list_ip_orders(None, None, 10, 0).await.unwrap();
        assert!(orders.is_empty());
        assert_eq!(f.mock.orders_placed(), 0);
    }

    #[tokio::test]
    async fn top_up_does_nothing_for_a_disabled_rule() {
        let mut r = rule(1_000_000, None);
        r.enabled = false;
        let f = fixture_with_rules(config(false, 10_000), vec![r]).await;
        f.service.top_up().await.unwrap();
        assert_eq!(f.mock.orders_placed(), 0);
    }

    #[tokio::test]
    async fn config_changes_apply_on_the_next_tick_without_a_restart() {
        let f = fixture_with_rules(config(false, 10_000), vec![rule(1_000_000, None)]).await;
        let mut p = f.db.get_ip_provider(1).await.unwrap();
        p.enabled = false;
        f.db.update_ip_provider(&p).await.unwrap();
        f.service.top_up().await.unwrap();
        assert_eq!(f.mock.orders_placed(), 0);
        p.enabled = true;
        f.db.update_ip_provider(&p).await.unwrap();
        f.service.top_up().await.unwrap();
        assert_eq!(f.mock.orders_placed(), 1);
    }
}
