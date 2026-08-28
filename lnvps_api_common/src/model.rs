use crate::VmRunningState;
use crate::pricing::PricingEngine;
use crate::ssh_host_key::{ApiVmHostKey, parse_ssh_host_keys};
use crate::traffic::quota_period;
use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Days, NaiveDate, Utc};
use futures::future::join_all;
use ipnetwork::IpNetwork;
use lnvps_db::{
    CpuArch, CpuFeature, CpuMfg, IpRange, LNVpsDb, LNVpsDbBase, LineItemType, Region, Subscription,
    SubscriptionLineItem, Vm, VmCostPlan, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate,
    VmHost, VmTemplate,
};
use payments_rs::currency::{Currency, CurrencyAmount};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

pub trait Template {
    fn cpu(&self) -> u16;
    fn memory(&self) -> u64;
    fn disk_size(&self) -> u64;
    fn disk_type(&self) -> lnvps_db::DiskType;
    fn disk_interface(&self) -> lnvps_db::DiskInterface;
    /// Requested CPU manufacturer. [`CpuMfg::Unknown`] means "any".
    fn cpu_mfg(&self) -> CpuMfg;
    /// Requested CPU architecture. [`CpuArch::Unknown`] means "any".
    fn cpu_arch(&self) -> CpuArch;
    /// Required CPU feature flags. An empty list means "any".
    fn cpu_features(&self) -> &[CpuFeature];
    /// Number of IPv4 addresses the offer includes.
    fn ip4_count(&self) -> u16;
    /// Number of IPv6 addresses the offer includes.
    fn ip6_count(&self) -> u16;
}

impl Template for VmTemplate {
    fn cpu(&self) -> u16 {
        self.cpu
    }

    fn memory(&self) -> u64 {
        self.memory
    }

    fn disk_size(&self) -> u64 {
        self.disk_size
    }

    fn disk_type(&self) -> lnvps_db::DiskType {
        self.disk_type
    }

    fn disk_interface(&self) -> lnvps_db::DiskInterface {
        self.disk_interface
    }

    fn cpu_mfg(&self) -> CpuMfg {
        self.cpu_mfg.clone()
    }

    fn cpu_arch(&self) -> CpuArch {
        self.cpu_arch.clone()
    }

    fn cpu_features(&self) -> &[CpuFeature] {
        &self.cpu_features
    }

    fn ip4_count(&self) -> u16 {
        self.ip4_count
    }

    fn ip6_count(&self) -> u16 {
        self.ip6_count
    }
}

impl Template for VmCustomTemplate {
    fn cpu(&self) -> u16 {
        self.cpu
    }

    fn memory(&self) -> u64 {
        self.memory
    }

    fn disk_size(&self) -> u64 {
        self.disk_size
    }

    fn disk_type(&self) -> lnvps_db::DiskType {
        self.disk_type
    }

    fn disk_interface(&self) -> lnvps_db::DiskInterface {
        self.disk_interface
    }

    fn cpu_mfg(&self) -> CpuMfg {
        self.cpu_mfg.clone()
    }

    fn cpu_arch(&self) -> CpuArch {
        self.cpu_arch.clone()
    }

    fn cpu_features(&self) -> &[CpuFeature] {
        &self.cpu_features
    }

    fn ip4_count(&self) -> u16 {
        self.ip4_count
    }

    fn ip6_count(&self) -> u16 {
        self.ip6_count
    }
}

impl ApiVmTemplate {
    pub async fn from_standard(db: &Arc<dyn LNVpsDb>, template_id: u64) -> Result<Self> {
        let template = db.get_vm_template(template_id).await?;
        let cost_plan = db.get_cost_plan(template.cost_plan_id).await?;
        let region = db.get_host_region(template.region_id).await?;
        Self::from_standard_data(&template, &cost_plan, &region)
    }

    pub async fn from_custom(db: &Arc<dyn LNVpsDb>, template_id: u64) -> Result<Self> {
        let template = db.get_custom_vm_template(template_id).await?;
        let pricing = db.get_custom_pricing(template.pricing_id).await?;
        let region = db.get_host_region(pricing.region_id).await?;
        let price = PricingEngine::get_custom_vm_cost_amount(db, &template).await?;
        Ok(Self {
            id: template.id,
            name: "Custom".to_string(),
            created: pricing.created,
            expires: pricing.expires,
            cpu: template.cpu,
            cpu_features: template
                .cpu_features
                .iter()
                .map(|x| x.to_string())
                .collect(),
            cpu_mfg: if matches!(template.cpu_mfg, CpuMfg::Unknown) {
                None
            } else {
                Some(template.cpu_mfg.to_string())
            },
            cpu_arch: if matches!(template.cpu_arch, CpuArch::Unknown) {
                None
            } else {
                Some(template.cpu_arch.to_string())
            },
            memory: template.memory,
            disk_size: template.disk_size,
            disk_type: template.disk_type.into(),
            disk_interface: template.disk_interface.into(),
            cost_plan: ApiVmCostPlan {
                id: pricing.id,
                name: pricing.name,
                amount: price.total(),
                currency: price.currency.into(),
                other_price: vec![], // filled externally
                interval_amount: 1,
                interval_type: ApiIntervalType::Month,
            },
            region: ApiVmHostRegion {
                id: region.id,
                name: region.name,
                country_code: region.country_code,
                company_id: region.company_id,
            },
            ip4_count: template.ip4_count,
            ip6_count: template.ip6_count,
            transfer_gb: template.transfer_gb,
            // Copied onto the custom template when it was ordered, so the caps
            // reported are the ones this VM actually runs under, not whatever
            // the pricing plan says today.
            limits: (&template).into(),
        })
    }

    pub async fn from_vm(db: &Arc<dyn LNVpsDb>, vm: &Vm) -> Result<Self> {
        if let Some(t) = vm.template_id {
            return Self::from_standard(db, t).await;
        }
        if let Some(t) = vm.custom_template_id {
            return Self::from_custom(db, t).await;
        }
        bail!("Invalid VM config, no template or custom template")
    }

    pub fn from_standard_data(
        template: &VmTemplate,
        cost_plan: &VmCostPlan,
        region: &Region,
    ) -> Result<Self> {
        Ok(Self {
            id: template.id,
            name: template.name.clone(),
            created: template.created,
            expires: template.expires,
            cpu: template.cpu,
            cpu_features: template
                .cpu_features
                .iter()
                .map(|x| x.to_string())
                .collect(),
            cpu_mfg: if matches!(template.cpu_mfg, CpuMfg::Unknown) {
                None
            } else {
                Some(template.cpu_mfg.to_string())
            },
            cpu_arch: if matches!(template.cpu_arch, CpuArch::Unknown) {
                None
            } else {
                Some(template.cpu_arch.to_string())
            },
            memory: template.memory,
            disk_size: template.disk_size,
            disk_type: template.disk_type.into(),
            disk_interface: template.disk_interface.into(),
            cost_plan: ApiVmCostPlan {
                id: cost_plan.id,
                name: cost_plan.name.clone(),
                amount: cost_plan.amount,
                currency: Currency::from_str(&cost_plan.currency)
                    .map_err(|_| anyhow!("Invalid currency: {}", &cost_plan.currency))?
                    .into(),
                other_price: vec![], //filled externally
                interval_amount: cost_plan.interval_amount,
                interval_type: cost_plan.interval_type.into(),
            },
            region: ApiVmHostRegion {
                id: region.id,
                name: region.name.clone(),
                country_code: region.country_code.clone(),
                company_id: region.company_id,
            },
            ip4_count: template.ip4_count,
            ip6_count: template.ip6_count,
            transfer_gb: template.transfer_gb,
            limits: template.into(),
        })
    }
}

// Main API's full ApiVmStatus (moved from common)
#[derive(Serialize)]
pub struct ApiVmStatus {
    /// Unique VM ID (Same in proxmox)
    pub id: u64,
    /// When the subscription was created (i.e. when the VM was ordered)
    pub created: DateTime<Utc>,
    /// When the VM's subscription expires (None = never paid)
    pub expires: Option<DateTime<Utc>>,
    /// Network MAC address
    pub mac_address: String,
    /// OS Image in use
    pub image: ApiVmOsImage,
    /// VM template
    pub template: ApiVmTemplate,
    /// SSH key attached to this VM
    pub ssh_key: ApiUserSshKey,
    /// IPs assigned to this VM
    pub ip_assignments: Vec<ApiVmIpAssignment>,
    /// Current running state of the VM
    pub status: VmRunningState,
    /// Enable automatic renewal (from subscription)
    pub auto_renewal_enabled: bool,
    /// Date the VM will be deleted if not renewed (expiry + dynamic grace period).
    /// `None` when the VM has no expiry (never paid).
    pub deleting_on: Option<DateTime<Utc>>,
    /// The subscription this VM is billed under. Renew the VM by renewing this
    /// subscription (`/api/v1/subscriptions/{id}/renew`). `None` if the VM has
    /// no subscription record yet (never paid).
    pub subscription_id: Option<u64>,
    /// When the host this VM runs on is being decommissioned ("sunset"), this is
    /// the date by which the VM must be migrated elsewhere. Renewals are blocked
    /// once the VM's expiry reaches this date. `None` when the host is not being
    /// sunset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_sunset_date: Option<DateTime<Utc>>,
    /// Maximum number of days this VM may be prepaid/renewed in advance. A
    /// renewal is rejected once it would push `expires` beyond `now +
    /// max_prepay_days`. Clients should cap the renewal interval selector
    /// accordingly (given `expires` and the subscription's interval length).
    pub max_prepay_days: u16,
    /// CPU architecture of the host this VM runs on (e.g. `"x86_64"`, `"arm64"`).
    /// Sourced from the host record, so — unlike the optional
    /// `template.cpu_arch` constraint — it is present whenever the host arch is
    /// known. Clients can use it to always pass `?arch=` when listing OS images
    /// for a reinstall. `None`/omitted when the host arch is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_arch: Option<String>,
    /// The VM's own SSH host keys, captured from the guest after it booted, for
    /// verifying the host on first connect instead of trusting the key it
    /// presents. Empty until the capture succeeds, and re-captured after a
    /// reinstall (which regenerates them). Not to be confused with `ssh_key`,
    /// which is the customer's authorized key.
    pub host_ssh_keys: Vec<ApiVmHostKey>,
    /// Network transfer used in the current UTC calendar month, against the
    /// plan's allowance.
    ///
    /// Included here rather than only on `GET /api/v1/vm/{id}/traffic` so a
    /// dashboard can render a usage bar from the VM it already fetched. Use the
    /// traffic endpoint for the day-by-day breakdown or an arbitrary range.
    pub traffic: ApiVmTrafficSummary,
}

/// A VM's transfer in the current quota period.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ApiVmTrafficSummary {
    /// Outbound transfer included per calendar month, in GB. Omitted when the
    /// plan is unmetered, in which case the byte counts below are informational
    /// only. Same value as `template.transfer_gb`, repeated so a usage bar can
    /// be rendered from this object alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_gb: Option<u32>,
    /// First day of the current quota period (the 1st of this UTC month)
    pub period_start: NaiveDate,
    /// Last day of the current quota period
    pub period_end: NaiveDate,
    /// Bytes sent so far this period — the figure `transfer_gb` bounds
    pub bytes_out: u64,
    /// Bytes received so far this period, for display only; never counted
    /// against the allowance
    pub bytes_in: u64,
}

/// Grace period (days) for a subscription, tiered by how long the subscription
/// has existed (age-based). Newer subscriptions get shorter grace windows so
/// resources aren't held open for days after a brand-new VM expires.
///
/// | Age (days) | Grace (days) |
/// |------------|---------------|
/// | ≤ 1        | 1             |
/// | ≤ 7        | 2             |
/// | ≤ 28       | 7             |
/// | ≤ 180      | 14            |
/// | > 180      | delete_after  |
pub fn grace_period_days_for_sub(sub: &Subscription, now: DateTime<Utc>, delete_after: u16) -> u16 {
    let age_days = (now - sub.created).num_days().max(0);
    if age_days <= 1 {
        1
    } else if age_days <= 7 {
        2
    } else if age_days <= 28 {
        7
    } else if age_days <= 180 {
        14
    } else {
        delete_after
    }
}

// Function to build ApiVmStatus from VM data (moved from common)
///
/// `host` is the VM's host, passed in by the caller so that listing endpoints
/// can bulk-load hosts once (there are few) instead of issuing one lookup per
/// VM. Pass `None` if the host is unknown/unavailable — host-derived fields
/// (`host_sunset_date`, `cpu_arch`) are then simply omitted.
pub async fn vm_to_status(
    db: &Arc<dyn LNVpsDb>,
    vm: Vm,
    host: Option<VmHost>,
    state: Option<VmRunningState>,
    delete_after: u16,
    max_prepay_days_default: u16,
) -> Result<ApiVmStatus> {
    let image = db.get_os_image(vm.image_id).await?;
    let ssh_key: ApiUserSshKey = match vm.ssh_key_id {
        Some(k) => db.get_user_ssh_key(k).await?.into(),
        None => ApiUserSshKey::default(),
    };
    let ips = db.list_vm_ip_assignments(vm.id).await?;
    let ip_range_ids: HashSet<u64> = ips.iter().map(|i| i.ip_range_id).collect();
    let ip_ranges: Vec<_> = ip_range_ids.iter().map(|i| db.get_ip_range(*i)).collect();
    // Propagate errors instead of silently dropping failed range lookups — a
    // dropped range later caused an `.expect()` panic when building the IP
    // assignments below.
    let ip_ranges: HashMap<u64, IpRange> = join_all(ip_ranges)
        .await
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?
        .into_iter()
        .map(|i| (i.id, i))
        .collect();

    let template = ApiVmTemplate::from_vm(db, &vm).await?;
    let template_transfer_gb = template.transfer_gb;
    // Load subscription for created + expiry + auto_renewal + dynamic deletion date
    let (sub_id, sub_created, sub_expires, sub_auto_renewal, deleting_on, max_prepay_days) =
        match db
            .get_subscription_by_line_item_id(vm.subscription_line_item_id)
            .await
        {
            Ok(sub) => {
                // Deletion happens once `expires + grace_period` has passed; the grace
                // period is dynamic (subscription-age based), so surface the resulting
                // date rather than a fixed offset.
                let deleting_on = sub.expires.and_then(|expires| {
                    let grace = grace_period_days_for_sub(&sub, Utc::now(), delete_after);
                    expires.checked_add_days(Days::new(grace as u64))
                });
                // Effective prepay window: the company override when set, else the
                // global default. Surfaced so the client can cap the renewal
                // interval selector to what the server will accept.
                let max_prepay_days = match db.get_company(sub.company_id).await {
                    Ok(c) if c.max_prepay_days > 0 => c.max_prepay_days,
                    _ => max_prepay_days_default,
                };
                (
                    Some(sub.id),
                    sub.created,
                    sub.expires,
                    sub.auto_renewal_enabled,
                    deleting_on,
                    max_prepay_days,
                )
            }
            Err(_) => (None, Utc::now(), None, false, None, max_prepay_days_default),
        };

    let host_ssh_keys = vm
        .ssh_host_keys
        .as_deref()
        .map(parse_ssh_host_keys)
        .unwrap_or_default();

    // One extra aggregate per VM. `vm_to_status` already issues a dozen
    // queries, so this does not change the shape of a listing, and the quota
    // itself is free: it rides on the template already loaded above.
    let (period_start, period_end) = quota_period(Utc::now().date_naive());
    let (traffic_in, traffic_out) = db
        .get_vm_traffic_total(vm.id, period_start, period_end)
        .await?;

    Ok(ApiVmStatus {
        id: vm.id,
        created: sub_created,
        expires: sub_expires,
        mac_address: vm.mac_address,
        image: image.into(),
        template,
        ssh_key,
        status: state.unwrap_or_default(),
        ip_assignments: ips
            .into_iter()
            .map(|i| {
                let range = ip_ranges
                    .get(&i.ip_range_id)
                    .ok_or_else(|| anyhow::anyhow!("ip range {} not found", i.ip_range_id))?;
                Ok(ApiVmIpAssignment::from(&i, range))
            })
            .collect::<Result<Vec<_>>>()?,
        auto_renewal_enabled: sub_auto_renewal,
        deleting_on,
        subscription_id: sub_id,
        // Surface the host's sunset date so clients can warn users on VMs that
        // must be migrated before the host is decommissioned.
        host_sunset_date: host.as_ref().and_then(|h| h.sunset_date),
        // Surface the host's CPU architecture (skip the "unknown" sentinel).
        cpu_arch: host.as_ref().and_then(|h| match h.cpu_arch {
            lnvps_db::CpuArch::Unknown => None,
            arch => Some(arch.to_string()),
        }),
        max_prepay_days,
        host_ssh_keys,
        traffic: ApiVmTrafficSummary {
            transfer_gb: template_transfer_gb,
            period_start,
            period_end,
            bytes_out: traffic_out,
            bytes_in: traffic_in,
        },
    })
}

#[derive(Serialize)]
pub struct ApiVmIpAssignment {
    pub id: u64,
    pub ip: String,
    pub gateway: String,
    pub forward_dns: Option<String>,
    pub reverse_dns: Option<String>,
}

impl ApiVmIpAssignment {
    pub fn from(ip: &lnvps_db::VmIpAssignment, range: &lnvps_db::IpRange) -> Self {
        ApiVmIpAssignment {
            id: ip.id,
            ip: IpNetwork::new(
                IpNetwork::from_str(&ip.ip).unwrap().ip(),
                IpNetwork::from_str(&range.cidr).unwrap().prefix(),
            )
            .unwrap()
            .to_string(),
            gateway: range.gateway.to_string(),
            forward_dns: ip.dns_forward.clone(),
            reverse_dns: ip.dns_reverse.clone(),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ApiDiskType {
    HDD = 0,
    SSD = 1,
}

impl From<lnvps_db::DiskType> for ApiDiskType {
    fn from(value: lnvps_db::DiskType) -> Self {
        match value {
            lnvps_db::DiskType::HDD => Self::HDD,
            lnvps_db::DiskType::SSD => Self::SSD,
        }
    }
}

impl From<ApiDiskType> for lnvps_db::DiskType {
    fn from(val: ApiDiskType) -> Self {
        match val {
            ApiDiskType::HDD => lnvps_db::DiskType::HDD,
            ApiDiskType::SSD => lnvps_db::DiskType::SSD,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ApiDiskInterface {
    SATA = 0,
    SCSI = 1,
    PCIe = 2,
}

impl From<lnvps_db::DiskInterface> for ApiDiskInterface {
    fn from(value: lnvps_db::DiskInterface) -> Self {
        match value {
            lnvps_db::DiskInterface::SATA => Self::SATA,
            lnvps_db::DiskInterface::SCSI => Self::SCSI,
            lnvps_db::DiskInterface::PCIe => Self::PCIe,
        }
    }
}

impl From<ApiDiskInterface> for lnvps_db::DiskInterface {
    fn from(value: ApiDiskInterface) -> Self {
        match value {
            ApiDiskInterface::SATA => Self::SATA,
            ApiDiskInterface::SCSI => Self::SCSI,
            ApiDiskInterface::PCIe => Self::PCIe,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ApiVmTemplate {
    pub id: u64,
    pub name: String,
    pub created: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_type: ApiDiskType,
    pub disk_interface: ApiDiskInterface,
    pub cost_plan: ApiVmCostPlan,
    pub region: ApiVmHostRegion,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cpu_features: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_mfg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_arch: Option<String>,
    /// IPv4 addresses included
    pub ip4_count: u16,
    /// IPv6 addresses included. Assignment is best-effort: a region without an
    /// IPv6 range still provisions, so a VM may hold fewer than this.
    pub ip6_count: u16,
    /// Outbound transfer included per calendar month, in GB. Omitted when the
    /// offer is unmetered. Inbound transfer is never counted.
    ///
    /// Exceeding it does not throttle or suspend the VM; see
    /// `GET /api/v1/vm/{id}/traffic` for usage against it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_gb: Option<u32>,
    /// Performance caps enforced on a VM built from this offer.
    pub limits: ApiVmTemplateLimits,
}

/// The performance caps an offer carries, as enforced on the hypervisor.
///
/// Every field is **omitted when uncapped**, so an empty object means a VM on
/// this offer is limited only by the hardware it lands on. They are properties
/// of the *offer*, not of a host: two hosts backing the same plan must be
/// indistinguishable to the buyer, so a host's own capacity is never reported
/// here.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq)]
pub struct ApiVmTemplateLimits {
    /// Maximum disk read IOPS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_iops_read: Option<u32>,
    /// Maximum disk write IOPS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_iops_write: Option<u32>,
    /// Maximum disk read throughput in MB/s
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_mbps_read: Option<u32>,
    /// Maximum disk write throughput in MB/s
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_mbps_write: Option<u32>,
    /// Maximum network bandwidth in Mbit/s, applied in each direction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_mbps: Option<u32>,
    /// Maximum CPU usage as a fraction of the allocated cores (0.5 = half of
    /// what `cpu` states). Distinct from `cpu`: a capped offer hands the guest
    /// the cores but not all of their time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_limit: Option<f32>,
    /// Maximum user firewall rules per VM. Omitted when the offer sets none,
    /// in which case the server's global default applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_rule_limit: Option<u16>,
}

impl From<&VmTemplate> for ApiVmTemplateLimits {
    fn from(t: &VmTemplate) -> Self {
        Self {
            disk_iops_read: t.disk_iops_read,
            disk_iops_write: t.disk_iops_write,
            disk_mbps_read: t.disk_mbps_read,
            disk_mbps_write: t.disk_mbps_write,
            network_mbps: t.network_mbps,
            cpu_limit: t.cpu_limit,
            firewall_rule_limit: t.firewall_rule_limit,
        }
    }
}

impl From<&VmCustomTemplate> for ApiVmTemplateLimits {
    fn from(t: &VmCustomTemplate) -> Self {
        Self {
            disk_iops_read: t.disk_iops_read,
            disk_iops_write: t.disk_iops_write,
            disk_mbps_read: t.disk_mbps_read,
            disk_mbps_write: t.disk_mbps_write,
            network_mbps: t.network_mbps,
            cpu_limit: t.cpu_limit,
            firewall_rule_limit: t.firewall_rule_limit,
        }
    }
}

impl From<&VmCustomPricing> for ApiVmTemplateLimits {
    fn from(p: &VmCustomPricing) -> Self {
        Self {
            disk_iops_read: p.disk_iops_read,
            disk_iops_write: p.disk_iops_write,
            disk_mbps_read: p.disk_mbps_read,
            disk_mbps_write: p.disk_mbps_write,
            network_mbps: p.network_mbps,
            cpu_limit: p.cpu_limit,
            // A custom pricing plan carries no firewall rule limit; a VM built
            // from one uses the server default.
            firewall_rule_limit: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApiIntervalType {
    Day = 0,
    Month = 1,
    Year = 2,
}

impl From<lnvps_db::IntervalType> for ApiIntervalType {
    fn from(value: lnvps_db::IntervalType) -> Self {
        match value {
            lnvps_db::IntervalType::Day => Self::Day,
            lnvps_db::IntervalType::Month => Self::Month,
            lnvps_db::IntervalType::Year => Self::Year,
        }
    }
}

impl From<ApiIntervalType> for lnvps_db::IntervalType {
    fn from(value: ApiIntervalType) -> Self {
        match value {
            ApiIntervalType::Day => Self::Day,
            ApiIntervalType::Month => Self::Month,
            ApiIntervalType::Year => Self::Year,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiCurrency {
    EUR,
    BTC,
    USD,
    GBP,
    CAD,
    CHF,
    AUD,
    JPY,
}

impl From<Currency> for ApiCurrency {
    fn from(value: Currency) -> Self {
        match value {
            Currency::EUR => ApiCurrency::EUR,
            Currency::BTC => ApiCurrency::BTC,
            Currency::USD => ApiCurrency::USD,
            Currency::GBP => ApiCurrency::GBP,
            Currency::CAD => ApiCurrency::CAD,
            Currency::CHF => ApiCurrency::CHF,
            Currency::AUD => ApiCurrency::AUD,
            Currency::JPY => ApiCurrency::JPY,
        }
    }
}

impl From<ApiCurrency> for Currency {
    fn from(val: ApiCurrency) -> Self {
        match val {
            ApiCurrency::EUR => Currency::EUR,
            ApiCurrency::BTC => Currency::BTC,
            ApiCurrency::USD => Currency::USD,
            ApiCurrency::GBP => Currency::GBP,
            ApiCurrency::CAD => Currency::CAD,
            ApiCurrency::CHF => Currency::CHF,
            ApiCurrency::AUD => Currency::AUD,
            ApiCurrency::JPY => Currency::JPY,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ApiVmCostPlan {
    pub id: u64,
    pub name: String,
    pub currency: ApiCurrency,
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC)
    pub amount: u64,
    /// **Deprecated (#230)** — the same price converted to the other supported
    /// currencies. Use `GET /api/v1/exchange-rate` for a single, consistent
    /// conversion source instead. Still populated for backward compatibility;
    /// will be removed in a future release.
    pub other_price: Vec<ApiPrice>,
    pub interval_amount: u64,
    pub interval_type: ApiIntervalType,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ApiVmHostRegion {
    pub id: u64,
    pub name: String,
    /// ISO 3166-1 alpha-2 country code of the region's location, if known.
    /// Clients should render the flag/country from this instead of parsing the name.
    pub country_code: Option<String>,
    /// Seller company id for this region; use with the account `tax` info to
    /// determine the VAT rate that applies to payments for VMs in this region.
    pub company_id: u64,
}

// Shared models used by ApiVmStatus
#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ApiOsDistribution {
    Ubuntu = 0,
    Debian = 1,
    CentOS = 2,
    Fedora = 3,
    FreeBSD = 4,
    OpenSUSE = 5,
    ArchLinux = 6,
    RedHatEnterprise = 7,
    AlmaLinux = 8,
    RockyLinux = 9,
    Alpine = 10,
    NixOS = 11,
    OpenBSD = 12,
    NetBSD = 13,
    Gentoo = 14,
    VoidLinux = 15,
}

impl From<lnvps_db::OsDistribution> for ApiOsDistribution {
    fn from(value: lnvps_db::OsDistribution) -> Self {
        match value {
            lnvps_db::OsDistribution::Ubuntu => Self::Ubuntu,
            lnvps_db::OsDistribution::Debian => Self::Debian,
            lnvps_db::OsDistribution::CentOS => Self::CentOS,
            lnvps_db::OsDistribution::Fedora => Self::Fedora,
            lnvps_db::OsDistribution::FreeBSD => Self::FreeBSD,
            lnvps_db::OsDistribution::OpenSUSE => Self::OpenSUSE,
            lnvps_db::OsDistribution::ArchLinux => Self::ArchLinux,
            lnvps_db::OsDistribution::RedHatEnterprise => Self::RedHatEnterprise,
            lnvps_db::OsDistribution::AlmaLinux => Self::AlmaLinux,
            lnvps_db::OsDistribution::RockyLinux => Self::RockyLinux,
            lnvps_db::OsDistribution::Alpine => Self::Alpine,
            lnvps_db::OsDistribution::NixOS => Self::NixOS,
            lnvps_db::OsDistribution::OpenBSD => Self::OpenBSD,
            lnvps_db::OsDistribution::NetBSD => Self::NetBSD,
            lnvps_db::OsDistribution::Gentoo => Self::Gentoo,
            lnvps_db::OsDistribution::VoidLinux => Self::VoidLinux,
        }
    }
}

impl From<ApiOsDistribution> for lnvps_db::OsDistribution {
    fn from(value: ApiOsDistribution) -> Self {
        match value {
            ApiOsDistribution::Ubuntu => Self::Ubuntu,
            ApiOsDistribution::Debian => Self::Debian,
            ApiOsDistribution::CentOS => Self::CentOS,
            ApiOsDistribution::Fedora => Self::Fedora,
            ApiOsDistribution::FreeBSD => Self::FreeBSD,
            ApiOsDistribution::OpenSUSE => Self::OpenSUSE,
            ApiOsDistribution::ArchLinux => Self::ArchLinux,
            ApiOsDistribution::RedHatEnterprise => Self::RedHatEnterprise,
            ApiOsDistribution::AlmaLinux => Self::AlmaLinux,
            ApiOsDistribution::RockyLinux => Self::RockyLinux,
            ApiOsDistribution::Alpine => Self::Alpine,
            ApiOsDistribution::NixOS => Self::NixOS,
            ApiOsDistribution::OpenBSD => Self::OpenBSD,
            ApiOsDistribution::NetBSD => Self::NetBSD,
            ApiOsDistribution::Gentoo => Self::Gentoo,
            ApiOsDistribution::VoidLinux => Self::VoidLinux,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ApiVmOsImage {
    pub id: u64,
    pub distribution: ApiOsDistribution,
    pub flavour: String,
    pub version: String,
    pub release_date: DateTime<Utc>,
    /// CPU architecture this image targets (e.g. `x86_64`, `arm64`).
    /// `None` means unspecified/any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_arch: Option<String>,
    pub default_username: Option<String>,
    /// Popularity of this image expressed as a fraction (0.0â1.0) of all
    /// active VMs currently using it
    pub popularity: f32,
}

impl From<lnvps_db::VmOsImage> for ApiVmOsImage {
    fn from(image: lnvps_db::VmOsImage) -> Self {
        ApiVmOsImage {
            id: image.id,
            distribution: image.distribution.into(),
            flavour: image.flavour,
            version: image.version,
            release_date: image.release_date,
            cpu_arch: if matches!(image.cpu_arch, CpuArch::Unknown) {
                None
            } else {
                Some(image.cpu_arch.to_string())
            },
            default_username: image.default_username,
            popularity: 0.0,
        }
    }
}

#[derive(Serialize, Default)]
pub struct ApiUserSshKey {
    pub id: u64,
    pub name: String,
    pub created: DateTime<Utc>,
    /// IDs of the user's active VMs currently using this SSH key
    pub vms: Vec<u64>,
}

impl From<lnvps_db::UserSshKey> for ApiUserSshKey {
    fn from(ssh_key: lnvps_db::UserSshKey) -> Self {
        ApiUserSshKey {
            id: ssh_key.id,
            name: ssh_key.name,
            created: ssh_key.created,
            vms: vec![],
        }
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ApiPrice {
    pub currency: ApiCurrency,
    pub amount: u64,
}

impl From<CurrencyAmount> for ApiPrice {
    fn from(amount: CurrencyAmount) -> Self {
        ApiPrice {
            currency: amount.currency().into(),
            amount: amount.value(),
        }
    }
}

/// A custom VM spec as it travels over the wire: enum fields are the same
/// strings the customer order API accepts, because neither the work queue nor a
/// JSON body can carry the database enums directly.
///
/// The region is not part of the spec — it comes from `pricing_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomVmSpec {
    pub pricing_id: u64,
    pub cpu: u16,
    /// Memory in bytes
    pub memory: u64,
    /// Disk size in bytes
    pub disk: u64,
    /// "hdd" or "ssd"
    pub disk_type: String,
    /// "sata", "scsi" or "pcie"
    pub disk_interface: String,
    /// CPU manufacturer (e.g. "intel", "amd"); `None` means any
    pub cpu_mfg: Option<String>,
    /// CPU architecture (e.g. "x86_64", "arm64"); `None` means any
    pub cpu_arch: Option<String>,
    #[serde(default)]
    pub cpu_feature: Vec<String>,
    /// IPv4 addresses to assign; defaults to 1, the count every order implied
    /// before this was selectable.
    #[serde(default = "default_ip_count")]
    pub ip4_count: u16,
    /// IPv6 addresses to assign; defaults to 1.
    #[serde(default = "default_ip_count")]
    pub ip6_count: u16,
}

fn default_ip_count() -> u16 {
    1
}

impl CustomVmSpec {
    /// Build the template this spec describes.
    ///
    /// An unknown enum spelling is an error rather than a default: a silently
    /// downgraded disk or architecture is worse than a rejected request.
    pub fn to_template(&self) -> Result<VmCustomTemplate> {
        let mut cpu_features = Vec::with_capacity(self.cpu_feature.len());
        for f in &self.cpu_feature {
            cpu_features
                .push(CpuFeature::from_str(f).map_err(|_| anyhow!("unknown cpu feature {}", f))?);
        }
        Ok(VmCustomTemplate {
            id: 0,
            cpu: self.cpu,
            memory: self.memory,
            disk_size: self.disk,
            disk_type: lnvps_db::DiskType::from_str(&self.disk_type)?,
            disk_interface: lnvps_db::DiskInterface::from_str(&self.disk_interface)?,
            pricing_id: self.pricing_id,
            cpu_mfg: match &self.cpu_mfg {
                Some(v) => {
                    CpuMfg::from_str(v).map_err(|_| anyhow!("unknown cpu manufacturer {}", v))?
                }
                None => CpuMfg::default(),
            },
            cpu_arch: match &self.cpu_arch {
                Some(v) => {
                    CpuArch::from_str(v).map_err(|_| anyhow!("unknown cpu architecture {}", v))?
                }
                None => CpuArch::default(),
            },
            cpu_features: cpu_features.into(),
            ip4_count: self.ip4_count,
            ip6_count: self.ip6_count,
            ..Default::default()
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeConfig {
    pub new_cpu: Option<u16>,
    pub new_memory: Option<u64>,
    pub new_disk: Option<u64>,
}

impl UpgradeConfig {
    pub fn new(new_cpu: Option<u16>, new_memory: Option<u64>, new_disk: Option<u64>) -> Self {
        Self {
            new_cpu,
            new_memory,
            new_disk,
        }
    }
}

#[derive(Serialize, Clone)]
pub struct ApiCustomTemplateParams {
    pub id: u64,
    pub name: String,
    pub region: ApiVmHostRegion,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cpu_features: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cpu_mfg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cpu_arch: Option<String>,
    pub max_cpu: u16,
    pub min_cpu: u16,
    pub min_memory: u64,
    pub max_memory: u64,
    /// Minimum IPv4 addresses selectable on this plan
    pub min_ip4: u16,
    /// Maximum IPv4 addresses selectable, already capped by region capacity
    pub max_ip4: u16,
    /// Minimum IPv6 addresses selectable on this plan
    pub min_ip6: u16,
    /// Maximum IPv6 addresses selectable on this plan
    pub max_ip6: u16,
    pub disks: Vec<ApiCustomTemplateDiskParam>,
    /// Outbound transfer included per calendar month, in GB, copied onto every
    /// custom VM built from this plan. Omitted when the plan is unmetered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_gb: Option<u32>,
    /// Performance caps applied to every custom VM built from this plan,
    /// whatever specification is chosen. Not selectable.
    pub limits: ApiVmTemplateLimits,
}

impl ApiCustomTemplateParams {
    pub fn from(
        pricing: &VmCustomPricing,
        disks: &Vec<VmCustomPricingDisk>,
        region: &Region,
    ) -> Self {
        ApiCustomTemplateParams {
            id: pricing.id,
            name: pricing.name.clone(),
            region: ApiVmHostRegion {
                id: region.id,
                name: region.name.clone(),
                country_code: region.country_code.clone(),
                company_id: region.company_id,
            },
            cpu_features: pricing
                .cpu_features
                .iter()
                .map(ToString::to_string)
                .collect(),
            cpu_mfg: if matches!(pricing.cpu_mfg, CpuMfg::Unknown) {
                None
            } else {
                Some(pricing.cpu_mfg.to_string())
            },
            cpu_arch: if matches!(pricing.cpu_arch, CpuArch::Unknown) {
                None
            } else {
                Some(pricing.cpu_arch.to_string())
            },
            max_cpu: pricing.max_cpu,
            min_cpu: pricing.min_cpu,
            min_memory: pricing.min_memory,
            max_memory: pricing.max_memory,
            min_ip4: pricing.min_ip4,
            max_ip4: pricing.max_ip4,
            min_ip6: pricing.min_ip6,
            max_ip6: pricing.max_ip6,
            disks: disks
                .iter()
                .filter(|d| d.pricing_id == pricing.id)
                .map(|d| ApiCustomTemplateDiskParam {
                    min_disk: d.min_disk_size,
                    max_disk: d.max_disk_size,
                    disk_type: d.kind.into(),
                    disk_interface: d.interface.into(),
                })
                .collect(),
            transfer_gb: pricing.transfer_gb,
            limits: pricing.into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ApiCustomTemplateDiskParam {
    pub min_disk: u64,
    pub max_disk: u64,
    pub disk_type: ApiDiskType,
    pub disk_interface: ApiDiskInterface,
}

/// Typed reference to the resource a subscription line item bills for.
///
/// This is resolved from the line item's [`LineItemType`] discriminant by
/// looking up the back-reference tables (`vm.subscription_line_item_id`,
/// `ip_range_subscription.subscription_line_item_id`, ...). It is NOT derived
/// from the line item's `configuration` column, which stores upgrade data only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum ApiSubscriptionLineItemResource {
    /// A VPS (virtual private server).
    #[serde(rename = "vps")]
    Vps { vm_id: u64 },
    /// An IP range allocation.
    #[serde(rename = "ip_range")]
    IpRange { ip_range_subscription_id: u64 },
    /// A sponsored AS number.
    #[serde(rename = "asn")]
    Asn { asn_subscription_id: u64 },
    /// A managed app deployment.
    #[serde(rename = "app")]
    App { app_deployment_id: u64 },
    /// A marketplace node's one-off listing fee.
    #[serde(rename = "marketplace_node")]
    MarketplaceNode { marketplace_node_id: u64 },
    /// A consumer VPN plan.
    #[serde(rename = "vpn")]
    Vpn { vpn_subscription_id: u64 },
}

impl ApiSubscriptionLineItemResource {
    /// Resolve the linked resource for a line item from its subscription type.
    ///
    /// Returns `None` when the type has no linkable resource (e.g. ASN
    /// sponsoring, DNS hosting) or the back-reference row cannot be found.
    /// Resolve the linked resource for many line items with one query per
    /// resource table, keyed by line item id.
    ///
    /// The batch counterpart to [`Self::resolve`]: rendering a page of line
    /// items must not issue a back-reference query per row. Line items whose
    /// type has no linkable resource, or whose back-reference row is missing,
    /// are simply absent from the map.
    pub async fn resolve_many<D: LNVpsDbBase + ?Sized>(
        db: &D,
        line_items: &[SubscriptionLineItem],
    ) -> HashMap<u64, Self> {
        let ids_of = |t: LineItemType| -> Vec<u64> {
            line_items
                .iter()
                .filter(|li| li.subscription_type == t)
                .map(|li| li.id)
                .collect()
        };
        let mut out = HashMap::new();

        let vps = ids_of(LineItemType::Vps);
        if !vps.is_empty() {
            for vm in db.list_vms_by_line_items(&vps).await.unwrap_or_default() {
                out.insert(vm.subscription_line_item_id, Self::Vps { vm_id: vm.id });
            }
        }

        let ip_ranges = ids_of(LineItemType::IpRange);
        if !ip_ranges.is_empty() {
            for sub in db
                .list_ip_range_subscriptions_by_line_items(&ip_ranges)
                .await
                .unwrap_or_default()
            {
                out.entry(sub.subscription_line_item_id)
                    .or_insert(Self::IpRange {
                        ip_range_subscription_id: sub.id,
                    });
            }
        }

        let asns = ids_of(LineItemType::AsnSponsoring);
        if !asns.is_empty() {
            for sub in db
                .list_asn_subscriptions_by_line_items(&asns)
                .await
                .unwrap_or_default()
            {
                out.entry(sub.subscription_line_item_id)
                    .or_insert(Self::Asn {
                        asn_subscription_id: sub.id,
                    });
            }
        }

        let apps = ids_of(LineItemType::App);
        if !apps.is_empty() {
            for d in db
                .list_app_deployments_by_line_items(&apps)
                .await
                .unwrap_or_default()
            {
                out.entry(d.subscription_line_item_id).or_insert(Self::App {
                    app_deployment_id: d.id,
                });
            }
        }

        let nodes = ids_of(LineItemType::MarketplaceNodeFee);
        if !nodes.is_empty() {
            for n in db
                .list_marketplace_nodes_by_line_items(&nodes)
                .await
                .unwrap_or_default()
            {
                if let Some(li) = n.subscription_line_item_id {
                    out.entry(li).or_insert(Self::MarketplaceNode {
                        marketplace_node_id: n.id,
                    });
                }
            }
        }

        out
    }

    pub async fn resolve<D: LNVpsDbBase + ?Sized>(
        db: &D,
        line_item: &SubscriptionLineItem,
    ) -> Option<Self> {
        match line_item.subscription_type {
            LineItemType::Vps => db
                .get_vm_by_line_item(line_item.id)
                .await
                .ok()
                .map(|vm| Self::Vps { vm_id: vm.id }),
            LineItemType::IpRange => db
                .list_ip_range_subscriptions_by_line_item(line_item.id)
                .await
                .ok()
                .and_then(|subs| subs.into_iter().next())
                .map(|sub| Self::IpRange {
                    ip_range_subscription_id: sub.id,
                }),
            LineItemType::AsnSponsoring => db
                .list_asn_subscriptions_by_line_item(line_item.id)
                .await
                .ok()
                .and_then(|subs| subs.into_iter().next())
                .map(|sub| Self::Asn {
                    asn_subscription_id: sub.id,
                }),
            LineItemType::App => db
                .get_app_deployment_by_line_item(line_item.id)
                .await
                .ok()
                .map(|d| Self::App {
                    app_deployment_id: d.id,
                }),
            LineItemType::MarketplaceNodeFee => db
                .get_marketplace_node_by_line_item(line_item.id)
                .await
                .ok()
                .map(|n| Self::MarketplaceNode {
                    marketplace_node_id: n.id,
                }),
            LineItemType::Vpn => db
                .get_vpn_subscription_by_line_item(line_item.id)
                .await
                .ok()
                .flatten()
                .map(|p| Self::Vpn {
                    vpn_subscription_id: p.id,
                }),
            LineItemType::DnsHosting => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `resolve_many` must issue one query per resource *table*, never per line
    /// item, and must tolerate a line item whose backing row is missing.
    #[tokio::test]
    async fn resolve_many_batches_every_resource_type() {
        use crate::MockDb;
        use lnvps_db::LNVpsDbBase;

        let db = MockDb::default();
        let user_id = db.upsert_user(&[9u8; 32]).await.unwrap();
        let sub_id = db
            .insert_subscription(&lnvps_db::Subscription {
                id: 0,
                user_id,
                company_id: 1,
                name: "sub".to_string(),
                description: None,
                created: Utc::now(),
                expires: None,
                is_active: true,
                is_setup: true,
                currency: "EUR".to_string(),
                interval_amount: 1,
                interval_type: lnvps_db::IntervalType::Month,
                setup_fee: 0,
                auto_renewal_enabled: true,
                external_id: None,
            })
            .await
            .unwrap();

        let mut ids: Vec<(LineItemType, u64)> = Vec::new();
        let id_of = |ids: &[(LineItemType, u64)], t: LineItemType| -> u64 {
            ids.iter().find(|(k, _)| *k == t).unwrap().1
        };
        for t in [
            LineItemType::Vps,
            LineItemType::IpRange,
            LineItemType::AsnSponsoring,
            LineItemType::App,
            LineItemType::MarketplaceNodeFee,
            LineItemType::DnsHosting,
        ] {
            let id = db
                .insert_subscription_line_item(&SubscriptionLineItem {
                    id: 0,
                    subscription_id: sub_id,
                    subscription_type: t,
                    name: format!("{t:?}"),
                    description: None,
                    amount: 100,
                    setup_amount: 0,
                    configuration: None,
                })
                .await
                .unwrap();
            ids.push((t, id));
        }

        // Only the VPS line item gets a backing row; the rest exercise the
        // "queried, found nothing" path.
        let mut vm = MockDb::mock_vm();
        vm.user_id = user_id;
        vm.ssh_key_id = None;
        vm.subscription_line_item_id = id_of(&ids, LineItemType::Vps);
        let vm_id = db.insert_vm(&vm).await.unwrap();

        let line_items = db
            .list_subscription_line_items_by_subscriptions(&[sub_id])
            .await
            .unwrap();
        assert_eq!(line_items.len(), 6);

        let resolved = ApiSubscriptionLineItemResource::resolve_many(&db, &line_items).await;
        assert_eq!(
            resolved.get(&id_of(&ids, LineItemType::Vps)),
            Some(&ApiSubscriptionLineItemResource::Vps { vm_id })
        );
        for t in [
            LineItemType::IpRange,
            LineItemType::AsnSponsoring,
            LineItemType::App,
            LineItemType::MarketplaceNodeFee,
            LineItemType::DnsHosting,
        ] {
            assert!(
                !resolved.contains_key(&id_of(&ids, t)),
                "{t:?} has no backing row"
            );
        }

        // Same answer as the per-row path it replaces
        for li in &line_items {
            let one = ApiSubscriptionLineItemResource::resolve(&db, li).await;
            assert_eq!(one.as_ref(), resolved.get(&li.id));
        }

        // Nothing to resolve issues no queries at all
        assert!(
            ApiSubscriptionLineItemResource::resolve_many(&db, &[])
                .await
                .is_empty()
        );
    }

    #[test]
    fn test_api_os_distribution_roundtrip_with_db() {
        let all = [
            lnvps_db::OsDistribution::Ubuntu,
            lnvps_db::OsDistribution::Debian,
            lnvps_db::OsDistribution::CentOS,
            lnvps_db::OsDistribution::Fedora,
            lnvps_db::OsDistribution::FreeBSD,
            lnvps_db::OsDistribution::OpenSUSE,
            lnvps_db::OsDistribution::ArchLinux,
            lnvps_db::OsDistribution::RedHatEnterprise,
            lnvps_db::OsDistribution::AlmaLinux,
            lnvps_db::OsDistribution::RockyLinux,
            lnvps_db::OsDistribution::Alpine,
            lnvps_db::OsDistribution::NixOS,
            lnvps_db::OsDistribution::OpenBSD,
            lnvps_db::OsDistribution::NetBSD,
            lnvps_db::OsDistribution::Gentoo,
            lnvps_db::OsDistribution::VoidLinux,
        ];
        for d in all {
            let api = ApiOsDistribution::from(d);
            let back = lnvps_db::OsDistribution::from(api);
            assert_eq!(d, back);
            // Serialized (lowercase) form must parse back via the DB FromStr
            let json = serde_json::to_string(&api).unwrap();
            let name = json.trim_matches('"');
            assert_eq!(name.parse::<lnvps_db::OsDistribution>().unwrap(), d);
        }
    }

    fn custom_spec() -> CustomVmSpec {
        CustomVmSpec {
            pricing_id: 7,
            cpu: 4,
            memory: 8 * 1024 * 1024 * 1024,
            disk: 100 * 1024 * 1024 * 1024,
            disk_type: "ssd".to_string(),
            disk_interface: "pcie".to_string(),
            cpu_mfg: None,
            cpu_arch: None,
            cpu_feature: vec![],
            ip4_count: 1,
            ip6_count: 1,
        }
    }

    /// An omitted count means the single address every order implied before the
    /// counts were selectable, not zero.
    #[test]
    fn test_custom_vm_spec_defaults_ip_counts_to_one() {
        let spec: CustomVmSpec = serde_json::from_str(
            r#"{"pricing_id":7,"cpu":4,"memory":1073741824,"disk":10737418240,
                "disk_type":"ssd","disk_interface":"pcie"}"#,
        )
        .unwrap();
        assert_eq!(1, spec.ip4_count);
        assert_eq!(1, spec.ip6_count);

        let t = spec.to_template().unwrap();
        assert_eq!(1, t.ip4_count);
        assert_eq!(1, t.ip6_count);
    }

    #[test]
    fn test_custom_vm_spec_carries_ip_counts() {
        let spec = CustomVmSpec {
            ip4_count: 2,
            ip6_count: 0,
            ..custom_spec()
        };
        let t = spec.to_template().unwrap();
        assert_eq!(2, t.ip4_count);
        assert_eq!(0, t.ip6_count);
    }

    #[test]
    fn test_custom_vm_spec_to_template() {
        let spec = CustomVmSpec {
            cpu_mfg: Some("amd".to_string()),
            cpu_arch: Some("x86_64".to_string()),
            cpu_feature: vec!["AVX2".to_string()],
            ..custom_spec()
        };
        let t = spec.to_template().unwrap();
        assert_eq!(t.id, 0);
        assert_eq!(t.pricing_id, 7);
        assert_eq!(t.cpu, 4);
        assert_eq!(t.memory, 8 * 1024 * 1024 * 1024);
        assert_eq!(t.disk_size, 100 * 1024 * 1024 * 1024);
        assert_eq!(t.disk_type, lnvps_db::DiskType::SSD);
        assert_eq!(t.disk_interface, lnvps_db::DiskInterface::PCIe);
        assert_eq!(t.cpu_mfg, CpuMfg::Amd);
        assert_eq!(t.cpu_arch, CpuArch::X86_64);
        assert_eq!(t.cpu_features.0, vec![CpuFeature::AVX2]);
    }

    #[test]
    fn test_custom_vm_spec_omitted_cpu_fields_mean_any() {
        let t = custom_spec().to_template().unwrap();
        assert_eq!(t.cpu_mfg, CpuMfg::default());
        assert_eq!(t.cpu_arch, CpuArch::default());
        assert!(t.cpu_features.0.is_empty());
    }

    #[test]
    fn test_custom_vm_spec_rejects_unknown_enum_values() {
        // Never silently default: a typo must not become a different machine.
        for spec in [
            CustomVmSpec {
                disk_type: "nvme".to_string(),
                ..custom_spec()
            },
            CustomVmSpec {
                disk_interface: "ide".to_string(),
                ..custom_spec()
            },
            CustomVmSpec {
                cpu_mfg: Some("acme".to_string()),
                ..custom_spec()
            },
            CustomVmSpec {
                cpu_arch: Some("sparc".to_string()),
                ..custom_spec()
            },
            CustomVmSpec {
                cpu_feature: vec!["TELEPATHY".to_string()],
                ..custom_spec()
            },
        ] {
            assert!(spec.to_template().is_err());
        }
    }

    #[test]
    fn test_vps_serialization_includes_type_tag() {
        let res = ApiSubscriptionLineItemResource::Vps { vm_id: 1 };
        let s = serde_json::to_string(&res).unwrap();
        assert!(s.contains(r#""type":"vps""#));
        assert!(s.contains(r#""vm_id":1"#));
    }

    #[test]
    fn test_ip_range_serialization_includes_type_tag() {
        let res = ApiSubscriptionLineItemResource::IpRange {
            ip_range_subscription_id: 7,
        };
        let s = serde_json::to_string(&res).unwrap();
        assert!(s.contains(r#""type":"ip_range""#));
        assert!(s.contains(r#""ip_range_subscription_id":7"#));
    }

    const EXPECTED_LIMITS: ApiVmTemplateLimits = ApiVmTemplateLimits {
        disk_iops_read: Some(5000),
        disk_iops_write: Some(2500),
        disk_mbps_read: Some(500),
        disk_mbps_write: Some(250),
        network_mbps: Some(1000),
        cpu_limit: Some(0.5),
        firewall_rule_limit: Some(20),
    };

    /// A standard offer reports every cap it carries.
    #[test]
    fn test_limits_from_vm_template() {
        let t = VmTemplate {
            disk_iops_read: Some(5000),
            disk_iops_write: Some(2500),
            disk_mbps_read: Some(500),
            disk_mbps_write: Some(250),
            network_mbps: Some(1000),
            cpu_limit: Some(0.5),
            firewall_rule_limit: Some(20),
            ..Default::default()
        };
        assert_eq!(ApiVmTemplateLimits::from(&t), EXPECTED_LIMITS);
    }

    /// A custom VM reports the caps copied onto it when it was ordered, so an
    /// edit to the pricing plan cannot misdescribe a running machine.
    #[test]
    fn test_limits_from_custom_vm_template() {
        let t = VmCustomTemplate {
            disk_iops_read: Some(5000),
            disk_iops_write: Some(2500),
            disk_mbps_read: Some(500),
            disk_mbps_write: Some(250),
            network_mbps: Some(1000),
            cpu_limit: Some(0.5),
            firewall_rule_limit: Some(20),
            ..Default::default()
        };
        assert_eq!(ApiVmTemplateLimits::from(&t), EXPECTED_LIMITS);
    }

    /// A pricing plan carries no firewall rule limit of its own — a custom VM
    /// built from one falls back to the server default, so reporting a number
    /// here would be inventing one.
    #[test]
    fn test_limits_from_custom_pricing_has_no_firewall_limit() {
        let p = VmCustomPricing {
            disk_iops_read: Some(5000),
            disk_iops_write: Some(2500),
            disk_mbps_read: Some(500),
            disk_mbps_write: Some(250),
            network_mbps: Some(1000),
            cpu_limit: Some(0.5),
            ..Default::default()
        };
        let limits = ApiVmTemplateLimits::from(&p);
        assert_eq!(limits.network_mbps, Some(1000));
        assert_eq!(limits.cpu_limit, Some(0.5));
        assert_eq!(limits.firewall_rule_limit, None);
    }

    /// An uncapped offer serialises as an empty object rather than a wall of
    /// nulls: absent means "limited only by the hardware", which is what every
    /// offer says today.
    #[test]
    fn test_uncapped_limits_serialise_empty() {
        let limits = ApiVmTemplateLimits::from(&VmTemplate::default());
        assert_eq!(serde_json::to_string(&limits).unwrap(), "{}");
    }

    /// A cap that is set must survive the round trip, including the fractional
    /// CPU limit — a client reading 0.5 as 0 would advertise a plan as twice
    /// the CPU it delivers.
    #[test]
    fn test_capped_limits_round_trip() {
        let json = serde_json::to_string(&EXPECTED_LIMITS).unwrap();
        assert!(json.contains(r#""network_mbps":1000"#));
        assert!(json.contains(r#""cpu_limit":0.5"#));
        let back: ApiVmTemplateLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(back, EXPECTED_LIMITS);
    }
}

/// A VM discovered directly on a host, described in host-native terms.
///
/// Used to import VMs that exist on a host but are not tracked in the database
/// (see issue #166). `mapped_vm_id` is the LNVPS database id this host VM would
/// map to (e.g. Proxmox `vmid - 100`), or `None` when the host VM falls outside
/// the managed id range and therefore can't be imported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostVmSpec {
    /// Raw host VM id (e.g. Proxmox vmid)
    pub host_vm_id: i64,
    /// LNVPS database id this VM maps to, if within the managed range
    pub mapped_vm_id: Option<u64>,
    /// Host-reported VM name
    pub name: Option<String>,
    /// Allocated CPU cores
    pub cpu: u16,
    /// Allocated memory in bytes
    pub memory: u64,
    /// Primary disk size in bytes
    pub disk_size: u64,
    /// Storage pool backing the primary disk
    pub disk_storage: Option<String>,
    /// Primary NIC MAC address
    pub mac_address: Option<String>,
    /// Whether the VM is currently running
    pub running: bool,
}

/// The last resource usage the cluster reported for an app deployment.
///
/// Same units as the deployment's quota fields, so the two divide directly.
/// Shared by the customer and admin APIs so oversight sees exactly the object
/// the customer is looking at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDeploymentUsage {
    pub cpu_milli: u64,
    pub memory_bytes: u64,
    /// Volume usage. `None` for a deployment with no volumes, or when the
    /// metrics source carries no kubelet volume statistics — CPU and memory are
    /// still reported in that case.
    pub storage_bytes: Option<u64>,
    /// When the reading was taken. Usage is sampled on the operator's reconcile
    /// interval, not on request, so it is always somewhat behind — render it
    /// with the age rather than as a live figure.
    pub collected: DateTime<Utc>,
    /// Per-service CPU and memory behind the totals above. Empty when nothing
    /// has been observed yet.
    ///
    /// Worth rendering beside the totals rather than instead of them: CPU and
    /// memory limits are enforced per container, so a total cannot say which
    /// service is the one at its limit.
    pub services: Vec<AppDeploymentServiceUsage>,
    /// Per-volume storage behind `storage_bytes`, keyed the way the app's
    /// declared volumes are. Empty when nothing has been observed yet.
    ///
    /// The size limit is per volume, so a deployment well under its total can
    /// still have one volume that is full.
    pub volumes: Vec<AppDeploymentVolumeUsage>,
}

/// One service's share of a deployment's observed CPU and memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDeploymentServiceUsage {
    /// Compose service name.
    pub service: String,
    pub cpu_milli: u64,
    pub memory_bytes: u64,
}

/// One volume's observed use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDeploymentVolumeUsage {
    /// Compose service this volume belongs to. Sent because a volume name is
    /// only unique within its service.
    pub service: String,
    /// Compose volume name.
    pub name: String,
    pub storage_bytes: u64,
}

impl AppDeploymentUsage {
    /// Assemble a deployment's usage from its stored totals and breakdown.
    ///
    /// `None` unless the totals are complete: a timestamp with no figures, or
    /// figures with no timestamp, is a half-written row, and dating an unknown
    /// sample `now` would overstate how fresh it is. The breakdown is allowed
    /// to be empty — a reading taken before per-service series were collected
    /// has totals and no parts.
    pub fn from_parts(
        d: &lnvps_db::AppDeployment,
        services: Vec<lnvps_db::AppDeploymentServiceUsage>,
        volumes: Vec<lnvps_db::AppDeploymentVolumeUsage>,
    ) -> Option<Self> {
        let (cpu_milli, memory_bytes, collected) =
            match (d.usage_cpu_milli, d.usage_memory_bytes, d.usage_collected) {
                (Some(c), Some(m), Some(t)) => (c, m, t),
                _ => return None,
            };
        Some(Self {
            cpu_milli: cpu_milli as u64,
            memory_bytes,
            storage_bytes: d.usage_storage_bytes,
            collected,
            services: services
                .into_iter()
                .map(|s| AppDeploymentServiceUsage {
                    service: s.service,
                    cpu_milli: s.cpu_milli as u64,
                    memory_bytes: s.memory_bytes,
                })
                .collect(),
            volumes: volumes
                .into_iter()
                .map(|v| AppDeploymentVolumeUsage {
                    service: v.service,
                    name: v.name,
                    storage_bytes: v.storage_bytes,
                })
                .collect(),
        })
    }
}
