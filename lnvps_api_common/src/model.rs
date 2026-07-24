use crate::VmRunningState;
use crate::pricing::PricingEngine;
use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Days, Utc};
use futures::future::join_all;
use ipnetwork::IpNetwork;
use lnvps_db::{
    CpuArch, CpuFeature, CpuMfg, IpRange, LNVpsDb, LNVpsDbBase, Subscription, SubscriptionLineItem,
    SubscriptionType, Vm, VmCostPlan, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate,
    VmHost, VmHostRegion, VmTemplate,
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
}

impl ApiVmTemplate {
    pub async fn from_standard(db: &Arc<dyn LNVpsDb>, template_id: u64) -> Result<Self> {
        let template = db.get_vm_template(template_id).await?;
        let cost_plan = db.get_cost_plan(template.cost_plan_id).await?;
        let region = db.get_host_region(template.region_id).await?;
        Self::from_standard_data(&template, &cost_plan, &region)
    }

    pub async fn from_custom(db: &Arc<dyn LNVpsDb>, vm_id: u64, template_id: u64) -> Result<Self> {
        let template = db.get_custom_vm_template(template_id).await?;
        let pricing = db.get_custom_pricing(template.pricing_id).await?;
        let region = db.get_host_region(pricing.region_id).await?;
        let price = PricingEngine::get_custom_vm_cost_amount(db, vm_id, &template).await?;
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
                company_id: region.company_id,
            },
        })
    }

    pub async fn from_vm(db: &Arc<dyn LNVpsDb>, vm: &Vm) -> Result<Self> {
        if let Some(t) = vm.template_id {
            return Self::from_standard(db, t).await;
        }
        if let Some(t) = vm.custom_template_id {
            return Self::from_custom(db, vm.id, t).await;
        }
        bail!("Invalid VM config, no template or custom template")
    }

    pub fn from_standard_data(
        template: &VmTemplate,
        cost_plan: &VmCostPlan,
        region: &VmHostRegion,
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
                company_id: region.company_id,
            },
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
}

#[derive(Serialize, Deserialize, Clone, Copy)]
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
    pub other_price: Vec<ApiPrice>,
    pub interval_amount: u64,
    pub interval_type: ApiIntervalType,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ApiVmHostRegion {
    pub id: u64,
    pub name: String,
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
    pub disks: Vec<ApiCustomTemplateDiskParam>,
}

impl ApiCustomTemplateParams {
    pub fn from(
        pricing: &VmCustomPricing,
        disks: &Vec<VmCustomPricingDisk>,
        region: &VmHostRegion,
    ) -> Self {
        ApiCustomTemplateParams {
            id: pricing.id,
            name: pricing.name.clone(),
            region: ApiVmHostRegion {
                id: region.id,
                name: region.name.clone(),
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
/// This is resolved from the line item's [`SubscriptionType`] discriminant by
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
}

impl ApiSubscriptionLineItemResource {
    /// Resolve the linked resource for a line item from its subscription type.
    ///
    /// Returns `None` when the type has no linkable resource (e.g. ASN
    /// sponsoring, DNS hosting) or the back-reference row cannot be found.
    pub async fn resolve<D: LNVpsDbBase + ?Sized>(
        db: &D,
        line_item: &SubscriptionLineItem,
    ) -> Option<Self> {
        match line_item.subscription_type {
            SubscriptionType::Vps => db
                .get_vm_by_line_item(line_item.id)
                .await
                .ok()
                .map(|vm| Self::Vps { vm_id: vm.id }),
            SubscriptionType::IpRange => db
                .list_ip_range_subscriptions_by_line_item(line_item.id)
                .await
                .ok()
                .and_then(|subs| subs.into_iter().next())
                .map(|sub| Self::IpRange {
                    ip_range_subscription_id: sub.id,
                }),
            SubscriptionType::AsnSponsoring => db
                .list_asn_subscriptions_by_line_item(line_item.id)
                .await
                .ok()
                .and_then(|subs| subs.into_iter().next())
                .map(|sub| Self::Asn {
                    asn_subscription_id: sub.id,
                }),
            SubscriptionType::DnsHosting => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
