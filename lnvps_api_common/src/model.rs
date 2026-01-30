use crate::VmRunningState;
use crate::pricing::PricingEngine;
use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use futures::future::join_all;
use ipnetwork::IpNetwork;
use lnvps_db::{
    IpRange, LNVpsDb, Vm, VmCostPlan, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate,
    VmHostRegion, VmTemplate,
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
                interval_type: ApiVmCostPlanIntervalType::Month,
            },
            region: ApiVmHostRegion {
                id: region.id,
                name: region.name,
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
                interval_type: cost_plan.interval_type.clone().into(),
            },
            region: ApiVmHostRegion {
                id: region.id,
                name: region.name.clone(),
            },
        })
    }
}

// Main API's full ApiVmStatus (moved from common)
#[derive(Serialize)]
pub struct ApiVmStatus {
    /// Unique VM ID (Same in proxmox)
    pub id: u64,
    /// When the VM was created
    pub created: DateTime<Utc>,
    /// When the VM expires
    pub expires: DateTime<Utc>,
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
    /// Enable automatic renewal via NWC for this VM
    pub auto_renewal_enabled: bool,
}

// Function to build ApiVmStatus from VM data (moved from common)
pub async fn vm_to_status(
    db: &Arc<dyn LNVpsDb>,
    vm: Vm,
    state: Option<VmRunningState>,
) -> Result<ApiVmStatus> {
    let image = db.get_os_image(vm.image_id).await?;
    let ssh_key = db.get_user_ssh_key(vm.ssh_key_id).await?;
    let ips = db.list_vm_ip_assignments(vm.id).await?;
    let ip_range_ids: HashSet<u64> = ips.iter().map(|i| i.ip_range_id).collect();
    let ip_ranges: Vec<_> = ip_range_ids.iter().map(|i| db.get_ip_range(*i)).collect();
    let ip_ranges: HashMap<u64, IpRange> = join_all(ip_ranges)
        .await
        .into_iter()
        .filter_map(Result::ok)
        .map(|i| (i.id, i))
        .collect();

    let template = ApiVmTemplate::from_vm(db, &vm).await?;
    Ok(ApiVmStatus {
        id: vm.id,
        created: vm.created,
        expires: vm.expires,
        mac_address: vm.mac_address,
        image: image.into(),
        template,
        ssh_key: ssh_key.into(),
        status: state.map(|s| s.into()).unwrap_or_default(),
        ip_assignments: ips
            .into_iter()
            .map(|i| {
                let range = ip_ranges
                    .get(&i.ip_range_id)
                    .expect("ip range id not found");
                ApiVmIpAssignment::from(&i, range)
            })
            .collect(),
        auto_renewal_enabled: vm.auto_renewal_enabled,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum VmState {
    Pending,
    Running,
    #[default]
    Stopped,
    Failed,
}

impl From<crate::status::VmRunningStates> for VmState {
    fn from(running_state: crate::status::VmRunningStates) -> Self {
        match running_state {
            crate::status::VmRunningStates::Running => VmState::Running,
            crate::status::VmRunningStates::Stopped => VmState::Stopped,
            crate::status::VmRunningStates::Starting => VmState::Pending,
            crate::status::VmRunningStates::Deleting => VmState::Failed,
        }
    }
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
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ApiVmCostPlanIntervalType {
    Day = 0,
    Month = 1,
    Year = 2,
}

impl From<lnvps_db::VmCostPlanIntervalType> for ApiVmCostPlanIntervalType {
    fn from(value: lnvps_db::VmCostPlanIntervalType) -> Self {
        match value {
            lnvps_db::VmCostPlanIntervalType::Day => Self::Day,
            lnvps_db::VmCostPlanIntervalType::Month => Self::Month,
            lnvps_db::VmCostPlanIntervalType::Year => Self::Year,
        }
    }
}

impl From<ApiVmCostPlanIntervalType> for lnvps_db::VmCostPlanIntervalType {
    fn from(value: ApiVmCostPlanIntervalType) -> Self {
        match value {
            ApiVmCostPlanIntervalType::Day => Self::Day,
            ApiVmCostPlanIntervalType::Month => Self::Month,
            ApiVmCostPlanIntervalType::Year => Self::Year,
        }
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
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

impl Into<Currency> for ApiCurrency {
    fn into(self) -> Currency {
        match self {
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
    pub amount: f32,
    pub other_price: Vec<ApiPrice>,
    pub interval_amount: u64,
    pub interval_type: ApiVmCostPlanIntervalType,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ApiVmHostRegion {
    pub id: u64,
    pub name: String,
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
    pub default_username: Option<String>,
}

impl From<lnvps_db::VmOsImage> for ApiVmOsImage {
    fn from(image: lnvps_db::VmOsImage) -> Self {
        ApiVmOsImage {
            id: image.id,
            distribution: image.distribution.into(),
            flavour: image.flavour,
            version: image.version,
            release_date: image.release_date,
            default_username: image.default_username,
        }
    }
}

#[derive(Serialize)]
pub struct ApiUserSshKey {
    pub id: u64,
    pub name: String,
    pub created: DateTime<Utc>,
}

impl From<lnvps_db::UserSshKey> for ApiUserSshKey {
    fn from(ssh_key: lnvps_db::UserSshKey) -> Self {
        ApiUserSshKey {
            id: ssh_key.id,
            name: ssh_key.name,
            created: ssh_key.created,
        }
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ApiPrice {
    pub currency: ApiCurrency,
    pub amount: f32,
}

impl From<CurrencyAmount> for ApiPrice {
    fn from(amount: CurrencyAmount) -> Self {
        ApiPrice {
            currency: amount.currency().into(),
            amount: amount.value_f32(),
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
