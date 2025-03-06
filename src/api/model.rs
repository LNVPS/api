use crate::exchange::Currency;
use crate::provisioner::PricingEngine;
use crate::status::VmState;
use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use lnvps_db::{LNVpsDb, Vm, VmCostPlan, VmCustomTemplate, VmHost, VmHostRegion, VmTemplate};
use nostr::util::hex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Serialize, Deserialize, JsonSchema)]
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
    pub status: VmState,
}

#[derive(Serialize, Deserialize, JsonSchema)]
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

#[derive(Serialize, Deserialize, JsonSchema)]
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

#[derive(Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DiskType {
    HDD = 0,
    SSD = 1,
}

impl From<lnvps_db::DiskType> for DiskType {
    fn from(value: lnvps_db::DiskType) -> Self {
        match value {
            lnvps_db::DiskType::HDD => Self::HDD,
            lnvps_db::DiskType::SSD => Self::SSD,
        }
    }
}

impl Into<lnvps_db::DiskType> for DiskType {
    fn into(self) -> lnvps_db::DiskType {
        match self {
            DiskType::HDD => lnvps_db::DiskType::HDD,
            DiskType::SSD => lnvps_db::DiskType::SSD,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DiskInterface {
    SATA = 0,
    SCSI = 1,
    PCIe = 2,
}

impl From<lnvps_db::DiskInterface> for DiskInterface {
    fn from(value: lnvps_db::DiskInterface) -> Self {
        match value {
            lnvps_db::DiskInterface::SATA => Self::SATA,
            lnvps_db::DiskInterface::SCSI => Self::SCSI,
            lnvps_db::DiskInterface::PCIe => Self::PCIe,
        }
    }
}

impl From<DiskInterface> for lnvps_db::DiskInterface {
    fn from(value: DiskInterface) -> Self {
        match value {
            DiskInterface::SATA => Self::SATA,
            DiskInterface::SCSI => Self::SCSI,
            DiskInterface::PCIe => Self::PCIe,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ApiTemplatesResponse {
    pub templates: Vec<ApiVmTemplate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_template: Option<Vec<ApiCustomTemplateParams>>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ApiCustomTemplateParams {
    pub id: u64,
    pub name: String,
    pub region: ApiVmHostRegion,
    pub max_cpu: u16,
    pub min_cpu: u16,
    pub min_memory: u64,
    pub max_memory: u64,
    pub min_disk: u64,
    pub max_disk: u64,
    pub disks: Vec<ApiCustomTemplateDiskParam>,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiCustomTemplateDiskParam {
    pub disk_type: DiskType,
    pub disk_interface: DiskInterface,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiCustomVmRequest {
    pub pricing_id: u64,
    pub cpu: u16,
    pub memory: u64,
    pub disk: u64,
    pub disk_type: DiskType,
    pub disk_interface: DiskInterface,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ApiCustomVmOrder {
    #[serde(flatten)]
    pub spec: ApiCustomVmRequest,
    pub image_id: u64,
    pub ssh_key_id: u64,
    pub ref_code: Option<String>,
}

impl From<ApiCustomVmRequest> for VmCustomTemplate {
    fn from(value: ApiCustomVmRequest) -> Self {
        VmCustomTemplate {
            id: 0,
            cpu: value.cpu,
            memory: value.memory,
            disk_size: value.disk,
            disk_type: value.disk_type.into(),
            disk_interface: value.disk_interface.into(),
            pricing_id: value.pricing_id,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ApiCustomPrice {
    pub currency: String,
    pub amount: f32,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ApiVmTemplate {
    pub id: u64,
    pub name: String,
    pub created: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_type: DiskType,
    pub disk_interface: DiskInterface,
    pub cost_plan: ApiVmCostPlan,
    pub region: ApiVmHostRegion,
}

impl ApiVmTemplate {
    pub async fn from_standard(db: &Arc<dyn LNVpsDb>, template_id: u64) -> Result<Self> {
        let template = db.get_vm_template(template_id).await?;
        let cost_plan = db.get_cost_plan(template.cost_plan_id).await?;
        let region = db.get_host_region(template.region_id).await?;
        Ok(Self::from_standard_data(&template, &cost_plan, &region))
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
                currency: price.currency,
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
    ) -> Self {
        Self {
            id: template.id,
            name: template.name.clone(),
            created: template.created,
            expires: template.expires,
            cpu: template.cpu,
            memory: template.memory,
            disk_size: template.disk_size,
            disk_type: template.disk_type.clone().into(),
            disk_interface: template.disk_interface.clone().into(),
            cost_plan: ApiVmCostPlan {
                id: cost_plan.id,
                name: cost_plan.name.clone(),
                amount: cost_plan.amount,
                currency: cost_plan.currency.clone(),
                interval_amount: cost_plan.interval_amount,
                interval_type: cost_plan.interval_type.clone().into(),
            },
            region: ApiVmHostRegion {
                id: region.id,
                name: region.name.clone(),
            },
        }
    }
}
#[derive(Serialize, Deserialize, JsonSchema)]
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

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ApiVmCostPlan {
    pub id: u64,
    pub name: String,
    pub amount: f32,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: ApiVmCostPlanIntervalType,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ApiVmHostRegion {
    pub id: u64,
    pub name: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct VMPatchRequest {
    /// SSH key assigned to vm
    pub ssh_key_id: Option<u64>,
    /// Reverse DNS PTR domain
    pub reverse_dns: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AccountPatchRequest {
    pub email: Option<String>,
    pub contact_nip17: bool,
    pub contact_email: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateVmRequest {
    pub template_id: u64,
    pub image_id: u64,
    pub ssh_key_id: u64,
    pub ref_code: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateSshKey {
    pub name: String,
    pub key_data: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
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

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ApiVmOsImage {
    pub id: u64,
    pub distribution: ApiOsDistribution,
    pub flavour: String,
    pub version: String,
    pub release_date: DateTime<Utc>,
}

impl From<lnvps_db::VmOsImage> for ApiVmOsImage {
    fn from(image: lnvps_db::VmOsImage) -> Self {
        ApiVmOsImage {
            id: image.id,
            distribution: image.distribution.into(),
            flavour: image.flavour,
            version: image.version,
            release_date: image.release_date,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ApiVmPayment {
    /// Payment hash hex
    pub id: String,
    pub vm_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64,
    pub invoice: String,
    pub is_paid: bool,
}

impl From<lnvps_db::VmPayment> for ApiVmPayment {
    fn from(value: lnvps_db::VmPayment) -> Self {
        Self {
            id: hex::encode(&value.id),
            vm_id: value.vm_id,
            created: value.created,
            expires: value.expires,
            amount: value.amount,
            invoice: value.invoice,
            is_paid: value.is_paid,
        }
    }
}
