#![allow(unused)]
use crate::dns::{BasicRecord, DnsServer, RecordType};
use lnvps_api_common::{ExchangeRateService, Ticker, TickerRate};
use crate::host::{
    FullVmInfo, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient, VmHostInfo,
};
use crate::lightning::{AddInvoiceRequest, AddInvoiceResult, InvoiceUpdate, LightningNode};
use crate::router::{ArpEntry, Router};
use crate::status::{VmRunningState, VmState};
use anyhow::{anyhow, bail, ensure, Context};
use chrono::{DateTime, TimeDelta, Utc};
use fedimint_tonic_lnd::tonic::codegen::tokio_stream::Stream;
use lnvps_db::{
    async_trait, AccessPolicy, Company, DiskInterface, DiskType, IpRange, IpRangeAllocationMode,
    LNVpsDb, NostrDomain, NostrDomainHandle, OsDistribution, User, UserSshKey, Vm,
    VmCostPlan, VmCostPlanIntervalType, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate,
    VmHost, VmHostDisk, VmHostKind, VmHostRegion, VmHistory, VmIpAssignment, VmOsImage, VmPayment, VmTemplate,
};
#[cfg(feature = "nostr-domain")]
use lnvps_db::nostr::LNVPSNostrDb;
use std::collections::HashMap;
use std::ops::Add;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct MockRouter {
    arp: Arc<Mutex<HashMap<u64, ArpEntry>>>,
}

impl Default for MockRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl MockRouter {
    pub fn new() -> Self {
        static LAZY_ARP: LazyLock<Arc<Mutex<HashMap<u64, ArpEntry>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

        Self {
            arp: LAZY_ARP.clone(),
        }
    }
}
#[async_trait]
impl Router for MockRouter {
    async fn generate_mac(&self, ip: &str, comment: &str) -> anyhow::Result<Option<ArpEntry>> {
        Ok(None)
    }

    async fn list_arp_entry(&self) -> anyhow::Result<Vec<ArpEntry>> {
        let arp = self.arp.lock().await;
        Ok(arp.values().cloned().collect())
    }

    async fn add_arp_entry(&self, entry: &ArpEntry) -> anyhow::Result<ArpEntry> {
        let mut arp = self.arp.lock().await;
        if arp.iter().any(|(k, v)| v.address == entry.address) {
            bail!("Address is already in use");
        }
        let max_id = *arp.keys().max().unwrap_or(&0);
        let e = ArpEntry {
            id: Some((max_id + 1).to_string()),
            ..entry.clone()
        };
        arp.insert(max_id + 1, e.clone());
        Ok(e)
    }

    async fn remove_arp_entry(&self, id: &str) -> anyhow::Result<()> {
        let mut arp = self.arp.lock().await;
        arp.remove(&id.parse::<u64>()?);
        Ok(())
    }

    async fn update_arp_entry(&self, entry: &ArpEntry) -> anyhow::Result<ArpEntry> {
        ensure!(entry.id.is_some(), "id is missing");
        let mut arp = self.arp.lock().await;
        if let Some(mut a) = arp.get_mut(&entry.id.as_ref().unwrap().parse::<u64>()?) {
            a.mac_address = entry.mac_address.clone();
            a.address = entry.address.clone();
            a.interface = entry.interface.clone();
            a.comment = entry.comment.clone();
        }
        Ok(entry.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MockNode {
    pub invoices: Arc<Mutex<HashMap<String, MockInvoice>>>,
}

#[derive(Debug, Clone)]
pub struct MockInvoice {
    pub pr: String,
    pub amount: u64,
    pub expiry: DateTime<Utc>,
    pub is_paid: bool,
}

impl MockNode {
    pub fn new() -> Self {
        static LAZY_INVOICES: LazyLock<Arc<Mutex<HashMap<String, MockInvoice>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
        Self {
            invoices: LAZY_INVOICES.clone(),
        }
    }
}

#[async_trait]
impl LightningNode for MockNode {
    async fn add_invoice(&self, req: AddInvoiceRequest) -> anyhow::Result<AddInvoiceResult> {
        let mut invoices = self.invoices.lock().await;
        let id: [u8; 32] = rand::random();
        let hex_id = hex::encode(id);
        invoices.insert(
            hex_id.clone(),
            MockInvoice {
                pr: format!("lnrt1{}", hex_id),
                amount: req.amount,
                expiry: Utc::now().add(TimeDelta::seconds(req.expire.unwrap_or(3600) as i64)),
                is_paid: false,
            },
        );
        Ok(AddInvoiceResult {
            pr: format!("lnrt1{}", hex_id),
            payment_hash: hex_id.clone(),
            external_id: None,
        })
    }

    async fn subscribe_invoices(
        &self,
        from_payment_hash: Option<Vec<u8>>,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = InvoiceUpdate> + Send>>> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct MockVmHost {
    vms: Arc<Mutex<HashMap<u64, MockVm>>>,
}

#[derive(Debug, Clone)]
struct MockVm {
    pub state: VmRunningState,
}

impl Default for MockVmHost {
    fn default() -> Self {
        Self::new()
    }
}

impl MockVmHost {
    pub fn new() -> Self {
        static LAZY_VMS: LazyLock<Arc<Mutex<HashMap<u64, MockVm>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
        Self {
            vms: LAZY_VMS.clone(),
        }
    }
}

#[async_trait]
impl VmHostClient for MockVmHost {
    async fn get_info(&self) -> anyhow::Result<VmHostInfo> {
        todo!()
    }

    async fn download_os_image(&self, image: &VmOsImage) -> anyhow::Result<()> {
        Ok(())
    }

    async fn generate_mac(&self, vm: &Vm) -> anyhow::Result<String> {
        Ok(format!(
            "ff:ff:ff:{}:{}:{}",
            hex::encode([rand::random::<u8>()]),
            hex::encode([rand::random::<u8>()]),
            hex::encode([rand::random::<u8>()]),
        ))
    }

    async fn start_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        if let Some(mut vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningState::Running;
        }
        Ok(())
    }

    async fn stop_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        if let Some(mut vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningState::Stopped;
        }
        Ok(())
    }

    async fn reset_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        if let Some(mut vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningState::Running;
        }
        Ok(())
    }

    async fn create_vm(&self, cfg: &FullVmInfo) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        let max_id = *vms.keys().max().unwrap_or(&0);
        vms.insert(
            max_id + 1,
            MockVm {
                state: VmRunningState::Stopped,
            },
        );
        Ok(())
    }

    async fn delete_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        vms.remove(&vm.id);
        Ok(())
    }

    async fn reinstall_vm(&self, cfg: &FullVmInfo) -> anyhow::Result<()> {
        todo!()
    }

    async fn get_vm_state(&self, vm: &Vm) -> anyhow::Result<VmState> {
        let vms = self.vms.lock().await;
        if let Some(vm) = vms.get(&vm.id) {
            Ok(VmState {
                timestamp: Utc::now().timestamp() as u64,
                state: vm.state.clone(),
                cpu_usage: 69.0,
                mem_usage: 69.0,
                uptime: 100,
                net_in: 69,
                net_out: 69,
                disk_write: 69,
                disk_read: 69,
            })
        } else {
            bail!("No vm with id {}", vm.id)
        }
    }

    async fn configure_vm(&self, vm: &FullVmInfo) -> anyhow::Result<()> {
        Ok(())
    }

    async fn patch_firewall(&self, cfg: &FullVmInfo) -> anyhow::Result<()> {
        todo!()
    }

    async fn get_time_series_data(
        &self,
        vm: &Vm,
        series: TimeSeries,
    ) -> anyhow::Result<Vec<TimeSeriesData>> {
        Ok(vec![])
    }

    async fn connect_terminal(&self, vm: &Vm) -> anyhow::Result<TerminalStream> {
        todo!()
    }
}

pub struct MockDnsServer {
    pub zones: Arc<Mutex<HashMap<String, HashMap<String, MockDnsEntry>>>>,
}

pub struct MockDnsEntry {
    pub name: String,
    pub value: String,
    pub kind: String,
}

impl Default for MockDnsServer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDnsServer {
    pub fn new() -> Self {
        static LAZY_ZONES: LazyLock<Arc<Mutex<HashMap<String, HashMap<String, MockDnsEntry>>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
        Self {
            zones: LAZY_ZONES.clone(),
        }
    }
}
#[async_trait]
impl DnsServer for MockDnsServer {
    async fn add_record(&self, zone_id: &str, record: &BasicRecord) -> anyhow::Result<BasicRecord> {
        let mut zones = self.zones.lock().await;
        let table = if let Some(t) = zones.get_mut(zone_id) {
            t
        } else {
            zones.insert(zone_id.to_string(), HashMap::new());
            zones.get_mut(zone_id).unwrap()
        };

        if table
            .values()
            .any(|v| v.name == record.name && v.kind == record.kind.to_string())
        {
            bail!("Duplicate record with name {}", record.name);
        }

        let rnd_id: [u8; 12] = rand::random();
        let id = hex::encode(rnd_id);
        table.insert(
            id.clone(),
            MockDnsEntry {
                name: record.name.to_string(),
                value: record.value.to_string(),
                kind: record.kind.to_string(),
            },
        );
        Ok(BasicRecord {
            name: match record.kind {
                RecordType::PTR => format!("{}.X.Y.Z.addr.in-arpa", record.name),
                _ => format!("{}.lnvps.mock", record.name),
            },
            value: record.value.clone(),
            id: Some(id),
            kind: record.kind.clone(),
        })
    }

    async fn delete_record(&self, zone_id: &str, record: &BasicRecord) -> anyhow::Result<()> {
        let mut zones = self.zones.lock().await;
        let table = if let Some(t) = zones.get_mut(zone_id) {
            t
        } else {
            zones.insert(zone_id.to_string(), HashMap::new());
            zones.get_mut(zone_id).unwrap()
        };
        ensure!(record.id.is_some(), "Id is missing");
        table.remove(record.id.as_ref().unwrap());
        Ok(())
    }

    async fn update_record(
        &self,
        zone_id: &str,
        record: &BasicRecord,
    ) -> anyhow::Result<BasicRecord> {
        let mut zones = self.zones.lock().await;
        let table = if let Some(t) = zones.get_mut(zone_id) {
            t
        } else {
            zones.insert(zone_id.to_string(), HashMap::new());
            zones.get_mut(zone_id).unwrap()
        };
        ensure!(record.id.is_some(), "Id is missing");
        if let Some(mut r) = table.get_mut(record.id.as_ref().unwrap()) {
            r.name = record.name.clone();
            r.value = record.value.clone();
            r.kind = record.kind.to_string();
        }
        Ok(record.clone())
    }
}
