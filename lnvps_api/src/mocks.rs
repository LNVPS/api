#![allow(unused)]
use crate::dns::{BasicRecord, DnsServer, RecordType};
use crate::host::{
    FullVmInfo, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient, VmHostInfo,
};
use crate::router::{ArpEntry, Router};
use anyhow::{Context, anyhow, bail, ensure};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use chrono::{DateTime, TimeDelta, Utc};
use futures::Stream;
use hex::ToHex;
use lightning_invoice::{
    Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret, PositiveTimestamp, RawBolt11Invoice,
    RawDataPart, RawHrp, SignedRawBolt11Invoice, TaggedField,
};
use lnvps_api_common::retry::{OpError, OpResult};
use lnvps_api_common::{op_fatal, ExchangeRateService, VmRunningState, VmRunningStates};
#[cfg(feature = "nostr-domain")]
use lnvps_db::nostr::LNVPSNostrDb;
use lnvps_db::{
    AccessPolicy, Company, DiskInterface, DiskType, IpRange, IpRangeAllocationMode, LNVpsDb,
    NostrDomain, NostrDomainHandle, OsDistribution, User, UserSshKey, Vm, VmCostPlan,
    VmCostPlanIntervalType, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate, VmHistory,
    VmHost, VmHostDisk, VmHostKind, VmHostRegion, VmIpAssignment, VmOsImage, VmPayment, VmTemplate,
};
use nostr_sdk::Timestamp;
use payments_rs::lightning::{AddInvoiceRequest, AddInvoiceResponse, InvoiceUpdate, LightningNode, PayInvoiceRequest, PayInvoiceResponse};
use ssh2::HashType::Sha256;
use std::collections::HashMap;
use std::ops::Add;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
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

    async fn list_arp_entry(&self) -> OpResult<Vec<ArpEntry>> {
        let arp = self.arp.lock().await;
        Ok(arp.values().cloned().collect())
    }

    async fn add_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry> {
        let mut arp = self.arp.lock().await;
        if arp.iter().any(|(k, v)| v.address == entry.address) {
            return Err(OpError::Fatal(anyhow::anyhow!(
                "Address is already in use {:?}",
                entry
            )));
        }
        let max_id = *arp.keys().max().unwrap_or(&0);
        let e = ArpEntry {
            id: Some((max_id + 1).to_string()),
            ..entry.clone()
        };
        arp.insert(max_id + 1, e.clone());
        Ok(e)
    }

    async fn remove_arp_entry(&self, id: &str) -> OpResult<()> {
        let mut arp = self.arp.lock().await;
        arp.remove(&id.parse::<u64>().map_err(|e| OpError::Fatal(e.into()))?);
        Ok(())
    }

    async fn update_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry> {
        if entry.id.is_none() {
            return Err(OpError::Fatal(anyhow::anyhow!("id is missing")));
        }
        let mut arp = self.arp.lock().await;
        if let Some(mut a) = arp.get_mut(
            &entry
                .id
                .as_ref()
                .unwrap()
                .parse::<u64>()
                .map_err(|e| OpError::Fatal(e.into()))?,
        ) {
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
    async fn add_invoice(&self, req: AddInvoiceRequest) -> anyhow::Result<AddInvoiceResponse> {
        const NODE_KEY: [u8; 32] = [0xcd; 32];

        let mut invoices = self.invoices.lock().await;
        let secret: [u8; 32] = rand::random();
        let pr = InvoiceBuilder::new(Currency::Regtest)
            .duration_since_epoch(Duration::from_secs(Timestamp::now().as_secs()))
            .payment_hash(bitcoin::hashes::sha256::Hash::from_slice(&secret).unwrap())
            .payment_secret(PaymentSecret(secret))
            .description("mock-invoice".to_string())
            .build_raw()
            .map_err(|e| anyhow!(e))?
            .sign::<_, anyhow::Error>(|s| {
                let sk = bitcoin::secp256k1::SecretKey::from_slice(&NODE_KEY)?;
                Ok(bitcoin::secp256k1::Secp256k1::signing_only().sign_ecdsa_recoverable(s, &sk))
            })?;
        let ph = hex::encode(&pr.payment_hash().unwrap().0);
        let pr = pr.to_string();
        invoices.insert(
            ph.clone(),
            MockInvoice {
                pr: pr.clone(),
                amount: req.amount,
                expiry: Utc::now().add(TimeDelta::seconds(req.expire.unwrap_or(3600) as i64)),
                is_paid: false,
            },
        );
        Ok(AddInvoiceResponse::from_invoice(&pr, None)?)
    }

    async fn cancel_invoice(&self, id: &Vec<u8>) -> anyhow::Result<()> {
        todo!()
    }

    async fn pay_invoice(&self, req: PayInvoiceRequest) -> anyhow::Result<PayInvoiceResponse> {
        todo!()
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
    pub state: VmRunningStates,
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
    async fn get_info(&self) -> OpResult<VmHostInfo> {
        todo!()
    }

    async fn download_os_image(&self, image: &VmOsImage) -> OpResult<()> {
        Ok(())
    }

    async fn generate_mac(&self, vm: &Vm) -> OpResult<String> {
        Ok(format!(
            "ff:ff:ff:{}:{}:{}",
            hex::encode([rand::random::<u8>()]),
            hex::encode([rand::random::<u8>()]),
            hex::encode([rand::random::<u8>()]),
        ))
    }

    async fn start_vm(&self, vm: &Vm) -> OpResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(mut vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningStates::Running;
        }
        Ok(())
    }

    async fn stop_vm(&self, vm: &Vm) -> OpResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(mut vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningStates::Stopped;
        }
        Ok(())
    }

    async fn reset_vm(&self, vm: &Vm) -> OpResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(mut vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningStates::Running;
        }
        Ok(())
    }

    async fn create_vm(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let mut vms = self.vms.lock().await;
        let max_id = *vms.keys().max().unwrap_or(&0);
        vms.insert(
            max_id + 1,
            MockVm {
                state: VmRunningStates::Stopped,
            },
        );
        Ok(())
    }

    async fn delete_vm(&self, vm: &Vm) -> OpResult<()> {
        let mut vms = self.vms.lock().await;
        vms.remove(&vm.id);
        Ok(())
    }

    async fn reinstall_vm(&self, cfg: &FullVmInfo) -> OpResult<()> {
        todo!()
    }

    async fn resize_disk(&self, cfg: &FullVmInfo) -> OpResult<()> {
        // Mock implementation - just return Ok for testing
        Ok(())
    }

    async fn get_vm_state(&self, vm: &Vm) -> OpResult<VmRunningState> {
        let vms = self.vms.lock().await;
        if let Some(vm) = vms.get(&vm.id) {
            Ok(VmRunningState {
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
            op_fatal!("No vm with id {}", vm.id)
        }
    }

    async fn get_all_vm_states(&self) -> OpResult<Vec<(u64, VmRunningState)>> {
        let vms = self.vms.lock().await;
        let states = vms
            .iter()
            .map(|(vm_id, vm)| {
                (
                    *vm_id,
                    VmRunningState {
                        timestamp: Utc::now().timestamp() as u64,
                        state: vm.state.clone(),
                        cpu_usage: 69.0,
                        mem_usage: 69.0,
                        uptime: 100,
                        net_in: 69,
                        net_out: 69,
                        disk_write: 69,
                        disk_read: 69,
                    },
                )
            })
            .collect();
        Ok(states)
    }

    async fn configure_vm(&self, vm: &FullVmInfo) -> OpResult<()> {
        Ok(())
    }

    async fn patch_firewall(&self, cfg: &FullVmInfo) -> OpResult<()> {
        todo!()
    }

    async fn get_time_series_data(
        &self,
        vm: &Vm,
        series: TimeSeries,
    ) -> OpResult<Vec<TimeSeriesData>> {
        Ok(vec![])
    }

    async fn connect_terminal(&self, vm: &Vm) -> OpResult<TerminalStream> {
        todo!()
    }
}

#[derive(Clone)]
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
        Self {
            zones: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
#[async_trait]
impl DnsServer for MockDnsServer {
    async fn add_record(&self, zone_id: &str, record: &BasicRecord) -> OpResult<BasicRecord> {
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
            return Err(OpError::Fatal(anyhow::anyhow!(
                "Duplicate record with name {}",
                record.name
            )));
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

    async fn delete_record(&self, zone_id: &str, record: &BasicRecord) -> OpResult<()> {
        let mut zones = self.zones.lock().await;
        let table = if let Some(t) = zones.get_mut(zone_id) {
            t
        } else {
            zones.insert(zone_id.to_string(), HashMap::new());
            zones.get_mut(zone_id).unwrap()
        };
        if record.id.is_none() {
            return Err(OpError::Fatal(anyhow::anyhow!("Id is missing")));
        }
        table.remove(record.id.as_ref().unwrap());
        Ok(())
    }

    async fn update_record(&self, zone_id: &str, record: &BasicRecord) -> OpResult<BasicRecord> {
        let mut zones = self.zones.lock().await;
        let table = if let Some(t) = zones.get_mut(zone_id) {
            t
        } else {
            zones.insert(zone_id.to_string(), HashMap::new());
            zones.get_mut(zone_id).unwrap()
        };
        if record.id.is_none() {
            return Err(OpError::Fatal(anyhow::anyhow!("Id is missing")));
        }
        if let Some(mut r) = table.get_mut(record.id.as_ref().unwrap()) {
            r.name = record.name.clone();
            r.value = record.value.clone();
            r.kind = record.kind.to_string();
        }
        Ok(record.clone())
    }
}
