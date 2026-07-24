#![allow(unused)]
use crate::host::dummy_host::DummyVmHost;
use crate::host::{
    FullVmInfo, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient, VmHostInfo,
};
use crate::router::{
    ArpEntry, BgpPeer, BgpRoute, BgpRouter, BgpSession, Router, Tunnel, TunnelRouter, TunnelTraffic,
};
pub use lnvps_api_common::MockDnsServer;

/// Type alias so tests can refer to the in-memory VM host as `MockVmHost`.
pub type MockVmHost = DummyVmHost;
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
use lnvps_api_common::{ExchangeRateService, VmRunningState, VmRunningStates, op_fatal};
#[cfg(feature = "nostr-domain")]
use lnvps_db::nostr::LNVPSNostrDb;
use lnvps_db::{
    AccessPolicy, Company, DiskInterface, DiskType, IpRange, IpRangeAllocationMode, LNVpsDb,
    NostrDomain, NostrDomainHandle, OsDistribution, User, UserSshKey, Vm, VmCostPlan,
    VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate, VmHistory, VmHost, VmHostDisk,
    VmHostKind, VmHostRegion, VmIpAssignment, VmOsImage, VmTemplate,
};
use nostr_sdk::Timestamp;
use payments_rs::lightning::{
    AddInvoiceRequest, AddInvoiceResponse, InvoiceUpdate, LightningNode, PayInvoiceRequest,
    PayInvoiceResponse,
};
use payments_rs::onchain::{
    ChainPaymentUpdate, NewAddressRequest, NewAddressResponse, OnChainProvider, PaymentCursor,
    SendCoinsRequest, SendCoinsResponse,
};
use ssh2::HashType::Sha256;
use std::collections::HashMap;
use std::ops::Add;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct MockRouter {
    arp: Arc<Mutex<HashMap<u64, ArpEntry>>>,
    tunnels: Arc<Mutex<HashMap<String, Tunnel>>>,
    sessions: Arc<Mutex<HashMap<String, BgpSession>>>,
    default_route: Arc<Mutex<Option<BgpRoute>>>,
}

impl Default for MockRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl MockRouter {
    pub fn new() -> Self {
        // Per-test-thread state (NOT a process-global): every `MockRouter`
        // built on the same thread — the test's own handle and the one the
        // code-under-test gets from `get_router()` — shares one state, while
        // tests running in parallel on different libtest threads stay isolated.
        // `#[tokio::test]` uses a current-thread runtime, so all of a test's
        // async work (and thus every `MockRouter::new()`) runs on its thread.
        thread_local! {
            static TL_ARP: Arc<Mutex<HashMap<u64, ArpEntry>>> =
                Arc::new(Mutex::new(HashMap::new()));
            static TL_TUNNELS: Arc<Mutex<HashMap<String, Tunnel>>> =
                Arc::new(Mutex::new(HashMap::new()));
            static TL_SESSIONS: Arc<Mutex<HashMap<String, BgpSession>>> =
                Arc::new(Mutex::new(HashMap::new()));
            static TL_DEFAULT_ROUTE: Arc<Mutex<Option<BgpRoute>>> =
                Arc::new(Mutex::new(Some(BgpRoute {
                    prefix: "0.0.0.0/0".to_string(),
                    next_hop: Some("192.0.2.1".to_string()),
                })));
        }

        Self {
            arp: TL_ARP.with(|a| a.clone()),
            tunnels: TL_TUNNELS.with(|t| t.clone()),
            sessions: TL_SESSIONS.with(|s| s.clone()),
            default_route: TL_DEFAULT_ROUTE.with(|d| d.clone()),
        }
    }

    /// Clear all ARP entries, tunnels and BGP sessions - useful for test isolation
    pub async fn clear(&self) {
        let mut arp = self.arp.lock().await;
        arp.clear();
        let mut tunnels = self.tunnels.lock().await;
        tunnels.clear();
        let mut sessions = self.sessions.lock().await;
        sessions.clear();
    }

    /// Seed a BGP session for tests
    pub async fn add_session(&self, session: BgpSession) {
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session.id.clone(), session);
    }
}

#[async_trait]
impl Router for MockRouter {
    async fn generate_mac(&self, ip: &str, comment: &str) -> anyhow::Result<Option<ArpEntry>> {
        // Generate a deterministic but distinct MAC from the IP so tests can verify
        // that vm.mac_address is set from ArpEntry.mac_address, not ArpEntry.address
        let bytes: Vec<u8> = ip.split('.').filter_map(|o| o.parse::<u8>().ok()).collect();
        let mac = format!(
            "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes.first().copied().unwrap_or(0),
            bytes.get(1).copied().unwrap_or(0),
            bytes.get(2).copied().unwrap_or(0),
            bytes.get(3).copied().unwrap_or(0),
        );
        let id = format!("{}={}", &mac, ip);
        let entry = ArpEntry {
            id: Some(id),
            address: ip.to_string(),
            mac_address: mac,
            interface: None,
            comment: Some(comment.to_string()),
        };
        // Store in the map so remove_arp_entry can find it later
        let mut arp = self.arp.lock().await;
        let max_id = *arp.keys().max().unwrap_or(&0);
        arp.insert(max_id + 1, entry.clone());
        Ok(Some(entry))
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
        // Try numeric key first (entries added via add_arp_entry), then fall back
        // to matching by the entry's own id field (entries added via generate_mac).
        if let Ok(numeric_id) = id.parse::<u64>() {
            arp.remove(&numeric_id);
        } else {
            arp.retain(|_, v| v.id.as_deref() != Some(id));
        }
        Ok(())
    }

    async fn update_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry> {
        if entry.id.is_none() {
            return Err(OpError::Fatal(anyhow::anyhow!("id is missing")));
        }
        let id_str = entry.id.as_ref().unwrap();
        let mut arp = self.arp.lock().await;

        // Try numeric key first (entries stored by add_arp_entry), then fall back
        // to matching by the entry's own id field (entries stored by generate_mac).
        if let Ok(numeric_id) = id_str.parse::<u64>() {
            if let Some(a) = arp.get_mut(&numeric_id) {
                a.mac_address = entry.mac_address.clone();
                a.address = entry.address.clone();
                a.interface = entry.interface.clone();
                a.comment = entry.comment.clone();
            }
        } else {
            for a in arp.values_mut() {
                if a.id.as_deref() == Some(id_str) {
                    a.mac_address = entry.mac_address.clone();
                    a.address = entry.address.clone();
                    a.interface = entry.interface.clone();
                    a.comment = entry.comment.clone();
                    break;
                }
            }
        }
        Ok(entry.clone())
    }

    fn tunnel(&self) -> Option<&dyn TunnelRouter> {
        Some(self)
    }

    fn bgp(&self) -> Option<&dyn BgpRouter> {
        Some(self)
    }
}

#[async_trait]
impl TunnelRouter for MockRouter {
    async fn list_tunnels(&self) -> OpResult<Vec<Tunnel>> {
        let tunnels = self.tunnels.lock().await;
        Ok(tunnels.values().cloned().collect())
    }

    async fn add_tunnel(&self, tunnel: &Tunnel) -> OpResult<Tunnel> {
        let mut tunnels = self.tunnels.lock().await;
        if tunnels.contains_key(&tunnel.name) {
            return Err(OpError::Fatal(anyhow::anyhow!(
                "Tunnel already exists: {}",
                tunnel.name
            )));
        }
        let stored = Tunnel {
            id: Some(tunnel.name.clone()),
            enabled: true,
            ..tunnel.clone()
        };
        tunnels.insert(tunnel.name.clone(), stored.clone());
        Ok(stored)
    }

    async fn remove_tunnel(&self, id: &str) -> OpResult<()> {
        let mut tunnels = self.tunnels.lock().await;
        tunnels.remove(id);
        Ok(())
    }

    async fn update_tunnel(&self, tunnel: &Tunnel) -> OpResult<Tunnel> {
        let mut tunnels = self.tunnels.lock().await;
        let stored = Tunnel {
            id: Some(tunnel.name.clone()),
            ..tunnel.clone()
        };
        tunnels.insert(tunnel.name.clone(), stored.clone());
        Ok(stored)
    }

    async fn set_tunnel_enabled(&self, id: &str, enabled: bool) -> OpResult<()> {
        // The mock keys tunnels by name, which is also their backend id.
        let mut tunnels = self.tunnels.lock().await;
        if let Some(t) = tunnels.get_mut(id) {
            t.enabled = enabled;
        }
        Ok(())
    }

    async fn tunnel_traffic(&self) -> OpResult<Vec<TunnelTraffic>> {
        let tunnels = self.tunnels.lock().await;
        Ok(tunnels
            .values()
            .map(|t| TunnelTraffic {
                name: t.name.clone(),
                rx_bytes: 0,
                tx_bytes: 0,
            })
            .collect())
    }
}

#[async_trait]
impl BgpRouter for MockRouter {
    async fn list_sessions(&self) -> OpResult<Vec<BgpSession>> {
        let sessions = self.sessions.lock().await;
        Ok(sessions.values().cloned().collect())
    }

    async fn originated_routes(&self, candidates: &[String]) -> OpResult<Vec<BgpRoute>> {
        let all = vec![BgpRoute {
            prefix: "203.0.113.0/24".to_string(),
            next_hop: None,
        }];
        if candidates.is_empty() {
            Ok(all)
        } else {
            Ok(all
                .into_iter()
                .filter(|r| candidates.contains(&r.prefix))
                .collect())
        }
    }

    async fn default_routes(&self) -> OpResult<Vec<BgpRoute>> {
        Ok(self
            .default_route
            .lock()
            .await
            .clone()
            .into_iter()
            .collect())
    }

    async fn set_default_route(&self, next_hop: &str) -> OpResult<()> {
        let is_v6 = next_hop.parse::<std::net::Ipv6Addr>().is_ok();
        let prefix = if is_v6 { "::/0" } else { "0.0.0.0/0" };
        *self.default_route.lock().await = Some(BgpRoute {
            prefix: prefix.to_string(),
            next_hop: Some(next_hop.to_string()),
        });
        Ok(())
    }

    async fn clear_default_route(&self) -> OpResult<()> {
        *self.default_route.lock().await = None;
        Ok(())
    }

    async fn discover_peers(&self) -> OpResult<Vec<BgpPeer>> {
        let sessions = self.sessions.lock().await;
        Ok(sessions
            .values()
            .map(|s| BgpPeer {
                peer_ip: s.peer_ip.clone(),
                asn: s.peer_asn,
                direction: s.direction,
            })
            .collect())
    }

    async fn set_session_enabled(&self, id: &str, enabled: bool) -> OpResult<()> {
        let mut sessions = self.sessions.lock().await;
        if let Some(s) = sessions.get_mut(id) {
            s.enabled = enabled;
        }
        Ok(())
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
        // Per-test-thread state (see `MockRouter::new`): isolates parallel
        // tests while sharing within a single test.
        thread_local! {
            static TL_INVOICES: Arc<Mutex<HashMap<String, MockInvoice>>> =
                Arc::new(Mutex::new(HashMap::new()));
        }
        Self {
            invoices: TL_INVOICES.with(|i| i.clone()),
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

    async fn cancel_invoice(&self, id: &[u8]) -> anyhow::Result<()> {
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

/// Mock on-chain provider, mirrors [`MockNode`] for on-chain payments.
///
/// Derives unique fake bech32-style addresses and records every request.
/// Chain updates can be pushed by tests via [`MockOnChainProvider::updates`].
#[derive(Clone, Debug, Default)]
pub struct MockOnChainProvider {
    /// Addresses handed out so far, in order.
    pub addresses: Arc<Mutex<Vec<String>>>,
    /// Scripted chain updates returned from `subscribe_payments`.
    pub updates: Arc<Mutex<Vec<ChainPaymentUpdate>>>,
    /// Every `send_coins` request received, in call order, for assertions.
    pub sends: Arc<Mutex<Vec<SendCoinsRequest>>>,
}

#[async_trait]
impl OnChainProvider for MockOnChainProvider {
    async fn new_address(&self, req: NewAddressRequest) -> anyhow::Result<NewAddressResponse> {
        let mut addresses = self.addresses.lock().await;
        let address = format!("bcrt1qmock{:08}", addresses.len());
        addresses.push(address.clone());
        Ok(NewAddressResponse {
            address,
            label: req.label,
        })
    }

    async fn subscribe_payments(
        &self,
        _from: Option<PaymentCursor>,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = ChainPaymentUpdate> + Send>>> {
        let updates = self.updates.lock().await.clone();
        Ok(Box::pin(futures::stream::iter(updates)))
    }

    async fn send_coins(&self, req: SendCoinsRequest) -> anyhow::Result<SendCoinsResponse> {
        use std::str::FromStr;
        ensure!(!req.outputs.is_empty(), "send_coins requires an output");
        let total_msat = req.total_msat();
        // Build a real (input-less) transaction paying each output so the
        // returned raw_tx is decodable and the txid is its true id — this lets
        // callers exercise outpoint (txid:vout) extraction against the mock.
        let mut tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        for o in &req.outputs {
            let script = bitcoin::Address::from_str(o.address.trim())
                .map_err(|_| anyhow!("invalid address {}", o.address))?
                .assume_checked()
                .script_pubkey();
            tx.output.push(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(o.amount.value() / 1000),
                script_pubkey: script,
            });
        }
        let txid = tx.compute_txid().to_string();
        let raw_tx = hex::encode(bitcoin::consensus::encode::serialize(&tx));
        let mut sends = self.sends.lock().await;
        sends.push(req);
        Ok(SendCoinsResponse {
            txid,
            total_amount: payments_rs::currency::CurrencyAmount::millisats(total_msat),
            fee: None,
            raw_tx: Some(raw_tx),
        })
    }
}
