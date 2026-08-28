use crate::{ExchangeRateService, Ticker, TickerRate};
use anyhow::{Context, anyhow};
use chrono::{DateTime, Days, Months, NaiveDate, TimeDelta, Utc};
use lnvps_db::nostr::LNVPSNostrDb;
use lnvps_db::{
    AccessPolicy, AgentConversation, AgentConversationFilter, AgentConversationOverview,
    AgentMessage, App, AppBackupState, AppCluster, AppDeployment, AppDeploymentBackup,
    AppDeploymentDesiredState, AppDeploymentFilter, AppDeploymentServiceUsage, AppDeploymentStatus,
    AppDeploymentVolumeUsage, AppTag, AsnSubscription, AsnSubscriptionStatus, AvailableIpSpace,
    BulkMessageTarget, Company, CpuArch, CpuMfg, DbError, DbResult, Discount, DiscountRedemption,
    DiskInterface, DiskType, DnsServer, DnsServerKind, EncryptedString, IntervalType, IpRange,
    IpRangeAllocationMode, IpRangeSubscription, IpSpacePricing, LNVpsDbBase, MarketplaceNode,
    MarketplaceNodeHealth, MarketplaceNodeStatus, MarketplaceOperator, NewAgentMessage,
    NostrDomain, NostrDomainHandle, OsDistribution, PaymentMethod, PaymentMethodConfig, Referral,
    ReferralCostUsage, ReferralPayout, Region, Router, RouterBgpRoute, RouterBgpSession,
    RouterTunnel, RouterTunnelTraffic, Subscription, SubscriptionLineItem, SubscriptionPayment,
    SubscriptionPaymentWithCompany, Tunnel, TunnelPool, TunnelRoute, User, UserPaymentMethod,
    UserSshKey, Vm, VmCostPlan, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate,
    VmFirewallPolicy, VmFirewallRule, VmHistory, VmHost, VmHostDisk, VmHostKind, VmIpAssignment,
    VmOsImage, VmTemplate, VmTrafficDaily, VmTrafficSample, VmTrafficTotal, VpnDevice, VpnService,
    VpnSubscription, WebauthnCredential,
};

use async_trait::async_trait;
#[cfg(feature = "admin")]
use lnvps_db::{AdminRole, AdminRoleAssignment, AdminUserInfo, AdminVmHost, RegionStats};
use std::collections::{HashMap, HashSet};
use std::ops::Add;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Take one page out of an already-filtered and sorted set, returning
/// `(page, total)` the way the paginated DB queries do. In-memory skip/take is
/// fine here — the real implementations push `LIMIT`/`OFFSET` into SQL.
fn paginate<T>(all: Vec<T>, limit: u64, offset: u64) -> (Vec<T>, u64) {
    let total = all.len() as u64;
    let page = all
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();
    (page, total)
}

#[derive(Debug, Clone)]
pub struct MockDb {
    pub regions: Arc<Mutex<HashMap<u64, Region>>>,
    pub hosts: Arc<Mutex<HashMap<u64, VmHost>>>,
    pub host_disks: Arc<Mutex<HashMap<u64, VmHostDisk>>>,
    pub users: Arc<Mutex<HashMap<u64, User>>>,
    pub user_ssh_keys: Arc<Mutex<HashMap<u64, UserSshKey>>>,
    pub user_payment_methods: Arc<Mutex<HashMap<u64, UserPaymentMethod>>>,
    pub cost_plans: Arc<Mutex<HashMap<u64, VmCostPlan>>>,
    pub os_images: Arc<Mutex<HashMap<u64, VmOsImage>>>,
    pub templates: Arc<Mutex<HashMap<u64, VmTemplate>>>,
    pub vms: Arc<Mutex<HashMap<u64, Vm>>>,
    pub ip_range: Arc<Mutex<HashMap<u64, IpRange>>>,
    pub ip_assignments: Arc<Mutex<HashMap<u64, VmIpAssignment>>>,
    pub custom_pricing: Arc<Mutex<HashMap<u64, VmCustomPricing>>>,
    pub custom_pricing_disk: Arc<Mutex<HashMap<u64, VmCustomPricingDisk>>>,
    pub custom_template: Arc<Mutex<HashMap<u64, VmCustomTemplate>>>,
    pub router: Arc<Mutex<HashMap<u64, Router>>>,
    pub dns_servers: Arc<Mutex<HashMap<u64, DnsServer>>>,
    pub access_policy: Arc<Mutex<HashMap<u64, AccessPolicy>>>,
    pub companies: Arc<Mutex<HashMap<u64, Company>>>,
    pub vm_history: Arc<Mutex<HashMap<u64, VmHistory>>>,
    /// Support-agent conversation threads, keyed by id.
    pub agent_conversations: Arc<Mutex<HashMap<u64, AgentConversation>>>,
    /// Support-agent messages. A `Vec` rather than a map because the log is
    /// append-only and always read in insertion order.
    pub agent_messages: Arc<Mutex<Vec<AgentMessage>>>,
    pub subscriptions: Arc<Mutex<HashMap<u64, Subscription>>>,
    pub subscription_line_items: Arc<Mutex<HashMap<u64, SubscriptionLineItem>>>,
    pub subscription_payments: Arc<Mutex<Vec<SubscriptionPayment>>>,
    pub ip_range_subscriptions: Arc<Mutex<HashMap<u64, IpRangeSubscription>>>,
    pub available_ip_space: Arc<Mutex<HashMap<u64, AvailableIpSpace>>>,
    pub asn_subscriptions: Arc<Mutex<HashMap<u64, AsnSubscription>>>,
    pub payment_method_configs: Arc<Mutex<HashMap<u64, PaymentMethodConfig>>>,
    pub referrals: Arc<Mutex<HashMap<u64, Referral>>>,
    pub discounts: Arc<Mutex<HashMap<u64, Discount>>>,
    pub discount_redemptions: Arc<Mutex<Vec<DiscountRedemption>>>,
    pub marketplace_operators: Arc<Mutex<HashMap<u64, MarketplaceOperator>>>,
    pub marketplace_nodes: Arc<Mutex<HashMap<u64, MarketplaceNode>>>,
    pub marketplace_node_health: Arc<Mutex<HashMap<u64, MarketplaceNodeHealth>>>,
    pub tunnels: Arc<Mutex<HashMap<u64, Tunnel>>>,
    pub tunnel_pools: Arc<Mutex<HashMap<u64, TunnelPool>>>,
    pub vpn_services: Arc<Mutex<HashMap<u64, VpnService>>>,
    /// `vpn_service_pool`, keyed by pool id because an interface terminates at
    /// most one service.
    pub vpn_service_pools: Arc<Mutex<HashMap<u64, u64>>>,
    pub vpn_subscriptions: Arc<Mutex<HashMap<u64, VpnSubscription>>>,
    pub vpn_devices: Arc<Mutex<HashMap<u64, VpnDevice>>>,
    /// `tunnel_route`, keyed by tunnel: the prefixes behind that peer.
    pub tunnel_routes: Arc<Mutex<HashMap<u64, Vec<String>>>>,
    pub referral_payouts: Arc<Mutex<Vec<ReferralPayout>>>,
    pub router_tunnels: Arc<Mutex<HashMap<u64, RouterTunnel>>>,
    pub router_tunnel_traffic: Arc<Mutex<Vec<RouterTunnelTraffic>>>,
    pub router_bgp_sessions: Arc<Mutex<HashMap<u64, RouterBgpSession>>>,
    pub router_bgp_routes: Arc<Mutex<HashMap<u64, RouterBgpRoute>>>,
    pub firewall_rules: Arc<Mutex<HashMap<u64, VmFirewallRule>>>,
    /// Daily traffic rows keyed by `(vm_id, day)` — the same composite primary
    /// key the table has.
    pub vm_traffic_daily: Arc<Mutex<HashMap<(u64, NaiveDate), VmTrafficDaily>>>,
    /// Last raw counter reading per VM.
    pub vm_traffic_samples: Arc<Mutex<HashMap<u64, VmTrafficSample>>>,
    pub webauthn_credentials: Arc<Mutex<HashMap<u64, WebauthnCredential>>>,
    pub apps: Arc<Mutex<HashMap<u64, App>>>,
    pub app_tags: Arc<Mutex<HashMap<u64, AppTag>>>,
    /// Assignments as `(app_id, tag_id)` pairs, standing in for the
    /// `app_tag_assignment` rows. A `Vec` rather than a map because the row id
    /// is never addressed — the unique key is the pair.
    pub app_tag_assignments: Arc<Mutex<Vec<(u64, u64)>>>,
    pub app_clusters: Arc<Mutex<HashMap<u64, AppCluster>>>,
    pub app_deployments: Arc<Mutex<HashMap<u64, AppDeployment>>>,
    pub app_deployment_backups: Arc<Mutex<HashMap<u64, AppDeploymentBackup>>>,
    #[allow(clippy::type_complexity)]
    pub app_deployment_usage_breakdown: Arc<
        Mutex<
            HashMap<
                u64,
                (
                    Vec<AppDeploymentServiceUsage>,
                    Vec<AppDeploymentVolumeUsage>,
                ),
            >,
        >,
    >,
    /// Deployment ids whose usage totals write fails. A failing write is
    /// otherwise unreachable here, and the callers' job is to survive one.
    pub failing_usage_writes: Arc<Mutex<HashSet<u64>>>,
    /// Deployment ids whose usage breakdown write fails. Separate from the
    /// totals: a grant can cover `app_deployment` and not the breakdown tables,
    /// so the two fail independently.
    pub failing_usage_breakdown_writes: Arc<Mutex<HashSet<u64>>>,
}

impl MockDb {
    /// Set a company's one-off marketplace node listing fee.
    ///
    /// Test support: the fee is normally set through the admin API, which is
    /// behind a feature the consumer API crate does not enable, so its tests
    /// cannot reach `admin_update_company`.
    pub async fn set_marketplace_node_fee(&self, company_id: u64, fee: u64) {
        let mut companies = self.companies.lock().await;
        if let Some(company) = companies.get_mut(&company_id) {
            company.marketplace_node_fee = fee;
        }
    }

    /// The `uk_tunnel_*` unique keys: a peer key or an inner address may belong
    /// to at most one tunnel. Two tunnels sharing an inner address is a routing
    /// collision that delivers one tenant's traffic to another, so the mock
    /// enforces it exactly as the schema does.
    /// `fk_tunnel_pool`: the composite key `(pool_id, router_id)` against the
    /// pool's `(id, router_id)`. A tunnel pointing at a pool on some other
    /// router would be a peer configured on an interface that is not there.
    async fn check_tunnel_pool_link(&self, tunnel: &Tunnel) -> DbResult<()> {
        let Some(pool_id) = tunnel.pool_id else {
            return Ok(());
        };
        let pools = self.tunnel_pools.lock().await;
        let pool = pools
            .get(&pool_id)
            .ok_or_else(|| DbError::Other(anyhow!("Tunnel pool {} not found", pool_id)))?;
        // A NULL in either column skips the constraint, exactly as the database
        // does for a composite foreign key.
        if let Some(router_id) = tunnel.router_id
            && router_id != pool.router_id
        {
            return Err(anyhow!(
                "Tunnel pool {} is on router {}, not router {} (fk_tunnel_pool)",
                pool_id,
                pool.router_id,
                router_id
            )
            .into());
        }
        Ok(())
    }

    /// The `uk_vpn_device_*` unique keys: a slot on a plan, and the tunnel a
    /// device is. The slot key is what makes the device limit unforgeable under
    /// concurrent registration, so a mock that did not enforce it would let a
    /// test pass that production loses. The key and address indexes live on
    /// `tunnel` now, because a device *is* a peer.
    fn check_vpn_device_uniqueness(
        devices: &HashMap<u64, VpnDevice>,
        candidate: &VpnDevice,
        skip_id: Option<u64>,
    ) -> DbResult<()> {
        for other in devices.values() {
            if Some(other.id) == skip_id {
                continue;
            }
            if other.vpn_subscription_id == candidate.vpn_subscription_id
                && other.slot == candidate.slot
            {
                return Err(anyhow!(
                    "Slot {} is already taken on this plan (uk_vpn_device_slot)",
                    candidate.slot
                )
                .into());
            }
            if other.tunnel_id == candidate.tunnel_id {
                return Err(anyhow!("That tunnel already terminates a device").into());
            }
        }
        Ok(())
    }

    fn check_tunnel_uniqueness(
        tunnels: &HashMap<u64, Tunnel>,
        candidate: &Tunnel,
        skip_id: Option<u64>,
    ) -> DbResult<()> {
        for other in tunnels.values() {
            if Some(other.id) == skip_id {
                continue;
            }
            if candidate.peer_pubkey.is_some() && other.peer_pubkey == candidate.peer_pubkey {
                return Err(anyhow!("A tunnel with that peer key already exists").into());
            }
            if candidate.address4.is_some() && other.address4 == candidate.address4 {
                return Err(anyhow!("Address {:?} is already assigned", candidate.address4).into());
            }
            if candidate.address6.is_some() && other.address6 == candidate.address6 {
                return Err(anyhow!("Address {:?} is already assigned", candidate.address6).into());
            }
        }
        Ok(())
    }

    pub fn empty() -> MockDb {
        Self {
            ..Default::default()
        }
    }

    pub fn mock_cost_plan() -> VmCostPlan {
        VmCostPlan {
            id: 1,
            name: "mock".to_string(),
            created: Utc::now(),
            amount: 132,                 // 132 cents = €1.32 (in smallest currency units)
            currency: "EUR".to_string(), // This can be overridden based on company config
            interval_amount: 1,
            interval_type: IntervalType::Month,
        }
    }

    pub fn mock_template() -> VmTemplate {
        VmTemplate {
            id: 1,
            name: "mock".to_string(),
            enabled: true,
            created: Utc::now(),
            expires: None,
            cpu: 2,
            cpu_mfg: CpuMfg::Unknown,
            cpu_arch: CpuArch::Unknown,
            cpu_features: Default::default(),
            memory: crate::GB * 2,
            disk_size: crate::GB * 64,
            disk_type: DiskType::SSD,
            disk_interface: DiskInterface::PCIe,
            cost_plan_id: 1,
            region_id: 1,
            ip4_count: 1,
            ip6_count: 1,
            disk_iops_read: None,
            disk_iops_write: None,
            disk_mbps_read: None,
            disk_mbps_write: None,
            network_mbps: None,
            cpu_limit: None,
            transfer_gb: None,
            firewall_rule_limit: None,
        }
    }

    pub fn mock_vm() -> Vm {
        let template = Self::mock_template();
        Vm {
            id: 1,
            host_id: 1,
            user_id: 1,
            image_id: 1,
            template_id: Some(template.id),
            custom_template_id: None,
            subscription_line_item_id: 1,
            ssh_key_id: Some(1),
            disk_id: 1,
            mac_address: "ff:ff:ff:ff:ff:ff".to_string(),
            ssh_host_keys: None,
            deleted: false,
            ref_code: None,
            disabled: false,
            fw_policy_in: None,
            fw_policy_out: None,
            admin_notes: None,
        }
    }
}

impl Default for MockDb {
    fn default() -> Self {
        let mut regions = HashMap::new();
        regions.insert(
            1,
            Region {
                id: 1,
                name: "Mock".to_string(),
                enabled: true,
                company_id: 1, // Link to default company
                country_code: Some("IE".to_string()),
            },
        );
        // Default mock DNS server (forward records via the shared MockDnsServer).
        let mut dns_servers = HashMap::new();
        dns_servers.insert(
            1,
            DnsServer {
                id: 1,
                name: "mock-dns".to_string(),
                enabled: true,
                kind: DnsServerKind::MockDns,
                url: "https://localhost".to_string(),
                token: "mock-token".into(),
            },
        );
        let mut ip_ranges = HashMap::new();
        ip_ranges.insert(
            1,
            IpRange {
                id: 1,
                cidr: "10.0.0.0/24".to_string(),
                gateway: "10.0.0.1/8".to_string(),
                enabled: true,
                region_id: 1,
                allocation_mode: IpRangeAllocationMode::Random, // use random due to race conditions
                forward_dns_server_id: Some(1),
                forward_zone_id: Some("mock-forward-zone-id".to_string()),
                ..Default::default()
            },
        );
        ip_ranges.insert(
            2,
            IpRange {
                id: 2,
                cidr: "fd00::/64".to_string(),
                gateway: "fd00::1".to_string(),
                enabled: true,
                region_id: 1,
                allocation_mode: IpRangeAllocationMode::SlaacEui64,
                forward_dns_server_id: Some(1),
                forward_zone_id: Some("mock-forward-zone-id".to_string()),
                ..Default::default()
            },
        );
        let mut hosts = HashMap::new();
        hosts.insert(
            1,
            VmHost {
                id: 1,
                kind: VmHostKind::Dummy,
                region_id: 1,
                name: "mock-host".to_string(),
                ip: "https://localhost".to_string(),
                cpu: 4,
                cpu_mfg: CpuMfg::Intel,
                cpu_arch: CpuArch::X86_64,
                cpu_features: Default::default(),
                memory: 8 * crate::GB,
                enabled: true,
                api_token: "".into(),
                load_cpu: 1.5,
                load_memory: 2.0,
                load_disk: 3.0,
                vlan_id: Some(100),
                mtu: None,
                ssh_user: None,
                ssh_key: None,
                sunset_date: None,
                marketplace_node_id: None,
            },
        );
        let mut host_disks = HashMap::new();
        host_disks.insert(
            1,
            VmHostDisk {
                id: 1,
                host_id: 1,
                name: "mock-disk".to_string(),
                size: crate::TB * 10,
                kind: DiskType::SSD,
                interface: DiskInterface::PCIe,
                enabled: true,
            },
        );
        let mut cost_plans = HashMap::new();
        cost_plans.insert(1, Self::mock_cost_plan());
        let mut templates = HashMap::new();
        templates.insert(1, Self::mock_template());
        let mut os_images = HashMap::new();
        os_images.insert(
            1,
            VmOsImage {
                id: 1,
                distribution: OsDistribution::Debian,
                flavour: "server".to_string(),
                version: "12".to_string(),
                enabled: true,
                release_date: Utc::now(),
                url: "https://example.com/debian_12.img".to_string(),
                cpu_arch: CpuArch::X86_64,
                default_username: None,
                sha2: None,
                sha2_url: None,
            },
        );
        Self {
            agent_conversations: Arc::new(Mutex::new(HashMap::new())),
            agent_messages: Arc::new(Mutex::new(Vec::new())),
            vm_traffic_daily: Arc::new(Mutex::new(HashMap::new())),
            vm_traffic_samples: Arc::new(Mutex::new(HashMap::new())),
            regions: Arc::new(Mutex::new(regions)),
            ip_range: Arc::new(Mutex::new(ip_ranges)),
            hosts: Arc::new(Mutex::new(hosts)),
            host_disks: Arc::new(Mutex::new(host_disks)),
            cost_plans: Arc::new(Mutex::new(cost_plans)),
            templates: Arc::new(Mutex::new(templates)),
            os_images: Arc::new(Mutex::new(os_images)),
            users: Arc::new(Default::default()),
            vms: Arc::new(Default::default()),
            ip_assignments: Arc::new(Default::default()),
            custom_pricing: Arc::new(Default::default()),
            custom_pricing_disk: Arc::new(Default::default()),
            user_ssh_keys: Arc::new(Mutex::new(Default::default())),
            user_payment_methods: Arc::new(Default::default()),
            custom_template: Arc::new(Default::default()),
            router: Arc::new(Default::default()),
            dns_servers: Arc::new(Mutex::new(dns_servers)),
            access_policy: Arc::new(Default::default()),
            companies: Arc::new(Mutex::new({
                let mut companies = HashMap::new();
                companies.insert(
                    1,
                    Company {
                        id: 1,
                        created: Utc::now(),
                        name: "Default Company".to_string(),
                        address_1: None,
                        address_2: None,
                        city: None,
                        state: None,
                        country_code: None,
                        tax_id: None,
                        postcode: None,
                        phone: None,
                        email: None,
                        base_currency: "EUR".to_string(),
                        referral_rate: 0.0,
                        max_prepay_days: 0,
                        marketplace_rate: 0.0,
                        marketplace_node_fee: 0,
                    },
                );
                companies
            })),
            vm_history: Arc::new(Default::default()),
            subscriptions: Arc::new(Mutex::new({
                let mut m = HashMap::new();
                m.insert(
                    1u64,
                    Subscription {
                        id: 1,
                        user_id: 1,
                        company_id: 1,
                        name: "mock subscription".to_string(),
                        description: None,
                        created: Utc::now(),
                        expires: None,
                        is_active: false,
                        is_setup: false,
                        currency: "BTC".to_string(),
                        interval_amount: 1,
                        interval_type: IntervalType::Month,
                        setup_fee: 0,
                        auto_renewal_enabled: false,
                        external_id: None,
                    },
                );
                m
            })),
            subscription_line_items: Arc::new(Mutex::new({
                let mut m = HashMap::new();
                m.insert(
                    1u64,
                    SubscriptionLineItem {
                        id: 1,
                        subscription_id: 1,
                        subscription_type: lnvps_db::LineItemType::Vps,
                        name: "mock vm renewal".to_string(),
                        description: None,
                        amount: 1000,
                        setup_amount: 0,
                        configuration: None,
                    },
                );
                m
            })),
            subscription_payments: Arc::new(Default::default()),
            ip_range_subscriptions: Arc::new(Default::default()),
            available_ip_space: Arc::new(Default::default()),
            asn_subscriptions: Arc::new(Default::default()),
            payment_method_configs: Arc::new(Default::default()),
            referrals: Arc::new(Default::default()),
            discounts: Arc::new(Default::default()),
            discount_redemptions: Arc::new(Default::default()),
            marketplace_operators: Arc::new(Default::default()),
            marketplace_nodes: Arc::new(Default::default()),
            marketplace_node_health: Arc::new(Default::default()),
            tunnels: Arc::new(Default::default()),
            tunnel_pools: Arc::new(Default::default()),
            vpn_services: Arc::new(Default::default()),
            vpn_service_pools: Arc::new(Default::default()),
            vpn_subscriptions: Arc::new(Default::default()),
            vpn_devices: Arc::new(Default::default()),
            tunnel_routes: Arc::new(Default::default()),
            referral_payouts: Arc::new(Default::default()),
            router_tunnels: Arc::new(Default::default()),
            router_tunnel_traffic: Arc::new(Default::default()),
            router_bgp_sessions: Arc::new(Default::default()),
            router_bgp_routes: Arc::new(Default::default()),
            firewall_rules: Arc::new(Default::default()),
            webauthn_credentials: Arc::new(Default::default()),
            apps: Arc::new(Default::default()),
            app_tags: Arc::new(Default::default()),
            app_tag_assignments: Arc::new(Default::default()),
            app_clusters: Arc::new(Default::default()),
            app_deployments: Arc::new(Default::default()),
            app_deployment_backups: Arc::new(Default::default()),
            app_deployment_usage_breakdown: Arc::new(Default::default()),
            failing_usage_writes: Arc::new(Default::default()),
            failing_usage_breakdown_writes: Arc::new(Default::default()),
        }
    }
}

#[async_trait]
impl LNVpsDbBase for MockDb {
    async fn migrate(&self) -> DbResult<()> {
        Ok(())
    }

    async fn upsert_user(&self, pubkey: &[u8; 32]) -> DbResult<u64> {
        let mut users = self.users.lock().await;
        if let Some(e) = users.iter().find(|(_k, u)| u.pubkey == *pubkey) {
            Ok(*e.0)
        } else {
            let max = *users.keys().max().unwrap_or(&0);
            users.insert(
                max + 1,
                User {
                    id: max + 1,
                    pubkey: pubkey.to_vec(),
                    created: Utc::now(),
                    country_code: Some("USA".to_string()),
                    ..Default::default()
                },
            );
            Ok(max + 1)
        }
    }

    async fn upsert_oauth_user(&self, pubkey: &[u8; 32]) -> DbResult<u64> {
        let mut users = self.users.lock().await;
        if let Some(e) = users.iter().find(|(_k, u)| u.pubkey == *pubkey) {
            Ok(*e.0)
        } else {
            let max = *users.keys().max().unwrap_or(&0);
            users.insert(
                max + 1,
                User {
                    id: max + 1,
                    pubkey: pubkey.to_vec(),
                    account_type: lnvps_db::AccountType::OAuth,
                    created: Utc::now(),
                    country_code: Some("USA".to_string()),
                    ..Default::default()
                },
            );
            Ok(max + 1)
        }
    }

    async fn upsert_webauthn_user(&self, pubkey: &[u8; 32]) -> DbResult<u64> {
        let mut users = self.users.lock().await;
        if let Some(e) = users.iter().find(|(_k, u)| u.pubkey == *pubkey) {
            Ok(*e.0)
        } else {
            let max = *users.keys().max().unwrap_or(&0);
            users.insert(
                max + 1,
                User {
                    id: max + 1,
                    pubkey: pubkey.to_vec(),
                    account_type: lnvps_db::AccountType::Webauthn,
                    created: Utc::now(),
                    country_code: Some("USA".to_string()),
                    ..Default::default()
                },
            );
            Ok(max + 1)
        }
    }

    async fn insert_webauthn_credential(&self, cred: &WebauthnCredential) -> DbResult<u64> {
        let mut creds = self.webauthn_credentials.lock().await;
        let max = *creds.keys().max().unwrap_or(&0);
        let id = max + 1;
        let mut stored = cred.clone();
        stored.id = id;
        stored.created = Utc::now();
        creds.insert(id, stored);
        Ok(id)
    }

    async fn list_webauthn_credentials(&self, user_id: u64) -> DbResult<Vec<WebauthnCredential>> {
        let creds = self.webauthn_credentials.lock().await;
        Ok(creds
            .values()
            .filter(|c| c.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn get_webauthn_credential(&self, cred_id: &[u8]) -> DbResult<WebauthnCredential> {
        let creds = self.webauthn_credentials.lock().await;
        Ok(creds
            .values()
            .find(|c| c.cred_id == cred_id)
            .ok_or(anyhow!("no credential"))?
            .clone())
    }

    async fn update_webauthn_credential(&self, id: u64, passkey: &str) -> DbResult<()> {
        let mut creds = self.webauthn_credentials.lock().await;
        if let Some(c) = creds.get_mut(&id) {
            c.passkey = passkey.to_string();
            c.last_used = Some(Utc::now());
        }
        Ok(())
    }

    async fn delete_webauthn_credential(&self, id: u64, user_id: u64) -> DbResult<()> {
        let mut creds = self.webauthn_credentials.lock().await;
        creds.retain(|_, c| !(c.id == id && c.user_id == user_id));
        Ok(())
    }

    async fn get_user(&self, id: u64) -> DbResult<User> {
        let users = self.users.lock().await;
        Ok(users.get(&id).ok_or(anyhow!("no user"))?.clone())
    }

    async fn update_user(&self, user: &User) -> DbResult<()> {
        let mut users = self.users.lock().await;
        if let Some(u) = users.get_mut(&user.id) {
            u.email = user.email.clone();
            u.email_hash = user.email_hash.clone();
            u.email_verified = user.email_verified;
            u.email_verify_token = user.email_verify_token.clone();
            u.email_verify_sent = user.email_verify_sent;
            u.session_version = user.session_version;
            u.contact_email = user.contact_email;
            u.contact_nip17 = user.contact_nip17;
            u.contact_telegram = user.contact_telegram;
            u.telegram_chat_id = user.telegram_chat_id;
            u.telegram_link_token = user.telegram_link_token.clone();
            u.contact_whatsapp = user.contact_whatsapp;
            u.whatsapp_number = user.whatsapp_number.clone();
            u.whatsapp_verified = user.whatsapp_verified;
            u.whatsapp_verify_code = user.whatsapp_verify_code.clone();
            u.whatsapp_verify_attempts = user.whatsapp_verify_attempts;
            u.country_code = user.country_code.clone();
            u.billing_name = user.billing_name.clone();
            u.billing_address_1 = user.billing_address_1.clone();
            u.billing_address_2 = user.billing_address_2.clone();
            u.billing_city = user.billing_city.clone();
            u.billing_state = user.billing_state.clone();
            u.billing_postcode = user.billing_postcode.clone();
            u.billing_tax_id = user.billing_tax_id.clone();
            u.geo_country_code = user.geo_country_code.clone();
            u.geo_ip = user.geo_ip.clone();
            u.geo_updated = user.geo_updated;
        }
        Ok(())
    }

    async fn set_user_geo(
        &self,
        user_id: u64,
        country_code: Option<&str>,
        ip: &str,
    ) -> DbResult<()> {
        let mut users = self.users.lock().await;
        if let Some(u) = users.get_mut(&user_id) {
            u.geo_country_code = country_code.map(|s| s.to_string());
            u.geo_ip = Some(ip.to_string());
            u.geo_updated = Some(chrono::Utc::now());
        }
        Ok(())
    }

    async fn delete_user(&self, id: u64) -> DbResult<()> {
        // Guard: refuse to purge a user with live (non-deleted) VMs.
        let user_vm_ids: Vec<u64> = {
            let vms = self.vms.lock().await;
            if vms.values().any(|v| v.user_id == id && !v.deleted) {
                return Err(DbError::Other(anyhow!(
                    "Cannot delete user with active VM(s); delete the VMs first"
                )));
            }
            vms.values()
                .filter(|v| v.user_id == id)
                .map(|v| v.id)
                .collect()
        };

        // Collect the per-VM custom templates (1:1 with their VM) so they can be
        // removed alongside the VMs.
        let custom_template_ids: Vec<u64> = {
            let vms = self.vms.lock().await;
            vms.values()
                .filter(|v| v.user_id == id)
                .filter_map(|v| v.custom_template_id)
                .collect()
        };

        // Remove VM child records.
        self.ip_assignments
            .lock()
            .await
            .retain(|_, a| !user_vm_ids.contains(&a.vm_id));
        self.firewall_rules
            .lock()
            .await
            .retain(|_, r| !user_vm_ids.contains(&r.vm_id));
        self.vm_history
            .lock()
            .await
            .retain(|_, h| !user_vm_ids.contains(&h.vm_id));
        // Stands in for the ON DELETE CASCADE on the traffic tables; the mock
        // has no foreign keys to do it.
        self.vm_traffic_daily
            .lock()
            .await
            .retain(|_, t| !user_vm_ids.contains(&t.vm_id));
        self.vm_traffic_samples
            .lock()
            .await
            .retain(|vm_id, _| !user_vm_ids.contains(vm_id));

        // Remove the VMs, their 1:1 custom templates, and the user's other records.
        self.vms.lock().await.retain(|_, v| v.user_id != id);
        self.custom_template
            .lock()
            .await
            .retain(|tid, _| !custom_template_ids.contains(tid));
        self.user_ssh_keys
            .lock()
            .await
            .retain(|_, k| k.user_id != id);
        self.user_payment_methods
            .lock()
            .await
            .retain(|_, m| m.user_id != id);
        self.subscription_payments
            .lock()
            .await
            .retain(|p| p.user_id != id);
        let removed_subs: Vec<u64> = {
            let mut subs = self.subscriptions.lock().await;
            let ids: Vec<u64> = subs
                .values()
                .filter(|s| s.user_id == id)
                .map(|s| s.id)
                .collect();
            subs.retain(|_, s| s.user_id != id);
            ids
        };
        self.subscription_line_items
            .lock()
            .await
            .retain(|_, li| !removed_subs.contains(&li.subscription_id));
        let removed_refs: Vec<u64> = {
            let mut refs = self.referrals.lock().await;
            let ids: Vec<u64> = refs
                .values()
                .filter(|r| r.user_id == id)
                .map(|r| r.id)
                .collect();
            refs.retain(|_, r| r.user_id != id);
            ids
        };
        self.referral_payouts
            .lock()
            .await
            .retain(|p| !removed_refs.contains(&p.referral_id));
        self.webauthn_credentials
            .lock()
            .await
            .retain(|_, c| c.user_id != id);

        self.users.lock().await.remove(&id);
        Ok(())
    }

    async fn get_user_by_email_verify_token(&self, token: &str) -> DbResult<User> {
        let users = self.users.lock().await;
        users
            .values()
            .find(|u| !u.email_verify_token.is_empty() && u.email_verify_token == token)
            .cloned()
            .ok_or_else(|| DbError::Other(anyhow!("no user with that token")))
    }

    async fn get_user_by_telegram_link_token(&self, token: &str) -> DbResult<User> {
        let users = self.users.lock().await;
        users
            .values()
            .find(|u| u.telegram_link_token.as_deref() == Some(token))
            .cloned()
            .ok_or_else(|| DbError::Other(anyhow!("no user with that token")))
    }

    async fn link_telegram_chat(&self, user_id: u64, chat_id: i64) -> DbResult<()> {
        let mut users = self.users.lock().await;
        if let Some(u) = users.get_mut(&user_id) {
            u.telegram_chat_id = Some(chat_id);
            u.contact_telegram = true;
            u.telegram_link_token = None;
        }
        Ok(())
    }

    async fn list_users(&self) -> DbResult<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users.values().cloned().collect())
    }

    async fn list_users_by_ids(&self, ids: &[u64]) -> DbResult<Vec<User>> {
        let users = self.users.lock().await;
        Ok(ids.iter().filter_map(|id| users.get(id).cloned()).collect())
    }

    async fn list_users_paginated(&self, limit: u64, offset: u64) -> DbResult<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn count_users(&self) -> DbResult<u64> {
        let users = self.users.lock().await;
        Ok(users.len() as u64)
    }

    async fn insert_user_payment_method(&self, pm: &UserPaymentMethod) -> DbResult<u64> {
        let mut methods = self.user_payment_methods.lock().await;
        let id = *methods.keys().max().unwrap_or(&0) + 1;
        let mut new_pm = pm.clone();
        new_pm.id = id;
        methods.insert(id, new_pm);
        Ok(id)
    }

    async fn list_user_payment_methods(
        &self,
        user_id: u64,
        provider: Option<&str>,
    ) -> DbResult<Vec<UserPaymentMethod>> {
        let methods = self.user_payment_methods.lock().await;
        let mut out: Vec<UserPaymentMethod> = methods
            .values()
            .filter(|m| m.user_id == user_id)
            .filter(|m| provider.map(|p| m.provider == p).unwrap_or(true))
            .cloned()
            .collect();
        out.sort_by(|a, b| b.is_default.cmp(&a.is_default).then(a.id.cmp(&b.id)));
        Ok(out)
    }

    async fn get_user_payment_method(&self, id: u64) -> DbResult<UserPaymentMethod> {
        let methods = self.user_payment_methods.lock().await;
        methods
            .get(&id)
            .cloned()
            .ok_or_else(|| DbError::from(anyhow!("Payment method not found")))
    }

    async fn admin_list_user_payment_methods_paginated(
        &self,
        limit: u64,
        offset: u64,
        user_id: Option<u64>,
    ) -> DbResult<(Vec<UserPaymentMethod>, u64)> {
        let methods = self.user_payment_methods.lock().await;
        let mut all: Vec<UserPaymentMethod> = methods
            .values()
            .filter(|m| user_id.map(|u| m.user_id == u).unwrap_or(true))
            .cloned()
            .collect();
        all.sort_by(|a, b| b.id.cmp(&a.id));
        let total = all.len() as u64;
        let page = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, total))
    }

    async fn update_user_payment_method(&self, pm: &UserPaymentMethod) -> DbResult<()> {
        let mut methods = self.user_payment_methods.lock().await;
        methods.insert(pm.id, pm.clone());
        Ok(())
    }

    async fn delete_user_payment_method(&self, id: u64) -> DbResult<()> {
        let mut methods = self.user_payment_methods.lock().await;
        methods.remove(&id);
        Ok(())
    }

    async fn insert_user_ssh_key(&self, new_key: &UserSshKey) -> DbResult<u64> {
        let mut ssh_keys = self.user_ssh_keys.lock().await;
        let max_keys = *ssh_keys.keys().max().unwrap_or(&0);
        ssh_keys.insert(
            max_keys + 1,
            UserSshKey {
                id: max_keys + 1,
                ..new_key.clone()
            },
        );
        Ok(max_keys + 1)
    }

    async fn get_user_ssh_key(&self, id: u64) -> DbResult<UserSshKey> {
        let keys = self.user_ssh_keys.lock().await;
        Ok(keys.get(&id).ok_or(anyhow!("no key"))?.clone())
    }

    async fn list_user_ssh_keys_by_ids(&self, ids: &[u64]) -> DbResult<Vec<UserSshKey>> {
        let keys = self.user_ssh_keys.lock().await;
        Ok(ids.iter().filter_map(|id| keys.get(id).cloned()).collect())
    }

    async fn delete_user_ssh_key(&self, id: u64) -> DbResult<()> {
        let mut keys = self.user_ssh_keys.lock().await;
        keys.remove(&id);
        Ok(())
    }

    async fn list_user_ssh_key(&self, user_id: u64) -> DbResult<Vec<UserSshKey>> {
        let keys = self.user_ssh_keys.lock().await;
        Ok(keys
            .values()
            .filter(|u| u.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn list_host_region(&self) -> DbResult<Vec<Region>> {
        let regions = self.regions.lock().await;
        Ok(regions.values().filter(|r| r.enabled).cloned().collect())
    }

    async fn list_host_region_all(&self) -> DbResult<Vec<Region>> {
        let regions = self.regions.lock().await;
        Ok(regions.values().cloned().collect())
    }

    async fn get_host_region(&self, id: u64) -> DbResult<Region> {
        let regions = self.regions.lock().await;
        Ok(regions.get(&id).ok_or(anyhow!("no region"))?.clone())
    }

    async fn get_host_region_by_name(&self, name: &str) -> DbResult<Region> {
        let regions = self.regions.lock().await;
        Ok(regions
            .iter()
            .find(|(_, v)| v.name == name)
            .ok_or(anyhow!("no region"))?
            .1
            .clone())
    }

    async fn list_hosts(&self) -> DbResult<Vec<VmHost>> {
        let hosts = self.hosts.lock().await;
        let regions = self.regions.lock().await;
        // Mirrors the SQL: a host in a disabled region is not a placement
        // target either.
        Ok(hosts
            .values()
            .filter(|h| {
                h.enabled
                    && regions
                        .get(&h.region_id)
                        .map(|r| r.enabled)
                        .unwrap_or(false)
            })
            .cloned()
            .collect())
    }

    async fn list_hosts_all(&self) -> DbResult<Vec<VmHost>> {
        let hosts = self.hosts.lock().await;
        Ok(hosts.values().cloned().collect())
    }

    async fn list_hosts_paginated(&self, limit: u64, offset: u64) -> DbResult<(Vec<VmHost>, u64)> {
        let hosts = self.hosts.lock().await;
        let filtered_hosts: Vec<VmHost> = hosts.values().filter(|h| h.enabled).cloned().collect();
        let total = filtered_hosts.len() as u64;
        let paginated: Vec<VmHost> = filtered_hosts
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((paginated, total))
    }

    async fn list_hosts_with_regions_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<(VmHost, Region)>, u64)> {
        let hosts = self.hosts.lock().await;
        let regions = self.regions.lock().await;
        let filtered_hosts: Vec<VmHost> = hosts.values().filter(|h| h.enabled).cloned().collect();
        let total = filtered_hosts.len() as u64;

        let mut hosts_with_regions = Vec::new();
        for host in filtered_hosts
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
        {
            if let Some(region) = regions.get(&host.region_id) {
                hosts_with_regions.push((host, region.clone()));
            }
        }
        Ok((hosts_with_regions, total))
    }

    async fn get_host(&self, id: u64) -> DbResult<VmHost> {
        let hosts = self.hosts.lock().await;
        Ok(hosts.get(&id).ok_or(anyhow!("no host"))?.clone())
    }

    async fn update_host(&self, host: &VmHost) -> DbResult<()> {
        let mut hosts = self.hosts.lock().await;
        if let Some(h) = hosts.get_mut(&host.id) {
            // Every column the real UPDATE writes, and only those:
            // `marketplace_node_id` is deliberately absent, because a host
            // cannot change which machine backs it.
            let marketplace_node_id = h.marketplace_node_id;
            *h = VmHost {
                marketplace_node_id,
                ..host.clone()
            };
        }
        Ok(())
    }

    async fn create_host(&self, host: &VmHost) -> DbResult<u64> {
        // fk/uk_vm_host_marketplace_node: a node backs exactly one host, so a
        // second approval must not be able to create a second host that no
        // control channel would ever reach.
        if let Some(node_id) = host.marketplace_node_id {
            if !self.marketplace_nodes.lock().await.contains_key(&node_id) {
                return Err(anyhow!("Marketplace node {} not found", node_id).into());
            }
            if self
                .hosts
                .lock()
                .await
                .values()
                .any(|h| h.marketplace_node_id == Some(node_id))
            {
                return Err(anyhow!("Marketplace node {} already backs a host", node_id).into());
            }
        }
        let mut hosts = self.hosts.lock().await;
        let id = (hosts.len() as u64) + 1;
        let mut new_host = host.clone();
        new_host.id = id;
        hosts.insert(id, new_host);
        Ok(id)
    }

    async fn list_host_disks(&self, host_id: u64) -> DbResult<Vec<VmHostDisk>> {
        let disks = self.host_disks.lock().await;
        Ok(disks
            .values()
            .filter(|d| d.enabled && d.host_id == host_id)
            .cloned()
            .collect())
    }

    async fn list_host_disks_all(&self, host_id: u64) -> DbResult<Vec<VmHostDisk>> {
        let disks = self.host_disks.lock().await;
        Ok(disks
            .values()
            .filter(|d| d.host_id == host_id)
            .cloned()
            .collect())
    }

    async fn get_host_disk(&self, disk_id: u64) -> DbResult<VmHostDisk> {
        let disks = self.host_disks.lock().await;
        Ok(disks.get(&disk_id).ok_or(anyhow!("no disk"))?.clone())
    }

    async fn update_host_disk(&self, disk: &VmHostDisk) -> DbResult<()> {
        let mut disks = self.host_disks.lock().await;
        if let Some(d) = disks.get_mut(&disk.id) {
            d.name = disk.name.clone();
            d.size = disk.size;
            d.kind = disk.kind;
            d.interface = disk.interface;
            d.enabled = disk.enabled;
        }
        Ok(())
    }

    async fn create_host_disk(&self, disk: &VmHostDisk) -> DbResult<u64> {
        let mut disks = self.host_disks.lock().await;
        let max_id = disks.keys().max().unwrap_or(&0);
        let new_id = max_id + 1;
        let mut new_disk = disk.clone();
        new_disk.id = new_id;
        disks.insert(new_id, new_disk);
        Ok(new_id)
    }

    async fn get_os_image(&self, id: u64) -> DbResult<VmOsImage> {
        let os_images = self.os_images.lock().await;
        Ok(os_images.get(&id).ok_or(anyhow!("no image"))?.clone())
    }

    async fn list_os_image(&self) -> DbResult<Vec<VmOsImage>> {
        let os_images = self.os_images.lock().await;
        Ok(os_images.values().filter(|i| i.enabled).cloned().collect())
    }

    async fn count_vms_by_os_image(&self) -> DbResult<Vec<(u64, u64)>> {
        let vms = self.vms.lock().await;
        let mut counts: HashMap<u64, u64> = HashMap::new();
        for vm in vms.values().filter(|v| !v.deleted) {
            *counts.entry(vm.image_id).or_insert(0) += 1;
        }
        Ok(counts.into_iter().collect())
    }

    async fn update_os_image(&self, image: &VmOsImage) -> DbResult<()> {
        let mut os_images = self.os_images.lock().await;
        os_images.insert(image.id, image.clone());
        Ok(())
    }

    async fn get_ip_range(&self, id: u64) -> DbResult<IpRange> {
        let ip_range = self.ip_range.lock().await;
        Ok(ip_range.get(&id).ok_or(anyhow!("no ip range"))?.clone())
    }

    async fn list_ip_range(&self) -> DbResult<Vec<IpRange>> {
        let ip_range = self.ip_range.lock().await;
        Ok(ip_range.values().filter(|r| r.enabled).cloned().collect())
    }

    async fn list_ip_range_in_region(&self, region_id: u64) -> DbResult<Vec<IpRange>> {
        let ip_range = self.ip_range.lock().await;
        Ok(ip_range
            .values()
            .filter(|r| r.enabled && r.region_id == region_id)
            .cloned()
            .collect())
    }

    async fn get_cost_plan(&self, id: u64) -> DbResult<VmCostPlan> {
        let cost_plans = self.cost_plans.lock().await;
        Ok(cost_plans.get(&id).ok_or(anyhow!("no cost plan"))?.clone())
    }

    async fn list_cost_plans(&self) -> DbResult<Vec<VmCostPlan>> {
        let cost_plans = self.cost_plans.lock().await;
        Ok(cost_plans.values().cloned().collect())
    }

    async fn list_cost_plans_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<VmCostPlan>, u64)> {
        let cost_plans = self.cost_plans.lock().await;
        let mut all: Vec<_> = cost_plans.values().cloned().collect();
        all.sort_by(|a, b| b.id.cmp(&a.id));
        let total = all.len() as u64;
        let page = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, total))
    }

    async fn insert_cost_plan(&self, cost_plan: &VmCostPlan) -> DbResult<u64> {
        let mut cost_plans = self.cost_plans.lock().await;
        let max = *cost_plans.keys().max().unwrap_or(&0);
        let id = max + 1;
        let mut new_cost_plan = cost_plan.clone();
        new_cost_plan.id = id;
        cost_plans.insert(id, new_cost_plan);
        Ok(id)
    }

    async fn update_cost_plan(&self, cost_plan: &VmCostPlan) -> DbResult<()> {
        let mut cost_plans = self.cost_plans.lock().await;
        if cost_plans.contains_key(&cost_plan.id) {
            cost_plans.insert(cost_plan.id, cost_plan.clone());
        }
        Ok(())
    }

    async fn delete_cost_plan(&self, id: u64) -> DbResult<()> {
        let mut cost_plans = self.cost_plans.lock().await;
        cost_plans.remove(&id);
        Ok(())
    }

    async fn get_vm_template(&self, id: u64) -> DbResult<VmTemplate> {
        let templates = self.templates.lock().await;
        Ok(templates.get(&id).ok_or(anyhow!("no template"))?.clone())
    }

    async fn list_vm_templates(&self) -> DbResult<Vec<VmTemplate>> {
        let templates = self.templates.lock().await;
        Ok(templates
            .values()
            .filter(|t| t.enabled && t.expires.as_ref().map(|e| *e > Utc::now()).unwrap_or(true))
            .cloned()
            .collect())
    }

    async fn list_vm_templates_all(&self) -> DbResult<Vec<VmTemplate>> {
        let templates = self.templates.lock().await;
        Ok(templates.values().cloned().collect())
    }

    async fn insert_vm_template(&self, template: &VmTemplate) -> DbResult<u64> {
        let mut templates = self.templates.lock().await;
        let max_id = *templates.keys().max().unwrap_or(&0);
        templates.insert(
            max_id + 1,
            VmTemplate {
                id: max_id + 1,
                ..template.clone()
            },
        );
        Ok(max_id + 1)
    }

    async fn get_vm_traffic_sample(&self, vm_id: u64) -> DbResult<Option<VmTrafficSample>> {
        let samples = self.vm_traffic_samples.lock().await;
        Ok(samples.get(&vm_id).cloned())
    }

    async fn upsert_vm_traffic_sample(
        &self,
        vm_id: u64,
        bytes_in: u64,
        bytes_out: u64,
    ) -> DbResult<()> {
        let mut samples = self.vm_traffic_samples.lock().await;
        samples.insert(
            vm_id,
            VmTrafficSample {
                vm_id,
                last_bytes_in: bytes_in,
                last_bytes_out: bytes_out,
                sampled: Utc::now(),
            },
        );
        Ok(())
    }

    async fn add_vm_traffic(
        &self,
        vm_id: u64,
        day: NaiveDate,
        bytes_in: u64,
        bytes_out: u64,
    ) -> DbResult<()> {
        let mut traffic = self.vm_traffic_daily.lock().await;
        let row = traffic
            .entry((vm_id, day))
            .or_insert_with(|| VmTrafficDaily {
                vm_id,
                day,
                bytes_in: 0,
                bytes_out: 0,
            });
        row.bytes_in += bytes_in;
        row.bytes_out += bytes_out;
        Ok(())
    }

    async fn list_vm_traffic(
        &self,
        vm_id: u64,
        start: NaiveDate,
        end: NaiveDate,
    ) -> DbResult<Vec<VmTrafficDaily>> {
        let traffic = self.vm_traffic_daily.lock().await;
        let mut rows: Vec<VmTrafficDaily> = traffic
            .values()
            .filter(|r| r.vm_id == vm_id && r.day >= start && r.day <= end)
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.day);
        Ok(rows)
    }

    async fn list_vm_traffic_totals(
        &self,
        start: NaiveDate,
        end: NaiveDate,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<VmTrafficTotal>, u64)> {
        let vms = self.vms.lock().await;
        let traffic = self.vm_traffic_daily.lock().await;

        let mut totals: HashMap<u64, VmTrafficTotal> = HashMap::new();
        for row in traffic.values() {
            if row.day < start || row.day > end {
                continue;
            }
            // Rows whose VM is gone cannot be attributed, matching the join in
            // the MySQL implementation.
            let Some(vm) = vms.get(&row.vm_id) else {
                continue;
            };
            let entry = totals.entry(row.vm_id).or_insert(VmTrafficTotal {
                vm_id: row.vm_id,
                user_id: vm.user_id,
                bytes_in: 0,
                bytes_out: 0,
            });
            entry.bytes_in += row.bytes_in;
            entry.bytes_out += row.bytes_out;
        }

        let mut rows: Vec<VmTrafficTotal> = totals.into_values().collect();
        rows.sort_by(|a, b| b.bytes_out.cmp(&a.bytes_out).then(a.vm_id.cmp(&b.vm_id)));
        let total = rows.len() as u64;
        Ok((
            rows.into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect(),
            total,
        ))
    }

    async fn list_vm_traffic_totals_by_vms(
        &self,
        vm_ids: &[u64],
        start: NaiveDate,
        end: NaiveDate,
    ) -> DbResult<Vec<lnvps_db::VmTrafficTotal>> {
        let vms = self.vms.lock().await;
        let owners: std::collections::HashMap<u64, u64> = vms
            .values()
            .map(|v| (v.id, v.user_id))
            .filter(|(id, _)| vm_ids.contains(id))
            .collect();
        drop(vms);

        let rows = self.vm_traffic_daily.lock().await;
        let mut totals: std::collections::HashMap<u64, (u64, u64)> = Default::default();
        for ((vm_id, day), row) in rows.iter() {
            if !vm_ids.contains(vm_id) || *day < start || *day > end {
                continue;
            }
            let e = totals.entry(*vm_id).or_default();
            e.0 += row.bytes_in;
            e.1 += row.bytes_out;
        }

        Ok(totals
            .into_iter()
            .map(|(vm_id, (bytes_in, bytes_out))| lnvps_db::VmTrafficTotal {
                vm_id,
                user_id: owners.get(&vm_id).copied().unwrap_or_default(),
                bytes_in,
                bytes_out,
            })
            .collect())
    }

    async fn get_vm_traffic_total(
        &self,
        vm_id: u64,
        start: NaiveDate,
        end: NaiveDate,
    ) -> DbResult<(u64, u64)> {
        let rows = self.list_vm_traffic(vm_id, start, end).await?;
        Ok(rows
            .iter()
            .fold((0, 0), |(i, o), r| (i + r.bytes_in, o + r.bytes_out)))
    }

    async fn list_vms(&self) -> DbResult<Vec<Vm>> {
        let vms = self.vms.lock().await;
        Ok(vms.values().filter(|v| !v.deleted).cloned().collect())
    }

    async fn list_vms_on_host(&self, host_id: u64) -> DbResult<Vec<Vm>> {
        let vms = self.vms.lock().await;
        Ok(vms
            .values()
            .filter(|v| !v.deleted && v.host_id == host_id)
            .cloned()
            .collect())
    }

    async fn count_active_vms_on_host(&self, host_id: u64) -> DbResult<u64> {
        let vms = self.vms.lock().await;
        Ok(vms
            .values()
            .filter(|v| !v.deleted && v.host_id == host_id)
            .count() as u64)
    }

    async fn list_expired_vms(&self) -> DbResult<Vec<Vm>> {
        // In the mock, cross-reference subscription expires.
        // Collect VM ids and subscription line item ids first.
        let vm_list: Vec<Vm> = {
            let vms = self.vms.lock().await;
            vms.values().filter(|v| !v.deleted).cloned().collect()
        };
        let mut expired = Vec::new();
        for vm in vm_list {
            let line_items = self.subscription_line_items.lock().await;
            let sub_id = line_items
                .get(&vm.subscription_line_item_id)
                .map(|li| li.subscription_id);
            drop(line_items);
            if let Some(sid) = sub_id {
                let subs = self.subscriptions.lock().await;
                if let Some(sub) = subs.get(&sid) {
                    if sub.expires.map(|e| e < Utc::now()).unwrap_or(true) {
                        expired.push(vm);
                    }
                }
            }
        }
        Ok(expired)
    }

    async fn list_active_vms(&self) -> DbResult<Vec<Vm>> {
        // Active VMs: non-deleted whose subscription has been set up (paid at
        // least once), regardless of current expiry (expired VMs included).
        let vm_list: Vec<Vm> = {
            let vms = self.vms.lock().await;
            vms.values().filter(|v| !v.deleted).cloned().collect()
        };
        let mut active = Vec::new();
        for vm in vm_list {
            let sub_id = {
                let line_items = self.subscription_line_items.lock().await;
                line_items
                    .get(&vm.subscription_line_item_id)
                    .map(|li| li.subscription_id)
            };
            if let Some(sid) = sub_id {
                let subs = self.subscriptions.lock().await;
                if let Some(sub) = subs.get(&sid) {
                    if sub.is_setup {
                        active.push(vm);
                    }
                }
            }
        }
        Ok(active)
    }

    async fn list_user_vms(&self, id: u64) -> DbResult<Vec<Vm>> {
        let vms = self.vms.lock().await;
        Ok(vms
            .values()
            .filter(|v| !v.deleted && v.user_id == id)
            .cloned()
            .collect())
    }

    async fn get_vm(&self, vm_id: u64) -> DbResult<Vm> {
        let vms = self.vms.lock().await;
        Ok(vms.get(&vm_id).ok_or(anyhow!("no vm"))?.clone())
    }

    async fn list_vms_by_mac(&self, mac_address: &str) -> DbResult<Vec<Vm>> {
        let vms = self.vms.lock().await;
        Ok(vms
            .values()
            .filter(|v| !v.deleted && v.mac_address == mac_address)
            .cloned()
            .collect())
    }

    async fn insert_vm(&self, vm: &Vm) -> DbResult<u64> {
        let mut vms = self.vms.lock().await;
        let max_id = *vms.keys().max().unwrap_or(&0);

        // lazy test FK
        self.get_host(vm.host_id).await?;
        self.get_user(vm.user_id).await?;
        self.get_os_image(vm.image_id).await?;
        if let Some(t) = vm.template_id {
            self.get_vm_template(t).await?;
        }
        if let Some(t) = vm.custom_template_id {
            self.get_custom_vm_template(t).await?;
        }
        if let Some(k) = vm.ssh_key_id {
            self.get_user_ssh_key(k).await?;
        }
        self.get_host_disk(vm.disk_id).await?;

        vms.insert(
            max_id + 1,
            Vm {
                id: max_id + 1,
                ..vm.clone()
            },
        );
        Ok(max_id + 1)
    }

    async fn insert_vm_with_id(&self, vm: &Vm) -> DbResult<u64> {
        let mut vms = self.vms.lock().await;
        if vm.id == 0 {
            return Err(DbError::from(anyhow!(
                "insert_vm_with_id requires a non-zero id"
            )));
        }
        if vms.contains_key(&vm.id) {
            return Err(DbError::from(anyhow!("VM id {} already exists", vm.id)));
        }

        // lazy test FK
        self.get_host(vm.host_id).await?;
        self.get_user(vm.user_id).await?;
        self.get_os_image(vm.image_id).await?;
        if let Some(t) = vm.template_id {
            self.get_vm_template(t).await?;
        }
        if let Some(t) = vm.custom_template_id {
            self.get_custom_vm_template(t).await?;
        }
        if let Some(k) = vm.ssh_key_id {
            self.get_user_ssh_key(k).await?;
        }
        self.get_host_disk(vm.disk_id).await?;

        vms.insert(vm.id, vm.clone());
        Ok(vm.id)
    }

    async fn delete_vm(&self, vm_id: u64) -> DbResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(vm) = vms.get_mut(&vm_id) {
            vm.deleted = true;
            vm.ssh_key_id = None;
        }
        Ok(())
    }

    async fn hard_delete_vm(&self, vm_id: u64) -> DbResult<()> {
        // Resolve the subscription for this VM (via its line item) before removal.
        let subscription_id = {
            let vms = self.vms.lock().await;
            let line_items = self.subscription_line_items.lock().await;
            vms.get(&vm_id)
                .and_then(|vm| line_items.get(&vm.subscription_line_item_id))
                .map(|li| li.subscription_id)
        };

        self.vms.lock().await.remove(&vm_id);
        self.vm_history.lock().await.retain(|_, h| h.vm_id != vm_id);
        self.firewall_rules
            .lock()
            .await
            .retain(|_, r| r.vm_id != vm_id);
        self.ip_assignments
            .lock()
            .await
            .retain(|_, a| a.vm_id != vm_id);
        // Stands in for the ON DELETE CASCADE on the traffic tables; the mock
        // has no foreign keys to do it.
        self.vm_traffic_daily
            .lock()
            .await
            .retain(|_, t| t.vm_id != vm_id);
        self.vm_traffic_samples.lock().await.remove(&vm_id);

        if let Some(subscription_id) = subscription_id {
            self.subscription_payments
                .lock()
                .await
                .retain(|p| p.subscription_id != subscription_id);
            self.subscription_line_items
                .lock()
                .await
                .retain(|_, li| li.subscription_id != subscription_id);
            self.subscriptions.lock().await.remove(&subscription_id);
        }
        Ok(())
    }

    async fn list_deleted_never_paid_vm_ids(&self) -> DbResult<Vec<u64>> {
        let vms = self.vms.lock().await;
        let line_items = self.subscription_line_items.lock().await;
        let subscriptions = self.subscriptions.lock().await;
        Ok(vms
            .values()
            .filter(|v| v.deleted)
            .filter(|v| {
                line_items
                    .get(&v.subscription_line_item_id)
                    .and_then(|li| subscriptions.get(&li.subscription_id))
                    .map(|s| !s.is_setup)
                    .unwrap_or(false)
            })
            .map(|v| v.id)
            .collect())
    }

    async fn update_vm(&self, vm: &Vm) -> DbResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(v) = vms.get_mut(&vm.id) {
            v.image_id = vm.image_id;
            v.template_id = vm.template_id;
            v.custom_template_id = vm.custom_template_id;
            v.subscription_line_item_id = vm.subscription_line_item_id;
            v.ssh_key_id = vm.ssh_key_id;
            v.disk_id = vm.disk_id;
            v.mac_address = vm.mac_address.clone();
            v.disabled = vm.disabled;
        }
        Ok(())
    }

    async fn update_vm_host(&self, vm_id: u64, host_id: u64, disk_id: u64) -> DbResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(v) = vms.get_mut(&vm_id) {
            v.host_id = host_id;
            v.disk_id = disk_id;
        }
        Ok(())
    }

    async fn set_vm_ssh_host_keys(&self, vm_id: u64, keys: Option<&str>) -> DbResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(v) = vms.get_mut(&vm_id) {
            v.ssh_host_keys = keys.map(|k| k.to_string());
        }
        Ok(())
    }

    async fn get_vm_by_line_item(&self, line_item_id: u64) -> DbResult<Vm> {
        let vms = self.vms.lock().await;
        vms.values()
            .find(|v| v.subscription_line_item_id == line_item_id && !v.deleted)
            .cloned()
            .ok_or_else(|| anyhow!("VM not found for line item {}", line_item_id).into())
    }

    async fn list_vms_by_line_items(&self, line_item_ids: &[u64]) -> DbResult<Vec<Vm>> {
        let vms = self.vms.lock().await;
        Ok(vms
            .values()
            .filter(|v| line_item_ids.contains(&v.subscription_line_item_id) && !v.deleted)
            .cloned()
            .collect())
    }

    async fn get_vm_by_subscription(&self, subscription_id: u64) -> DbResult<Vm> {
        use lnvps_db::LineItemType;
        let items = self.subscription_line_items.lock().await;
        let line_item_id = items
            .values()
            .find(|li| {
                li.subscription_id == subscription_id
                    && matches!(li.subscription_type, LineItemType::Vps)
            })
            .map(|li| li.id)
            .ok_or_else(|| {
                DbError::Other(anyhow!(
                    "No VM line item for subscription {}",
                    subscription_id
                ))
            })?;
        drop(items);
        // Mirror the MySQL impl: unlike get_vm_by_line_item, this does NOT
        // filter deleted VMs (callers such as the on-chain watcher need to
        // see deleted VMs to hold deposits for manual resolution).
        let vms = self.vms.lock().await;
        vms.values()
            .find(|v| v.subscription_line_item_id == line_item_id)
            .cloned()
            .ok_or_else(|| anyhow!("VM not found for line item {}", line_item_id).into())
    }

    async fn list_vm_subscription_payments(
        &self,
        vm_id: u64,
    ) -> DbResult<Vec<SubscriptionPayment>> {
        let vms = self.vms.lock().await;
        let vm = vms
            .get(&vm_id)
            .ok_or_else(|| DbError::Other(anyhow!("VM not found")))?;
        let line_item_id = vm.subscription_line_item_id;
        drop(vms);

        // resolve subscription_id via line_item
        let items = self.subscription_line_items.lock().await;
        let subscription_id = items
            .get(&line_item_id)
            .ok_or_else(|| DbError::Other(anyhow!("Line item {} not found", line_item_id)))?
            .subscription_id;
        drop(items);

        let payments = self.subscription_payments.lock().await;
        let mut result: Vec<_> = payments
            .iter()
            .filter(|p| p.subscription_id == subscription_id)
            .cloned()
            .collect();
        result.sort_by(|a, b| b.created.cmp(&a.created));
        Ok(result)
    }

    async fn list_pending_vm_subscription_payments(
        &self,
        vm_id: u64,
    ) -> DbResult<Vec<SubscriptionPayment>> {
        let all = self.list_vm_subscription_payments(vm_id).await?;
        let now = Utc::now();
        Ok(all
            .into_iter()
            .filter(|p| !p.is_paid && p.expires > now)
            .collect())
    }

    async fn list_vm_subscription_payments_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<Vec<SubscriptionPayment>> {
        let all = self.list_vm_subscription_payments(vm_id).await?;
        Ok(all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn count_vm_subscription_payments(&self, vm_id: u64) -> DbResult<u64> {
        let all = self.list_vm_subscription_payments(vm_id).await?;
        Ok(all.len() as u64)
    }

    async fn insert_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> DbResult<u64> {
        let mut ip_assignments = self.ip_assignments.lock().await;
        let max = *ip_assignments.keys().max().unwrap_or(&0);
        ip_assignments.insert(
            max + 1,
            VmIpAssignment {
                id: max + 1,
                ..ip_assignment.clone()
            },
        );
        Ok(max + 1)
    }

    async fn update_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> DbResult<()> {
        let mut ip_assignments = self.ip_assignments.lock().await;
        if let Some(i) = ip_assignments.get_mut(&ip_assignment.id) {
            i.arp_ref = ip_assignment.arp_ref.clone();
            i.dns_forward = ip_assignment.dns_forward.clone();
            i.dns_reverse = ip_assignment.dns_reverse.clone();
            i.dns_reverse_ref = ip_assignment.dns_reverse_ref.clone();
            i.dns_forward_ref = ip_assignment.dns_forward_ref.clone();
        }
        Ok(())
    }

    async fn list_vm_ip_assignments(&self, vm_id: u64) -> DbResult<Vec<VmIpAssignment>> {
        let ip_assignments = self.ip_assignments.lock().await;
        Ok(ip_assignments
            .values()
            .filter(|a| a.vm_id == vm_id && !a.deleted)
            .cloned()
            .collect())
    }

    async fn list_vm_ip_assignments_by_vms(&self, vm_ids: &[u64]) -> DbResult<Vec<VmIpAssignment>> {
        let ip_assignments = self.ip_assignments.lock().await;
        Ok(ip_assignments
            .values()
            .filter(|a| vm_ids.contains(&a.vm_id) && !a.deleted)
            .cloned()
            .collect())
    }

    async fn list_vm_ip_assignments_in_range(
        &self,
        range_id: u64,
    ) -> DbResult<Vec<VmIpAssignment>> {
        let ip_assignments = self.ip_assignments.lock().await;
        Ok(ip_assignments
            .values()
            .filter(|a| a.ip_range_id == range_id && !a.deleted)
            .cloned()
            .collect())
    }

    async fn delete_vm_ip_assignments_by_vm_id(&self, vm_id: u64) -> DbResult<()> {
        let mut ip_assignments = self.ip_assignments.lock().await;
        for ip_assignment in ip_assignments.values_mut() {
            if ip_assignment.vm_id == vm_id {
                ip_assignment.deleted = true;
            }
        }
        Ok(())
    }

    async fn hard_delete_vm_ip_assignments_by_vm_id(&self, vm_id: u64) -> DbResult<()> {
        let mut ip_assignments = self.ip_assignments.lock().await;
        ip_assignments.retain(|_, v| v.vm_id != vm_id);
        Ok(())
    }

    async fn hard_delete_vm_ip_assignment(&self, assignment_id: u64) -> DbResult<()> {
        let mut ip_assignments = self.ip_assignments.lock().await;
        ip_assignments.retain(|_, v| v.id != assignment_id);
        Ok(())
    }

    async fn delete_vm_ip_assignment(&self, assignment_id: u64) -> DbResult<()> {
        let mut ip_assignments = self.ip_assignments.lock().await;
        for ip_assignment in ip_assignments.values_mut() {
            if ip_assignment.id == assignment_id {
                ip_assignment.deleted = true;
            }
        }
        Ok(())
    }

    async fn insert_vm_firewall_rule(&self, rule: &VmFirewallRule) -> DbResult<u64> {
        let mut rules = self.firewall_rules.lock().await;
        let max = *rules.keys().max().unwrap_or(&0);
        let id = max + 1;
        rules.insert(id, VmFirewallRule { id, ..rule.clone() });
        Ok(id)
    }

    async fn get_vm_firewall_rule(&self, rule_id: u64) -> DbResult<VmFirewallRule> {
        let rules = self.firewall_rules.lock().await;
        rules
            .get(&rule_id)
            .cloned()
            .ok_or_else(|| DbError::Other(anyhow!("Firewall rule not found")))
    }

    async fn list_vm_firewall_rules(&self, vm_id: u64) -> DbResult<Vec<VmFirewallRule>> {
        let rules = self.firewall_rules.lock().await;
        let mut out: Vec<VmFirewallRule> = rules
            .values()
            .filter(|r| r.vm_id == vm_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.id.cmp(&b.id)));
        Ok(out)
    }

    async fn update_vm_firewall_rule(&self, rule: &VmFirewallRule) -> DbResult<()> {
        let mut rules = self.firewall_rules.lock().await;
        if let Some(r) = rules.get_mut(&rule.id) {
            r.priority = rule.priority;
            r.direction = rule.direction;
            r.protocol = rule.protocol;
            r.action = rule.action;
            r.src_cidr = rule.src_cidr.clone();
            r.dst_port_start = rule.dst_port_start;
            r.dst_port_end = rule.dst_port_end;
            r.enabled = rule.enabled;
        }
        Ok(())
    }

    async fn delete_vm_firewall_rule(&self, rule_id: u64) -> DbResult<()> {
        let mut rules = self.firewall_rules.lock().await;
        rules.remove(&rule_id);
        Ok(())
    }

    async fn update_vm_firewall_policy(
        &self,
        vm_id: u64,
        policy_in: Option<VmFirewallPolicy>,
        policy_out: Option<VmFirewallPolicy>,
    ) -> DbResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(vm) = vms.get_mut(&vm_id) {
            vm.fw_policy_in = policy_in;
            vm.fw_policy_out = policy_out;
        }
        Ok(())
    }

    async fn list_custom_pricing(&self, _tb: u64) -> DbResult<Vec<VmCustomPricing>> {
        let p = self.custom_pricing.lock().await;
        Ok(p.values().cloned().collect())
    }

    async fn list_all_custom_pricing(&self) -> DbResult<Vec<VmCustomPricing>> {
        let p = self.custom_pricing.lock().await;
        Ok(p.values().cloned().collect())
    }

    async fn list_custom_pricing_paginated(
        &self,
        region_id: Option<u64>,
        enabled: Option<bool>,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<VmCustomPricing>, u64)> {
        let p = self.custom_pricing.lock().await;
        let mut all: Vec<_> = p
            .values()
            .filter(|v| region_id.map_or(true, |r| v.region_id == r))
            .filter(|v| enabled.map_or(true, |e| v.enabled == e))
            .cloned()
            .collect();
        all.sort_by(|a, b| b.id.cmp(&a.id));
        let total = all.len() as u64;
        let page = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, total))
    }

    async fn get_custom_pricing(&self, id: u64) -> DbResult<VmCustomPricing> {
        let p = self.custom_pricing.lock().await;
        Ok(p.get(&id).cloned().context("no custom pricing")?)
    }

    async fn get_custom_vm_template(&self, id: u64) -> DbResult<VmCustomTemplate> {
        let t = self.custom_template.lock().await;
        Ok(t.get(&id).cloned().context("no custom template")?)
    }

    async fn list_custom_vm_templates_by_ids(
        &self,
        ids: &[u64],
    ) -> DbResult<Vec<VmCustomTemplate>> {
        let t = self.custom_template.lock().await;
        Ok(ids.iter().filter_map(|id| t.get(id).cloned()).collect())
    }

    async fn insert_custom_vm_template(&self, template: &VmCustomTemplate) -> DbResult<u64> {
        let mut t = self.custom_template.lock().await;
        let max_id = *t.keys().max().unwrap_or(&0);
        t.insert(
            max_id + 1,
            VmCustomTemplate {
                id: max_id + 1,
                ..template.clone()
            },
        );
        Ok(max_id + 1)
    }

    async fn update_custom_vm_template(&self, template: &VmCustomTemplate) -> DbResult<()> {
        let mut t = self.custom_template.lock().await;
        t.insert(template.id, template.clone());
        Ok(())
    }

    async fn delete_orphaned_custom_vm_templates(&self) -> DbResult<u64> {
        let referenced: std::collections::HashSet<u64> = {
            let vms = self.vms.lock().await;
            vms.values().filter_map(|v| v.custom_template_id).collect()
        };
        let mut t = self.custom_template.lock().await;
        let before = t.len();
        t.retain(|id, _| referenced.contains(id));
        Ok((before - t.len()) as u64)
    }

    async fn list_custom_pricing_disk(
        &self,
        pricing_id: u64,
    ) -> DbResult<Vec<VmCustomPricingDisk>> {
        let d = self.custom_pricing_disk.lock().await;
        Ok(d.values()
            .filter(|d| d.pricing_id == pricing_id)
            .cloned()
            .collect())
    }

    async fn get_router(&self, router_id: u64) -> DbResult<Router> {
        let r = self.router.lock().await;
        Ok(r.get(&router_id).cloned().context("no router")?)
    }

    async fn list_routers(&self) -> DbResult<Vec<Router>> {
        let routers = self.router.lock().await;
        Ok(routers.values().cloned().collect())
    }

    async fn get_dns_server(&self, dns_server_id: u64) -> DbResult<DnsServer> {
        let d = self.dns_servers.lock().await;
        Ok(d.get(&dns_server_id).cloned().context("no dns server")?)
    }

    async fn list_dns_servers(&self) -> DbResult<Vec<DnsServer>> {
        let d = self.dns_servers.lock().await;
        Ok(d.values().cloned().collect())
    }

    async fn list_dns_servers_paginated(
        &self,
        _limit: u64,
        _offset: u64,
    ) -> DbResult<(Vec<DnsServer>, u64)> {
        let d = self.dns_servers.lock().await;
        let all: Vec<DnsServer> = d.values().cloned().collect();
        let total = all.len() as u64;
        Ok((all, total))
    }

    async fn insert_dns_server(&self, dns_server: &DnsServer) -> DbResult<u64> {
        let mut d = self.dns_servers.lock().await;
        let id = d.keys().max().copied().unwrap_or(0) + 1;
        let mut new = dns_server.clone();
        new.id = id;
        d.insert(id, new);
        Ok(id)
    }

    async fn update_dns_server(&self, dns_server: &DnsServer) -> DbResult<()> {
        let mut d = self.dns_servers.lock().await;
        d.insert(dns_server.id, dns_server.clone());
        Ok(())
    }

    async fn delete_dns_server(&self, dns_server_id: u64) -> DbResult<()> {
        let mut d = self.dns_servers.lock().await;
        d.remove(&dns_server_id);
        Ok(())
    }

    async fn count_dns_server_ip_ranges(&self, dns_server_id: u64) -> DbResult<u64> {
        let ranges = self.ip_range.lock().await;
        Ok(ranges
            .values()
            .filter(|r| {
                r.forward_dns_server_id == Some(dns_server_id)
                    || r.reverse_dns_server_id == Some(dns_server_id)
            })
            .count() as u64)
    }

    async fn update_ip_range_dns(&self, range: &IpRange) -> DbResult<()> {
        let mut ranges = self.ip_range.lock().await;
        if let Some(existing) = ranges.get_mut(&range.id) {
            existing.forward_dns_server_id = range.forward_dns_server_id;
            existing.reverse_dns_server_id = range.reverse_dns_server_id;
            existing.forward_zone_id = range.forward_zone_id.clone();
            existing.reverse_zone_id = range.reverse_zone_id.clone();
        }
        Ok(())
    }

    async fn list_router_tunnels(&self, router_id: u64) -> DbResult<Vec<RouterTunnel>> {
        let t = self.router_tunnels.lock().await;
        Ok(t.values()
            .filter(|x| x.router_id == router_id)
            .cloned()
            .collect())
    }

    async fn upsert_router_tunnel(&self, tunnel: &RouterTunnel) -> DbResult<u64> {
        let mut t = self.router_tunnels.lock().await;
        if let Some(existing) = t
            .values_mut()
            .find(|x| x.router_id == tunnel.router_id && x.name == tunnel.name)
        {
            let id = existing.id;
            *existing = RouterTunnel {
                id,
                last_seen: Utc::now(),
                ..tunnel.clone()
            };
            return Ok(id);
        }
        let id = t.keys().max().copied().unwrap_or(0) + 1;
        t.insert(
            id,
            RouterTunnel {
                id,
                last_seen: Utc::now(),
                ..tunnel.clone()
            },
        );
        Ok(id)
    }

    async fn delete_router_tunnel(&self, id: u64) -> DbResult<()> {
        let mut t = self.router_tunnels.lock().await;
        t.remove(&id);
        Ok(())
    }

    async fn insert_router_tunnel_traffic(&self, sample: &RouterTunnelTraffic) -> DbResult<u64> {
        let mut t = self.router_tunnel_traffic.lock().await;
        let id = t.len() as u64 + 1;
        t.push(RouterTunnelTraffic {
            id,
            sampled_at: Utc::now(),
            ..sample.clone()
        });
        Ok(id)
    }

    async fn list_router_tunnel_traffic(
        &self,
        router_id: u64,
        tunnel_name: &str,
        from: chrono::DateTime<Utc>,
        to: chrono::DateTime<Utc>,
    ) -> DbResult<Vec<RouterTunnelTraffic>> {
        let t = self.router_tunnel_traffic.lock().await;
        let mut out: Vec<RouterTunnelTraffic> = t
            .iter()
            .filter(|x| {
                x.router_id == router_id
                    && x.tunnel_name == tunnel_name
                    && x.sampled_at >= from
                    && x.sampled_at <= to
            })
            .cloned()
            .collect();
        out.sort_by_key(|x| x.sampled_at);
        Ok(out)
    }

    async fn list_router_bgp_sessions(&self, router_id: u64) -> DbResult<Vec<RouterBgpSession>> {
        let s = self.router_bgp_sessions.lock().await;
        Ok(s.values()
            .filter(|x| x.router_id == router_id)
            .cloned()
            .collect())
    }

    async fn upsert_router_bgp_session(&self, session: &RouterBgpSession) -> DbResult<u64> {
        let mut s = self.router_bgp_sessions.lock().await;
        if let Some(existing) = s
            .values_mut()
            .find(|x| x.router_id == session.router_id && x.name == session.name)
        {
            let id = existing.id;
            // `enabled` is only set on first import; afterwards it is admin-controlled
            // and discovery refreshes must not clobber it.
            let enabled = existing.enabled;
            *existing = RouterBgpSession {
                id,
                enabled,
                last_seen: Utc::now(),
                ..session.clone()
            };
            return Ok(id);
        }
        let id = s.keys().max().copied().unwrap_or(0) + 1;
        s.insert(
            id,
            RouterBgpSession {
                id,
                last_seen: Utc::now(),
                ..session.clone()
            },
        );
        Ok(id)
    }

    async fn set_router_bgp_session_enabled(
        &self,
        router_id: u64,
        name: &str,
        enabled: bool,
    ) -> DbResult<()> {
        let mut s = self.router_bgp_sessions.lock().await;
        if let Some(existing) = s
            .values_mut()
            .find(|x| x.router_id == router_id && x.name == name)
        {
            existing.enabled = enabled;
        }
        Ok(())
    }

    async fn delete_router_bgp_session(&self, id: u64) -> DbResult<()> {
        let mut s = self.router_bgp_sessions.lock().await;
        s.remove(&id);
        Ok(())
    }

    async fn list_router_bgp_routes(&self, router_id: u64) -> DbResult<Vec<RouterBgpRoute>> {
        let r = self.router_bgp_routes.lock().await;
        Ok(r.values()
            .filter(|x| x.router_id == router_id)
            .cloned()
            .collect())
    }

    async fn replace_router_bgp_routes(
        &self,
        router_id: u64,
        routes: &[RouterBgpRoute],
    ) -> DbResult<()> {
        let mut r = self.router_bgp_routes.lock().await;
        r.retain(|_, x| x.router_id != router_id);
        let mut next_id = r.keys().max().copied().unwrap_or(0) + 1;
        for route in routes {
            r.insert(
                next_id,
                RouterBgpRoute {
                    id: next_id,
                    router_id,
                    last_seen: Utc::now(),
                    ..route.clone()
                },
            );
            next_id += 1;
        }
        Ok(())
    }

    async fn get_vm_ip_assignment(&self, id: u64) -> DbResult<VmIpAssignment> {
        let assignments = self.ip_assignments.lock().await;
        Ok(assignments
            .values()
            .find(|a| a.id == id)
            .cloned()
            .ok_or_else(|| anyhow!("IP assignment not found for {}", id))?)
    }

    async fn get_vm_ip_assignment_by_ip(&self, ip: &str) -> DbResult<VmIpAssignment> {
        let assignments = self.ip_assignments.lock().await;
        Ok(assignments
            .values()
            .find(|a| a.ip == ip)
            .cloned()
            .ok_or_else(|| anyhow!("IP assignment not found for {}", ip))?)
    }

    async fn get_access_policy(&self, access_policy_id: u64) -> DbResult<AccessPolicy> {
        let p = self.access_policy.lock().await;
        Ok(p.get(&access_policy_id)
            .cloned()
            .context("no access policy")?)
    }

    async fn get_company(&self, company_id: u64) -> DbResult<Company> {
        let companies = self.companies.lock().await;
        Ok(companies
            .get(&company_id)
            .cloned()
            .ok_or_else(|| anyhow!("Company with id {} not found", company_id))?)
    }

    async fn list_companies(&self) -> DbResult<Vec<Company>> {
        let companies = self.companies.lock().await;
        let mut result: Vec<Company> = companies.values().cloned().collect();
        result.sort_by_key(|c| c.id);
        Ok(result)
    }

    async fn get_vm_base_currency(&self, vm_id: u64) -> DbResult<String> {
        // Follow VM -> Host -> Region -> Company chain
        let vms = self.vms.lock().await;
        let vm = vms.get(&vm_id).ok_or_else(|| anyhow!("VM not found"))?;

        let hosts = self.hosts.lock().await;
        let host = hosts
            .get(&vm.host_id)
            .ok_or_else(|| anyhow!("Host not found"))?;

        let regions = self.regions.lock().await;
        let region = regions
            .get(&host.region_id)
            .ok_or_else(|| anyhow!("Region not found"))?;

        let companies = self.companies.lock().await;
        let company = companies
            .get(&region.company_id)
            .ok_or_else(|| anyhow!("Company not found"))?;
        Ok(company.base_currency.clone())
    }

    async fn get_vm_company_id(&self, vm_id: u64) -> DbResult<u64> {
        // Follow VM -> Host -> Region -> Company chain
        let vms = self.vms.lock().await;
        let vm = vms.get(&vm_id).ok_or_else(|| anyhow!("VM not found"))?;

        let hosts = self.hosts.lock().await;
        let host = hosts
            .get(&vm.host_id)
            .ok_or_else(|| anyhow!("Host not found"))?;

        let regions = self.regions.lock().await;
        let region = regions
            .get(&host.region_id)
            .ok_or_else(|| anyhow!("Region not found"))?;

        Ok(region.company_id)
    }

    // ── Support agent conversations ──────────────────────────────

    async fn upsert_agent_conversation(
        &self,
        conversation_key: &str,
        user_id: Option<u64>,
    ) -> DbResult<AgentConversation> {
        let mut conversations = self.agent_conversations.lock().await;

        if let Some(existing) = conversations
            .values_mut()
            .find(|c| c.conversation_key == conversation_key)
        {
            // Link a thread that started anonymous, but never clear the link.
            if existing.user_id.is_none() && user_id.is_some() {
                existing.user_id = user_id;
            }
            return Ok(existing.clone());
        }

        let id = (conversations.len() + 1) as u64;
        let now = chrono::Utc::now();
        let conversation = AgentConversation {
            id,
            conversation_key: conversation_key.to_string(),
            user_id,
            summary: None,
            compacted_upto: 0,
            created: now,
            updated: now,
        };
        conversations.insert(id, conversation.clone());
        Ok(conversation)
    }

    async fn get_agent_conversation(&self, id: u64) -> DbResult<AgentConversation> {
        self.agent_conversations
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| DbError::from(anyhow!("agent conversation {} not found", id)))
    }

    async fn get_agent_conversation_overview(
        &self,
        id: u64,
    ) -> DbResult<AgentConversationOverview> {
        let conversation = self.get_agent_conversation(id).await?;
        let messages = self.agent_messages.lock().await;
        let own: Vec<&AgentMessage> = messages
            .iter()
            .filter(|m| m.conversation_id == id)
            .collect();
        Ok(AgentConversationOverview {
            id: conversation.id,
            conversation_key: conversation.conversation_key,
            user_id: conversation.user_id,
            summary: conversation.summary,
            compacted_upto: conversation.compacted_upto,
            created: conversation.created,
            updated: conversation.updated,
            message_count: own.len() as u64,
            last_message_at: own.iter().map(|m| m.created).max(),
        })
    }

    async fn list_agent_conversations(
        &self,
        filter: &AgentConversationFilter,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<AgentConversationOverview>, u64)> {
        let messages = self.agent_messages.lock().await.clone();
        let mut matched: Vec<AgentConversationOverview> = self
            .agent_conversations
            .lock()
            .await
            .values()
            .filter(|c| filter.user_id.is_none() || c.user_id == filter.user_id)
            .filter(|c| {
                // Case-insensitive, matching the SQL implementation's LOWER().
                filter.key_search.as_ref().is_none_or(|s| {
                    c.conversation_key
                        .to_lowercase()
                        .contains(&s.trim().to_lowercase())
                })
            })
            .map(|c| {
                let own: Vec<&AgentMessage> = messages
                    .iter()
                    .filter(|m| m.conversation_id == c.id)
                    .collect();
                AgentConversationOverview {
                    id: c.id,
                    conversation_key: c.conversation_key.clone(),
                    user_id: c.user_id,
                    summary: c.summary.clone(),
                    compacted_upto: c.compacted_upto,
                    created: c.created,
                    updated: c.updated,
                    message_count: own.len() as u64,
                    last_message_at: own.iter().map(|m| m.created).max(),
                }
            })
            .collect();

        // Same order as the SQL: most recently active first, id as tie-break.
        matched.sort_by(|a, b| b.updated.cmp(&a.updated).then(b.id.cmp(&a.id)));
        let total = matched.len() as u64;
        Ok((
            matched
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect(),
            total,
        ))
    }

    async fn count_agent_messages(&self, conversation_id: u64) -> DbResult<u64> {
        Ok(self
            .agent_messages
            .lock()
            .await
            .iter()
            .filter(|m| m.conversation_id == conversation_id)
            .count() as u64)
    }

    async fn max_agent_message_id(&self, conversation_id: u64) -> DbResult<u64> {
        Ok(self
            .agent_messages
            .lock()
            .await
            .iter()
            .filter(|m| m.conversation_id == conversation_id)
            .map(|m| m.id)
            .max()
            .unwrap_or(0))
    }

    async fn set_agent_conversation_memory(
        &self,
        conversation_id: u64,
        summary: Option<&str>,
        compacted_upto: u64,
    ) -> DbResult<()> {
        let mut conversations = self.agent_conversations.lock().await;
        let conversation = conversations.get_mut(&conversation_id).ok_or_else(|| {
            DbError::from(anyhow!("agent conversation {} not found", conversation_id))
        })?;
        // Unlike compact_agent_conversation this is not monotonic — see the
        // trait docs for why an admin reset must be able to go backwards.
        conversation.summary = summary.map(str::to_string);
        conversation.compacted_upto = compacted_upto;
        conversation.updated = chrono::Utc::now();
        Ok(())
    }

    async fn append_agent_messages(
        &self,
        conversation_id: u64,
        messages: &[NewAgentMessage],
    ) -> DbResult<Vec<u64>> {
        if messages.is_empty() {
            return Ok(vec![]);
        }
        let mut log = self.agent_messages.lock().await;
        let mut ids = Vec::with_capacity(messages.len());
        for message in messages {
            let id = (log.len() + 1) as u64;
            log.push(AgentMessage {
                id,
                conversation_id,
                role: message.role,
                channel: message.channel,
                content: message.content.clone().map(EncryptedString::new),
                // Bytes, mirroring how MariaDB returns a JSON column.
                tool_calls: message.tool_calls.clone().map(String::into_bytes),
                tool_call_id: message.tool_call_id.clone(),
                created: chrono::Utc::now(),
            });
            ids.push(id);
        }
        drop(log);

        if let Some(conversation) = self
            .agent_conversations
            .lock()
            .await
            .get_mut(&conversation_id)
        {
            conversation.updated = chrono::Utc::now();
        }
        Ok(ids)
    }

    async fn list_agent_messages_after_watermark(
        &self,
        conversation_id: u64,
    ) -> DbResult<Vec<AgentMessage>> {
        let watermark = self
            .agent_conversations
            .lock()
            .await
            .get(&conversation_id)
            .map(|c| c.compacted_upto)
            .unwrap_or(0);

        Ok(self
            .agent_messages
            .lock()
            .await
            .iter()
            .filter(|m| m.conversation_id == conversation_id && m.id > watermark)
            .cloned()
            .collect())
    }

    async fn list_agent_messages_paginated(
        &self,
        conversation_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<Vec<AgentMessage>> {
        Ok(self
            .agent_messages
            .lock()
            .await
            .iter()
            .filter(|m| m.conversation_id == conversation_id)
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn compact_agent_conversation(
        &self,
        conversation_id: u64,
        summary: &str,
        compacted_upto: u64,
    ) -> DbResult<()> {
        let mut conversations = self.agent_conversations.lock().await;
        let conversation = conversations.get_mut(&conversation_id).ok_or_else(|| {
            DbError::from(anyhow!("agent conversation {} not found", conversation_id))
        })?;
        conversation.summary = Some(summary.to_string());
        // Monotonic, matching the `greatest(...)` in the SQL implementation.
        conversation.compacted_upto = conversation.compacted_upto.max(compacted_upto);
        conversation.updated = chrono::Utc::now();
        Ok(())
    }

    async fn insert_vm_history(&self, history: &VmHistory) -> DbResult<u64> {
        let mut vm_history_map = self.vm_history.lock().await;
        let id = (vm_history_map.len() + 1) as u64;
        let mut new_history = history.clone();
        new_history.id = id;
        vm_history_map.insert(id, new_history);
        Ok(id)
    }

    async fn list_vm_history(&self, vm_id: u64) -> DbResult<Vec<VmHistory>> {
        let vm_history_map = self.vm_history.lock().await;
        let mut history: Vec<VmHistory> = vm_history_map
            .values()
            .filter(|h| h.vm_id == vm_id)
            .cloned()
            .collect();
        // Sort by timestamp descending (newest first)
        history.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(history)
    }

    async fn list_vm_history_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<Vec<VmHistory>> {
        let all_history = self.list_vm_history(vm_id).await?;
        let start = offset as usize;
        let end = (start + limit as usize).min(all_history.len());
        if start >= all_history.len() {
            Ok(vec![])
        } else {
            Ok(all_history[start..end].to_vec())
        }
    }

    async fn get_vm_history(&self, id: u64) -> DbResult<VmHistory> {
        let vm_history_map = self.vm_history.lock().await;
        Ok(vm_history_map
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("VM history not found: {}", id))?)
    }

    async fn execute_query(&self, _query: &str) -> DbResult<u64> {
        // Mock implementation - always returns success
        Ok(0)
    }

    async fn execute_query_with_string_params(
        &self,
        _query: &str,
        _params: Vec<String>,
    ) -> DbResult<u64> {
        // Mock implementation - always returns success
        Ok(0)
    }

    async fn fetch_raw_strings(&self, _query: &str) -> DbResult<Vec<(u64, String)>> {
        // Mock implementation - returns empty result
        Ok(vec![])
    }

    async fn get_bulk_message_recipients(&self, target: &BulkMessageTarget) -> DbResult<Vec<User>> {
        if target.is_explicitly_empty() {
            return Ok(vec![]);
        }

        let users = self.users.lock().await;
        let vms = self.vms.lock().await;
        let hosts = self.hosts.lock().await;

        let mut ids: HashSet<u64> = HashSet::new();
        if target.is_empty() {
            ids.extend(vms.values().filter(|v| !v.deleted).map(|v| v.user_id));
        } else {
            if let Some(user_ids) = &target.user_ids {
                ids.extend(user_ids.iter().copied());
            }
            if let Some(vm_ids) = &target.vm_ids {
                ids.extend(
                    vms.values()
                        .filter(|v| !v.deleted && vm_ids.contains(&v.id))
                        .map(|v| v.user_id),
                );
            }
            if let Some(host_ids) = &target.host_ids {
                ids.extend(
                    vms.values()
                        .filter(|v| !v.deleted && host_ids.contains(&v.host_id))
                        .map(|v| v.user_id),
                );
            }
            if let Some(region_ids) = &target.region_ids {
                ids.extend(
                    vms.values()
                        .filter(|v| {
                            !v.deleted
                                && hosts
                                    .get(&v.host_id)
                                    .is_some_and(|h| region_ids.contains(&h.region_id))
                        })
                        .map(|v| v.user_id),
                );
            }
        }

        let mut result: Vec<User> = ids.iter().filter_map(|id| users.get(id).cloned()).collect();
        result.sort_by_key(|u| u.id);
        Ok(result)
    }

    async fn list_admin_user_ids(&self) -> DbResult<Vec<u64>> {
        Ok(vec![])
    }

    // Subscription methods
    async fn list_subscriptions(&self) -> DbResult<Vec<Subscription>> {
        let subscriptions = self.subscriptions.lock().await;
        Ok(subscriptions.values().cloned().collect())
    }

    async fn list_subscriptions_by_user(&self, user_id: u64) -> DbResult<Vec<Subscription>> {
        let subscriptions = self.subscriptions.lock().await;
        Ok(subscriptions
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn list_subscriptions_paginated(
        &self,
        user_id: Option<u64>,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<Subscription>, u64)> {
        let subscriptions = self.subscriptions.lock().await;
        let mut all: Vec<_> = subscriptions
            .values()
            .filter(|s| user_id.map_or(true, |u| s.user_id == u))
            .cloned()
            .collect();
        all.sort_by(|a, b| b.id.cmp(&a.id));
        let total = all.len() as u64;
        let page = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, total))
    }

    async fn admin_list_subscriptions_filtered(
        &self,
        limit: u64,
        offset: u64,
        user_id: Option<u64>,
        search: Option<&str>,
        is_active: Option<bool>,
        auto_renewal: Option<bool>,
    ) -> DbResult<(Vec<Subscription>, u64)> {
        let search = search
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);
        let subscriptions = self.subscriptions.lock().await;
        let mut all: Vec<_> = subscriptions
            .values()
            .filter(|s| user_id.map_or(true, |u| s.user_id == u))
            .filter(|s| is_active.map_or(true, |a| s.is_active == a))
            .filter(|s| auto_renewal.map_or(true, |a| s.auto_renewal_enabled == a))
            .filter(|s| {
                search.as_ref().map_or(true, |q| {
                    s.name.to_lowercase().contains(q)
                        || s.description
                            .as_ref()
                            .map_or(false, |d| d.to_lowercase().contains(q))
                })
            })
            .cloned()
            .collect();
        all.sort_by(|a, b| b.id.cmp(&a.id));
        let total = all.len() as u64;
        let page = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, total))
    }

    async fn list_subscriptions_active(&self, user_id: u64) -> DbResult<Vec<Subscription>> {
        let subscriptions = self.subscriptions.lock().await;
        Ok(subscriptions
            .values()
            .filter(|s| s.is_active && s.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn list_expiring_subscriptions(
        &self,
        within_seconds: u64,
    ) -> DbResult<Vec<Subscription>> {
        let subscriptions = self.subscriptions.lock().await;
        let deadline = Utc::now() + chrono::Duration::seconds(within_seconds as i64);
        Ok(subscriptions
            .values()
            .filter(|s| {
                s.is_active
                    && s.expires
                        .map(|e| e > Utc::now() && e < deadline)
                        .unwrap_or(false)
            })
            .cloned()
            .collect())
    }

    async fn list_expired_subscriptions(&self) -> DbResult<Vec<Subscription>> {
        let subscriptions = self.subscriptions.lock().await;
        Ok(subscriptions
            .values()
            .filter(|s| s.is_active && s.expires.map(|e| e < Utc::now()).unwrap_or(false))
            .cloned()
            .collect())
    }

    async fn list_lifecycle_subscriptions(&self) -> DbResult<Vec<Subscription>> {
        let subscriptions = self.subscriptions.lock().await;
        Ok(subscriptions
            .values()
            .filter(|s| s.is_active && s.expires.is_some())
            .cloned()
            .collect())
    }

    async fn deactivate_subscription(&self, id: u64) -> DbResult<()> {
        let mut subscriptions = self.subscriptions.lock().await;
        if let Some(sub) = subscriptions.get_mut(&id) {
            sub.is_active = false;
        }
        drop(subscriptions);
        let line_items = self.subscription_line_items.lock().await;
        let line_item_ids: Vec<u64> = line_items
            .values()
            .filter(|li| li.subscription_id == id)
            .map(|li| li.id)
            .collect();
        drop(line_items);
        let mut ip_subs = self.ip_range_subscriptions.lock().await;
        for ips in ip_subs.values_mut() {
            if line_item_ids.contains(&ips.subscription_line_item_id) && ips.ended_at.is_none() {
                ips.is_active = false;
                ips.ended_at = Some(Utc::now());
            }
        }
        Ok(())
    }

    async fn get_subscription(&self, id: u64) -> DbResult<Subscription> {
        let subscriptions = self.subscriptions.lock().await;
        Ok(subscriptions
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("Subscription not found: {}", id))?)
    }

    async fn get_subscription_by_ext_id(&self, ext_id: &str) -> DbResult<Subscription> {
        let subscriptions = self.subscriptions.lock().await;
        Ok(subscriptions
            .values()
            .find(|s| s.external_id.as_deref() == Some(ext_id))
            .cloned()
            .ok_or_else(|| anyhow!("Subscription not found with external_id: {}", ext_id))?)
    }

    async fn insert_subscription(&self, subscription: &Subscription) -> DbResult<u64> {
        let mut subscriptions = self.subscriptions.lock().await;
        let id = subscriptions.keys().max().copied().unwrap_or(0) + 1;
        let mut s = subscription.clone();
        s.id = id;
        subscriptions.insert(id, s);
        Ok(id)
    }

    async fn insert_subscription_with_line_items(
        &self,
        subscription: &Subscription,
        line_items: Vec<SubscriptionLineItem>,
    ) -> DbResult<(u64, Vec<u64>)> {
        let subscription_id = self.insert_subscription(subscription).await?;
        let mut items = self.subscription_line_items.lock().await;
        let mut line_item_ids = Vec::with_capacity(line_items.len());
        for mut item in line_items {
            let item_id = items.keys().max().copied().unwrap_or(0) + 1;
            item.id = item_id;
            item.subscription_id = subscription_id;
            items.insert(item_id, item);
            line_item_ids.push(item_id);
        }
        Ok((subscription_id, line_item_ids))
    }

    async fn update_subscription(&self, subscription: &Subscription) -> DbResult<()> {
        let mut subscriptions = self.subscriptions.lock().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            subscriptions.entry(subscription.id)
        {
            e.insert(subscription.clone());
            Ok(())
        } else {
            Err(anyhow!("Subscription not found: {}", subscription.id).into())
        }
    }

    async fn delete_subscription(&self, id: u64) -> DbResult<()> {
        let mut subscriptions = self.subscriptions.lock().await;
        subscriptions.remove(&id);
        Ok(())
    }

    async fn hard_delete_subscription(&self, id: u64) -> DbResult<()> {
        let line_item_ids: Vec<u64> = self
            .subscription_line_items
            .lock()
            .await
            .values()
            .filter(|li| li.subscription_id == id)
            .map(|li| li.id)
            .collect();

        // Guard: refuse while a VM or app deployment still references a line item.
        let attached_vms = self
            .vms
            .lock()
            .await
            .values()
            .filter(|v| line_item_ids.contains(&v.subscription_line_item_id))
            .count();
        if attached_vms > 0 {
            return Err(DbError::Other(anyhow!(
                "Cannot purge subscription with {attached_vms} attached VM(s); delete them first"
            )));
        }
        let attached_deployments = self
            .app_deployments
            .lock()
            .await
            .values()
            .filter(|d| line_item_ids.contains(&d.subscription_line_item_id))
            .count();
        if attached_deployments > 0 {
            return Err(DbError::Other(anyhow!(
                "Cannot purge subscription with {attached_deployments} attached app deployment(s); delete them first"
            )));
        }

        self.subscription_payments
            .lock()
            .await
            .retain(|p| p.subscription_id != id);
        self.subscription_line_items
            .lock()
            .await
            .retain(|_, li| li.subscription_id != id);
        self.subscriptions.lock().await.remove(&id);
        Ok(())
    }

    async fn get_subscription_base_currency(&self, subscription_id: u64) -> DbResult<String> {
        // Get currency from the subscription itself
        let subscriptions = self.subscriptions.lock().await;
        if let Some(subscription) = subscriptions.get(&subscription_id) {
            Ok(subscription.currency.clone())
        } else {
            Ok("EUR".to_string()) // Default fallback
        }
    }

    // Subscription line item methods
    async fn list_subscription_line_items(
        &self,
        subscription_id: u64,
    ) -> DbResult<Vec<SubscriptionLineItem>> {
        let line_items = self.subscription_line_items.lock().await;
        Ok(line_items
            .values()
            .filter(|item| item.subscription_id == subscription_id)
            .cloned()
            .collect())
    }

    async fn list_subscriptions_by_ids(&self, ids: &[u64]) -> DbResult<Vec<Subscription>> {
        let subs = self.subscriptions.lock().await;
        Ok(ids.iter().filter_map(|id| subs.get(id).cloned()).collect())
    }

    async fn list_subscription_line_items_by_ids(
        &self,
        ids: &[u64],
    ) -> DbResult<Vec<SubscriptionLineItem>> {
        let line_items = self.subscription_line_items.lock().await;
        Ok(ids
            .iter()
            .filter_map(|id| line_items.get(id).cloned())
            .collect())
    }

    async fn list_subscription_line_items_by_subscriptions(
        &self,
        subscription_ids: &[u64],
    ) -> DbResult<Vec<SubscriptionLineItem>> {
        let line_items = self.subscription_line_items.lock().await;
        Ok(line_items
            .values()
            .filter(|item| subscription_ids.contains(&item.subscription_id))
            .cloned()
            .collect())
    }

    async fn count_subscription_payments_by_subscriptions(
        &self,
        subscription_ids: &[u64],
    ) -> DbResult<Vec<(u64, u64)>> {
        let payments = self.subscription_payments.lock().await;
        let mut counts: std::collections::HashMap<u64, u64> = Default::default();
        for p in payments.iter() {
            if subscription_ids.contains(&p.subscription_id) {
                *counts.entry(p.subscription_id).or_default() += 1;
            }
        }
        Ok(counts.into_iter().collect())
    }

    async fn get_subscription_line_item(&self, id: u64) -> DbResult<SubscriptionLineItem> {
        let line_items = self.subscription_line_items.lock().await;
        Ok(line_items
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("Subscription line item not found: {}", id))?)
    }

    async fn get_subscription_by_line_item_id(&self, line_item_id: u64) -> DbResult<Subscription> {
        let line_items = self.subscription_line_items.lock().await;
        let sub_id = match line_items.get(&line_item_id) {
            Some(li) => li.subscription_id,
            None => {
                return Err(DbError::Other(anyhow::anyhow!(
                    "subscription not found for line item {}",
                    line_item_id
                )));
            }
        };
        drop(line_items);
        let subscriptions = self.subscriptions.lock().await;
        subscriptions
            .get(&sub_id)
            .cloned()
            .ok_or_else(|| DbError::Other(anyhow::anyhow!("subscription {} not found", sub_id)))
    }

    async fn insert_subscription_line_item(
        &self,
        line_item: &SubscriptionLineItem,
    ) -> DbResult<u64> {
        let mut line_items = self.subscription_line_items.lock().await;
        let max_id = line_items.keys().max().unwrap_or(&0);
        let new_id = max_id + 1;
        let mut new_line_item = line_item.clone();
        new_line_item.id = new_id;
        line_items.insert(new_id, new_line_item);
        Ok(new_id)
    }

    async fn update_subscription_line_item(
        &self,
        line_item: &SubscriptionLineItem,
    ) -> DbResult<()> {
        let mut line_items = self.subscription_line_items.lock().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) = line_items.entry(line_item.id) {
            e.insert(line_item.clone());
            Ok(())
        } else {
            Err(anyhow!("Subscription line item not found: {}", line_item.id).into())
        }
    }

    async fn delete_subscription_line_item(&self, id: u64) -> DbResult<()> {
        let mut line_items = self.subscription_line_items.lock().await;
        line_items.remove(&id);
        Ok(())
    }

    // Subscription payment methods
    async fn list_subscription_payments(
        &self,
        subscription_id: u64,
    ) -> DbResult<Vec<SubscriptionPayment>> {
        let payments = self.subscription_payments.lock().await;
        Ok(payments
            .iter()
            .filter(|p| p.subscription_id == subscription_id)
            .cloned()
            .collect())
    }

    async fn list_subscription_payments_paginated(
        &self,
        subscription_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<SubscriptionPayment>, u64)> {
        let payments = self.subscription_payments.lock().await;
        let mut all: Vec<_> = payments
            .iter()
            .filter(|p| p.subscription_id == subscription_id)
            .cloned()
            .collect();
        all.sort_by(|a, b| b.created.cmp(&a.created));
        let total = all.len() as u64;
        let page = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, total))
    }

    async fn list_subscription_payments_by_user(
        &self,
        user_id: u64,
    ) -> DbResult<Vec<SubscriptionPayment>> {
        let payments = self.subscription_payments.lock().await;
        Ok(payments
            .iter()
            .filter(|p| p.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn get_subscription_payment(&self, id: &Vec<u8>) -> DbResult<SubscriptionPayment> {
        let payments = self.subscription_payments.lock().await;
        Ok(payments
            .iter()
            .find(|p| &p.id == id)
            .cloned()
            .context("Subscription payment not found")?)
    }

    async fn list_refunds_for_payment(
        &self,
        payment_id: &Vec<u8>,
    ) -> DbResult<Vec<SubscriptionPayment>> {
        let payments = self.subscription_payments.lock().await;
        let mut out: Vec<SubscriptionPayment> = payments
            .iter()
            .filter(|p| p.refunded_payment_id.as_ref() == Some(payment_id))
            .cloned()
            .collect();
        out.sort_by_key(|p| p.created);
        Ok(out)
    }

    async fn get_subscription_payment_by_ext_id(
        &self,
        ext_id: &str,
    ) -> DbResult<SubscriptionPayment> {
        let payments = self.subscription_payments.lock().await;
        Ok(payments
            .iter()
            .find(|p| p.external_id.as_deref() == Some(ext_id))
            .cloned()
            .context("Subscription payment not found")?)
    }

    async fn list_subscription_payments_by_method(
        &self,
        method: lnvps_db::PaymentMethod,
    ) -> DbResult<Vec<SubscriptionPayment>> {
        let payments = self.subscription_payments.lock().await;
        Ok(payments
            .iter()
            .filter(|p| p.payment_method == method)
            .cloned()
            .collect())
    }

    async fn get_subscription_payment_with_company(
        &self,
        id: &Vec<u8>,
    ) -> DbResult<SubscriptionPaymentWithCompany> {
        let payments = self.subscription_payments.lock().await;
        let payment = payments
            .iter()
            .find(|p| &p.id == id)
            .cloned()
            .context("Subscription payment not found")?;

        // For mock, use placeholder company/host/region data
        Ok(SubscriptionPaymentWithCompany {
            id: payment.id,
            subscription_id: payment.subscription_id,
            user_id: payment.user_id,
            created: payment.created,
            expires: payment.expires,
            amount: payment.amount,
            currency: payment.currency,
            payment_method: payment.payment_method,
            payment_type: payment.payment_type,
            external_data: payment.external_data,
            external_id: payment.external_id,
            is_paid: payment.is_paid,
            rate: payment.rate,
            time_value: payment.time_value,
            metadata: payment.metadata,
            tax: payment.tax,
            processing_fee: payment.processing_fee,
            paid_at: payment.paid_at,
            tax_rate: payment.tax_rate,
            tax_country_code: payment.tax_country_code.clone(),
            tax_treatment: payment.tax_treatment.clone(),
            tax_evidence: payment.tax_evidence.clone(),
            tax_breakdown: payment.tax_breakdown.clone(),
            refunded_payment_id: payment.refunded_payment_id.clone(),
            company_id: 0,
            company_name: String::new(),
            company_base_currency: "EUR".to_string(),
            vm_id: None,
            host_id: None,
            host_name: None,
            region_id: None,
            region_name: None,
            renewal_source: None,
        })
    }

    async fn insert_subscription_payment(&self, payment: &SubscriptionPayment) -> DbResult<()> {
        let mut payments = self.subscription_payments.lock().await;
        payments.push(payment.clone());
        Ok(())
    }

    async fn update_subscription_payment(&self, payment: &SubscriptionPayment) -> DbResult<()> {
        let mut payments = self.subscription_payments.lock().await;
        if let Some(p) = payments.iter_mut().find(|p| p.id == payment.id) {
            // Mirror the MySQL impl: update every column that query writes
            p.subscription_id = payment.subscription_id;
            p.user_id = payment.user_id;
            p.created = payment.created;
            p.expires = payment.expires;
            p.amount = payment.amount;
            p.currency = payment.currency.clone();
            p.payment_method = payment.payment_method;
            p.payment_type = payment.payment_type;
            p.external_data = payment.external_data.clone();
            p.external_id = payment.external_id.clone();
            p.is_paid = payment.is_paid;
            p.rate = payment.rate;
            p.tax = payment.tax;
            p.processing_fee = payment.processing_fee;
            p.time_value = payment.time_value;
            p.metadata = payment.metadata.clone();
            Ok(())
        } else {
            Err(anyhow!("Subscription payment not found").into())
        }
    }

    async fn subscription_payment_paid(&self, payment: &SubscriptionPayment) -> DbResult<()> {
        // Mark payment as paid with timestamp. Idempotent: if the payment is already
        // paid (or unknown), do nothing and skip the expiry extension below.
        let mut payments = self.subscription_payments.lock().await;
        match payments.iter_mut().find(|p| p.id == payment.id) {
            Some(p) if !p.is_paid => {
                p.is_paid = true;
                p.paid_at = Some(Utc::now());
                p.external_data = payment.external_data.clone();
            }
            _ => {
                drop(payments);
                return Ok(());
            }
        }
        drop(payments);

        // Same one-off rule as the real schema: a subscription that bills nothing
        // recurring never acquires an expiry, or a paid-once listing fee would
        // start being dunned for renewal. Mirrored here on purpose — a mock that
        // expires what MariaDB leaves alone makes every test about it fiction.
        let one_off = {
            let items = self.subscription_line_items.lock().await;
            let mine: Vec<_> = items
                .values()
                .filter(|li| li.subscription_id == payment.subscription_id)
                .collect();
            !mine.is_empty()
                && mine.iter().all(|li| li.amount == 0)
                && mine.iter().any(|li| li.setup_amount > 0)
        };

        let mut subscriptions = self.subscriptions.lock().await;
        if let Some(subscription) = subscriptions.get_mut(&payment.subscription_id) {
            if one_off {
                // Activated, but never given an expiry.
                subscription.is_active = true;
                subscription.is_setup = true;
            } else {
                let base = subscription
                    .expires
                    .unwrap_or_else(Utc::now)
                    .max(Utc::now());

                let new_expires = if let Some(time_value) = payment.time_value {
                    // VM path: extend by explicit time_value seconds
                    base.add(TimeDelta::seconds(time_value as i64))
                } else {
                    // Regular subscription path: use interval from subscription
                    match subscription.interval_type {
                        IntervalType::Day => base.add(Days::new(subscription.interval_amount)),
                        IntervalType::Month => {
                            base.add(Months::new(subscription.interval_amount as u32))
                        }
                        IntervalType::Year => {
                            base.add(Months::new((12 * subscription.interval_amount) as u32))
                        }
                    }
                };
                subscription.expires = Some(new_expires);
                subscription.is_active = true;
                subscription.is_setup = true;
            }
        }
        drop(subscriptions);

        // Un-delete any VM linked to this subscription (e.g. auto-cleaned up before
        // payment arrived).
        let line_items = self.subscription_line_items.lock().await;
        let line_item_ids: Vec<u64> = line_items
            .values()
            .filter(|li| li.subscription_id == payment.subscription_id)
            .map(|li| li.id)
            .collect();
        drop(line_items);
        let mut vms = self.vms.lock().await;
        for vm in vms.values_mut() {
            if line_item_ids.contains(&vm.subscription_line_item_id) {
                vm.deleted = false;
            }
        }
        drop(vms);

        Ok(())
    }

    async fn last_paid_subscription_invoice(&self) -> DbResult<Option<SubscriptionPayment>> {
        let payments = self.subscription_payments.lock().await;
        Ok(payments
            .iter()
            .filter(|p| p.is_paid)
            .max_by(|a, b| a.created.cmp(&b.created))
            .cloned())
    }

    async fn list_available_ip_space(&self) -> DbResult<Vec<AvailableIpSpace>> {
        Ok(self
            .available_ip_space
            .lock()
            .await
            .values()
            .cloned()
            .collect())
    }

    async fn list_available_ip_space_paginated(
        &self,
        _is_available: Option<bool>,
        _is_reserved: Option<bool>,
        _registry: Option<u8>,
        _limit: u64,
        _offset: u64,
    ) -> DbResult<(Vec<AvailableIpSpace>, u64)> {
        todo!()
    }

    async fn get_available_ip_space(&self, id: u64) -> DbResult<AvailableIpSpace> {
        self.available_ip_space
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| DbError::from(anyhow!("available_ip_space {} not found", id)))
    }

    async fn get_available_ip_space_by_cidr(&self, cidr: &str) -> DbResult<AvailableIpSpace> {
        todo!()
    }

    async fn insert_available_ip_space(&self, space: &AvailableIpSpace) -> DbResult<u64> {
        let mut m = self.available_ip_space.lock().await;
        let id = if space.id == 0 {
            m.keys().max().copied().unwrap_or(0) + 1
        } else {
            space.id
        };
        let mut s = space.clone();
        s.id = id;
        m.insert(id, s);
        Ok(id)
    }

    async fn update_available_ip_space(&self, space: &AvailableIpSpace) -> DbResult<()> {
        todo!()
    }

    async fn delete_available_ip_space(&self, id: u64) -> DbResult<()> {
        todo!()
    }

    async fn list_ip_space_pricing_by_space(
        &self,
        available_ip_space_id: u64,
    ) -> DbResult<Vec<IpSpacePricing>> {
        todo!()
    }

    async fn list_ip_space_pricing_by_space_paginated(
        &self,
        _available_ip_space_id: u64,
        _limit: u64,
        _offset: u64,
    ) -> DbResult<(Vec<IpSpacePricing>, u64)> {
        todo!()
    }

    async fn get_ip_space_pricing(&self, id: u64) -> DbResult<IpSpacePricing> {
        todo!()
    }

    async fn get_ip_space_pricing_by_prefix(
        &self,
        available_ip_space_id: u64,
        prefix_size: u16,
    ) -> DbResult<IpSpacePricing> {
        todo!()
    }

    async fn insert_ip_space_pricing(&self, pricing: &IpSpacePricing) -> DbResult<u64> {
        todo!()
    }

    async fn update_ip_space_pricing(&self, pricing: &IpSpacePricing) -> DbResult<()> {
        todo!()
    }

    async fn delete_ip_space_pricing(&self, id: u64) -> DbResult<()> {
        todo!()
    }

    async fn list_ip_range_subscriptions_by_line_item(
        &self,
        subscription_line_item_id: u64,
    ) -> DbResult<Vec<IpRangeSubscription>> {
        let ip_subs = self.ip_range_subscriptions.lock().await;
        Ok(ip_subs
            .values()
            .filter(|s| s.subscription_line_item_id == subscription_line_item_id)
            .cloned()
            .collect())
    }

    async fn list_ip_range_subscriptions_by_line_items(
        &self,
        subscription_line_item_ids: &[u64],
    ) -> DbResult<Vec<IpRangeSubscription>> {
        let ip_subs = self.ip_range_subscriptions.lock().await;
        Ok(ip_subs
            .values()
            .filter(|s| subscription_line_item_ids.contains(&s.subscription_line_item_id))
            .cloned()
            .collect())
    }

    async fn list_ip_range_subscriptions_by_subscription(
        &self,
        subscription_id: u64,
    ) -> DbResult<Vec<IpRangeSubscription>> {
        let line_items = self.subscription_line_items.lock().await;
        let line_item_ids: Vec<u64> = line_items
            .values()
            .filter(|li| li.subscription_id == subscription_id)
            .map(|li| li.id)
            .collect();
        drop(line_items);
        let ip_subs = self.ip_range_subscriptions.lock().await;
        Ok(ip_subs
            .values()
            .filter(|s| line_item_ids.contains(&s.subscription_line_item_id))
            .cloned()
            .collect())
    }

    async fn list_ip_range_subscriptions_by_user(
        &self,
        user_id: u64,
    ) -> DbResult<Vec<IpRangeSubscription>> {
        let subscriptions = self.subscriptions.lock().await;
        let sub_ids: Vec<u64> = subscriptions
            .values()
            .filter(|s| s.user_id == user_id)
            .map(|s| s.id)
            .collect();
        drop(subscriptions);
        let line_items = self.subscription_line_items.lock().await;
        let line_item_ids: Vec<u64> = line_items
            .values()
            .filter(|li| sub_ids.contains(&li.subscription_id))
            .map(|li| li.id)
            .collect();
        drop(line_items);
        let ip_subs = self.ip_range_subscriptions.lock().await;
        Ok(ip_subs
            .values()
            .filter(|s| line_item_ids.contains(&s.subscription_line_item_id))
            .cloned()
            .collect())
    }

    async fn list_ip_range_subscriptions_by_space_paginated(
        &self,
        available_ip_space_id: u64,
        user_id: Option<u64>,
        is_active: Option<bool>,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<IpRangeSubscription>, u64)> {
        let subscriptions = self.subscriptions.lock().await;
        let line_items = self.subscription_line_items.lock().await;
        let ip_subs = self.ip_range_subscriptions.lock().await;
        let mut all: Vec<IpRangeSubscription> = ip_subs
            .values()
            .filter(|s| {
                if s.available_ip_space_id != available_ip_space_id {
                    return false;
                }
                if let Some(active) = is_active {
                    if s.is_active != active {
                        return false;
                    }
                }
                if let Some(uid) = user_id {
                    let li_id = s.subscription_line_item_id;
                    let sub_id = line_items
                        .values()
                        .find(|li| li.id == li_id)
                        .map(|li| li.subscription_id);
                    if let Some(sid) = sub_id {
                        if !subscriptions
                            .get(&sid)
                            .map(|s| s.user_id == uid)
                            .unwrap_or(false)
                        {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        all.sort_by(|a, b| b.id.cmp(&a.id));
        let total = all.len() as u64;
        let page = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, total))
    }

    async fn get_ip_range_subscription(&self, id: u64) -> DbResult<IpRangeSubscription> {
        let ip_subs = self.ip_range_subscriptions.lock().await;
        ip_subs
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("IpRangeSubscription not found: {}", id).into())
    }

    async fn get_ip_range_subscription_by_cidr(&self, cidr: &str) -> DbResult<IpRangeSubscription> {
        let ip_subs = self.ip_range_subscriptions.lock().await;
        ip_subs
            .values()
            .find(|s| s.cidr == cidr)
            .cloned()
            .ok_or_else(|| anyhow!("IpRangeSubscription not found for cidr: {}", cidr).into())
    }

    async fn insert_ip_range_subscription(
        &self,
        subscription: &IpRangeSubscription,
    ) -> DbResult<u64> {
        let mut ip_subs = self.ip_range_subscriptions.lock().await;
        let id = ip_subs.len() as u64 + 1;
        let mut new = subscription.clone();
        new.id = id;
        ip_subs.insert(id, new);
        Ok(id)
    }

    async fn update_ip_range_subscription(
        &self,
        subscription: &IpRangeSubscription,
    ) -> DbResult<()> {
        let mut ip_subs = self.ip_range_subscriptions.lock().await;
        ip_subs.insert(subscription.id, subscription.clone());
        Ok(())
    }

    async fn delete_ip_range_subscription(&self, id: u64) -> DbResult<()> {
        let mut ip_subs = self.ip_range_subscriptions.lock().await;
        ip_subs.remove(&id);
        Ok(())
    }

    // ASN Subscriptions
    async fn list_asn_subscriptions_by_line_item(
        &self,
        subscription_line_item_id: u64,
    ) -> DbResult<Vec<AsnSubscription>> {
        let subs = self.asn_subscriptions.lock().await;
        Ok(subs
            .values()
            .filter(|s| s.subscription_line_item_id == subscription_line_item_id)
            .cloned()
            .collect())
    }

    async fn list_asn_subscriptions_by_line_items(
        &self,
        subscription_line_item_ids: &[u64],
    ) -> DbResult<Vec<AsnSubscription>> {
        let subs = self.asn_subscriptions.lock().await;
        Ok(subs
            .values()
            .filter(|s| subscription_line_item_ids.contains(&s.subscription_line_item_id))
            .cloned()
            .collect())
    }

    async fn list_asn_subscriptions_by_subscription(
        &self,
        subscription_id: u64,
    ) -> DbResult<Vec<AsnSubscription>> {
        let subs = self.asn_subscriptions.lock().await;
        let line_items = self.subscription_line_items.lock().await;
        Ok(subs
            .values()
            .filter(|s| {
                line_items
                    .get(&s.subscription_line_item_id)
                    .map(|li| li.subscription_id == subscription_id)
                    .unwrap_or(false)
            })
            .cloned()
            .collect())
    }

    async fn list_asn_subscriptions_by_user(&self, user_id: u64) -> DbResult<Vec<AsnSubscription>> {
        let subs = self.asn_subscriptions.lock().await;
        let line_items = self.subscription_line_items.lock().await;
        let subscriptions = self.subscriptions.lock().await;
        Ok(subs
            .values()
            .filter(|s| {
                line_items
                    .get(&s.subscription_line_item_id)
                    .and_then(|li| subscriptions.get(&li.subscription_id))
                    .map(|sub| sub.user_id == user_id)
                    .unwrap_or(false)
            })
            .cloned()
            .collect())
    }

    async fn list_asn_subscriptions_paginated(
        &self,
        status: Option<AsnSubscriptionStatus>,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<AsnSubscription>, u64)> {
        let subs = self.asn_subscriptions.lock().await;
        let mut all: Vec<AsnSubscription> = subs
            .values()
            .filter(|s| status.map(|st| s.status == st).unwrap_or(true))
            .cloned()
            .collect();
        all.sort_by(|a, b| b.id.cmp(&a.id));
        let total = all.len() as u64;
        let page = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, total))
    }

    async fn get_asn_subscription(&self, id: u64) -> DbResult<AsnSubscription> {
        self.asn_subscriptions
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| DbError::from(anyhow!("asn_subscription {} not found", id)))
    }

    async fn get_asn_subscription_by_asn(&self, asn: u32) -> DbResult<AsnSubscription> {
        self.asn_subscriptions
            .lock()
            .await
            .values()
            .find(|s| s.asn == Some(asn))
            .cloned()
            .ok_or_else(|| DbError::from(anyhow!("asn_subscription for AS{} not found", asn)))
    }

    async fn insert_asn_subscription(&self, subscription: &AsnSubscription) -> DbResult<u64> {
        let mut subs = self.asn_subscriptions.lock().await;
        let id = if subscription.id == 0 {
            subs.keys().max().copied().unwrap_or(0) + 1
        } else {
            subscription.id
        };
        let mut s = subscription.clone();
        s.id = id;
        subs.insert(id, s);
        Ok(id)
    }

    async fn update_asn_subscription(&self, subscription: &AsnSubscription) -> DbResult<()> {
        let mut subs = self.asn_subscriptions.lock().await;
        subs.insert(subscription.id, subscription.clone());
        Ok(())
    }

    async fn delete_asn_subscription(&self, id: u64) -> DbResult<()> {
        self.asn_subscriptions.lock().await.remove(&id);
        Ok(())
    }

    // Payment Method Config
    async fn list_payment_method_configs(&self) -> DbResult<Vec<PaymentMethodConfig>> {
        let configs = self.payment_method_configs.lock().await;
        Ok(configs.values().cloned().collect())
    }

    async fn list_payment_method_configs_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<PaymentMethodConfig>, u64)> {
        let configs = self.payment_method_configs.lock().await;
        let mut all: Vec<_> = configs.values().cloned().collect();
        all.sort_by(|a, b| a.company_id.cmp(&b.company_id).then(a.id.cmp(&b.id)));
        let total = all.len() as u64;
        let page = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, total))
    }

    async fn list_payment_method_configs_for_company(
        &self,
        company_id: u64,
    ) -> DbResult<Vec<PaymentMethodConfig>> {
        let configs = self.payment_method_configs.lock().await;
        Ok(configs
            .values()
            .filter(|c| c.company_id == company_id)
            .cloned()
            .collect())
    }

    async fn list_enabled_payment_method_configs_for_company(
        &self,
        company_id: u64,
    ) -> DbResult<Vec<PaymentMethodConfig>> {
        let configs = self.payment_method_configs.lock().await;
        Ok(configs
            .values()
            .filter(|c| c.company_id == company_id && c.enabled)
            .cloned()
            .collect())
    }

    async fn get_payment_method_config(&self, id: u64) -> DbResult<PaymentMethodConfig> {
        let configs = self.payment_method_configs.lock().await;
        Ok(configs
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("Payment method config not found: {}", id))?)
    }

    async fn get_payment_method_config_for_company(
        &self,
        company_id: u64,
        method: PaymentMethod,
    ) -> DbResult<PaymentMethodConfig> {
        let configs = self.payment_method_configs.lock().await;
        Ok(configs
            .values()
            .find(|c| c.company_id == company_id && c.payment_method == method)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "Payment method config not found for company {} / {:?}",
                    company_id,
                    method
                )
            })?)
    }

    async fn insert_payment_method_config(&self, config: &PaymentMethodConfig) -> DbResult<u64> {
        let mut configs = self.payment_method_configs.lock().await;
        let max_id = configs.keys().max().unwrap_or(&0);
        let new_id = max_id + 1;
        let mut new_config = config.clone();
        new_config.id = new_id;
        configs.insert(new_id, new_config);
        Ok(new_id)
    }

    async fn update_payment_method_config(&self, config: &PaymentMethodConfig) -> DbResult<()> {
        let mut configs = self.payment_method_configs.lock().await;
        if configs.contains_key(&config.id) {
            configs.insert(config.id, config.clone());
            Ok(())
        } else {
            Err(anyhow!("Payment method config not found: {}", config.id).into())
        }
    }

    async fn delete_payment_method_config(&self, id: u64) -> DbResult<()> {
        let mut configs = self.payment_method_configs.lock().await;
        configs.remove(&id);
        Ok(())
    }

    async fn get_referral_by_user(&self, user_id: u64) -> DbResult<Referral> {
        let referrals = self.referrals.lock().await;
        referrals
            .values()
            .find(|r| r.user_id == user_id)
            .cloned()
            .ok_or_else(|| anyhow!("Referral not found for user {}", user_id).into())
    }

    async fn get_referral_by_code(&self, code: &str) -> DbResult<Referral> {
        let referrals = self.referrals.lock().await;
        referrals
            .values()
            .find(|r| r.code == code)
            .cloned()
            .ok_or_else(|| anyhow!("Referral not found for code {}", code).into())
    }

    async fn insert_referral(&self, referral: &Referral) -> DbResult<u64> {
        let mut referrals = self.referrals.lock().await;
        let max_id = referrals.keys().max().copied().unwrap_or(0);
        let new_id = max_id + 1;
        referrals.insert(
            new_id,
            Referral {
                id: new_id,
                ..referral.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_referral(&self, referral: &Referral) -> DbResult<()> {
        let mut referrals = self.referrals.lock().await;
        if let Some(r) = referrals.get_mut(&referral.id) {
            let old_code = r.code.clone();
            r.code = referral.code.clone();
            r.address = referral.address.clone();
            r.mode = referral.mode;
            r.referral_rate = referral.referral_rate;
            r.payout_threshold = referral.payout_threshold;
            // Cascade a code rename onto VMs that recorded the old code so
            // historical referral attribution is preserved.
            if old_code != referral.code {
                let mut vms = self.vms.lock().await;
                for vm in vms.values_mut() {
                    if vm.ref_code.as_deref() == Some(old_code.as_str()) {
                        vm.ref_code = Some(referral.code.clone());
                    }
                }
            }
        }
        Ok(())
    }

    async fn delete_referral(&self, referral_id: u64) -> DbResult<()> {
        let mut referrals = self.referrals.lock().await;
        referrals.remove(&referral_id);
        Ok(())
    }

    async fn list_all_referrals(&self) -> DbResult<Vec<Referral>> {
        let referrals = self.referrals.lock().await;
        let mut all: Vec<Referral> = referrals.values().cloned().collect();
        all.sort_by_key(|r| r.id);
        Ok(all)
    }

    async fn delete_referral_payout(&self, payout_id: u64) -> DbResult<()> {
        let mut payouts = self.referral_payouts.lock().await;
        payouts.retain(|p| p.id != payout_id);
        Ok(())
    }

    async fn insert_referral_payout(&self, payout: &ReferralPayout) -> DbResult<u64> {
        let mut payouts = self.referral_payouts.lock().await;
        let new_id = payouts.len() as u64 + 1;
        payouts.push(ReferralPayout {
            id: new_id,
            ..payout.clone()
        });
        Ok(new_id)
    }

    async fn update_referral_payout(&self, payout: &ReferralPayout) -> DbResult<()> {
        let mut payouts = self.referral_payouts.lock().await;
        if let Some(p) = payouts.iter_mut().find(|p| p.id == payout.id) {
            p.is_paid = payout.is_paid;
            p.mode = payout.mode;
            p.output = payout.output.clone();
            p.pre_image = payout.pre_image.clone();
            p.fee = payout.fee;
            p.sent_fee = payout.sent_fee;
        }
        Ok(())
    }

    async fn list_referral_payouts(&self, referral_id: u64) -> DbResult<Vec<ReferralPayout>> {
        let payouts = self.referral_payouts.lock().await;
        Ok(payouts
            .iter()
            .filter(|p| p.referral_id == referral_id)
            .cloned()
            .collect())
    }

    async fn list_referral_usage(&self, code: &str) -> DbResult<Vec<ReferralCostUsage>> {
        let vms = self.vms.lock().await;
        let line_items = self.subscription_line_items.lock().await;
        let sub_payments = self.subscription_payments.lock().await;
        // Effective rate: referrer override, else the default company's rate.
        let effective_rate = {
            let referrals = self.referrals.lock().await;
            let override_rate = referrals
                .values()
                .find(|r| r.code == code)
                .and_then(|r| r.referral_rate);
            match override_rate {
                Some(r) => r,
                None => self
                    .companies
                    .lock()
                    .await
                    .get(&1)
                    .map(|c| c.referral_rate)
                    .unwrap_or(0.0),
            }
        };
        let mut result = Vec::new();
        for vm in vms.values().filter(|v| v.ref_code.as_deref() == Some(code)) {
            let subscription_id = line_items
                .get(&vm.subscription_line_item_id)
                .map(|sli| sli.subscription_id);
            if let Some(sid) = subscription_id {
                let mut vm_payments: Vec<&SubscriptionPayment> = sub_payments
                    .iter()
                    .filter(|p| p.subscription_id == sid && p.is_paid)
                    .collect();
                vm_payments.sort_by_key(|p| p.created);
                if let Some(first) = vm_payments.first() {
                    result.push(ReferralCostUsage {
                        vm_id: vm.id,
                        ref_code: code.to_string(),
                        created: first.created,
                        amount: first.amount,
                        currency: first.currency.clone(),
                        rate: first.rate,
                        base_currency: "EUR".to_string(),
                        effective_rate,
                    });
                }
            }
        }
        result.sort_by(|a, b| b.created.cmp(&a.created));
        Ok(result)
    }

    async fn list_referral_usage_paginated(
        &self,
        code: &str,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<ReferralCostUsage>, u64)> {
        let all = self.list_referral_usage(code).await?;
        let total = all.len() as u64;
        let page = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, total))
    }

    async fn count_failed_referrals(&self, code: &str) -> DbResult<u64> {
        let vms = self.vms.lock().await;
        let line_items = self.subscription_line_items.lock().await;
        let sub_payments = self.subscription_payments.lock().await;
        Ok(vms
            .values()
            .filter(|v| v.ref_code.as_deref() == Some(code))
            .filter(|v| {
                let sid = line_items
                    .get(&v.subscription_line_item_id)
                    .map(|sli| sli.subscription_id);
                !sid.map(|s| {
                    sub_payments
                        .iter()
                        .any(|p| p.subscription_id == s && p.is_paid)
                })
                .unwrap_or(false)
            })
            .count() as u64)
    }

    // ========================================================================
    // Discounts
    // ========================================================================

    async fn get_discount(&self, id: u64) -> DbResult<Discount> {
        let discounts = self.discounts.lock().await;
        discounts
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("Discount not found: {}", id).into())
    }

    async fn get_discount_by_code(&self, code: &str) -> DbResult<Discount> {
        let discounts = self.discounts.lock().await;
        // Exact match, like the SQL `WHERE code = ?`: codes are normalised to
        // upper case by the admin API and by the caller, not here.
        discounts
            .values()
            .find(|d| d.code.as_deref() == Some(code))
            .cloned()
            .ok_or_else(|| anyhow!("Discount not found for code {}", code).into())
    }

    async fn list_discounts_paginated(
        &self,
        company_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<Discount>, u64)> {
        let discounts = self.discounts.lock().await;
        let mut all: Vec<Discount> = discounts
            .values()
            .filter(|d| d.company_id == company_id)
            .cloned()
            .collect();
        all.sort_by_key(|d| std::cmp::Reverse(d.id));
        let total = all.len() as u64;
        Ok((
            all.into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect(),
            total,
        ))
    }

    async fn insert_discount(&self, discount: &Discount) -> DbResult<u64> {
        let mut discounts = self.discounts.lock().await;
        if discount.code.is_some() && discounts.values().any(|d| d.code == discount.code) {
            return Err(anyhow!("Duplicate discount code").into());
        }
        let new_id = discounts.keys().max().copied().unwrap_or(0) + 1;
        discounts.insert(
            new_id,
            Discount {
                id: new_id,
                used_count: 0,
                ..discount.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_discount(&self, discount: &Discount) -> DbResult<()> {
        let mut discounts = self.discounts.lock().await;
        if let Some(d) = discounts.get_mut(&discount.id) {
            // `used_count` is owned by settlement, matching the SQL impl.
            d.code = discount.code.clone();
            d.name = discount.name.clone();
            d.rule = discount.rule.clone();
            d.valid_from = discount.valid_from;
            d.valid_to = discount.valid_to;
            d.usage_limit = discount.usage_limit;
            d.per_user_limit = discount.per_user_limit;
            d.active = discount.active;
        }
        Ok(())
    }

    async fn delete_discount(&self, id: u64) -> DbResult<()> {
        let redemptions = self.discount_redemptions.lock().await;
        if redemptions.iter().any(|r| r.discount_id == id) {
            return Err(anyhow!("Discount has redemptions").into());
        }
        let mut discounts = self.discounts.lock().await;
        discounts.remove(&id);
        Ok(())
    }

    async fn count_discount_redemptions(&self, discount_id: u64, user_id: u64) -> DbResult<u64> {
        let redemptions = self.discount_redemptions.lock().await;
        Ok(redemptions
            .iter()
            .filter(|r| r.discount_id == discount_id && r.user_id == user_id && r.settled)
            .count() as u64)
    }

    async fn insert_discount_redemption(&self, redemption: &DiscountRedemption) -> DbResult<()> {
        let mut redemptions = self.discount_redemptions.lock().await;
        // A payment carries at most one discount, so a repeat is a no-op.
        if redemptions
            .iter()
            .any(|r| r.subscription_payment_id == redemption.subscription_payment_id)
        {
            return Ok(());
        }
        let new_id = redemptions.len() as u64 + 1;
        redemptions.push(DiscountRedemption {
            id: new_id,
            settled: false,
            settled_at: None,
            created: Utc::now(),
            ..redemption.clone()
        });
        Ok(())
    }

    async fn get_discount_redemption_by_payment(
        &self,
        subscription_payment_id: &Vec<u8>,
    ) -> DbResult<Option<DiscountRedemption>> {
        let redemptions = self.discount_redemptions.lock().await;
        Ok(redemptions
            .iter()
            .find(|r| &r.subscription_payment_id == subscription_payment_id)
            .cloned())
    }

    async fn get_discount_redemptions_by_payments(
        &self,
        subscription_payment_ids: &[Vec<u8>],
    ) -> DbResult<Vec<lnvps_db::DiscountRedemptionWithCode>> {
        let redemptions = self.discount_redemptions.lock().await;
        let discounts = self.discounts.lock().await;
        Ok(redemptions
            .iter()
            .filter(|r| subscription_payment_ids.contains(&r.subscription_payment_id))
            .filter_map(|r| {
                // An orphan redemption cannot exist (FK), so a missing discount
                // drops the row rather than inventing a code, matching the JOIN.
                discounts
                    .get(&r.discount_id)
                    .map(|d| lnvps_db::DiscountRedemptionWithCode {
                        redemption: r.clone(),
                        discount_code: d.code.clone(),
                    })
            })
            .collect())
    }

    async fn settle_discount_redemption(
        &self,
        subscription_payment_id: &Vec<u8>,
    ) -> DbResult<Option<DiscountRedemption>> {
        let mut redemptions = self.discount_redemptions.lock().await;
        let Some(row) = redemptions
            .iter_mut()
            .find(|r| &r.subscription_payment_id == subscription_payment_id && !r.settled)
        else {
            return Ok(None);
        };
        row.settled = true;
        row.settled_at = Some(Utc::now());
        let settled = row.clone();

        let mut discounts = self.discounts.lock().await;
        if let Some(d) = discounts.get_mut(&settled.discount_id) {
            d.used_count += 1;
        }
        Ok(Some(settled))
    }

    async fn list_discount_redemptions_paginated(
        &self,
        discount_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<DiscountRedemption>, u64)> {
        let redemptions = self.discount_redemptions.lock().await;
        let mut all: Vec<DiscountRedemption> = redemptions
            .iter()
            .filter(|r| r.discount_id == discount_id)
            .cloned()
            .collect();
        all.sort_by_key(|r| std::cmp::Reverse(r.id));
        let total = all.len() as u64;
        Ok((
            all.into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect(),
            total,
        ))
    }

    async fn sum_discount_redemptions(&self, discount_id: u64) -> DbResult<Vec<(String, u64)>> {
        let redemptions = self.discount_redemptions.lock().await;
        let mut totals: std::collections::BTreeMap<String, u64> = Default::default();
        for r in redemptions
            .iter()
            .filter(|r| r.discount_id == discount_id && r.settled)
        {
            *totals.entry(r.currency.clone()).or_default() += r.amount_off;
        }
        Ok(totals.into_iter().collect())
    }

    // ----- Marketplace (operator-run compute nodes) -----

    async fn get_marketplace_operator(&self, id: u64) -> DbResult<MarketplaceOperator> {
        let operators = self.marketplace_operators.lock().await;
        operators
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("Marketplace operator {} not found", id).into())
    }

    async fn get_marketplace_operator_by_user(
        &self,
        user_id: u64,
    ) -> DbResult<MarketplaceOperator> {
        let operators = self.marketplace_operators.lock().await;
        operators
            .values()
            .find(|o| o.user_id == user_id)
            .cloned()
            .ok_or_else(|| anyhow!("Marketplace operator not found for user {}", user_id).into())
    }

    async fn list_marketplace_operators(&self) -> DbResult<Vec<MarketplaceOperator>> {
        let operators = self.marketplace_operators.lock().await;
        let mut out: Vec<_> = operators.values().cloned().collect();
        out.sort_by_key(|o| o.id);
        Ok(out)
    }

    async fn insert_marketplace_operator(&self, operator: &MarketplaceOperator) -> DbResult<u64> {
        // FK marketplace_operator.user_id
        if !self.users.lock().await.contains_key(&operator.user_id) {
            return Err(anyhow!("User {} not found", operator.user_id).into());
        }
        let mut operators = self.marketplace_operators.lock().await;
        // uk_marketplace_operator_user
        if operators.values().any(|o| o.user_id == operator.user_id) {
            return Err(anyhow!("User {} is already an operator", operator.user_id).into());
        }
        let new_id = operators.keys().max().copied().unwrap_or(0) + 1;
        operators.insert(
            new_id,
            MarketplaceOperator {
                id: new_id,
                created: Utc::now(),
                ..operator.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_marketplace_operator(&self, operator: &MarketplaceOperator) -> DbResult<()> {
        let mut operators = self.marketplace_operators.lock().await;
        let existing = operators.get_mut(&operator.id).ok_or_else(|| {
            DbError::Other(anyhow!("Marketplace operator {} not found", operator.id))
        })?;
        // user_id and created are immutable, matching the UPDATE statement.
        existing.address = operator.address.clone();
        existing.mode = operator.mode;
        existing.payout_threshold = operator.payout_threshold;
        existing.rate = operator.rate;
        existing.enabled = operator.enabled;
        Ok(())
    }

    async fn delete_marketplace_operator(&self, id: u64) -> DbResult<()> {
        let nodes = self.marketplace_nodes.lock().await;
        // FK marketplace_node.operator_id
        if nodes.values().any(|n| n.operator_id == id) {
            return Err(anyhow!("Operator {} still has nodes", id).into());
        }
        self.marketplace_operators.lock().await.remove(&id);
        Ok(())
    }

    async fn get_marketplace_node(&self, id: u64) -> DbResult<MarketplaceNode> {
        let nodes = self.marketplace_nodes.lock().await;
        nodes
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("Marketplace node {} not found", id).into())
    }

    async fn get_marketplace_node_by_tls_fingerprint(
        &self,
        fingerprint: &[u8],
    ) -> DbResult<MarketplaceNode> {
        let nodes = self.marketplace_nodes.lock().await;
        nodes
            .values()
            .find(|n| n.tls_fingerprint.as_deref() == Some(fingerprint))
            .cloned()
            .ok_or_else(|| DbError::Other(anyhow!("Marketplace node not found")))
    }

    async fn get_marketplace_node_by_tunnel(
        &self,
        tunnel_id: u64,
    ) -> DbResult<Option<MarketplaceNode>> {
        let nodes = self.marketplace_nodes.lock().await;
        Ok(nodes
            .values()
            .find(|n| n.tunnel_id == Some(tunnel_id))
            .cloned())
    }

    async fn get_marketplace_node_by_line_item(
        &self,
        line_item_id: u64,
    ) -> DbResult<MarketplaceNode> {
        let nodes = self.marketplace_nodes.lock().await;
        nodes
            .values()
            .find(|n| n.subscription_line_item_id == Some(line_item_id))
            .cloned()
            .ok_or_else(|| DbError::Other(anyhow!("Marketplace node not found")))
    }

    async fn list_marketplace_nodes_by_line_items(
        &self,
        line_item_ids: &[u64],
    ) -> DbResult<Vec<MarketplaceNode>> {
        let nodes = self.marketplace_nodes.lock().await;
        Ok(nodes
            .values()
            .filter(|n| {
                n.subscription_line_item_id
                    .is_some_and(|id| line_item_ids.contains(&id))
            })
            .cloned()
            .collect())
    }

    async fn list_marketplace_nodes(&self, operator_id: u64) -> DbResult<Vec<MarketplaceNode>> {
        let nodes = self.marketplace_nodes.lock().await;
        let mut out: Vec<_> = nodes
            .values()
            .filter(|n| n.operator_id == operator_id)
            .cloned()
            .collect();
        out.sort_by_key(|n| n.id);
        Ok(out)
    }

    async fn list_all_marketplace_nodes(
        &self,
        status: Option<MarketplaceNodeStatus>,
    ) -> DbResult<Vec<MarketplaceNode>> {
        let nodes = self.marketplace_nodes.lock().await;
        let mut out: Vec<_> = nodes
            .values()
            .filter(|n| status.is_none_or(|s| n.status == s))
            .cloned()
            .collect();
        out.sort_by_key(|n| n.id);
        Ok(out)
    }

    async fn admin_list_marketplace_nodes_paginated(
        &self,
        limit: u64,
        offset: u64,
        status: Option<MarketplaceNodeStatus>,
        operator_id: Option<u64>,
    ) -> DbResult<(Vec<MarketplaceNode>, u64)> {
        let nodes = self.marketplace_nodes.lock().await;
        let mut out: Vec<_> = nodes
            .values()
            .filter(|n| status.is_none_or(|s| n.status == s))
            .filter(|n| operator_id.is_none_or(|o| n.operator_id == o))
            .cloned()
            .collect();
        // Newest first, matching the SQL ordering, so a review queue paginates
        // the same way against either implementation.
        out.sort_by(|a, b| b.id.cmp(&a.id));
        let total = out.len() as u64;
        Ok((
            out.into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect(),
            total,
        ))
    }

    async fn admin_list_marketplace_operators_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<MarketplaceOperator>, u64)> {
        let operators = self.marketplace_operators.lock().await;
        let mut out: Vec<_> = operators.values().cloned().collect();
        out.sort_by(|a, b| b.id.cmp(&a.id));
        let total = out.len() as u64;
        Ok((
            out.into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect(),
            total,
        ))
    }

    async fn get_marketplace_node_host(&self, node_id: u64) -> DbResult<Option<VmHost>> {
        let hosts = self.hosts.lock().await;
        Ok(hosts
            .values()
            .find(|h| h.marketplace_node_id == Some(node_id))
            .cloned())
    }

    async fn insert_marketplace_node_health(
        &self,
        health: &MarketplaceNodeHealth,
    ) -> DbResult<u64> {
        if !self
            .marketplace_nodes
            .lock()
            .await
            .contains_key(&health.node_id)
        {
            return Err(anyhow!("Marketplace node {} not found", health.node_id).into());
        }
        let mut rows = self.marketplace_node_health.lock().await;
        let id = rows.keys().max().copied().unwrap_or(0) + 1;
        rows.insert(
            id,
            MarketplaceNodeHealth {
                id,
                // The column defaults to now; rows written without one would
                // otherwise all sort equal and a "most recent first" list would
                // return them in whatever order the map happened to hold.
                created: if health.created == DateTime::<Utc>::default() {
                    Utc::now()
                } else {
                    health.created
                },
                ..health.clone()
            },
        );
        Ok(id)
    }

    async fn list_marketplace_node_health(
        &self,
        node_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<MarketplaceNodeHealth>, i64)> {
        let rows = self.marketplace_node_health.lock().await;
        let mut mine: Vec<_> = rows
            .values()
            .filter(|h| h.node_id == node_id)
            .cloned()
            .collect();
        mine.sort_by(|a, b| b.created.cmp(&a.created).then(b.id.cmp(&a.id)));
        let total = mine.len() as i64;
        Ok((
            mine.into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect(),
            total,
        ))
    }

    async fn insert_marketplace_node(&self, node: &MarketplaceNode) -> DbResult<u64> {
        let operators = self.marketplace_operators.lock().await;
        // FK marketplace_node.operator_id
        if !operators.contains_key(&node.operator_id) {
            return Err(anyhow!("Operator {} not found", node.operator_id).into());
        }
        drop(operators);
        if let Some(tunnel_id) = node.tunnel_id
            && !self.tunnels.lock().await.contains_key(&tunnel_id)
        {
            return Err(anyhow!("Tunnel {} not found", tunnel_id).into());
        }
        let mut nodes = self.marketplace_nodes.lock().await;
        // ck_marketplace_node_tls_fingerprint: a short value would be padded
        // by the real column and could then never match what the node serves.
        if let Some(fp) = node.tls_fingerprint.as_deref()
            && fp.len() != 32
        {
            return Err(anyhow!(
                "TLS fingerprint must be 32 bytes, got {} (ck_marketplace_node_tls_fingerprint)",
                fp.len()
            )
            .into());
        }
        // uk_marketplace_node_tls_fingerprint: two nodes serving the same
        // certificate would each be able to answer for the other.
        if let Some(fp) = node.tls_fingerprint.as_deref()
            && nodes
                .values()
                .any(|n| n.tls_fingerprint.as_deref() == Some(fp))
        {
            return Err(anyhow!("A node with that TLS fingerprint already exists").into());
        }
        // uk_marketplace_node_tunnel
        if let Some(tunnel_id) = node.tunnel_id
            && nodes.values().any(|n| n.tunnel_id == Some(tunnel_id))
        {
            return Err(anyhow!("Tunnel {} already backs another node", tunnel_id).into());
        }
        // fk/uk_marketplace_node_line_item: one paid fee covers exactly one
        // node, or the per-node gate silently degrades into a per-operator one.
        if let Some(li) = node.subscription_line_item_id {
            if !self.subscription_line_items.lock().await.contains_key(&li) {
                return Err(anyhow!("Subscription line item {} not found", li).into());
            }
            if nodes
                .values()
                .any(|n| n.subscription_line_item_id == Some(li))
            {
                return Err(anyhow!("Line item {} already bills another node", li).into());
            }
        }
        let new_id = nodes.keys().max().copied().unwrap_or(0) + 1;
        nodes.insert(
            new_id,
            MarketplaceNode {
                id: new_id,
                created: Utc::now(),
                ..node.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_marketplace_node(&self, node: &MarketplaceNode) -> DbResult<()> {
        if let Some(tunnel_id) = node.tunnel_id
            && !self.tunnels.lock().await.contains_key(&tunnel_id)
        {
            return Err(anyhow!("Tunnel {} not found", tunnel_id).into());
        }
        let mut nodes = self.marketplace_nodes.lock().await;
        if let Some(tunnel_id) = node.tunnel_id
            && nodes
                .values()
                .any(|n| n.id != node.id && n.tunnel_id == Some(tunnel_id))
        {
            return Err(anyhow!("Tunnel {} already backs another node", tunnel_id).into());
        }
        if let Some(fp) = node.tls_fingerprint.as_deref()
            && fp.len() != 32
        {
            return Err(anyhow!(
                "TLS fingerprint must be 32 bytes, got {} (ck_marketplace_node_tls_fingerprint)",
                fp.len()
            )
            .into());
        }
        if let Some(fp) = node.tls_fingerprint.as_deref()
            && nodes
                .values()
                .any(|n| n.id != node.id && n.tls_fingerprint.as_deref() == Some(fp))
        {
            return Err(anyhow!("A node with that TLS fingerprint already exists").into());
        }
        if let Some(li) = node.subscription_line_item_id {
            if !self.subscription_line_items.lock().await.contains_key(&li) {
                return Err(anyhow!("Subscription line item {} not found", li).into());
            }
            if nodes
                .values()
                .any(|n| n.id != node.id && n.subscription_line_item_id == Some(li))
            {
                return Err(anyhow!("Line item {} already bills another node", li).into());
            }
        }
        let existing = nodes
            .get_mut(&node.id)
            .ok_or_else(|| DbError::Other(anyhow!("Marketplace node {} not found", node.id)))?;
        // operator_id, created and last_seen are not written by the UPDATE:
        // a node cannot change hands, and heartbeats go through
        // `touch_marketplace_node`.
        existing.name = node.name.clone();
        existing.tls_fingerprint = node.tls_fingerprint.clone();
        existing.libvirt_cert = node.libvirt_cert.clone();
        existing.token_version = node.token_version;
        existing.status = node.status;
        existing.trust_tier = node.trust_tier;
        existing.tunnel_id = node.tunnel_id;
        existing.subscription_line_item_id = node.subscription_line_item_id;
        Ok(())
    }

    async fn touch_marketplace_node(&self, id: u64, seen: DateTime<Utc>) -> DbResult<()> {
        let mut nodes = self.marketplace_nodes.lock().await;
        let node = nodes
            .get_mut(&id)
            .ok_or_else(|| DbError::Other(anyhow!("Marketplace node {} not found", id)))?;
        node.last_seen = Some(seen);
        Ok(())
    }

    async fn delete_marketplace_node(&self, id: u64) -> DbResult<()> {
        let hosts = self.hosts.lock().await;
        // FK vm_host.marketplace_node_id
        if hosts.values().any(|h| h.marketplace_node_id == Some(id)) {
            return Err(anyhow!("Node {} still backs a vm_host", id).into());
        }
        drop(hosts);
        self.marketplace_nodes.lock().await.remove(&id);
        Ok(())
    }

    // ----- Tunnels -----

    async fn get_tunnel(&self, id: u64) -> DbResult<Tunnel> {
        let tunnels = self.tunnels.lock().await;
        tunnels
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("Tunnel {} not found", id).into())
    }

    async fn get_tunnel_by_peer_pubkey(&self, peer_pubkey: &[u8]) -> DbResult<Tunnel> {
        let tunnels = self.tunnels.lock().await;
        tunnels
            .values()
            .find(|t| t.peer_pubkey.as_deref() == Some(peer_pubkey))
            .cloned()
            .ok_or_else(|| anyhow!("No tunnel with that peer key").into())
    }

    async fn list_tunnels(&self) -> DbResult<Vec<Tunnel>> {
        let tunnels = self.tunnels.lock().await;
        let mut out: Vec<_> = tunnels.values().cloned().collect();
        out.sort_by_key(|t| t.id);
        Ok(out)
    }

    async fn list_tunnels_for_user(&self, user_id: u64) -> DbResult<Vec<Tunnel>> {
        let tunnels = self.tunnels.lock().await;
        let mut out: Vec<_> = tunnels
            .values()
            .filter(|t| t.user_id == user_id)
            .cloned()
            .collect();
        out.sort_by_key(|t| t.id);
        Ok(out)
    }

    async fn insert_tunnel(&self, tunnel: &Tunnel) -> DbResult<u64> {
        // FK tunnel.user_id (NOT NULL — every tunnel has an owner)
        if !self.users.lock().await.contains_key(&tunnel.user_id) {
            return Err(anyhow!("User {} not found", tunnel.user_id).into());
        }
        self.check_tunnel_pool_link(tunnel).await?;
        let mut tunnels = self.tunnels.lock().await;
        Self::check_tunnel_uniqueness(&tunnels, tunnel, None)?;
        let new_id = tunnels.keys().max().copied().unwrap_or(0) + 1;
        tunnels.insert(
            new_id,
            Tunnel {
                id: new_id,
                created: Utc::now(),
                ..tunnel.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_tunnel(&self, tunnel: &Tunnel) -> DbResult<()> {
        self.check_tunnel_pool_link(tunnel).await?;
        let mut tunnels = self.tunnels.lock().await;
        Self::check_tunnel_uniqueness(&tunnels, tunnel, Some(tunnel.id))?;
        let existing = tunnels
            .get_mut(&tunnel.id)
            .ok_or_else(|| DbError::Other(anyhow!("Tunnel {} not found", tunnel.id)))?;
        // user_id and created are not written: moving an allocation to another
        // owner would hand one tenant's addresses and key to another.
        existing.kind = tunnel.kind;
        existing.router_id = tunnel.router_id;
        existing.pool_id = tunnel.pool_id;
        existing.name = tunnel.name.clone();
        existing.peer_pubkey = tunnel.peer_pubkey.clone();
        existing.peer_endpoint = tunnel.peer_endpoint.clone();
        existing.address4 = tunnel.address4.clone();
        existing.address6 = tunnel.address6.clone();
        existing.keepalive = tunnel.keepalive;
        existing.enabled = tunnel.enabled;
        Ok(())
    }

    async fn delete_tunnel(&self, id: u64) -> DbResult<()> {
        // FK marketplace_node.tunnel_id
        if self
            .marketplace_nodes
            .lock()
            .await
            .values()
            .any(|n| n.tunnel_id == Some(id))
        {
            return Err(anyhow!("Tunnel {} still backs a marketplace node", id).into());
        }
        self.tunnels.lock().await.remove(&id);
        Ok(())
    }

    // ----- Tunnel pools -----

    async fn get_tunnel_pool(&self, id: u64) -> DbResult<TunnelPool> {
        let pools = self.tunnel_pools.lock().await;
        pools
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("Tunnel pool {} not found", id).into())
    }

    async fn list_tunnel_pools(&self, region_id: Option<u64>) -> DbResult<Vec<TunnelPool>> {
        let pools = self.tunnel_pools.lock().await;
        let mut out: Vec<_> = pools
            .values()
            .filter(|p| region_id.is_none_or(|r| p.region_id == r))
            .cloned()
            .collect();
        out.sort_by_key(|p| p.id);
        Ok(out)
    }

    async fn list_tunnels_in_pool(&self, pool_id: u64) -> DbResult<Vec<Tunnel>> {
        let tunnels = self.tunnels.lock().await;
        let mut out: Vec<_> = tunnels
            .values()
            .filter(|t| t.pool_id == Some(pool_id))
            .cloned()
            .collect();
        out.sort_by_key(|t| t.id);
        Ok(out)
    }

    async fn admin_list_tunnel_pools_paginated(
        &self,
        limit: u64,
        offset: u64,
        region_id: Option<u64>,
    ) -> DbResult<(Vec<TunnelPool>, u64)> {
        let pools = self.tunnel_pools.lock().await;
        let mut out: Vec<_> = pools
            .values()
            .filter(|p| region_id.is_none_or(|r| p.region_id == r))
            .cloned()
            .collect();
        out.sort_by(|a, b| b.id.cmp(&a.id));
        let total = out.len() as u64;
        Ok((
            out.into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect(),
            total,
        ))
    }

    async fn insert_tunnel_pool(&self, pool: &TunnelPool) -> DbResult<u64> {
        // FK tunnel_pool.router_id / region_id
        if !self.router.lock().await.contains_key(&pool.router_id) {
            return Err(anyhow!("Router {} not found", pool.router_id).into());
        }
        if !self.regions.lock().await.contains_key(&pool.region_id) {
            return Err(anyhow!("Region {} not found", pool.region_id).into());
        }
        // ck_tunnel_pool_has_a_block: a pool with neither block can allocate
        // nothing, and would only be discovered when a node asked for a tunnel.
        if pool.cidr4.is_none() && pool.cidr6.is_none() {
            return Err(anyhow!(
                "A tunnel pool must have an address block (ck_tunnel_pool_has_a_block)"
            )
            .into());
        }
        let mut pools = self.tunnel_pools.lock().await;
        // uk_tunnel_pool_router_port: an interface listens on every local
        // address at its port, so two of them collide over the port.
        if pools
            .values()
            .any(|p| p.router_id == pool.router_id && p.listen_port == pool.listen_port)
        {
            return Err(anyhow!(
                "Port {} on router {} is already used by another pool",
                pool.listen_port,
                pool.router_id
            )
            .into());
        }
        let id = pools.keys().max().copied().unwrap_or(0) + 1;
        pools.insert(
            id,
            TunnelPool {
                id,
                created: Utc::now(),
                ..pool.clone()
            },
        );
        Ok(id)
    }

    async fn bump_tunnel_pool_generation(&self, id: u64) -> DbResult<u64> {
        let mut pools = self.tunnel_pools.lock().await;
        let pool = pools
            .get_mut(&id)
            .ok_or_else(|| DbError::Other(anyhow!("Tunnel pool {} not found", id)))?;
        pool.generation += 1;
        Ok(pool.generation)
    }

    async fn update_tunnel_pool(&self, pool: &TunnelPool) -> DbResult<()> {
        if pool.cidr4.is_none() && pool.cidr6.is_none() {
            return Err(anyhow!(
                "A tunnel pool must have an address block (ck_tunnel_pool_has_a_block)"
            )
            .into());
        }
        let mut pools = self.tunnel_pools.lock().await;
        if pools.values().any(|p| {
            p.id != pool.id && p.router_id == pool.router_id && p.listen_port == pool.listen_port
        }) {
            return Err(anyhow!(
                "Port {} on router {} is already used by another pool",
                pool.listen_port,
                pool.router_id
            )
            .into());
        }
        // A pool already terminating a VPN service cannot have its block edited
        // away from its siblings': every interface on a service shares one
        // block, because a device holds one address in every region.
        {
            let links = self.vpn_service_pools.lock().await;
            if let Some(service_id) = links.get(&pool.id).copied()
                && let Some(other_id) = links
                    .iter()
                    .filter(|(pid, sid)| **sid == service_id && **pid != pool.id)
                    .filter_map(|(pid, _)| pools.get(pid).map(|p| (pid, p)))
                    .find(|(_, p)| p.cidr4 != pool.cidr4 || p.cidr6 != pool.cidr6)
                    .map(|(pid, _)| *pid)
            {
                return Err(anyhow!(
                    "Tunnel pool {} terminates a VPN service, so its block must stay the same \
                     as pool {}'s",
                    pool.id,
                    other_id
                )
                .into());
            }
        }
        let existing = pools
            .get_mut(&pool.id)
            .ok_or_else(|| DbError::Other(anyhow!("Tunnel pool {} not found", pool.id)))?;
        // router_id and created are not written: moving a pool to another route
        // server would leave every tunnel carved from it pointing at an
        // interface that does not exist there.
        existing.region_id = pool.region_id;
        existing.name = pool.name.clone();
        existing.listen_addr = pool.listen_addr.clone();
        existing.listen_port = pool.listen_port;
        existing.private_key = pool.private_key.clone();
        existing.public_key = pool.public_key.clone();
        existing.cidr4 = pool.cidr4.clone();
        existing.cidr6 = pool.cidr6.clone();
        existing.keepalive = pool.keepalive;
        existing.mtu = pool.mtu;
        existing.enabled = pool.enabled;
        Ok(())
    }

    async fn delete_tunnel_pool(&self, id: u64) -> DbResult<()> {
        // ON DELETE CASCADE: decommissioning an interface drops the link rather
        // than being refused by it.
        self.vpn_service_pools.lock().await.remove(&id);
        // FK tunnel.pool_id
        if self
            .tunnels
            .lock()
            .await
            .values()
            .any(|t| t.pool_id == Some(id))
        {
            return Err(anyhow!("Tunnel pool {} still has tunnels carved out of it", id).into());
        }
        self.tunnel_pools.lock().await.remove(&id);
        Ok(())
    }

    // ----- VPN -----

    async fn get_vpn_service(&self, id: u64) -> DbResult<VpnService> {
        self.vpn_services
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("VPN service {} not found", id).into())
    }

    async fn list_vpn_services(&self, enabled_only: bool) -> DbResult<Vec<VpnService>> {
        let services = self.vpn_services.lock().await;
        let mut out: Vec<_> = services
            .values()
            .filter(|s| !enabled_only || s.enabled)
            .cloned()
            .collect();
        out.sort_by_key(|s| s.id);
        Ok(out)
    }

    async fn insert_vpn_service(&self, service: &VpnService) -> DbResult<u64> {
        // FK vpn_service.company_id
        if !self
            .companies
            .lock()
            .await
            .contains_key(&service.company_id)
        {
            return Err(anyhow!("Company {} not found", service.company_id).into());
        }
        let mut services = self.vpn_services.lock().await;
        let new_id = services.keys().max().copied().unwrap_or(0) + 1;
        services.insert(
            new_id,
            VpnService {
                id: new_id,
                created: Utc::now(),
                ..service.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_vpn_service(&self, service: &VpnService) -> DbResult<()> {
        let mut services = self.vpn_services.lock().await;
        let existing = services
            .get(&service.id)
            .ok_or_else(|| DbError::Other(anyhow!("VPN service {} not found", service.id)))?;
        // `company_id` and `created` are immutable and are not written: moving
        // a service to another company would leave every plan sold on it booked
        // against a company that no longer owns it.
        let (company_id, created) = (existing.company_id, existing.created);
        services.insert(
            service.id,
            VpnService {
                company_id,
                created,
                ..service.clone()
            },
        );
        Ok(())
    }

    async fn delete_vpn_service(&self, id: u64) -> DbResult<()> {
        // FK vpn_subscription.vpn_service_id
        if self
            .vpn_subscriptions
            .lock()
            .await
            .values()
            .any(|s| s.vpn_service_id == id)
        {
            return Err(anyhow!("VPN service {} still has subscriptions", id).into());
        }
        // ON DELETE CASCADE on vpn_service_pool.vpn_service_id, after the guard
        // above and not before it: a refused delete must not have unlinked
        // anything. The link row is pure association, so it does not block.
        self.vpn_service_pools.lock().await.retain(|_, s| *s != id);
        self.vpn_services.lock().await.remove(&id);
        Ok(())
    }

    async fn get_vpn_service_for_pool(&self, tunnel_pool_id: u64) -> DbResult<Option<VpnService>> {
        let Some(service_id) = self
            .vpn_service_pools
            .lock()
            .await
            .get(&tunnel_pool_id)
            .copied()
        else {
            return Ok(None);
        };
        Ok(self.vpn_services.lock().await.get(&service_id).cloned())
    }

    async fn list_vpn_service_pools(&self, vpn_service_id: u64) -> DbResult<Vec<TunnelPool>> {
        let links = self.vpn_service_pools.lock().await;
        let pools = self.tunnel_pools.lock().await;
        let mut out: Vec<_> = links
            .iter()
            .filter(|(_, s)| **s == vpn_service_id)
            .filter_map(|(pool_id, _)| pools.get(pool_id).cloned())
            .collect();
        out.sort_by_key(|p| p.id);
        Ok(out)
    }

    async fn link_vpn_service_pool(
        &self,
        vpn_service_id: u64,
        tunnel_pool_id: u64,
    ) -> DbResult<()> {
        if !self.vpn_services.lock().await.contains_key(&vpn_service_id) {
            return Err(anyhow!("VPN service {} not found", vpn_service_id).into());
        }
        if !self.tunnel_pools.lock().await.contains_key(&tunnel_pool_id) {
            return Err(anyhow!("Tunnel pool {} not found", tunnel_pool_id).into());
        }
        // Every interface on a service shares one block, because a device holds
        // one address in every region. A pool with a different block would
        // route a subset of the devices and black-hole the rest.
        {
            let pools = self.tunnel_pools.lock().await;
            let links = self.vpn_service_pools.lock().await;
            let me = pools.get(&tunnel_pool_id);
            if let Some(me) = me
                && let Some((other_id, other)) = links
                    .iter()
                    .filter(|(pid, sid)| **sid == vpn_service_id && **pid != tunnel_pool_id)
                    .filter_map(|(pid, _)| pools.get(pid).map(|p| (pid, p)))
                    .find(|(_, p)| p.cidr4 != me.cidr4 || p.cidr6 != me.cidr6)
            {
                return Err(anyhow!(
                    "Tunnel pool {} cannot terminate VPN service {}: pool {} on it carries {:?}/{:?}",
                    tunnel_pool_id,
                    vpn_service_id,
                    other_id,
                    other.cidr4,
                    other.cidr6
                )
                .into());
            }
        }
        // Keyed by pool, so repointing replaces rather than adding a second
        // peer set to one interface.
        self.vpn_service_pools
            .lock()
            .await
            .insert(tunnel_pool_id, vpn_service_id);
        Ok(())
    }

    async fn unlink_vpn_service_pool(&self, tunnel_pool_id: u64) -> DbResult<()> {
        self.vpn_service_pools.lock().await.remove(&tunnel_pool_id);
        Ok(())
    }

    async fn admin_list_vpn_subscriptions_filtered(
        &self,
        limit: u64,
        offset: u64,
        user_id: Option<u64>,
        vpn_service_id: Option<u64>,
    ) -> DbResult<(Vec<VpnSubscription>, u64)> {
        let subs = self.vpn_subscriptions.lock().await;
        let mut matched: Vec<VpnSubscription> = subs
            .values()
            .filter(|s| user_id.is_none_or(|u| s.user_id == u))
            .filter(|s| vpn_service_id.is_none_or(|v| s.vpn_service_id == v))
            .cloned()
            .collect();
        matched.sort_by(|a, b| b.id.cmp(&a.id));
        let total = matched.len() as u64;
        Ok((
            matched
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect(),
            total,
        ))
    }

    async fn get_vpn_subscription(&self, id: u64) -> DbResult<VpnSubscription> {
        self.vpn_subscriptions
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("VPN subscription {} not found", id).into())
    }

    async fn get_vpn_subscription_for_user(
        &self,
        user_id: u64,
    ) -> DbResult<Option<VpnSubscription>> {
        Ok(self
            .vpn_subscriptions
            .lock()
            .await
            .values()
            .find(|s| s.user_id == user_id)
            .cloned())
    }

    async fn get_vpn_subscription_by_line_item(
        &self,
        subscription_line_item_id: u64,
    ) -> DbResult<Option<VpnSubscription>> {
        Ok(self
            .vpn_subscriptions
            .lock()
            .await
            .values()
            .find(|s| s.subscription_line_item_id == subscription_line_item_id)
            .cloned())
    }

    async fn insert_vpn_subscription(&self, sub: &VpnSubscription) -> DbResult<u64> {
        // FKs: the service, the account and the line item all have to exist.
        if !self
            .vpn_services
            .lock()
            .await
            .contains_key(&sub.vpn_service_id)
        {
            return Err(anyhow!("VPN service {} not found", sub.vpn_service_id).into());
        }
        if !self.users.lock().await.contains_key(&sub.user_id) {
            return Err(anyhow!("User {} not found", sub.user_id).into());
        }
        if !self
            .subscription_line_items
            .lock()
            .await
            .contains_key(&sub.subscription_line_item_id)
        {
            return Err(anyhow!(
                "Subscription line item {} not found",
                sub.subscription_line_item_id
            )
            .into());
        }
        let mut subs = self.vpn_subscriptions.lock().await;
        // uk_vpn_subscription_user: one plan per account. A lapsed customer
        // coming back reuses their row rather than getting a second one.
        if subs.values().any(|s| s.user_id == sub.user_id) {
            return Err(anyhow!(
                "User {} already has a VPN subscription (uk_vpn_subscription_user)",
                sub.user_id
            )
            .into());
        }
        // uk_vpn_subscription_line_item: one line item bills for one plan.
        if subs
            .values()
            .any(|s| s.subscription_line_item_id == sub.subscription_line_item_id)
        {
            return Err(anyhow!(
                "Line item {} already bills for a VPN subscription",
                sub.subscription_line_item_id
            )
            .into());
        }
        let new_id = subs.keys().max().copied().unwrap_or(0) + 1;
        subs.insert(
            new_id,
            VpnSubscription {
                id: new_id,
                created: Utc::now(),
                ..sub.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_vpn_subscription(&self, sub: &VpnSubscription) -> DbResult<()> {
        let mut subs = self.vpn_subscriptions.lock().await;
        let existing = subs
            .get(&sub.id)
            .cloned()
            .ok_or_else(|| DbError::Other(anyhow!("VPN subscription {} not found", sub.id)))?;
        if subs
            .values()
            .any(|s| s.id != sub.id && s.subscription_line_item_id == sub.subscription_line_item_id)
        {
            return Err(anyhow!(
                "Line item {} already bills for a VPN subscription",
                sub.subscription_line_item_id
            )
            .into());
        }
        // `user_id`, `vpn_service_id` and `created` are immutable and are not
        // written: moving a plan to another service would strand every device's
        // address, which is carved from the service's block.
        subs.insert(
            sub.id,
            VpnSubscription {
                user_id: existing.user_id,
                vpn_service_id: existing.vpn_service_id,
                created: existing.created,
                ..sub.clone()
            },
        );
        Ok(())
    }

    async fn get_vpn_device(&self, id: u64) -> DbResult<VpnDevice> {
        self.vpn_devices
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("VPN device {} not found", id).into())
    }

    async fn get_vpn_device_by_pubkey(&self, peer_pubkey: &[u8]) -> DbResult<Option<VpnDevice>> {
        let tunnels = self.tunnels.lock().await;
        let Some(tunnel) = tunnels
            .values()
            .find(|t| t.peer_pubkey.as_deref() == Some(peer_pubkey))
        else {
            return Ok(None);
        };
        Ok(self
            .vpn_devices
            .lock()
            .await
            .values()
            .find(|d| d.tunnel_id == tunnel.id)
            .cloned())
    }

    async fn list_vpn_devices(&self, vpn_subscription_id: u64) -> DbResult<Vec<VpnDevice>> {
        let devices = self.vpn_devices.lock().await;
        let mut out: Vec<_> = devices
            .values()
            .filter(|d| d.vpn_subscription_id == vpn_subscription_id)
            .cloned()
            .collect();
        out.sort_by_key(|d| d.slot);
        Ok(out)
    }

    async fn list_vpn_tunnels_in_service(&self, vpn_service_id: u64) -> DbResult<Vec<Tunnel>> {
        let subs = self.vpn_subscriptions.lock().await;
        let plans: Vec<u64> = subs
            .values()
            .filter(|s| s.vpn_service_id == vpn_service_id)
            .map(|s| s.id)
            .collect();
        let devices = self.vpn_devices.lock().await;
        let tunnels = self.tunnels.lock().await;
        let mut out: Vec<Tunnel> = devices
            .values()
            .filter(|d| plans.contains(&d.vpn_subscription_id))
            .filter_map(|d| tunnels.get(&d.tunnel_id).cloned())
            .collect();
        out.sort_by_key(|t| t.id);
        Ok(out)
    }

    async fn list_active_vpn_tunnels(&self, vpn_service_id: u64) -> DbResult<Vec<Tunnel>> {
        let subs = self.vpn_subscriptions.lock().await;
        let line_items = self.subscription_line_items.lock().await;
        let subscriptions = self.subscriptions.lock().await;
        let now = Utc::now();

        // The same billing join the SQL does, which is where suspension is
        // applied: an unpaid, deactivated or expired plan stops matching, so
        // its peers simply leave the set.
        let live: Vec<u64> = subs
            .values()
            .filter(|s| s.vpn_service_id == vpn_service_id)
            .filter(|s| {
                line_items
                    .get(&s.subscription_line_item_id)
                    .and_then(|li| subscriptions.get(&li.subscription_id))
                    .is_some_and(|sub| {
                        sub.is_active && sub.is_setup && sub.expires.is_none_or(|e| e > now)
                    })
            })
            .map(|s| s.id)
            .collect();

        let devices = self.vpn_devices.lock().await;
        let tunnels = self.tunnels.lock().await;
        let mut out: Vec<Tunnel> = devices
            .values()
            .filter(|d| live.contains(&d.vpn_subscription_id))
            .filter_map(|d| tunnels.get(&d.tunnel_id).cloned())
            .filter(|t| t.enabled)
            .collect();
        out.sort_by_key(|t| t.id);
        Ok(out)
    }

    async fn list_tunnel_routes(&self, tunnel_ids: &[u64]) -> DbResult<Vec<TunnelRoute>> {
        let routes = self.tunnel_routes.lock().await;
        let mut out: Vec<TunnelRoute> = tunnel_ids
            .iter()
            .filter_map(|id| routes.get(id).map(|p| (*id, p)))
            .flat_map(|(id, prefixes)| {
                prefixes.iter().map(move |p| TunnelRoute {
                    tunnel_id: id,
                    prefix: p.clone(),
                    created: Utc::now(),
                })
            })
            .collect();
        out.sort_by(|a, b| (a.tunnel_id, &a.prefix).cmp(&(b.tunnel_id, &b.prefix)));
        Ok(out)
    }

    async fn replace_tunnel_routes(&self, tunnel_id: u64, prefixes: &[String]) -> DbResult<()> {
        if !self.tunnels.lock().await.contains_key(&tunnel_id) {
            return Err(anyhow!("Tunnel {} not found", tunnel_id).into());
        }
        let mut routes = self.tunnel_routes.lock().await;
        if prefixes.is_empty() {
            routes.remove(&tunnel_id);
        } else {
            let mut p = prefixes.to_vec();
            p.sort();
            p.dedup();
            routes.insert(tunnel_id, p);
        }
        Ok(())
    }

    async fn insert_vpn_device(&self, device: &VpnDevice) -> DbResult<u64> {
        // FK vpn_device.vpn_subscription_id
        if !self
            .vpn_subscriptions
            .lock()
            .await
            .contains_key(&device.vpn_subscription_id)
        {
            return Err(
                anyhow!("VPN subscription {} not found", device.vpn_subscription_id).into(),
            );
        }
        if !self.tunnels.lock().await.contains_key(&device.tunnel_id) {
            return Err(anyhow!("Tunnel {} not found", device.tunnel_id).into());
        }
        let mut devices = self.vpn_devices.lock().await;
        Self::check_vpn_device_uniqueness(&devices, device, None)?;
        let new_id = devices.keys().max().copied().unwrap_or(0) + 1;
        devices.insert(
            new_id,
            VpnDevice {
                id: new_id,
                created: Utc::now(),
                ..device.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_vpn_device(&self, device: &VpnDevice) -> DbResult<()> {
        let mut devices = self.vpn_devices.lock().await;
        let existing = devices
            .get(&device.id)
            .cloned()
            .ok_or_else(|| DbError::Other(anyhow!("VPN device {} not found", device.id)))?;
        Self::check_vpn_device_uniqueness(&devices, device, Some(device.id))?;
        // Only the customer's label is mutable. The peer behind a device is
        // what their config points at, so moving it would strand the config
        // they are already holding.
        devices.insert(
            device.id,
            VpnDevice {
                name: device.name.clone(),
                ..existing
            },
        );
        Ok(())
    }

    async fn delete_vpn_device(&self, id: u64) -> DbResult<()> {
        // The tunnel goes with the device: only this row knows which tunnel
        // belongs to the customer, so deleting the link alone leaves a tunnel
        // no query can see, still holding a public key.
        let removed = self.vpn_devices.lock().await.remove(&id);
        if let Some(device) = removed {
            self.tunnels.lock().await.remove(&device.tunnel_id);
            // ON DELETE CASCADE off `tunnel`.
            self.tunnel_routes.lock().await.remove(&device.tunnel_id);
        }
        Ok(())
    }

    // ----- App catalog -----

    async fn list_apps(&self, enabled_only: bool) -> DbResult<Vec<App>> {
        let apps = self.apps.lock().await;
        let mut out: Vec<App> = apps
            .values()
            .filter(|a| !enabled_only || a.enabled)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        Ok(out)
    }

    async fn admin_list_apps_filtered(
        &self,
        limit: u64,
        offset: u64,
        enabled: Option<bool>,
        search: Option<&str>,
    ) -> DbResult<(Vec<App>, u64)> {
        let search = search
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);
        let apps = self.apps.lock().await;
        let mut all: Vec<App> = apps
            .values()
            .filter(|a| enabled.is_none_or(|e| a.enabled == e))
            .filter(|a| {
                search.as_ref().is_none_or(|q| {
                    a.name.to_lowercase().contains(q)
                        || a.display_name.to_lowercase().contains(q)
                        || a.description
                            .as_ref()
                            .is_some_and(|d| d.to_lowercase().contains(q))
                })
            })
            .cloned()
            .collect();
        all.sort_by(|a, b| b.id.cmp(&a.id));
        Ok(paginate(all, limit, offset))
    }

    async fn get_app(&self, id: u64) -> DbResult<App> {
        self.apps
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("app not found").into())
    }

    async fn get_app_by_name(&self, name: &str) -> DbResult<App> {
        self.apps
            .lock()
            .await
            .values()
            .find(|a| a.name == name)
            .cloned()
            .ok_or_else(|| anyhow!("app not found").into())
    }

    async fn insert_app(&self, app: &App) -> DbResult<u64> {
        let mut apps = self.apps.lock().await;
        if apps.values().any(|a| a.name == app.name) {
            return Err(DbError::Other(anyhow!("app name already exists")));
        }
        let new_id = apps.keys().max().copied().unwrap_or(0) + 1;
        apps.insert(
            new_id,
            App {
                id: new_id,
                ..app.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_app(&self, app: &App) -> DbResult<()> {
        let mut apps = self.apps.lock().await;
        if let Some(a) = apps.get_mut(&app.id) {
            *a = app.clone();
        }
        Ok(())
    }

    async fn delete_app(&self, id: u64) -> DbResult<()> {
        self.apps.lock().await.remove(&id);
        // Stands in for `fk_app_tag_assignment_app ON DELETE CASCADE`.
        self.app_tag_assignments
            .lock()
            .await
            .retain(|(app_id, _)| *app_id != id);
        Ok(())
    }

    // ----- App tags -----

    async fn list_app_tags(&self) -> DbResult<Vec<AppTag>> {
        let tags = self.app_tags.lock().await;
        let mut out: Vec<AppTag> = tags.values().cloned().collect();
        out.sort_by(|a, b| a.slug.cmp(&b.slug));
        Ok(out)
    }

    async fn list_app_tags_with_counts(&self) -> DbResult<Vec<(AppTag, u64)>> {
        let tags = self.list_app_tags().await?;
        let assignments = self.app_tag_assignments.lock().await;
        let apps = self.apps.lock().await;
        Ok(tags
            .into_iter()
            .map(|t| {
                let count = assignments
                    .iter()
                    .filter(|(app_id, tag_id)| {
                        // Enabled apps only, matching the LEFT JOIN condition
                        // in the MySQL implementation: a disabled app is not in
                        // the public catalog, so counting it would advertise a
                        // result a visitor cannot see.
                        *tag_id == t.id && apps.get(app_id).is_some_and(|a| a.enabled)
                    })
                    .count() as u64;
                (t, count)
            })
            .collect())
    }

    async fn get_app_tag(&self, id: u64) -> DbResult<AppTag> {
        self.app_tags
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("app tag not found").into())
    }

    async fn get_app_tag_by_slug(&self, slug: &str) -> DbResult<AppTag> {
        self.app_tags
            .lock()
            .await
            .values()
            .find(|t| t.slug == slug)
            .cloned()
            .ok_or_else(|| anyhow!("app tag not found").into())
    }

    async fn insert_app_tag(&self, tag: &AppTag) -> DbResult<u64> {
        let mut tags = self.app_tags.lock().await;
        // Stands in for `uq_app_tag_slug`.
        if tags.values().any(|t| t.slug == tag.slug) {
            return Err(DbError::Other(anyhow!("app tag slug already exists")));
        }
        let new_id = tags.keys().max().copied().unwrap_or(0) + 1;
        tags.insert(
            new_id,
            AppTag {
                id: new_id,
                ..tag.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_app_tag(&self, tag: &AppTag) -> DbResult<()> {
        let mut tags = self.app_tags.lock().await;
        if tags.values().any(|t| t.slug == tag.slug && t.id != tag.id) {
            return Err(DbError::Other(anyhow!("app tag slug already exists")));
        }
        if let Some(t) = tags.get_mut(&tag.id) {
            *t = tag.clone();
        }
        Ok(())
    }

    async fn delete_app_tag(&self, id: u64) -> DbResult<u64> {
        self.app_tags.lock().await.remove(&id);
        let mut assignments = self.app_tag_assignments.lock().await;
        let before = assignments.len();
        // Stands in for `fk_app_tag_assignment_tag ON DELETE CASCADE`.
        assignments.retain(|(_, tag_id)| *tag_id != id);
        Ok((before - assignments.len()) as u64)
    }

    async fn list_app_tag_assignments(&self, app_ids: &[u64]) -> DbResult<Vec<(u64, AppTag)>> {
        if app_ids.is_empty() {
            return Ok(vec![]);
        }
        let assignments = self.app_tag_assignments.lock().await;
        let tags = self.app_tags.lock().await;
        let mut out: Vec<(u64, AppTag)> = assignments
            .iter()
            .filter(|(app_id, _)| app_ids.contains(app_id))
            .filter_map(|(app_id, tag_id)| tags.get(tag_id).map(|t| (*app_id, t.clone())))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.slug.cmp(&b.1.slug)));
        Ok(out)
    }

    async fn set_app_tags(&self, app_id: u64, tag_ids: &[u64]) -> DbResult<()> {
        let mut assignments = self.app_tag_assignments.lock().await;
        assignments.retain(|(a, _)| *a != app_id);
        for tag_id in tag_ids {
            // De-duplicate, standing in for `uq_app_tag_assignment`: a request
            // listing the same slug twice is one assignment, not an error.
            if !assignments.contains(&(app_id, *tag_id)) {
                assignments.push((app_id, *tag_id));
            }
        }
        Ok(())
    }

    // ----- App clusters -----

    async fn list_app_clusters(&self, enabled_only: bool) -> DbResult<Vec<AppCluster>> {
        let clusters = self.app_clusters.lock().await;
        let mut out: Vec<AppCluster> = clusters
            .values()
            .filter(|c| !enabled_only || c.enabled)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn admin_list_app_clusters_filtered(
        &self,
        limit: u64,
        offset: u64,
        enabled: Option<bool>,
        region_id: Option<u64>,
        search: Option<&str>,
    ) -> DbResult<(Vec<AppCluster>, u64)> {
        let search = search
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);
        let clusters = self.app_clusters.lock().await;
        let mut all: Vec<AppCluster> = clusters
            .values()
            .filter(|c| enabled.is_none_or(|e| c.enabled == e))
            .filter(|c| region_id.is_none_or(|r| c.region_id == r))
            .filter(|c| {
                search.as_ref().is_none_or(|q| {
                    c.name.to_lowercase().contains(q) || c.ingress_domain.to_lowercase().contains(q)
                })
            })
            .cloned()
            .collect();
        all.sort_by(|a, b| b.id.cmp(&a.id));
        Ok(paginate(all, limit, offset))
    }

    async fn get_app_cluster(&self, id: u64) -> DbResult<AppCluster> {
        self.app_clusters
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("app cluster not found").into())
    }

    async fn insert_app_cluster(&self, cluster: &AppCluster) -> DbResult<u64> {
        let mut clusters = self.app_clusters.lock().await;
        let new_id = clusters.keys().max().copied().unwrap_or(0) + 1;
        clusters.insert(
            new_id,
            AppCluster {
                id: new_id,
                ..cluster.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_app_cluster(&self, cluster: &AppCluster) -> DbResult<()> {
        let mut clusters = self.app_clusters.lock().await;
        if let Some(c) = clusters.get_mut(&cluster.id) {
            *c = cluster.clone();
        }
        Ok(())
    }

    async fn delete_app_cluster(&self, id: u64) -> DbResult<()> {
        self.app_clusters.lock().await.remove(&id);
        Ok(())
    }

    // ----- App deployments -----

    async fn list_user_app_deployments(&self, user_id: u64) -> DbResult<Vec<AppDeployment>> {
        let d = self.app_deployments.lock().await;
        let mut out: Vec<AppDeployment> = d
            .values()
            .filter(|x| x.user_id == user_id && !x.deleted)
            .cloned()
            .collect();
        out.sort_by(|a, b| b.created.cmp(&a.created));
        Ok(out)
    }

    async fn list_all_app_deployments(&self) -> DbResult<Vec<AppDeployment>> {
        let d = self.app_deployments.lock().await;
        let mut out: Vec<AppDeployment> = d.values().filter(|x| !x.deleted).cloned().collect();
        out.sort_by_key(|x| x.id);
        Ok(out)
    }

    async fn admin_list_app_deployments_filtered(
        &self,
        limit: u64,
        offset: u64,
        filter: &AppDeploymentFilter,
    ) -> DbResult<(Vec<AppDeployment>, u64)> {
        // Resolve the region filter to cluster ids first, so the clusters lock
        // is released before the deployments lock is taken.
        let region_clusters: Option<Vec<u64>> = match filter.region_id {
            Some(region_id) => Some(
                self.app_clusters
                    .lock()
                    .await
                    .values()
                    .filter(|c| c.region_id == region_id)
                    .map(|c| c.id)
                    .collect(),
            ),
            None => None,
        };
        let search = filter
            .search
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);

        let deployments = self.app_deployments.lock().await;
        let mut all: Vec<AppDeployment> = deployments
            .values()
            .filter(|d| filter.include_deleted || !d.deleted)
            .filter(|d| filter.user_id.is_none_or(|u| d.user_id == u))
            .filter(|d| filter.app_id.is_none_or(|a| d.app_id == a))
            .filter(|d| filter.cluster_id.is_none_or(|c| d.cluster_id == c))
            .filter(|d| {
                region_clusters
                    .as_ref()
                    .is_none_or(|ids| ids.contains(&d.cluster_id))
            })
            .filter(|d| filter.status.is_none_or(|s| d.status == s))
            .filter(|d| filter.desired_state.is_none_or(|s| d.desired_state == s))
            .filter(|d| {
                search.as_ref().is_none_or(|q| {
                    d.name.to_lowercase().contains(q)
                        || d.hostname
                            .as_ref()
                            .is_some_and(|h| h.to_lowercase().contains(q))
                        || d.custom_domain
                            .as_ref()
                            .is_some_and(|c| c.to_lowercase().contains(q))
                })
            })
            .cloned()
            .collect();
        all.sort_by(|a, b| b.id.cmp(&a.id));
        Ok(paginate(all, limit, offset))
    }

    async fn get_app_deployment(&self, id: u64) -> DbResult<AppDeployment> {
        self.app_deployments
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("app deployment not found").into())
    }

    async fn get_app_deployment_by_line_item(&self, line_item_id: u64) -> DbResult<AppDeployment> {
        self.app_deployments
            .lock()
            .await
            .values()
            .find(|x| x.subscription_line_item_id == line_item_id)
            .cloned()
            .ok_or_else(|| anyhow!("app deployment not found").into())
    }

    async fn list_app_deployments_by_line_items(
        &self,
        line_item_ids: &[u64],
    ) -> DbResult<Vec<AppDeployment>> {
        Ok(self
            .app_deployments
            .lock()
            .await
            .values()
            .filter(|x| line_item_ids.contains(&x.subscription_line_item_id))
            .cloned()
            .collect())
    }

    async fn find_app_deployment_by_cluster_name(
        &self,
        cluster_id: u64,
        name: &str,
    ) -> DbResult<Option<AppDeployment>> {
        Ok(self
            .app_deployments
            .lock()
            .await
            .values()
            .find(|x| x.cluster_id == cluster_id && x.name == name && !x.deleted)
            .cloned())
    }

    async fn insert_app_deployment(&self, deployment: &AppDeployment) -> DbResult<u64> {
        let mut d = self.app_deployments.lock().await;
        let new_id = d.keys().max().copied().unwrap_or(0) + 1;
        d.insert(
            new_id,
            AppDeployment {
                id: new_id,
                ..deployment.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_app_deployment(&self, deployment: &AppDeployment) -> DbResult<()> {
        let mut d = self.app_deployments.lock().await;
        if let Some(x) = d.get_mut(&deployment.id) {
            *x = deployment.clone();
        }
        Ok(())
    }

    async fn set_app_deployment_custom_domain_verified(&self, id: u64) -> DbResult<()> {
        let mut d = self.app_deployments.lock().await;
        if let Some(x) = d.get_mut(&id) {
            x.custom_domain_verified = true;
        }
        Ok(())
    }

    async fn update_app_deployment_usage(
        &self,
        id: u64,
        cpu_milli: u32,
        memory_bytes: u64,
        storage_bytes: Option<u64>,
    ) -> DbResult<()> {
        if self.failing_usage_writes.lock().await.contains(&id) {
            return Err(DbError::Other(anyhow!("usage write denied for {id}")));
        }
        let mut d = self.app_deployments.lock().await;
        if let Some(x) = d.get_mut(&id) {
            x.usage_cpu_milli = Some(cpu_milli);
            x.usage_memory_bytes = Some(memory_bytes);
            x.usage_storage_bytes = storage_bytes;
            x.usage_collected = Some(Utc::now());
        }
        Ok(())
    }

    async fn replace_app_deployment_usage_breakdown(
        &self,
        id: u64,
        services: &[AppDeploymentServiceUsage],
        volumes: &[AppDeploymentVolumeUsage],
    ) -> DbResult<()> {
        if self
            .failing_usage_breakdown_writes
            .lock()
            .await
            .contains(&id)
        {
            return Err(DbError::Other(anyhow!(
                "usage breakdown write denied for {id}"
            )));
        }
        let mut b = self.app_deployment_usage_breakdown.lock().await;
        b.insert(id, (services.to_vec(), volumes.to_vec()));
        Ok(())
    }

    async fn list_app_deployment_usage_breakdown(
        &self,
        ids: &[u64],
    ) -> DbResult<(
        Vec<AppDeploymentServiceUsage>,
        Vec<AppDeploymentVolumeUsage>,
    )> {
        let b = self.app_deployment_usage_breakdown.lock().await;
        let mut services = Vec::new();
        let mut volumes = Vec::new();
        for id in ids {
            if let Some((s, v)) = b.get(id) {
                services.extend(s.iter().cloned());
                volumes.extend(v.iter().cloned());
            }
        }
        Ok((services, volumes))
    }

    async fn list_app_deployment_backups(
        &self,
        deployment_id: u64,
    ) -> DbResult<Vec<AppDeploymentBackup>> {
        let b = self.app_deployment_backups.lock().await;
        let mut out: Vec<AppDeploymentBackup> = b
            .values()
            .filter(|x| x.deployment_id == deployment_id && !x.deleted)
            .cloned()
            .collect();
        out.sort_by(|a, b| b.created.cmp(&a.created).then(b.id.cmp(&a.id)));
        Ok(out)
    }

    async fn get_app_deployment_backup(&self, id: u64) -> DbResult<AppDeploymentBackup> {
        self.app_deployment_backups
            .lock()
            .await
            .get(&id)
            .filter(|b| !b.deleted)
            .cloned()
            .ok_or_else(|| anyhow!("app deployment backup not found").into())
    }

    async fn insert_app_deployment_backup(&self, backup: &AppDeploymentBackup) -> DbResult<u64> {
        let mut b = self.app_deployment_backups.lock().await;
        let new_id = b.keys().max().copied().unwrap_or(0) + 1;
        b.insert(
            new_id,
            AppDeploymentBackup {
                id: new_id,
                ..backup.clone()
            },
        );
        Ok(new_id)
    }

    async fn update_app_deployment_backup(&self, backup: &AppDeploymentBackup) -> DbResult<()> {
        let mut b = self.app_deployment_backups.lock().await;
        if let Some(x) = b.get_mut(&backup.id) {
            // Mirrors the UPDATE's column list: everything else is immutable
            // once the row exists.
            x.object_key = backup.object_key.clone();
            x.size_bytes = backup.size_bytes;
            x.state = backup.state;
            x.message = backup.message.clone();
            x.started = backup.started;
            x.completed = backup.completed;
        }
        Ok(())
    }

    async fn list_active_app_deployment_backups(
        &self,
        cluster_id: u64,
    ) -> DbResult<Vec<AppDeploymentBackup>> {
        let deployments = self.app_deployments.lock().await;
        let b = self.app_deployment_backups.lock().await;
        let mut out: Vec<AppDeploymentBackup> = b
            .values()
            .filter(|x| {
                !x.deleted
                    && matches!(x.state, AppBackupState::Pending | AppBackupState::Running)
                    && deployments
                        .get(&x.deployment_id)
                        .is_some_and(|d| d.cluster_id == cluster_id)
            })
            .cloned()
            .collect();
        out.sort_by_key(|x| x.id);
        Ok(out)
    }

    async fn last_scheduled_app_deployment_backup(
        &self,
        deployment_id: u64,
    ) -> DbResult<Option<DateTime<Utc>>> {
        let b = self.app_deployment_backups.lock().await;
        Ok(b.values()
            .filter(|x| x.deployment_id == deployment_id && x.scheduled)
            .map(|x| x.created)
            .max())
    }

    async fn delete_app_deployment_backup(&self, id: u64) -> DbResult<()> {
        let mut b = self.app_deployment_backups.lock().await;
        if let Some(x) = b.get_mut(&id) {
            x.deleted = true;
        }
        Ok(())
    }

    async fn delete_app_deployment(&self, id: u64) -> DbResult<()> {
        let mut d = self.app_deployments.lock().await;
        if let Some(x) = d.get_mut(&id) {
            x.deleted = true;
        }
        Ok(())
    }

    async fn hard_delete_app_deployment(&self, id: u64) -> DbResult<()> {
        let Some(deployment) = self.app_deployments.lock().await.remove(&id) else {
            return Ok(());
        };
        // The usage tables cascade from the deployment row in MySQL.
        self.app_deployment_usage_breakdown.lock().await.remove(&id);

        // Remove the billing records the deployment was attached to.
        let subscription_id = self
            .subscription_line_items
            .lock()
            .await
            .get(&deployment.subscription_line_item_id)
            .map(|li| li.subscription_id);
        if let Some(subscription_id) = subscription_id {
            // Keep the billing rows if the subscription still bills something
            // else (a VM or another deployment).
            let line_item_ids: Vec<u64> = self
                .subscription_line_items
                .lock()
                .await
                .values()
                .filter(|li| li.subscription_id == subscription_id)
                .map(|li| li.id)
                .collect();
            let still_billed = self
                .vms
                .lock()
                .await
                .values()
                .any(|v| line_item_ids.contains(&v.subscription_line_item_id))
                || self
                    .app_deployments
                    .lock()
                    .await
                    .values()
                    .any(|d| line_item_ids.contains(&d.subscription_line_item_id));

            if !still_billed {
                self.subscription_payments
                    .lock()
                    .await
                    .retain(|p| p.subscription_id != subscription_id);
                self.subscription_line_items
                    .lock()
                    .await
                    .retain(|_, li| li.subscription_id != subscription_id);
                self.subscriptions.lock().await.remove(&subscription_id);
            }
        }
        Ok(())
    }
}

pub struct MockExchangeRate {
    pub rate: Arc<Mutex<HashMap<Ticker, f32>>>,
}

impl Default for MockExchangeRate {
    fn default() -> Self {
        Self::new()
    }
}

impl MockExchangeRate {
    pub fn new() -> Self {
        Self {
            rate: Arc::new(Mutex::new(Default::default())),
        }
    }
}

#[async_trait]
impl ExchangeRateService for MockExchangeRate {
    async fn fetch_rates(&self) -> anyhow::Result<Vec<TickerRate>> {
        let r = self.rate.lock().await;
        Ok(r.iter()
            .map(|(k, v)| TickerRate {
                ticker: *k,
                rate: *v,
            })
            .collect())
    }

    async fn set_rate(&self, ticker: Ticker, amount: f32) {
        let mut r = self.rate.lock().await;
        if let Some(v) = r.get_mut(&ticker) {
            *v += amount;
        } else {
            r.insert(ticker, amount);
        }
    }

    async fn get_rate(&self, ticker: Ticker) -> Option<f32> {
        let r = self.rate.lock().await;
        r.get(&ticker).cloned()
    }

    async fn list_rates(&self) -> anyhow::Result<Vec<TickerRate>> {
        self.fetch_rates().await
    }
}

// Admin trait implementation with stub methods
#[cfg(feature = "admin")]
#[async_trait]
impl lnvps_db::AdminDb for MockDb {
    async fn get_user_permissions(
        &self,
        _user_id: u64,
    ) -> DbResult<std::collections::HashSet<(u16, u16)>> {
        Ok(std::collections::HashSet::new())
    }

    async fn get_user_roles(&self, _user_id: u64) -> DbResult<Vec<u64>> {
        Ok(vec![])
    }

    async fn is_admin_user(&self, _user_id: u64) -> DbResult<bool> {
        Ok(false)
    }

    async fn assign_user_role(
        &self,
        _user_id: u64,
        _role_id: u64,
        _assigned_by: u64,
    ) -> DbResult<()> {
        Ok(())
    }

    async fn revoke_user_role(&self, _user_id: u64, _role_id: u64) -> DbResult<()> {
        Ok(())
    }

    async fn create_role(&self, _name: &str, _description: Option<&str>) -> DbResult<u64> {
        Ok(1)
    }

    async fn get_role(&self, _role_id: u64) -> DbResult<AdminRole> {
        todo!()
    }

    async fn get_role_by_name(&self, _name: &str) -> DbResult<AdminRole> {
        todo!()
    }

    async fn list_roles(&self) -> DbResult<Vec<AdminRole>> {
        Ok(vec![])
    }

    async fn list_roles_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<AdminRole>, u64)> {
        let page: Vec<AdminRole> = vec![]
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, 0))
    }

    async fn update_role(&self, _role: &AdminRole) -> DbResult<()> {
        Ok(())
    }

    async fn delete_role(&self, _role_id: u64) -> DbResult<()> {
        Ok(())
    }

    async fn add_role_permission(
        &self,
        _role_id: u64,
        _resource: u16,
        _action: u16,
    ) -> DbResult<()> {
        Ok(())
    }

    async fn remove_role_permission(
        &self,
        _role_id: u64,
        _resource: u16,
        _action: u16,
    ) -> DbResult<()> {
        Ok(())
    }

    async fn get_role_permissions(&self, _role_id: u64) -> DbResult<Vec<(u16, u16)>> {
        Ok(vec![])
    }

    async fn get_user_role_assignments(&self, _user_id: u64) -> DbResult<Vec<AdminRoleAssignment>> {
        Ok(vec![])
    }

    async fn count_role_users(&self, _role_id: u64) -> DbResult<u64> {
        Ok(0)
    }

    async fn admin_list_users(
        &self,
        limit: u64,
        offset: u64,
        _filters: &lnvps_db::UserFilters,
    ) -> DbResult<(Vec<AdminUserInfo>, u64)> {
        let users = self.users.lock().await;
        let total = users.len() as u64;
        let paginated_users: Vec<AdminUserInfo> = users
            .values()
            .skip(offset as usize)
            .take(limit as usize)
            .map(|u| AdminUserInfo {
                user_info: u.clone(),
                vm_count: 0,
                is_admin: false,
                has_nwc: false,
            })
            .collect();
        Ok((paginated_users, total))
    }

    /// Match on the hash of each seeded user's address, like the real query
    /// does against the indexed `email_hash` column.
    ///
    /// A stub returning `None` would make every caller of this lookup
    /// untestable against the mock — including the support agent, which
    /// resolves an email sender to an account through it.
    async fn admin_find_user_by_email_hash(
        &self,
        hash: &[u8; 32],
    ) -> DbResult<Option<AdminUserInfo>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .find(|u| {
                let email = u.email.as_str();
                !email.is_empty() && &lnvps_db::email_hash(email) == hash
            })
            .map(|u| AdminUserInfo {
                user_info: u.clone(),
                vm_count: 0,
                is_admin: false,
                has_nwc: false,
            }))
    }

    async fn admin_list_regions(&self, limit: u64, offset: u64) -> DbResult<(Vec<Region>, u64)> {
        let regions = self.regions.lock().await;
        let total = regions.len() as u64;
        let paginated_regions: Vec<Region> = regions
            .values()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok((paginated_regions, total))
    }

    // Add stub implementations for all remaining AdminDb methods
    async fn admin_create_region(
        &self,
        name: &str,
        enabled: bool,
        company_id: u64,
        country_code: Option<&str>,
    ) -> DbResult<u64> {
        // A real insert, not a stubbed `Ok(1)`: anything that derives a
        // company from a region — marketplace listing fees, IP space pricing —
        // would otherwise be tested against the seeded region no matter which
        // one it asked for, and a cross-company check would pass by accident.
        if !self.companies.lock().await.contains_key(&company_id) {
            return Err(anyhow!("Company {} not found", company_id).into());
        }
        let mut regions = self.regions.lock().await;
        let id = regions.keys().max().copied().unwrap_or(0) + 1;
        regions.insert(
            id,
            Region {
                id,
                name: name.to_string(),
                enabled,
                company_id,
                country_code: country_code.map(|c| c.to_string()),
            },
        );
        Ok(id)
    }
    async fn admin_update_region(&self, region: &Region) -> DbResult<()> {
        let mut regions = self.regions.lock().await;
        if let Some(r) = regions.get_mut(&region.id) {
            *r = region.clone();
        }
        Ok(())
    }
    async fn admin_delete_region(&self, _region_id: u64) -> DbResult<()> {
        Ok(())
    }
    async fn admin_count_region_hosts(&self, _region_id: u64) -> DbResult<u64> {
        Ok(0)
    }
    async fn admin_delete_host(&self, host_id: u64) -> DbResult<()> {
        let mut hosts = self.hosts.lock().await;
        if !hosts.contains_key(&host_id) {
            return Err(anyhow!("no host").into());
        }

        let vms = self.vms.lock().await;
        let active_vms = vms
            .values()
            .filter(|v| v.host_id == host_id && !v.deleted)
            .count();
        if active_vms > 0 {
            return Err(anyhow!("Cannot delete host with {} active VMs", active_vms).into());
        }
        let historic_vms = vms.values().filter(|v| v.host_id == host_id).count();
        if historic_vms > 0 {
            return Err(anyhow!(
                "Cannot delete host with {} deleted VM records still referencing it, disable the host instead",
                historic_vms
            )
            .into());
        }

        hosts.remove(&host_id);
        self.host_disks
            .lock()
            .await
            .retain(|_, d| d.host_id != host_id);
        Ok(())
    }
    async fn admin_get_region_stats(&self, region_id: u64) -> DbResult<RegionStats> {
        let hosts = self.hosts.lock().await;
        let region_hosts: Vec<&VmHost> = hosts
            .values()
            .filter(|h| h.region_id == region_id)
            .collect();
        let host_ids: Vec<u64> = region_hosts.iter().map(|h| h.id).collect();

        let vms = self.vms.lock().await;
        let region_vms: Vec<u64> = vms
            .values()
            .filter(|v| !v.deleted && host_ids.contains(&v.host_id))
            .map(|v| v.id)
            .collect();

        let ranges = self.ip_range.lock().await;
        let assignments = self.ip_assignments.lock().await;
        let mut total_ip_assignments = 0;
        let mut ipv4_assignments = 0;
        let mut ipv6_assignments = 0;
        for assignment in assignments
            .values()
            .filter(|a| !a.deleted && region_vms.contains(&a.vm_id))
        {
            total_ip_assignments += 1;
            match ranges.get(&assignment.ip_range_id) {
                // Address family is derived from the range CIDR, as in the MySQL impl
                Some(r) if r.cidr.contains(':') => ipv6_assignments += 1,
                Some(_) => ipv4_assignments += 1,
                None => {}
            }
        }

        Ok(RegionStats {
            host_count: region_hosts.len() as u64,
            total_vms: region_vms.len() as u64,
            total_cpu_cores: region_hosts.iter().map(|h| h.cpu as u64).sum(),
            total_memory_bytes: region_hosts.iter().map(|h| h.memory).sum(),
            total_ip_assignments,
            ipv4_assignments,
            ipv6_assignments,
        })
    }
    async fn admin_transfer_vm(&self, vm_id: u64, new_user_id: u64) -> DbResult<()> {
        let mut vms = self.vms.lock().await;
        let vm = vms.get_mut(&vm_id).ok_or(anyhow!("no vm"))?;
        vm.user_id = new_user_id;
        vm.ssh_key_id = None;
        Ok(())
    }

    async fn admin_list_vm_os_images(
        &self,
        _limit: u64,
        _offset: u64,
    ) -> DbResult<(Vec<VmOsImage>, u64)> {
        Ok((vec![], 0))
    }
    async fn admin_get_vm_os_image(&self, _image_id: u64) -> DbResult<VmOsImage> {
        todo!()
    }
    async fn admin_create_vm_os_image(&self, _image: &VmOsImage) -> DbResult<u64> {
        Ok(1)
    }
    async fn admin_update_vm_os_image(&self, _image: &VmOsImage) -> DbResult<()> {
        Ok(())
    }
    async fn admin_delete_vm_os_image(&self, _image_id: u64) -> DbResult<()> {
        Ok(())
    }
    async fn list_vm_templates_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> DbResult<(Vec<VmTemplate>, i64)> {
        let templates = self.templates.lock().await;
        let total = templates.len() as i64;
        let paginated: Vec<VmTemplate> = templates
            .values()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok((paginated, total))
    }
    async fn update_vm_template(&self, _template: &VmTemplate) -> DbResult<()> {
        Ok(())
    }
    async fn delete_vm_template(&self, _template_id: u64) -> DbResult<()> {
        Ok(())
    }
    async fn check_vm_template_usage(&self, _template_id: u64) -> DbResult<i64> {
        Ok(0)
    }
    async fn admin_list_hosts_with_regions_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<AdminVmHost>, u64)> {
        let (host_region_pairs, total) = self
            .list_hosts_with_regions_paginated(limit, offset)
            .await?;

        let mut admin_hosts = Vec::new();
        for (host, region) in host_region_pairs {
            let disks = self.list_host_disks(host.id).await?;
            let active_vm_count = self.count_active_vms_on_host(host.id).await.unwrap_or(0);

            let admin_host = AdminVmHost {
                host,
                region_id: region.id,
                region_name: region.name,
                region_enabled: region.enabled,
                region_company_id: region.company_id,
                region_country_code: region.country_code,
                disks,
                active_vm_count: active_vm_count as _,
            };
            admin_hosts.push(admin_host);
        }

        Ok((admin_hosts, total))
    }
    async fn insert_custom_pricing(&self, pricing: &VmCustomPricing) -> DbResult<u64> {
        let mut pricing_map = self.custom_pricing.lock().await;
        let max_id = pricing_map.keys().max().unwrap_or(&0) + 1;
        let mut new_pricing = pricing.clone();
        new_pricing.id = max_id;
        pricing_map.insert(max_id, new_pricing);
        Ok(max_id)
    }
    async fn update_custom_pricing(&self, pricing: &VmCustomPricing) -> DbResult<()> {
        let mut pricing_map = self.custom_pricing.lock().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) = pricing_map.entry(pricing.id) {
            e.insert(pricing.clone());
            Ok(())
        } else {
            Err(anyhow!("Custom pricing not found: {}", pricing.id).into())
        }
    }
    async fn delete_custom_pricing(&self, id: u64) -> DbResult<()> {
        let mut pricing_map = self.custom_pricing.lock().await;
        if pricing_map.remove(&id).is_some() {
            Ok(())
        } else {
            Err(anyhow!("Custom pricing not found: {}", id).into())
        }
    }
    async fn insert_custom_pricing_disk(&self, disk: &VmCustomPricingDisk) -> DbResult<u64> {
        let mut disk_map = self.custom_pricing_disk.lock().await;
        let max_id = disk_map.keys().max().unwrap_or(&0) + 1;
        let mut new_disk = disk.clone();
        new_disk.id = max_id;
        disk_map.insert(max_id, new_disk);
        Ok(max_id)
    }
    async fn delete_custom_pricing_disks(&self, pricing_id: u64) -> DbResult<()> {
        let mut disk_map = self.custom_pricing_disk.lock().await;
        disk_map.retain(|_, disk| disk.pricing_id != pricing_id);
        Ok(())
    }
    async fn count_custom_templates_by_pricing(&self, pricing_id: u64) -> DbResult<u64> {
        let template_map = self.custom_template.lock().await;
        let count = template_map
            .values()
            .filter(|template| template.pricing_id == pricing_id)
            .count();
        Ok(count as u64)
    }

    async fn list_custom_templates_by_pricing_paginated(
        &self,
        pricing_id: u64,
        limit: i64,
        offset: i64,
    ) -> DbResult<(Vec<VmCustomTemplate>, u64)> {
        let template_map = self.custom_template.lock().await;
        let filtered_templates: Vec<VmCustomTemplate> = template_map
            .values()
            .filter(|template| template.pricing_id == pricing_id)
            .cloned()
            .collect();
        let total = filtered_templates.len() as u64;
        let paginated: Vec<VmCustomTemplate> = filtered_templates
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((paginated, total))
    }

    async fn delete_custom_template(&self, id: u64) -> DbResult<()> {
        let mut template_map = self.custom_template.lock().await;
        if template_map.remove(&id).is_some() {
            Ok(())
        } else {
            Err(anyhow!("Custom template not found: {}", id).into())
        }
    }
    async fn list_vms_by_custom_template(&self, template_id: u64) -> DbResult<Vec<Vm>> {
        let vm_map = self.vms.lock().await;
        let mut rows: Vec<Vm> = vm_map
            .values()
            .filter(|vm| vm.custom_template_id == Some(template_id) && !vm.deleted)
            .cloned()
            .collect();
        rows.sort_by_key(|vm| vm.id);
        Ok(rows)
    }

    async fn count_vms_by_custom_template(&self, template_id: u64) -> DbResult<u64> {
        let vm_map = self.vms.lock().await;
        let count = vm_map
            .values()
            .filter(|vm| vm.custom_template_id == Some(template_id))
            .count();
        Ok(count as u64)
    }
    async fn admin_list_companies(&self, limit: u64, offset: u64) -> DbResult<(Vec<Company>, u64)> {
        let companies = self.companies.lock().await;
        let mut rows: Vec<Company> = companies.values().cloned().collect();
        // Newest first, matching the SQL implementation's ORDER BY created DESC,
        // with id as a tie-break because fixtures share a timestamp.
        rows.sort_by(|a, b| b.created.cmp(&a.created).then(b.id.cmp(&a.id)));
        let total = rows.len() as u64;
        Ok((
            rows.into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect(),
            total,
        ))
    }
    async fn admin_get_company(&self, company_id: u64) -> DbResult<Company> {
        self.get_company(company_id).await
    }
    async fn admin_create_company(&self, company: &Company) -> DbResult<u64> {
        let mut companies = self.companies.lock().await;
        let id = companies.keys().max().copied().unwrap_or(0) + 1;
        companies.insert(
            id,
            Company {
                id,
                ..company.clone()
            },
        );
        Ok(id)
    }
    async fn admin_update_company(&self, _company: &Company) -> DbResult<()> {
        Ok(())
    }
    async fn admin_delete_company(&self, _company_id: u64) -> DbResult<()> {
        Ok(())
    }
    async fn admin_count_company_regions(&self, _company_id: u64) -> DbResult<u64> {
        Ok(0)
    }
    async fn admin_list_subscription_renewal_outlook(
        &self,
        _start: chrono::DateTime<chrono::Utc>,
        _end: chrono::DateTime<chrono::Utc>,
        _company_id: u64,
        _region_id: Option<u64>,
    ) -> DbResult<Vec<lnvps_db::SubscriptionRenewalOutlook>> {
        Ok(vec![])
    }

    async fn admin_list_subscription_cohorts(
        &self,
        _start: chrono::DateTime<chrono::Utc>,
        _end: chrono::DateTime<chrono::Utc>,
        _company_id: u64,
        _region_id: Option<u64>,
    ) -> DbResult<Vec<lnvps_db::SubscriptionCohortRow>> {
        Ok(vec![])
    }

    async fn admin_get_payments_with_company_info(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
        currency: Option<&str>,
    ) -> DbResult<Vec<SubscriptionPaymentWithCompany>> {
        let sub_payments = self.subscription_payments.lock().await;
        let vms = self.vms.lock().await;
        let line_items = self.subscription_line_items.lock().await;
        let hosts = self.hosts.lock().await;
        let regions = self.regions.lock().await;
        let companies = self.companies.lock().await;

        let mut result = Vec::new();

        for payment in sub_payments.iter() {
            if !payment.is_paid || payment.created < start_date || payment.created >= end_date {
                continue;
            }

            if let Some(filter_currency) = currency {
                if payment.currency != filter_currency {
                    continue;
                }
            }

            // Find VM via subscription → line_item (VmRenewal/VmUpgrade) → vm
            let vm = vms.values().find(|v| {
                line_items
                    .get(&v.subscription_line_item_id)
                    .map(|sli| sli.subscription_id == payment.subscription_id)
                    .unwrap_or(false)
            });

            let (vm_id, host_id, host_name, region_id, region_name, region_company_id) =
                if let Some(vm) = vm {
                    if let Some(host) = hosts.get(&vm.host_id) {
                        if let Some(region) = regions.get(&host.region_id) {
                            (
                                Some(vm.id),
                                Some(host.id),
                                Some(host.name.clone()),
                                Some(region.id),
                                Some(region.name.clone()),
                                Some(region.company_id),
                            )
                        } else {
                            (
                                Some(vm.id),
                                Some(host.id),
                                Some(host.name.clone()),
                                None,
                                None,
                                None,
                            )
                        }
                    } else {
                        (Some(vm.id), None, None, None, None, None)
                    }
                } else {
                    (None, None, None, None, None, None)
                };

            // Resolve company
            let cid = region_company_id.unwrap_or(0);
            if cid != company_id {
                continue;
            }
            if let Some(company) = companies.get(&cid) {
                result.push(SubscriptionPaymentWithCompany {
                    id: payment.id.clone(),
                    subscription_id: payment.subscription_id,
                    user_id: payment.user_id,
                    created: payment.created,
                    expires: payment.expires,
                    amount: payment.amount,
                    currency: payment.currency.clone(),
                    payment_method: payment.payment_method,
                    payment_type: payment.payment_type,
                    external_data: payment.external_data.clone(),
                    external_id: payment.external_id.clone(),
                    is_paid: payment.is_paid,
                    rate: payment.rate,
                    time_value: payment.time_value,
                    metadata: payment.metadata.clone(),
                    tax: payment.tax,
                    processing_fee: payment.processing_fee,
                    paid_at: payment.paid_at,
                    tax_rate: payment.tax_rate,
                    tax_country_code: payment.tax_country_code.clone(),
                    tax_treatment: payment.tax_treatment.clone(),
                    tax_evidence: payment.tax_evidence.clone(),
                    tax_breakdown: payment.tax_breakdown.clone(),
                    refunded_payment_id: payment.refunded_payment_id.clone(),
                    company_id: cid,
                    company_name: company.name.clone(),
                    company_base_currency: company.base_currency.clone(),
                    vm_id,
                    host_id,
                    host_name,
                    region_id,
                    region_name,
                    renewal_source: None,
                });
            }
        }

        result.sort_by(|a, b| a.created.cmp(&b.created));
        Ok(result)
    }
    async fn admin_get_referral_usage_by_date_range(
        &self,
        _start_date: chrono::DateTime<chrono::Utc>,
        _end_date: chrono::DateTime<chrono::Utc>,
        _company_id: u64,
        _ref_code: Option<&str>,
    ) -> DbResult<Vec<lnvps_db::ReferralCostUsage>> {
        // Mock implementation - return empty for now
        Ok(vec![])
    }

    async fn admin_list_referrals(
        &self,
        limit: u64,
        offset: u64,
        search: Option<&str>,
    ) -> DbResult<(Vec<Referral>, u64)> {
        let referrals = self.referrals.lock().await;
        let mut all: Vec<Referral> = referrals
            .values()
            .filter(|r| match search {
                Some(s) if !s.trim().is_empty() => r.code.contains(s.trim()),
                _ => true,
            })
            .cloned()
            .collect();
        all.sort_by(|a, b| b.created.cmp(&a.created));
        let total = all.len() as u64;
        let page = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((page, total))
    }

    async fn admin_get_referral(&self, referral_id: u64) -> DbResult<Referral> {
        let referrals = self.referrals.lock().await;
        referrals
            .get(&referral_id)
            .cloned()
            .ok_or_else(|| DbError::Other(anyhow!("referral not found")))
    }

    async fn admin_list_ip_ranges(
        &self,
        _limit: u64,
        _offset: u64,
        _region_id: Option<u64>,
    ) -> DbResult<(Vec<IpRange>, u64)> {
        Ok((vec![], 0))
    }
    async fn admin_get_ip_range(&self, ip_range_id: u64) -> DbResult<IpRange> {
        self.get_ip_range(ip_range_id).await
    }
    async fn admin_create_ip_range(&self, _ip_range: &IpRange) -> DbResult<u64> {
        Ok(1)
    }
    async fn admin_update_ip_range(&self, _ip_range: &IpRange) -> DbResult<()> {
        Ok(())
    }
    async fn admin_delete_ip_range(&self, _ip_range_id: u64) -> DbResult<()> {
        Ok(())
    }
    async fn admin_count_ip_range_assignments(&self, _ip_range_id: u64) -> DbResult<u64> {
        Ok(0)
    }
    async fn admin_list_access_policies(&self) -> DbResult<Vec<AccessPolicy>> {
        Ok(vec![])
    }
    async fn admin_list_access_policies_paginated(
        &self,
        _limit: u64,
        _offset: u64,
    ) -> DbResult<(Vec<AccessPolicy>, u64)> {
        Ok((vec![], 0))
    }

    async fn admin_get_access_policy(&self, access_policy_id: u64) -> DbResult<AccessPolicy> {
        self.get_access_policy(access_policy_id).await
    }

    async fn admin_create_access_policy(&self, _access_policy: &AccessPolicy) -> DbResult<u64> {
        Ok(1)
    }

    async fn admin_update_access_policy(&self, _access_policy: &AccessPolicy) -> DbResult<()> {
        Ok(())
    }

    async fn admin_delete_access_policy(&self, _access_policy_id: u64) -> DbResult<()> {
        Ok(())
    }

    async fn admin_count_access_policy_ip_ranges(&self, _access_policy_id: u64) -> DbResult<u64> {
        Ok(0)
    }

    async fn admin_list_routers(&self) -> DbResult<Vec<Router>> {
        self.list_routers().await
    }

    async fn admin_list_routers_paginated(
        &self,
        _limit: u64,
        _offset: u64,
    ) -> DbResult<(Vec<Router>, u64)> {
        Ok((vec![], 0))
    }

    async fn admin_get_router(&self, router_id: u64) -> DbResult<Router> {
        self.get_router(router_id).await
    }

    async fn admin_create_router(&self, _router: &Router) -> DbResult<u64> {
        Ok(1)
    }

    async fn admin_update_router(&self, _router: &Router) -> DbResult<()> {
        Ok(())
    }

    async fn admin_delete_router(&self, _router_id: u64) -> DbResult<()> {
        Ok(())
    }

    async fn admin_count_router_access_policies(&self, _router_id: u64) -> DbResult<u64> {
        Ok(0)
    }

    async fn admin_list_vms_filtered(
        &self,
        limit: u64,
        offset: u64,
        user_id: Option<u64>,
        host_id: Option<u64>,
        pubkey: Option<&str>,
        region_id: Option<u64>,
        include_deleted: Option<bool>,
    ) -> DbResult<(Vec<Vm>, u64)> {
        let vms = self.vms.lock().await;
        let hosts = self.hosts.lock().await;

        // Resolve user_id from pubkey if provided
        let resolved_user_id = if let Some(pk) = pubkey {
            let pubkey_bytes = hex::decode(pk).map_err(|_| anyhow!("Invalid pubkey format"))?;

            match self.get_user_by_pubkey(&pubkey_bytes).await {
                Ok(user) => Some(user.id),
                Err(_) => return Ok((vec![], 0)), // No user found, return empty
            }
        } else {
            user_id
        };

        // Filter VMs based on criteria
        let filtered_vms: Vec<Vm> = vms
            .values()
            .filter(|vm| {
                // Filter by user_id
                if let Some(uid) = resolved_user_id {
                    if vm.user_id != uid {
                        return false;
                    }
                }

                // Filter by host_id
                if let Some(hid) = host_id {
                    if vm.host_id != hid {
                        return false;
                    }
                }

                // Filter by region_id
                if let Some(rid) = region_id {
                    if let Some(host) = hosts.get(&vm.host_id) {
                        if host.region_id != rid {
                            return false;
                        }
                    } else {
                        return false; // VM without valid host when region filter applied
                    }
                }

                // Filter by deleted status
                match include_deleted {
                    Some(false) | None => {
                        // Exclude deleted VMs (default behavior)
                        if vm.deleted {
                            return false;
                        }
                    }
                    Some(true) => {
                        // Include both deleted and non-deleted VMs
                    }
                }

                true
            })
            .cloned()
            .collect();

        let total = filtered_vms.len() as u64;

        // Apply pagination
        let paginated: Vec<Vm> = filtered_vms
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();

        Ok((paginated, total))
    }

    async fn get_user_by_pubkey(&self, pubkey: &[u8]) -> DbResult<User> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .find(|user| user.pubkey == pubkey)
            .cloned()
            .ok_or_else(|| anyhow!("User not found with provided pubkey"))?)
    }

    async fn admin_list_vm_ip_assignments(
        &self,
        _limit: u64,
        _offset: u64,
        _vm_id: Option<u64>,
        _ip_range_id: Option<u64>,
        _ip: Option<&str>,
        _include_deleted: Option<bool>,
    ) -> DbResult<(Vec<lnvps_db::VmIpAssignment>, u64)> {
        // Mock implementation
        Ok((vec![], 0))
    }

    async fn admin_get_vm_ip_assignment(
        &self,
        _assignment_id: u64,
    ) -> DbResult<lnvps_db::VmIpAssignment> {
        // Mock implementation
        Ok(lnvps_db::VmIpAssignment::default())
    }

    async fn admin_create_vm_ip_assignment(
        &self,
        _assignment: &lnvps_db::VmIpAssignment,
    ) -> DbResult<u64> {
        // Mock implementation
        Ok(1)
    }

    async fn admin_update_vm_ip_assignment(
        &self,
        _assignment: &lnvps_db::VmIpAssignment,
    ) -> DbResult<()> {
        // Mock implementation
        Ok(())
    }

    async fn admin_delete_vm_ip_assignment(&self, _assignment_id: u64) -> DbResult<()> {
        // Mock implementation
        Ok(())
    }

    async fn admin_list_resource_costs(
        &self,
        _limit: u64,
        _offset: u64,
        _resource_type: Option<lnvps_db::CostResourceType>,
        _resource_id: Option<u64>,
    ) -> DbResult<(Vec<lnvps_db::ResourceCost>, u64)> {
        Ok((vec![], 0))
    }

    async fn admin_list_resource_costs_for(
        &self,
        _resource_type: lnvps_db::CostResourceType,
        _resource_id: u64,
    ) -> DbResult<Vec<lnvps_db::ResourceCost>> {
        Ok(vec![])
    }

    async fn admin_get_resource_cost(&self, _id: u64) -> DbResult<lnvps_db::ResourceCost> {
        todo!()
    }

    async fn admin_create_resource_cost(&self, _cost: &lnvps_db::ResourceCost) -> DbResult<u64> {
        Ok(1)
    }

    async fn admin_update_resource_cost(&self, _cost: &lnvps_db::ResourceCost) -> DbResult<()> {
        Ok(())
    }

    async fn admin_delete_resource_cost(&self, _id: u64) -> DbResult<()> {
        Ok(())
    }

    async fn admin_list_resource_costs_active_between(
        &self,
        _start: chrono::DateTime<chrono::Utc>,
        _end: chrono::DateTime<chrono::Utc>,
    ) -> DbResult<Vec<lnvps_db::ResourceCost>> {
        Ok(vec![])
    }
}

// Nostr trait implementation with stub methods
#[async_trait]
impl LNVPSNostrDb for MockDb {
    async fn get_handle(&self, _handle_id: u64) -> DbResult<NostrDomainHandle> {
        todo!()
    }

    async fn get_handle_by_name(
        &self,
        _domain_id: u64,
        _handle: &str,
    ) -> DbResult<NostrDomainHandle> {
        todo!()
    }

    async fn insert_handle(&self, _handle: &NostrDomainHandle) -> DbResult<u64> {
        Ok(1)
    }

    async fn update_handle(&self, _handle: &NostrDomainHandle) -> DbResult<()> {
        Ok(())
    }

    async fn delete_handle(&self, _handle_id: u64) -> DbResult<()> {
        Ok(())
    }

    async fn list_handles(&self, _domain_id: u64) -> DbResult<Vec<NostrDomainHandle>> {
        Ok(vec![])
    }

    async fn get_domain(&self, _id: u64) -> DbResult<NostrDomain> {
        todo!()
    }

    async fn get_domain_by_name(&self, _name: &str) -> DbResult<NostrDomain> {
        todo!()
    }

    async fn get_domain_by_activation_hash(&self, _hash: &str) -> DbResult<NostrDomain> {
        todo!()
    }

    async fn list_domains(&self, _owner_id: u64) -> DbResult<Vec<NostrDomain>> {
        Ok(vec![])
    }

    async fn insert_domain(&self, _domain: &NostrDomain) -> DbResult<u64> {
        Ok(1)
    }

    async fn delete_domain(&self, _domain_id: u64) -> DbResult<()> {
        Ok(())
    }

    async fn list_all_domains(&self) -> DbResult<Vec<NostrDomain>> {
        Ok(vec![])
    }

    async fn list_active_domains(&self) -> DbResult<Vec<NostrDomain>> {
        Ok(vec![])
    }

    async fn list_disabled_domains(&self) -> DbResult<Vec<NostrDomain>> {
        Ok(vec![])
    }

    async fn enable_domain_with_https(&self, _domain_id: u64) -> DbResult<()> {
        Ok(())
    }

    async fn enable_domain_http_only(&self, _domain_id: u64) -> DbResult<()> {
        Ok(())
    }

    async fn disable_domain(&self, _domain_id: u64) -> DbResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use lnvps_db::{
        AgentChannel, AgentMessageRole, AppBackupMethod, IntervalType, LNVpsDbBase,
        SubscriptionPaymentType,
    };

    fn user_msg(text: &str, channel: AgentChannel) -> NewAgentMessage {
        NewAgentMessage {
            role: AgentMessageRole::User,
            channel,
            content: Some(text.to_string()),
            tool_calls: None,
            tool_call_id: None,
        }
    }

    #[tokio::test]
    async fn agent_conversation_is_created_once_per_key() {
        let db = MockDb::default();

        let a = db
            .upsert_agent_conversation("user:7", Some(7))
            .await
            .unwrap();
        let b = db
            .upsert_agent_conversation("user:7", Some(7))
            .await
            .unwrap();
        assert_eq!(a.id, b.id, "same key must reuse the thread");
        assert_eq!(a.compacted_upto, 0);
        assert!(a.summary.is_none());

        // A different key is a different thread.
        let other = db
            .upsert_agent_conversation("nostr:abc", Some(7))
            .await
            .unwrap();
        assert_ne!(a.id, other.id);
    }

    /// A thread that starts anonymous gets linked once the sender resolves,
    /// but an unresolved later lookup must never clear the link.
    #[tokio::test]
    async fn agent_conversation_links_user_without_clearing() {
        let db = MockDb::default();

        let anon = db
            .upsert_agent_conversation("email:bob@example.com", None)
            .await
            .unwrap();
        assert!(anon.user_id.is_none());

        let linked = db
            .upsert_agent_conversation("email:bob@example.com", Some(42))
            .await
            .unwrap();
        assert_eq!(linked.id, anon.id);
        assert_eq!(linked.user_id, Some(42));

        let relookup = db
            .upsert_agent_conversation("email:bob@example.com", None)
            .await
            .unwrap();
        assert_eq!(relookup.user_id, Some(42), "link must not be cleared");
    }

    #[tokio::test]
    async fn agent_messages_append_in_order_and_roundtrip_tool_calls() {
        let db = MockDb::default();
        let conv = db
            .upsert_agent_conversation("user:1", Some(1))
            .await
            .unwrap();

        let turn = vec![
            user_msg("my vm is down", AgentChannel::WebChat),
            NewAgentMessage {
                role: AgentMessageRole::Assistant,
                channel: AgentChannel::WebChat,
                content: None,
                tool_calls: Some(r#"[{"id":"c1","name":"start_vm","arguments":"{}"}]"#.to_string()),
                tool_call_id: None,
            },
            NewAgentMessage {
                role: AgentMessageRole::Tool,
                channel: AgentChannel::WebChat,
                content: Some("ok".to_string()),
                tool_calls: None,
                tool_call_id: Some("c1".to_string()),
            },
        ];
        let ids = db.append_agent_messages(conv.id, &turn).await.unwrap();
        assert_eq!(ids.len(), 3);
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "ids must ascend");

        let stored = db
            .list_agent_messages_after_watermark(conv.id)
            .await
            .unwrap();
        assert_eq!(stored.len(), 3);
        assert_eq!(stored[0].role, AgentMessageRole::User);
        assert_eq!(
            stored[0].content.as_ref().map(|c| c.as_str()),
            Some("my vm is down")
        );
        // An assistant turn that only called a tool stores no prose.
        assert!(stored[1].content.is_none());
        assert!(stored[1].tool_calls.is_some());
        assert_eq!(stored[2].tool_call_id.as_deref(), Some("c1"));

        // Appending nothing is a no-op, not an error.
        assert!(
            db.append_agent_messages(conv.id, &[])
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// The core of the training-corpus decision: compaction bounds what is
    /// replayed but must never destroy the transcript.
    #[tokio::test]
    async fn compaction_advances_watermark_without_deleting() {
        let db = MockDb::default();
        let conv = db
            .upsert_agent_conversation("user:2", Some(2))
            .await
            .unwrap();

        let first = db
            .append_agent_messages(
                conv.id,
                &[
                    user_msg("one", AgentChannel::Email),
                    user_msg("two", AgentChannel::Email),
                ],
            )
            .await
            .unwrap();
        let watermark = *first.last().unwrap();

        db.compact_agent_conversation(conv.id, "summary so far", watermark)
            .await
            .unwrap();

        // Context is now empty — everything is folded into the summary.
        assert!(
            db.list_agent_messages_after_watermark(conv.id)
                .await
                .unwrap()
                .is_empty()
        );
        let reloaded = db.get_agent_conversation(conv.id).await.unwrap();
        assert_eq!(reloaded.summary.as_deref(), Some("summary so far"));
        assert_eq!(reloaded.compacted_upto, watermark);

        // ...but the full transcript is still there for training.
        let all = db
            .list_agent_messages_paginated(conv.id, 100, 0)
            .await
            .unwrap();
        assert_eq!(all.len(), 2, "compaction must not delete messages");

        // New messages replay again.
        db.append_agent_messages(conv.id, &[user_msg("three", AgentChannel::WebChat)])
            .await
            .unwrap();
        let context = db
            .list_agent_messages_after_watermark(conv.id)
            .await
            .unwrap();
        assert_eq!(context.len(), 1);
        assert_eq!(
            context[0].content.as_ref().map(|c| c.as_str()),
            Some("three")
        );
    }

    /// A stale compaction must not drag the watermark backwards and re-expose
    /// messages already summarised.
    #[tokio::test]
    async fn compaction_watermark_is_monotonic() {
        let db = MockDb::default();
        let conv = db
            .upsert_agent_conversation("user:3", Some(3))
            .await
            .unwrap();
        let ids = db
            .append_agent_messages(
                conv.id,
                &[
                    user_msg("a", AgentChannel::Email),
                    user_msg("b", AgentChannel::Email),
                ],
            )
            .await
            .unwrap();

        db.compact_agent_conversation(conv.id, "newer", ids[1])
            .await
            .unwrap();
        db.compact_agent_conversation(conv.id, "stale", ids[0])
            .await
            .unwrap();

        let reloaded = db.get_agent_conversation(conv.id).await.unwrap();
        assert_eq!(
            reloaded.compacted_upto, ids[1],
            "watermark must not regress"
        );
    }

    /// Threads are isolated: the public Nostr thread must not leak into the
    /// private email/web-chat thread for the same customer.
    #[tokio::test]
    async fn agent_threads_are_isolated_by_key() {
        let db = MockDb::default();
        let private = db
            .upsert_agent_conversation("user:9", Some(9))
            .await
            .unwrap();
        let public = db
            .upsert_agent_conversation("nostr:deadbeef", Some(9))
            .await
            .unwrap();

        db.append_agent_messages(
            private.id,
            &[user_msg("my card ending 4242 failed", AgentChannel::Email)],
        )
        .await
        .unwrap();

        let public_context = db
            .list_agent_messages_after_watermark(public.id)
            .await
            .unwrap();
        assert!(
            public_context.is_empty(),
            "private message must not appear in the public nostr thread"
        );
    }

    #[tokio::test]
    async fn agent_messages_paginate() {
        let db = MockDb::default();
        let conv = db
            .upsert_agent_conversation("user:4", Some(4))
            .await
            .unwrap();
        let msgs: Vec<_> = (0..5)
            .map(|i| user_msg(&format!("m{i}"), AgentChannel::WebChat))
            .collect();
        db.append_agent_messages(conv.id, &msgs).await.unwrap();

        let page = db
            .list_agent_messages_paginated(conv.id, 2, 1)
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].content.as_ref().map(|c| c.as_str()), Some("m1"));
        assert_eq!(page[1].content.as_ref().map(|c| c.as_str()), Some("m2"));
    }

    #[tokio::test]
    async fn test_count_vms_by_os_image() {
        let db = MockDb::default();
        {
            let mut vms = db.vms.lock().await;
            vms.insert(
                1,
                Vm {
                    id: 1,
                    image_id: 1,
                    ..MockDb::mock_vm()
                },
            );
            vms.insert(
                2,
                Vm {
                    id: 2,
                    image_id: 1,
                    ..MockDb::mock_vm()
                },
            );
            vms.insert(
                3,
                Vm {
                    id: 3,
                    image_id: 2,
                    ..MockDb::mock_vm()
                },
            );
            vms.insert(
                4,
                Vm {
                    id: 4,
                    image_id: 2,
                    deleted: true,
                    ..MockDb::mock_vm()
                },
            );
        }

        let counts: HashMap<u64, u64> = db
            .count_vms_by_os_image()
            .await
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(counts.get(&1), Some(&2));
        assert_eq!(counts.get(&2), Some(&1)); // deleted VM excluded
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn test_admin_transfer_vm() {
        use lnvps_db::AdminDb;

        let db = MockDb::default();
        {
            let mut vms = db.vms.lock().await;
            vms.insert(
                1,
                Vm {
                    id: 1,
                    user_id: 1,
                    ssh_key_id: Some(5),
                    ..MockDb::mock_vm()
                },
            );
        }

        db.admin_transfer_vm(1, 42).await.unwrap();
        let vm = db.get_vm(1).await.unwrap();
        assert_eq!(vm.user_id, 42);
        assert_eq!(vm.ssh_key_id, None);
    }

    /// list_all_referrals + delete_referral base-trait methods.
    #[tokio::test]
    async fn test_referral_delete_and_list_all() {
        use lnvps_db::{Referral, ReferralPayoutMode};

        let db = MockDb::default();
        let mk = |code: &str| Referral {
            id: 0,
            user_id: 1,
            code: code.to_string(),
            address: Some("a@b.com".to_string()),
            mode: ReferralPayoutMode::LightningAddress,
            referral_rate: None,
            payout_threshold: None,
            created: Utc::now(),
        };
        let id_a = db.insert_referral(&mk("AAA")).await.unwrap();
        db.insert_referral(&mk("BBB")).await.unwrap();
        assert_eq!(db.list_all_referrals().await.unwrap().len(), 2);

        db.delete_referral(id_a).await.unwrap();
        let rest = db.list_all_referrals().await.unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].code, "BBB");
    }

    /// Renaming a referral code re-points existing VMs that recorded the old
    /// code so historical attribution is preserved.
    #[tokio::test]
    async fn test_update_referral_cascades_vm_ref_code() {
        use lnvps_db::{Referral, ReferralPayoutMode};

        let db = MockDb::default();
        let referral = Referral {
            id: 0,
            user_id: 1,
            code: "OLDCODE".to_string(),
            address: Some("a@b.com".to_string()),
            mode: ReferralPayoutMode::LightningAddress,
            referral_rate: None,
            payout_threshold: None,
            created: Utc::now(),
        };
        let ref_id = db.insert_referral(&referral).await.unwrap();

        // Two VMs used this referral's code; one used a different code.
        {
            let mut vms = db.vms.lock().await;
            vms.insert(
                1,
                Vm {
                    id: 1,
                    ref_code: Some("OLDCODE".to_string()),
                    ..MockDb::mock_vm()
                },
            );
            vms.insert(
                2,
                Vm {
                    id: 2,
                    ref_code: Some("OLDCODE".to_string()),
                    ..MockDb::mock_vm()
                },
            );
            vms.insert(
                3,
                Vm {
                    id: 3,
                    ref_code: Some("OTHER".to_string()),
                    ..MockDb::mock_vm()
                },
            );
        }

        // Rename the referral code.
        let updated = Referral {
            id: ref_id,
            code: "NEWCODE".to_string(),
            ..referral.clone()
        };
        db.update_referral(&updated).await.unwrap();

        // The enrollment and both matching VMs now carry the new code; the
        // unrelated VM is untouched.
        assert_eq!(db.get_referral_by_code("NEWCODE").await.unwrap().id, ref_id);
        let vms = db.vms.lock().await;
        assert_eq!(vms[&1].ref_code.as_deref(), Some("NEWCODE"));
        assert_eq!(vms[&2].ref_code.as_deref(), Some("NEWCODE"));
        assert_eq!(vms[&3].ref_code.as_deref(), Some("OTHER"));
    }

    /// admin_list_referrals (pagination + code search) and admin_get_referral.
    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn test_admin_referral_listing() {
        use lnvps_db::{AdminDb, Referral, ReferralPayoutMode};

        let db = MockDb::default();
        let mk = |code: &str| Referral {
            id: 0,
            user_id: 1,
            code: code.to_string(),
            address: Some("a@b.com".to_string()),
            mode: ReferralPayoutMode::LightningAddress,
            referral_rate: None,
            payout_threshold: None,
            created: Utc::now(),
        };
        let id_a = db.insert_referral(&mk("ALPHA123")).await.unwrap();
        db.insert_referral(&mk("BETA456")).await.unwrap();

        // List all
        let (rows, total) = db.admin_list_referrals(50, 0, None).await.unwrap();
        assert_eq!(total, 2);
        assert_eq!(rows.len(), 2);

        // Search by code substring
        let (rows, total) = db.admin_list_referrals(50, 0, Some("ALPHA")).await.unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0].code, "ALPHA123");

        // Pagination
        let (rows, total) = db.admin_list_referrals(1, 0, None).await.unwrap();
        assert_eq!(total, 2);
        assert_eq!(rows.len(), 1);

        // Get by id
        let got = db.admin_get_referral(id_a).await.unwrap();
        assert_eq!(got.code, "ALPHA123");
        assert!(db.admin_get_referral(9999).await.is_err());
    }

    /// user_payment_method CRUD + provider filter via the mock DB.
    #[tokio::test]
    async fn test_user_payment_method_crud() {
        use lnvps_db::UserPaymentMethod;

        let db = MockDb::default();
        let mk = |user_id: u64, provider: &str, default: bool| UserPaymentMethod {
            id: 0,
            user_id,
            created: Utc::now(),
            provider: provider.to_string(),
            name: None,
            external_customer_id: Some("cust".to_string().into()),
            external_id: "pm".to_string().into(),
            card_brand: Some("VISA".to_string()),
            card_last_four: Some("5709".to_string()),
            exp_month: Some(12),
            exp_year: Some(2029),
            is_default: default,
            enabled: true,
        };

        // Insert two revolut methods (2nd is default) + one other provider
        let id1 = db
            .insert_user_payment_method(&mk(1, "revolut", false))
            .await
            .unwrap();
        let id2 = db
            .insert_user_payment_method(&mk(1, "revolut", true))
            .await
            .unwrap();
        let _id3 = db
            .insert_user_payment_method(&mk(1, "stripe", false))
            .await
            .unwrap();
        assert_ne!(id1, id2);

        // Provider filter + default-first ordering
        let revolut = db
            .list_user_payment_methods(1, Some("revolut"))
            .await
            .unwrap();
        assert_eq!(revolut.len(), 2);
        assert_eq!(revolut[0].id, id2, "default method should sort first");

        // All providers for the user
        let all = db.list_user_payment_methods(1, None).await.unwrap();
        assert_eq!(all.len(), 3);

        // Admin cross-user paginated listing + user filter
        let _other = db
            .insert_user_payment_method(&mk(2, "nwc", true))
            .await
            .unwrap();
        let (page, total) = db
            .admin_list_user_payment_methods_paginated(10, 0, None)
            .await
            .unwrap();
        assert_eq!(total, 4);
        assert_eq!(page.len(), 4);
        // Newest id first
        assert!(page[0].id > page[1].id);
        // Pagination: limit 2 returns 2 of 4
        let (page2, total2) = db
            .admin_list_user_payment_methods_paginated(2, 0, None)
            .await
            .unwrap();
        assert_eq!(total2, 4);
        assert_eq!(page2.len(), 2);
        // Filter to user 2
        let (u2, u2_total) = db
            .admin_list_user_payment_methods_paginated(10, 0, Some(2))
            .await
            .unwrap();
        assert_eq!(u2_total, 1);
        assert_eq!(u2.len(), 1);
        assert_eq!(u2[0].user_id, 2);

        // Get one
        let got = db.get_user_payment_method(id1).await.unwrap();
        assert_eq!(got.provider, "revolut");

        // Update (disable + name it)
        let mut upd = got.clone();
        upd.enabled = false;
        upd.name = Some("My spare card".to_string());
        db.update_user_payment_method(&upd).await.unwrap();
        let after = db.get_user_payment_method(id1).await.unwrap();
        assert!(!after.enabled);
        assert_eq!(after.name.as_deref(), Some("My spare card"));

        // Delete
        db.delete_user_payment_method(id1).await.unwrap();
        assert!(db.get_user_payment_method(id1).await.is_err());
        assert_eq!(
            db.list_user_payment_methods(1, Some("revolut"))
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// Build a minimal SubscriptionPayment for the default mock subscription (id=1).
    fn make_payment(subscription_id: u64, time_value: Option<u64>) -> SubscriptionPayment {
        SubscriptionPayment {
            id: vec![1u8; 16],
            subscription_id,
            user_id: 1,
            created: Utc::now(),
            expires: Utc::now() + chrono::Duration::hours(1),
            amount: 1000,
            currency: "BTC".to_string(),
            payment_method: lnvps_db::PaymentMethod::Lightning,
            payment_type: SubscriptionPaymentType::Renewal,
            external_data: "".to_string().into(),
            external_id: None,
            is_paid: false,
            rate: 1.0,
            time_value,
            metadata: None,
            tax: 0,
            processing_fee: 0,
            paid_at: None,
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
            refunded_payment_id: None,
            renewal_source: None,
        }
    }

    /// hard_delete_vm removes the VM and every record that references it:
    /// history, firewall rules, IP assignments, and the VM's subscription along
    /// with its line items and payment history.
    #[tokio::test]
    async fn test_hard_delete_vm_purges_related_records() {
        use lnvps_db::{
            VmFirewallDirection, VmFirewallProtocol, VmFirewallRule, VmFirewallRuleAction,
            VmHistory, VmHistoryActionType, VmIpAssignment,
        };

        let db = MockDb::default();
        // subscription_payment inserts validate the owning user exists.
        db.upsert_user(&[1u8; 32]).await.unwrap();

        // The default MockDb has subscription 1 with Vps line item 1.
        let vm_id = db
            .insert_vm(&Vm {
                ssh_key_id: None,
                ..MockDb::mock_vm()
            })
            .await
            .unwrap();
        let sub_id = db.get_subscription_by_line_item_id(1).await.unwrap().id;

        // Related records referencing the VM.
        db.insert_vm_ip_assignment(&VmIpAssignment {
            id: 0,
            vm_id,
            ip_range_id: 1,
            ip: "10.0.0.5".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
        db.insert_vm_firewall_rule(&VmFirewallRule {
            id: 0,
            vm_id,
            priority: 1,
            direction: VmFirewallDirection::Inbound,
            protocol: VmFirewallProtocol::Tcp,
            action: VmFirewallRuleAction::Accept,
            src_cidr: None,
            dst_port_start: Some(22),
            dst_port_end: None,
            enabled: true,
            created: Utc::now(),
            updated: Utc::now(),
        })
        .await
        .unwrap();
        db.insert_vm_history(&VmHistory {
            id: 0,
            vm_id,
            action_type: VmHistoryActionType::Created,
            timestamp: Utc::now(),
            initiated_by_user: None,
            previous_state: None,
            new_state: None,
            metadata: None,
            description: None,
        })
        .await
        .unwrap();
        db.insert_subscription_payment(&make_payment(sub_id, Some(3600)))
            .await
            .unwrap();

        // Sanity: everything is present before the purge.
        assert!(db.get_vm(vm_id).await.is_ok());
        assert_eq!(db.list_vm_ip_assignments(vm_id).await.unwrap().len(), 1);
        assert_eq!(db.list_vm_firewall_rules(vm_id).await.unwrap().len(), 1);
        assert_eq!(db.list_vm_history(vm_id).await.unwrap().len(), 1);
        assert_eq!(db.subscription_payments.lock().await.len(), 1);

        db.hard_delete_vm(vm_id).await.unwrap();

        // The VM and every related record are gone.
        assert!(db.get_vm(vm_id).await.is_err());
        assert!(db.list_vm_ip_assignments(vm_id).await.unwrap().is_empty());
        assert!(db.list_vm_firewall_rules(vm_id).await.unwrap().is_empty());
        assert!(db.list_vm_history(vm_id).await.unwrap().is_empty());
        assert!(db.get_subscription(sub_id).await.is_err());
        assert!(
            db.list_subscription_line_items(sub_id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(db.subscription_payments.lock().await.is_empty());
    }

    /// list_deleted_never_paid_vm_ids returns only soft-deleted VMs whose
    /// subscription was never paid (is_setup = false).
    #[tokio::test]
    async fn test_list_deleted_never_paid_vm_ids() {
        let db = MockDb::default();
        db.upsert_user(&[1u8; 32]).await.unwrap();

        // Default subscription 1 is not set up (never paid).
        let vm_id = db
            .insert_vm(&Vm {
                ssh_key_id: None,
                ..MockDb::mock_vm()
            })
            .await
            .unwrap();

        // Live (non-deleted) never-paid VM is not returned.
        assert!(
            db.list_deleted_never_paid_vm_ids()
                .await
                .unwrap()
                .is_empty()
        );

        // Soft-delete it -> now eligible for purge.
        db.delete_vm(vm_id).await.unwrap();
        assert_eq!(
            db.list_deleted_never_paid_vm_ids().await.unwrap(),
            vec![vm_id]
        );

        // Mark the subscription as paid -> no longer eligible (preserve history).
        {
            let mut subs = db.subscriptions.lock().await;
            subs.get_mut(&1).unwrap().is_setup = true;
        }
        assert!(
            db.list_deleted_never_paid_vm_ids()
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Firewall rule CRUD via the mock DB.
    #[tokio::test]
    async fn test_firewall_rule_crud() {
        use lnvps_db::{
            VmFirewallDirection, VmFirewallProtocol, VmFirewallRule, VmFirewallRuleAction,
        };

        let db = MockDb::default();
        let mk = |vm_id: u64, priority: u16| VmFirewallRule {
            id: 0,
            vm_id,
            priority,
            direction: VmFirewallDirection::Inbound,
            protocol: VmFirewallProtocol::Tcp,
            action: VmFirewallRuleAction::Accept,
            src_cidr: None,
            dst_port_start: Some(22),
            dst_port_end: None,
            enabled: true,
            created: Utc::now(),
            updated: Utc::now(),
        };

        // insert two rules for vm 1 (out of order priority) and one for vm 2
        let id_a = db.insert_vm_firewall_rule(&mk(1, 10)).await.unwrap();
        let _id_b = db.insert_vm_firewall_rule(&mk(1, 1)).await.unwrap();
        let _id_c = db.insert_vm_firewall_rule(&mk(2, 5)).await.unwrap();

        // list returns only vm 1 rules ordered by priority
        let rules = db.list_vm_firewall_rules(1).await.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].priority, 1);
        assert_eq!(rules[1].priority, 10);

        // get
        let got = db.get_vm_firewall_rule(id_a).await.unwrap();
        assert_eq!(got.vm_id, 1);

        // update
        let mut upd = got.clone();
        upd.action = VmFirewallRuleAction::Drop;
        upd.dst_port_end = Some(80);
        db.update_vm_firewall_rule(&upd).await.unwrap();
        let got = db.get_vm_firewall_rule(id_a).await.unwrap();
        assert_eq!(got.action, VmFirewallRuleAction::Drop);
        assert_eq!(got.dst_port_end, Some(80));

        // delete
        db.delete_vm_firewall_rule(id_a).await.unwrap();
        assert!(db.get_vm_firewall_rule(id_a).await.is_err());
        assert_eq!(db.list_vm_firewall_rules(1).await.unwrap().len(), 1);
    }

    /// Per-VM firewall policy update via the mock DB.
    #[tokio::test]
    async fn test_firewall_policy_update() {
        use lnvps_db::{Vm, VmFirewallPolicy};

        let db = MockDb::default();
        db.vms.lock().await.insert(
            1,
            Vm {
                id: 1,
                ..Default::default()
            },
        );

        // default is inherit (None)
        let vm = db.get_vm(1).await.unwrap();
        assert_eq!(vm.fw_policy_in, None);
        assert_eq!(vm.fw_policy_out, None);

        // set policies
        db.update_vm_firewall_policy(
            1,
            Some(VmFirewallPolicy::Drop),
            Some(VmFirewallPolicy::Reject),
        )
        .await
        .unwrap();
        let vm = db.get_vm(1).await.unwrap();
        assert_eq!(vm.fw_policy_in, Some(VmFirewallPolicy::Drop));
        assert_eq!(vm.fw_policy_out, Some(VmFirewallPolicy::Reject));

        // reset to inherit
        db.update_vm_firewall_policy(1, None, None).await.unwrap();
        let vm = db.get_vm(1).await.unwrap();
        assert_eq!(vm.fw_policy_in, None);
        assert_eq!(vm.fw_policy_out, None);
    }

    /// subscription_payment_paid marks the payment as paid and sets paid_at.
    #[tokio::test]
    async fn test_set_user_geo_persists_evidence() {
        let db = MockDb::default();
        let uid = db.upsert_user(&[7u8; 32]).await.unwrap();

        // Resolved country is stored independently of country_code.
        db.set_user_geo(uid, Some("DEU"), "198.51.100.9")
            .await
            .unwrap();
        let user = db.get_user(uid).await.unwrap();
        assert_eq!(user.geo_country_code.as_deref(), Some("DEU"));
        assert_eq!(user.geo_ip.as_deref(), Some("198.51.100.9"));
        assert!(user.geo_updated.is_some());

        // An unresolved IP records the IP but no country.
        db.set_user_geo(uid, None, "10.0.0.1").await.unwrap();
        let user = db.get_user(uid).await.unwrap();
        assert_eq!(user.geo_country_code, None);
        assert_eq!(user.geo_ip.as_deref(), Some("10.0.0.1"));
    }

    #[tokio::test]
    async fn test_subscription_payment_paid_marks_payment() {
        let db = MockDb::default();
        let payment = make_payment(1, Some(86400));
        db.insert_subscription_payment(&payment).await.unwrap();

        db.subscription_payment_paid(&payment).await.unwrap();

        let payments = db.subscription_payments.lock().await;
        let p = payments.iter().find(|p| p.id == payment.id).unwrap();
        assert!(p.is_paid);
        assert!(p.paid_at.is_some());
    }

    /// VM path: time_value is set — subscription expires extended by that many seconds.
    #[tokio::test]
    async fn test_subscription_payment_paid_vm_extends_by_time_value() {
        let db = MockDb::default();
        db.vms.lock().await.insert(1, MockDb::mock_vm());

        let time_value_secs = 30 * 24 * 3600u64; // 30 days
        let payment = make_payment(1, Some(time_value_secs));
        db.insert_subscription_payment(&payment).await.unwrap();

        let before = Utc::now();
        db.subscription_payment_paid(&payment).await.unwrap();

        let expected_min = before + chrono::Duration::seconds(time_value_secs as i64 - 5);
        let expected_max = before + chrono::Duration::seconds(time_value_secs as i64 + 5);

        // Subscription expires must be extended
        let subs = db.subscriptions.lock().await;
        let sub = subs.get(&1).unwrap();
        let sub_expires = sub.expires.unwrap();
        assert!(
            sub_expires >= expected_min && sub_expires <= expected_max,
            "subscription expires {} not in expected range",
            sub_expires
        );
        assert!(sub.is_active);
        assert!(sub.is_setup);
        drop(subs);
    }

    /// Regular subscription path: time_value is None — expires extended by subscription interval.
    #[tokio::test]
    async fn test_subscription_payment_paid_interval_month() {
        let db = MockDb::default();
        // Default subscription has interval_amount=1, interval_type=Month
        let payment = make_payment(1, None);
        db.insert_subscription_payment(&payment).await.unwrap();

        let before = Utc::now();
        db.subscription_payment_paid(&payment).await.unwrap();

        let subs = db.subscriptions.lock().await;
        let sub = subs.get(&1).unwrap();
        let expires = sub.expires.unwrap();
        // Should be approximately 1 month from now
        let expected_min = before + chrono::Duration::days(28);
        let expected_max = before + chrono::Duration::days(32);
        assert!(
            expires >= expected_min && expires <= expected_max,
            "expires {} not in expected range for 1-month interval",
            expires
        );
    }

    /// Regular subscription path: year interval extends by 12 months.
    #[tokio::test]
    async fn test_subscription_payment_paid_interval_year() {
        let db = MockDb::default();
        // Update subscription to use 1-year interval
        {
            let mut subs = db.subscriptions.lock().await;
            let sub = subs.get_mut(&1).unwrap();
            sub.interval_amount = 1;
            sub.interval_type = IntervalType::Year;
        }
        let payment = make_payment(1, None);
        db.insert_subscription_payment(&payment).await.unwrap();

        let before = Utc::now();
        db.subscription_payment_paid(&payment).await.unwrap();

        let subs = db.subscriptions.lock().await;
        let sub = subs.get(&1).unwrap();
        let expires = sub.expires.unwrap();
        // Should be approximately 12 months from now
        let expected_min = before + chrono::Duration::days(364);
        let expected_max = before + chrono::Duration::days(367);
        assert!(
            expires >= expected_min && expires <= expected_max,
            "expires {} not in expected range for 1-year interval",
            expires
        );
    }

    /// Regular subscription path: day interval extends by N days.
    #[tokio::test]
    async fn test_subscription_payment_paid_interval_day() {
        let db = MockDb::default();
        {
            let mut subs = db.subscriptions.lock().await;
            let sub = subs.get_mut(&1).unwrap();
            sub.interval_amount = 7;
            sub.interval_type = IntervalType::Day;
        }
        let payment = make_payment(1, None);
        db.insert_subscription_payment(&payment).await.unwrap();

        let before = Utc::now();
        db.subscription_payment_paid(&payment).await.unwrap();

        let subs = db.subscriptions.lock().await;
        let sub = subs.get(&1).unwrap();
        let expires = sub.expires.unwrap();
        let expected_min = before + chrono::Duration::days(6);
        let expected_max = before + chrono::Duration::days(8);
        assert!(
            expires >= expected_min && expires <= expected_max,
            "expires {} not in expected range for 7-day interval",
            expires
        );
    }

    /// Consecutive payments stack: second payment extends from the first expiry.
    #[tokio::test]
    async fn test_subscription_payment_paid_stacks_from_previous_expiry() {
        let db = MockDb::default();
        let p1 = make_payment(1, Some(86400));
        let mut p2 = make_payment(1, Some(86400));
        p2.id = vec![2u8; 16]; // different id

        db.insert_subscription_payment(&p1).await.unwrap();
        db.insert_subscription_payment(&p2).await.unwrap();

        db.subscription_payment_paid(&p1).await.unwrap();
        let expires_after_first = {
            let subs = db.subscriptions.lock().await;
            subs.get(&1).unwrap().expires.unwrap()
        };

        db.subscription_payment_paid(&p2).await.unwrap();
        let expires_after_second = {
            let subs = db.subscriptions.lock().await;
            subs.get(&1).unwrap().expires.unwrap()
        };

        // Second payment adds another 86400s on top of the first expiry
        let diff = (expires_after_second - expires_after_first).num_seconds();
        assert!(
            (diff - 86400).abs() < 5,
            "Second payment should add ~86400s from first expiry, but diff was {}s",
            diff
        );
    }

    /// Regression: vm_to_status must return an error (not panic) when a VM's IP
    /// assignment references an IP range that cannot be loaded. Previously the
    /// failed range lookup was silently dropped and then `.expect()` panicked.
    #[tokio::test]
    async fn test_vm_to_status_missing_ip_range_errors_not_panics() {
        use crate::model::vm_to_status;
        use lnvps_db::{LNVpsDb, UserSshKey, VmIpAssignment};

        let db = MockDb::default();
        db.vms.lock().await.insert(1, MockDb::mock_vm());
        db.insert_user_ssh_key(&UserSshKey {
            id: 0,
            name: "k".to_string(),
            user_id: 1,
            ..Default::default()
        })
        .await
        .unwrap();
        // IP assignment pointing at a non-existent range id.
        db.ip_assignments.lock().await.insert(
            1,
            VmIpAssignment {
                id: 1,
                vm_id: 1,
                ip_range_id: 999,
                ip: "10.0.0.5".to_string(),
                ..Default::default()
            },
        );

        let db: std::sync::Arc<dyn LNVpsDb> = std::sync::Arc::new(db);
        let vm = db.get_vm(1).await.unwrap();
        let host = db.get_host(vm.host_id).await.ok();
        let res = vm_to_status(&db, vm, host, None, 0, 365).await;
        assert!(res.is_err(), "expected error, not a panic");
    }

    /// A VM's captured host keys reach the customer parsed, and a VM with none
    /// captured reports an empty list rather than a missing field.
    #[tokio::test]
    async fn test_vm_to_status_exposes_captured_host_keys() {
        use crate::model::vm_to_status;
        use lnvps_db::{LNVpsDb, UserSshKey};

        let db = MockDb::default();
        db.vms.lock().await.insert(1, MockDb::mock_vm());
        db.insert_user_ssh_key(&UserSshKey {
            id: 0,
            name: "k".to_string(),
            user_id: 1,
            ..Default::default()
        })
        .await
        .unwrap();

        let db: std::sync::Arc<dyn LNVpsDb> = std::sync::Arc::new(db);
        let vm = db.get_vm(1).await.unwrap();
        let host = db.get_host(vm.host_id).await.ok();
        let status = vm_to_status(&db, vm, host.clone(), None, 0, 365)
            .await
            .unwrap();
        assert!(status.host_ssh_keys.is_empty(), "nothing captured yet");

        db.set_vm_ssh_host_keys(
            1,
            Some(
                "10.0.0.5 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIxcwoVKDYPNmQud4AV/iPBbNVYPSr4X0E31b3FQxS/B\n",
            ),
        )
        .await
        .unwrap();
        let vm = db.get_vm(1).await.unwrap();
        let status = vm_to_status(&db, vm, host, None, 0, 365).await.unwrap();
        assert_eq!(status.host_ssh_keys.len(), 1);
        assert_eq!(status.host_ssh_keys[0].key_type, "ssh-ed25519");
        assert_eq!(
            status.host_ssh_keys[0].fingerprint_sha256,
            "SHA256:XXJM8fNyKu1oxISUmJkU3eTS4F4FcyW69THWriTri6M"
        );
    }

    /// vm_to_status surfaces the host's sunset date on VMs whose host is being
    /// decommissioned, and omits it otherwise.
    #[tokio::test]
    async fn test_vm_to_status_surfaces_host_sunset_date() {
        use crate::model::vm_to_status;
        use lnvps_db::{LNVpsDb, UserSshKey};

        let mdb = MockDb::default();
        mdb.vms.lock().await.insert(1, MockDb::mock_vm());
        mdb.insert_user_ssh_key(&UserSshKey {
            id: 0,
            name: "k".to_string(),
            user_id: 1,
            ..Default::default()
        })
        .await
        .unwrap();

        // Share the same underlying Arc-backed state (MockDb: Clone).
        let db: std::sync::Arc<dyn LNVpsDb> = std::sync::Arc::new(mdb.clone());

        // Not sunsetting -> field is None.
        let vm = db.get_vm(1).await.unwrap();
        let host = db.get_host(vm.host_id).await.ok();
        let status = vm_to_status(&db, vm.clone(), host, None, 0, 365)
            .await
            .unwrap();
        assert!(status.host_sunset_date.is_none());

        // Sunset host 1 -> field surfaces the date.
        let sunset = Utc::now() + chrono::Duration::days(30);
        mdb.hosts.lock().await.get_mut(&1).unwrap().sunset_date = Some(sunset);
        let host = db.get_host(vm.host_id).await.ok();
        let status = vm_to_status(&db, vm, host, None, 0, 365).await.unwrap();
        assert_eq!(status.host_sunset_date, Some(sunset));
    }

    /// vm_to_status surfaces the host's CPU architecture (from the host record,
    /// not the template constraint), and omits the "unknown" sentinel.
    #[tokio::test]
    async fn test_vm_to_status_surfaces_host_cpu_arch() {
        use crate::model::vm_to_status;
        use lnvps_db::{CpuArch, LNVpsDb, UserSshKey};

        let mdb = MockDb::default();
        mdb.vms.lock().await.insert(1, MockDb::mock_vm());
        mdb.insert_user_ssh_key(&UserSshKey {
            id: 0,
            name: "k".to_string(),
            user_id: 1,
            ..Default::default()
        })
        .await
        .unwrap();
        let db: std::sync::Arc<dyn LNVpsDb> = std::sync::Arc::new(mdb.clone());

        // Mock host 1 is x86_64 -> surfaced as a string.
        let vm = db.get_vm(1).await.unwrap();
        let host = db.get_host(vm.host_id).await.ok();
        let status = vm_to_status(&db, vm.clone(), host, None, 0, 365)
            .await
            .unwrap();
        assert_eq!(status.cpu_arch.as_deref(), Some("x86_64"));

        // arm64 host -> surfaced accordingly.
        mdb.hosts.lock().await.get_mut(&1).unwrap().cpu_arch = CpuArch::ARM64;
        let host = db.get_host(vm.host_id).await.ok();
        let status = vm_to_status(&db, vm.clone(), host, None, 0, 365)
            .await
            .unwrap();
        assert_eq!(status.cpu_arch.as_deref(), Some("arm64"));

        // Unknown host arch -> omitted (None), not the "unknown" sentinel.
        mdb.hosts.lock().await.get_mut(&1).unwrap().cpu_arch = CpuArch::Unknown;
        let host = db.get_host(vm.host_id).await.ok();
        let status = vm_to_status(&db, vm, host, None, 0, 365).await.unwrap();
        assert!(status.cpu_arch.is_none());
    }

    /// vm_to_status surfaces the effective prepay window: the global default
    /// when the company has none, and the company override when set.
    #[tokio::test]
    async fn test_vm_to_status_surfaces_max_prepay_days() {
        use crate::model::vm_to_status;
        use lnvps_db::{LNVpsDb, UserSshKey};

        let mdb = MockDb::default();
        mdb.vms.lock().await.insert(1, MockDb::mock_vm());
        mdb.insert_user_ssh_key(&UserSshKey {
            id: 0,
            name: "k".to_string(),
            user_id: 1,
            ..Default::default()
        })
        .await
        .unwrap();
        let db: std::sync::Arc<dyn LNVpsDb> = std::sync::Arc::new(mdb.clone());

        // Company default is 0 -> inherits the global default passed in.
        let vm = db.get_vm(1).await.unwrap();
        let host = db.get_host(vm.host_id).await.ok();
        let status = vm_to_status(&db, vm.clone(), host.clone(), None, 0, 365)
            .await
            .unwrap();
        assert_eq!(status.max_prepay_days, 365);

        // Company override wins over the global default.
        mdb.companies
            .lock()
            .await
            .get_mut(&1)
            .unwrap()
            .max_prepay_days = 90;
        let status = vm_to_status(&db, vm, host, None, 0, 365).await.unwrap();
        assert_eq!(status.max_prepay_days, 90);
    }

    /// Regression: paying the SAME payment twice (e.g. duplicate webhook / replayed
    /// settle event) must extend the subscription only once. Before the idempotency
    /// guard, the second call double-credited the subscription with free time.
    #[tokio::test]
    async fn test_subscription_payment_paid_is_idempotent() {
        let db = MockDb::default();
        let payment = make_payment(1, Some(86400));
        db.insert_subscription_payment(&payment).await.unwrap();

        db.subscription_payment_paid(&payment).await.unwrap();
        let expires_after_first = {
            let subs = db.subscriptions.lock().await;
            subs.get(&1).unwrap().expires.unwrap()
        };

        // Re-deliver the exact same (already paid) payment.
        db.subscription_payment_paid(&payment).await.unwrap();
        let expires_after_second = {
            let subs = db.subscriptions.lock().await;
            subs.get(&1).unwrap().expires.unwrap()
        };

        assert_eq!(
            expires_after_first, expires_after_second,
            "duplicate payment settlement must not extend the subscription again"
        );
    }

    /// list_vm_subscription_payments_paginated returns the correct window.
    #[tokio::test]
    async fn test_list_vm_subscription_payments_paginated() {
        let db = MockDb::default();
        // Insert default VM (id=1) which uses subscription_id=1
        {
            let mut vms = db.vms.lock().await;
            vms.insert(1, MockDb::mock_vm());
        }

        // Insert 5 payments for subscription_id=1
        for i in 0u8..5 {
            let mut p = make_payment(1, Some(86400));
            p.id = vec![i; 16];
            p.created = Utc::now() + chrono::Duration::seconds(i as i64);
            db.insert_subscription_payment(&p).await.unwrap();
        }

        // Page 0: first 2
        let page0 = db
            .list_vm_subscription_payments_paginated(1, 2, 0)
            .await
            .unwrap();
        assert_eq!(page0.len(), 2);

        // Page 1: next 2
        let page1 = db
            .list_vm_subscription_payments_paginated(1, 2, 2)
            .await
            .unwrap();
        assert_eq!(page1.len(), 2);

        // Page 2: last 1
        let page2 = db
            .list_vm_subscription_payments_paginated(1, 2, 4)
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);

        // Pages do not overlap
        assert_ne!(page0[0].id, page1[0].id);
        assert_ne!(page1[0].id, page2[0].id);
    }

    // =========================================================================
    // Subscription lifecycle DB tests (Increment 15)
    // =========================================================================

    /// list_expiring_subscriptions returns active subscriptions expiring within window.
    #[tokio::test]
    async fn test_list_expiring_subscriptions_returns_soon_expiring() {
        let db = MockDb::default();
        // Set subscription id=1 to expire 30 minutes from now (within 1-day window)
        {
            let mut subs = db.subscriptions.lock().await;
            let sub = subs.get_mut(&1).unwrap();
            sub.is_active = true;
            sub.expires = Some(Utc::now() + chrono::Duration::minutes(30));
        }

        let result = db.list_expiring_subscriptions(86400).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, 1);
    }

    /// list_expiring_subscriptions excludes subscriptions expiring outside the window.
    #[tokio::test]
    async fn test_list_expiring_subscriptions_excludes_far_future() {
        let db = MockDb::default();
        {
            let mut subs = db.subscriptions.lock().await;
            let sub = subs.get_mut(&1).unwrap();
            sub.is_active = true;
            sub.expires = Some(Utc::now() + chrono::Duration::days(10));
        }

        let result = db.list_expiring_subscriptions(86400).await.unwrap();
        assert!(result.is_empty());
    }

    /// list_expired_subscriptions returns active subscriptions whose expiry is in the past.
    #[tokio::test]
    async fn test_list_expired_subscriptions_returns_past_expiry() {
        let db = MockDb::default();
        {
            let mut subs = db.subscriptions.lock().await;
            let sub = subs.get_mut(&1).unwrap();
            sub.is_active = true;
            sub.expires = Some(Utc::now() - chrono::Duration::hours(1));
        }

        let result = db.list_expired_subscriptions().await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, 1);
    }

    /// list_expired_subscriptions excludes subscriptions not yet expired.
    #[tokio::test]
    async fn test_list_expired_subscriptions_excludes_active() {
        let db = MockDb::default();
        {
            let mut subs = db.subscriptions.lock().await;
            let sub = subs.get_mut(&1).unwrap();
            sub.is_active = true;
            sub.expires = Some(Utc::now() + chrono::Duration::hours(1));
        }

        let result = db.list_expired_subscriptions().await.unwrap();
        assert!(result.is_empty());
    }

    /// deactivate_subscription sets is_active=false on the subscription.
    #[tokio::test]
    async fn test_deactivate_subscription_flips_is_active() {
        let db = MockDb::default();
        {
            let mut subs = db.subscriptions.lock().await;
            let sub = subs.get_mut(&1).unwrap();
            sub.is_active = true;
        }

        db.deactivate_subscription(1).await.unwrap();

        let subs = db.subscriptions.lock().await;
        assert!(!subs[&1].is_active);
    }

    /// deactivate_subscription sets ended_at and is_active=false on linked ip_range_subscription rows.
    #[tokio::test]
    async fn test_deactivate_subscription_ends_ip_range_subscriptions() {
        let db = MockDb::default();
        {
            let mut subs = db.subscriptions.lock().await;
            let sub = subs.get_mut(&1).unwrap();
            sub.is_active = true;
        }

        // Insert an ip_range_subscription linked to line_item id=1 (which belongs to subscription id=1)
        let ip_sub = IpRangeSubscription {
            id: 0,
            subscription_line_item_id: 1,
            available_ip_space_id: 1,
            created: Utc::now(),
            cidr: "192.0.2.0/24".to_string(),
            origin_asn: None,
            is_active: true,
            started_at: Utc::now(),
            ended_at: None,
            metadata: None,
        };
        let inserted_id = db.insert_ip_range_subscription(&ip_sub).await.unwrap();

        db.deactivate_subscription(1).await.unwrap();

        let ip_subs = db.ip_range_subscriptions.lock().await;
        let updated = ip_subs.get(&inserted_id).unwrap();
        assert!(!updated.is_active);
        assert!(updated.ended_at.is_some());
    }

    #[tokio::test]
    async fn test_router_tunnel_crud() {
        use lnvps_db::{RouterTunnel, RouterTunnelKind};
        let db = MockDb::empty();

        let t = RouterTunnel {
            id: 0,
            router_id: 1,
            name: "gre1".to_string(),
            kind: RouterTunnelKind::Gre,
            local_addr: Some("10.0.0.1".to_string()),
            remote_addr: Some("10.0.0.2".to_string()),
            enabled: true,
            last_seen: Utc::now(),
        };
        let id = db.upsert_router_tunnel(&t).await.unwrap();
        assert_eq!(db.list_router_tunnels(1).await.unwrap().len(), 1);

        // upsert by (router_id, name) updates in place
        let mut t2 = t.clone();
        t2.enabled = false;
        let id2 = db.upsert_router_tunnel(&t2).await.unwrap();
        assert_eq!(id, id2);
        let tunnels = db.list_router_tunnels(1).await.unwrap();
        assert_eq!(tunnels.len(), 1);
        assert!(!tunnels[0].enabled);

        db.delete_router_tunnel(id).await.unwrap();
        assert!(db.list_router_tunnels(1).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_router_tunnel_traffic_window() {
        use lnvps_db::RouterTunnelTraffic;
        let db = MockDb::empty();
        db.insert_router_tunnel_traffic(&RouterTunnelTraffic {
            id: 0,
            router_id: 1,
            tunnel_name: "gre1".to_string(),
            rx_bytes: 100,
            tx_bytes: 200,
            sampled_at: Utc::now(),
        })
        .await
        .unwrap();

        let in_window = db
            .list_router_tunnel_traffic(
                1,
                "gre1",
                Utc::now() - chrono::Duration::hours(1),
                Utc::now() + chrono::Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(in_window.len(), 1);

        let out_window = db
            .list_router_tunnel_traffic(
                1,
                "gre1",
                Utc::now() + chrono::Duration::hours(1),
                Utc::now() + chrono::Duration::hours(2),
            )
            .await
            .unwrap();
        assert!(out_window.is_empty());
    }

    #[tokio::test]
    async fn test_router_bgp_session_crud() {
        use lnvps_db::{RouterBgpDirection, RouterBgpSession};
        let db = MockDb::empty();
        let s = RouterBgpSession {
            id: 0,
            router_id: 1,
            name: "peer1".to_string(),
            peer_ip: Some("192.0.2.1".to_string()),
            peer_asn: Some(64512),
            local_asn: Some(64500),
            state: "Established".to_string(),
            prefixes_received: Some(5),
            prefixes_sent: Some(1),
            enabled: true,
            direction: RouterBgpDirection::Upstream,
            last_seen: Utc::now(),
        };
        let id = db.upsert_router_bgp_session(&s).await.unwrap();
        assert_eq!(db.list_router_bgp_sessions(1).await.unwrap().len(), 1);

        let mut s2 = s.clone();
        s2.state = "Idle".to_string();
        let id2 = db.upsert_router_bgp_session(&s2).await.unwrap();
        assert_eq!(id, id2);
        let sessions = db.list_router_bgp_sessions(1).await.unwrap();
        assert_eq!(sessions[0].state, "Idle");

        db.delete_router_bgp_session(id).await.unwrap();
        assert!(db.list_router_bgp_sessions(1).await.unwrap().is_empty());
    }

    /// Regression: `enabled` is set on first import, but afterwards the database
    /// flag is authoritative — discovery refreshes must not overwrite it, and the
    /// explicit toggle must persist.
    #[tokio::test]
    async fn test_router_bgp_session_enabled_is_authoritative_after_import() {
        use lnvps_db::{RouterBgpDirection, RouterBgpSession};
        let db = MockDb::empty();
        let s = RouterBgpSession {
            id: 0,
            router_id: 1,
            name: "peer1".to_string(),
            peer_ip: Some("192.0.2.1".to_string()),
            peer_asn: Some(64512),
            local_asn: Some(64500),
            state: "Established".to_string(),
            prefixes_received: Some(5),
            prefixes_sent: Some(1),
            enabled: true,
            direction: RouterBgpDirection::Upstream,
            last_seen: Utc::now(),
        };
        // Initial import keeps the provided (state-derived) value.
        db.upsert_router_bgp_session(&s).await.unwrap();
        assert!(db.list_router_bgp_sessions(1).await.unwrap()[0].enabled);

        // Admin disables the session.
        db.set_router_bgp_session_enabled(1, "peer1", false)
            .await
            .unwrap();
        assert!(!db.list_router_bgp_sessions(1).await.unwrap()[0].enabled);

        // A later discovery refresh reporting enabled=true must NOT re-enable it.
        let mut refreshed = s.clone();
        refreshed.state = "Idle".to_string();
        refreshed.enabled = true;
        db.upsert_router_bgp_session(&refreshed).await.unwrap();
        let sessions = db.list_router_bgp_sessions(1).await.unwrap();
        assert_eq!(sessions[0].state, "Idle");
        assert!(
            !sessions[0].enabled,
            "discovery must not re-enable the session"
        );
    }

    /// Route cache: the whole per-router snapshot is replaced on each refresh,
    /// and multiple routes to the same prefix (ECMP / differing next-hops) are
    /// preserved.
    #[tokio::test]
    async fn test_router_bgp_route_cache() {
        use lnvps_db::RouterBgpRoute;
        let db = MockDb::empty();
        let mk = |router_id: u64, prefix: &str, next_hop: Option<&str>, is_default: bool| {
            RouterBgpRoute {
                id: 0,
                router_id,
                prefix: prefix.to_string(),
                next_hop: next_hop.map(|s| s.to_string()),
                is_default,
                last_seen: Utc::now(),
            }
        };

        // Two routes to the same prefix (ECMP) plus a default — all retained.
        db.replace_router_bgp_routes(
            1,
            &[
                mk(1, "192.0.2.0/24", Some("10.0.0.1"), false),
                mk(1, "192.0.2.0/24", Some("10.0.0.2"), false),
                mk(1, "0.0.0.0/0", Some("10.0.0.254"), true),
            ],
        )
        .await
        .unwrap();
        let routes = db.list_router_bgp_routes(1).await.unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(
            routes.iter().filter(|r| r.prefix == "192.0.2.0/24").count(),
            2
        );
        assert!(routes.iter().any(|r| r.is_default));

        // Routes for a different router are isolated by replace.
        db.replace_router_bgp_routes(2, &[mk(2, "203.0.113.0/24", None, false)])
            .await
            .unwrap();
        assert_eq!(db.list_router_bgp_routes(1).await.unwrap().len(), 3);
        assert_eq!(db.list_router_bgp_routes(2).await.unwrap().len(), 1);

        // Replacing with a smaller set drops the old snapshot.
        db.replace_router_bgp_routes(1, &[mk(1, "198.51.100.0/24", None, false)])
            .await
            .unwrap();
        let routes = db.list_router_bgp_routes(1).await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "198.51.100.0/24");

        // Replacing with an empty set clears the cache.
        db.replace_router_bgp_routes(1, &[]).await.unwrap();
        assert!(db.list_router_bgp_routes(1).await.unwrap().is_empty());
    }

    /// An OAuth user is created with `AccountType::OAuth` and is idempotent on
    /// the synthetic identity, distinct from Nostr users.
    #[tokio::test]
    async fn test_upsert_oauth_user() {
        use lnvps_db::{AccountType, oauth_pubkey};

        let db = MockDb::default();
        let pk = oauth_pubkey("google", "subject-123");

        let uid = db.upsert_oauth_user(&pk).await.unwrap();
        // Idempotent: same identity returns the same user id.
        assert_eq!(uid, db.upsert_oauth_user(&pk).await.unwrap());

        let user = db.get_user(uid).await.unwrap();
        assert_eq!(user.account_type, AccountType::OAuth);
        assert_eq!(user.pubkey, pk.to_vec());
        // OAuth accounts must not opt into NIP-17 (synthetic key is not a Nostr key).
        assert!(!user.contact_nip17);

        // A different subject yields a different user.
        let other = db
            .upsert_oauth_user(&oauth_pubkey("google", "subject-999"))
            .await
            .unwrap();
        assert_ne!(uid, other);
    }

    /// `oauth_pubkey` is deterministic and provider/subject sensitive.
    #[test]
    fn test_oauth_pubkey_derivation() {
        use lnvps_db::oauth_pubkey;
        assert_eq!(oauth_pubkey("a", "b"), oauth_pubkey("a", "b"));
        assert_ne!(oauth_pubkey("a", "b"), oauth_pubkey("a", "c"));
        // Provider tag is part of the identity, so `a:bc` != `ab:c`.
        assert_ne!(oauth_pubkey("a", "bc"), oauth_pubkey("ab", "c"));
    }

    /// Purging a user removes the account and cascades to their owned records,
    /// but only once no live VMs remain.
    #[tokio::test]
    async fn test_delete_user_purges_and_guards() {
        let db = MockDb::default();
        let uid = db.upsert_user(&[7u8; 32]).await.unwrap();

        // Give the user an SSH key and a soft-deleted + a live VM.
        db.user_ssh_keys.lock().await.insert(
            10,
            UserSshKey {
                id: 10,
                name: "k".to_string(),
                user_id: uid,
                created: Utc::now(),
                key_data: "ssh-ed25519 AAAA".into(),
            },
        );
        db.custom_template.lock().await.insert(
            55,
            VmCustomTemplate {
                id: 55,
                pricing_id: 1,
                ..Default::default()
            },
        );
        {
            let mut vms = db.vms.lock().await;
            vms.insert(
                100,
                Vm {
                    id: 100,
                    user_id: uid,
                    deleted: false,
                    custom_template_id: Some(55),
                    ..MockDb::mock_vm()
                },
            );
        }

        // Refuses while a live VM exists.
        assert!(db.delete_user(uid).await.is_err());
        assert!(db.get_user(uid).await.is_ok());

        // Soft-delete the VM, then purge succeeds.
        db.vms.lock().await.get_mut(&100).unwrap().deleted = true;
        db.delete_user(uid).await.unwrap();

        assert!(db.get_user(uid).await.is_err());
        assert!(db.vms.lock().await.get(&100).is_none());
        assert!(db.user_ssh_keys.lock().await.get(&10).is_none());
        // The 1:1 custom template is purged with its VM.
        assert!(db.custom_template.lock().await.get(&55).is_none());
    }

    /// Orphaned custom templates (not referenced by any VM) are removed; ones
    /// still linked to a VM are kept.
    #[tokio::test]
    async fn test_delete_orphaned_custom_vm_templates() {
        let db = MockDb::default();
        {
            let mut t = db.custom_template.lock().await;
            for id in [61u64, 62, 63] {
                t.insert(
                    id,
                    VmCustomTemplate {
                        id,
                        pricing_id: 1,
                        ..Default::default()
                    },
                );
            }
        }
        // Only template 62 is referenced by a live VM.
        db.vms.lock().await.insert(
            200,
            Vm {
                id: 200,
                custom_template_id: Some(62),
                ..MockDb::mock_vm()
            },
        );

        let deleted = db.delete_orphaned_custom_vm_templates().await.unwrap();
        assert_eq!(deleted, 2);
        let t = db.custom_template.lock().await;
        assert!(t.get(&61).is_none());
        assert!(t.get(&62).is_some());
        assert!(t.get(&63).is_none());

        // Idempotent: a second run deletes nothing.
        drop(t);
        assert_eq!(db.delete_orphaned_custom_vm_templates().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_asn_subscription_crud() {
        use lnvps_db::{AsnSubscription, AsnSubscriptionStatus, InternetRegistry};
        let db = MockDb::default();

        // Seed a line item + subscription so the by-subscription/by-user joins resolve.
        db.subscriptions.lock().await.insert(
            1,
            Subscription {
                id: 1,
                user_id: 7,
                company_id: 1,
                name: "s".to_string(),
                description: None,
                created: Utc::now(),
                expires: None,
                is_active: true,
                is_setup: true,
                currency: "EUR".to_string(),
                interval_amount: 1,
                interval_type: IntervalType::Month,
                setup_fee: 0,
                auto_renewal_enabled: false,
                external_id: None,
            },
        );
        db.subscription_line_items.lock().await.insert(
            50,
            SubscriptionLineItem {
                id: 50,
                subscription_id: 1,
                subscription_type: lnvps_db::LineItemType::AsnSponsoring,
                name: "ASN".to_string(),
                description: None,
                amount: 1000,
                setup_amount: 0,
                configuration: None,
            },
        );

        // Insert a pending request.
        let id = db
            .insert_asn_subscription(&AsnSubscription {
                id: 0,
                subscription_line_item_id: 50,
                registry: InternetRegistry::RIPE,
                asn: None,
                status: AsnSubscriptionStatus::Requested,
                created: Utc::now(),
                assigned_at: None,
                is_active: true,
                ended_at: None,
                aut_num_ref: None,
                metadata: None,
            })
            .await
            .unwrap();

        // Lookups by the various keys.
        assert_eq!(
            db.get_asn_subscription(id).await.unwrap().status,
            AsnSubscriptionStatus::Requested
        );
        assert_eq!(
            db.list_asn_subscriptions_by_line_item(50)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            db.list_asn_subscriptions_by_subscription(1)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(db.list_asn_subscriptions_by_user(7).await.unwrap().len(), 1);
        let (pending, total) = db
            .list_asn_subscriptions_paginated(Some(AsnSubscriptionStatus::Requested), 10, 0)
            .await
            .unwrap();
        assert_eq!((pending.len(), total), (1, 1));
        // Filtering by a different status excludes it.
        assert_eq!(
            db.list_asn_subscriptions_paginated(Some(AsnSubscriptionStatus::Assigned), 10, 0)
                .await
                .unwrap()
                .1,
            0
        );

        // Assign the ASN.
        let mut sub = db.get_asn_subscription(id).await.unwrap();
        sub.asn = Some(64500);
        sub.status = AsnSubscriptionStatus::Assigned;
        sub.assigned_at = Some(Utc::now());
        db.update_asn_subscription(&sub).await.unwrap();
        assert_eq!(db.get_asn_subscription_by_asn(64500).await.unwrap().id, id);

        // Delete.
        db.delete_asn_subscription(id).await.unwrap();
        assert!(db.get_asn_subscription(id).await.is_err());
    }

    #[tokio::test]
    async fn test_list_active_vms() {
        use lnvps_db::Vm;
        let db = MockDb::default();

        // Helper to seed a VM + line item + subscription with the given expiry
        // and setup state.
        async fn seed(
            db: &MockDb,
            id: u64,
            expires: Option<chrono::DateTime<Utc>>,
            is_setup: bool,
            deleted: bool,
        ) {
            db.subscriptions.lock().await.insert(
                id,
                Subscription {
                    id,
                    user_id: 1,
                    company_id: 1,
                    name: "s".to_string(),
                    description: None,
                    created: Utc::now(),
                    expires,
                    is_active: is_setup,
                    is_setup,
                    currency: "EUR".to_string(),
                    interval_amount: 1,
                    interval_type: IntervalType::Month,
                    setup_fee: 0,
                    auto_renewal_enabled: false,
                    external_id: None,
                },
            );
            db.subscription_line_items.lock().await.insert(
                id,
                SubscriptionLineItem {
                    id,
                    subscription_id: id,
                    subscription_type: lnvps_db::LineItemType::Vps,
                    name: "vm".to_string(),
                    description: None,
                    amount: 1000,
                    setup_amount: 0,
                    configuration: None,
                },
            );
            db.vms.lock().await.insert(
                id,
                Vm {
                    id,
                    subscription_line_item_id: id,
                    deleted,
                    ..Default::default()
                },
            );
        }

        let now = Utc::now();
        // (expires, is_setup, deleted)
        seed(&db, 1, Some(now + chrono::Duration::days(10)), true, false).await; // paid, future
        seed(&db, 2, Some(now - chrono::Duration::days(1)), true, false).await; // paid, expired
        seed(&db, 3, None, false, false).await; // never-paid pending order
        seed(&db, 4, Some(now + chrono::Duration::days(10)), true, true).await; // deleted

        let mut active: Vec<u64> = db
            .list_active_vms()
            .await
            .unwrap()
            .into_iter()
            .map(|v| v.id)
            .collect();
        active.sort();
        // Includes the expired-but-paid VM (2); excludes never-paid (3) and deleted (4).
        assert_eq!(
            active,
            vec![1, 2],
            "active = non-deleted, set-up VMs (incl. expired)"
        );
    }

    fn mk_app(name: &str) -> App {
        App {
            id: 0,
            name: name.to_string(),
            display_name: format!("{name} app"),
            description: None,
            icon: None,
            repo_url: None,
            category: "Nostr relay".to_string(),
            seo_title: None,
            seo_description: None,
            compose: "services: {}".to_string(),
            amount: 1000,
            currency: "USD".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            setup_amount: 0,
            enabled: true,
            cpu_milli: 500,
            memory_bytes: 512 * 1024 * 1024,
            storage_bytes: 1024 * 1024 * 1024,
            created: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_app_catalog_crud() {
        let db = MockDb::default();

        // Insert two apps; the second disabled.
        let id1 = db.insert_app(&mk_app("nostr-relay")).await.unwrap();
        let mut a2 = mk_app("blossom");
        a2.enabled = false;
        let id2 = db.insert_app(&a2).await.unwrap();

        // Duplicate name is rejected.
        assert!(db.insert_app(&mk_app("nostr-relay")).await.is_err());

        // get / get_by_name.
        assert_eq!(db.get_app(id1).await.unwrap().name, "nostr-relay");
        assert_eq!(db.get_app_by_name("blossom").await.unwrap().id, id2);
        assert!(db.get_app(9999).await.is_err());

        // list all vs enabled-only.
        assert_eq!(db.list_apps(false).await.unwrap().len(), 2);
        let enabled = db.list_apps(true).await.unwrap();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].id, id1);

        // update.
        let mut a1 = db.get_app(id1).await.unwrap();
        a1.display_name = "Relay!".to_string();
        db.update_app(&a1).await.unwrap();
        assert_eq!(db.get_app(id1).await.unwrap().display_name, "Relay!");

        // Catalog SEO metadata round-trips (issue #239): `category` is always
        // present, the two overrides default to unset and survive being set.
        let stored = db.get_app(id1).await.unwrap();
        assert_eq!(stored.category, "Nostr relay");
        assert_eq!(stored.seo_title, None);
        assert_eq!(stored.seo_description, None);

        let mut a1 = stored;
        a1.category = "Community Nostr relay".to_string();
        a1.seo_title = Some("Bespoke title".to_string());
        a1.seo_description = Some("Bespoke description".to_string());
        db.update_app(&a1).await.unwrap();
        let stored = db.get_app(id1).await.unwrap();
        assert_eq!(stored.category, "Community Nostr relay");
        assert_eq!(stored.seo_title.as_deref(), Some("Bespoke title"));
        assert_eq!(
            stored.seo_description.as_deref(),
            Some("Bespoke description")
        );

        // delete.
        db.delete_app(id2).await.unwrap();
        assert!(db.get_app(id2).await.is_err());
        assert_eq!(db.list_apps(false).await.unwrap().len(), 1);
    }

    /// App tags (issue #240): the vocabulary, replace-set assignment, the
    /// enabled-only counts and both cascade directions.
    #[tokio::test]
    async fn test_app_tag_vocabulary_and_assignment() {
        let db = MockDb::default();
        let tag = |slug: &str, display_name: &str| AppTag {
            id: 0,
            slug: slug.to_string(),
            display_name: display_name.to_string(),
            description: None,
            created: Utc::now(),
        };

        let nostr = db.insert_app_tag(&tag("nostr", "Nostr")).await.unwrap();
        let relay = db.insert_app_tag(&tag("relay", "Relay")).await.unwrap();
        let blossom = db.insert_app_tag(&tag("blossom", "Blossom")).await.unwrap();

        // Ordered by slug so a chip row / facet bar is stable across renders,
        // not by insertion order.
        let slugs: Vec<String> = db
            .list_app_tags()
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.slug)
            .collect();
        assert_eq!(slugs, vec!["blossom", "nostr", "relay"]);

        // Stands in for uq_app_tag_slug: the vocabulary is controlled, so a
        // duplicate slug is an error rather than a second tag reading the same.
        assert!(
            db.insert_app_tag(&tag("nostr", "Nostr again"))
                .await
                .is_err()
        );
        assert_eq!(db.get_app_tag_by_slug("nostr").await.unwrap().id, nostr);
        assert!(db.get_app_tag_by_slug("no-such-tag").await.is_err());

        let mut app = App {
            id: 0,
            name: "strfry".to_string(),
            display_name: "strfry".to_string(),
            description: None,
            icon: None,
            repo_url: None,
            category: "Nostr relay".to_string(),
            seo_title: None,
            seo_description: None,
            compose: "services: {}".to_string(),
            amount: 1000,
            currency: "USD".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            setup_amount: 0,
            enabled: true,
            cpu_milli: 0,
            memory_bytes: 0,
            storage_bytes: 0,
            created: Utc::now(),
        };
        let strfry = db.insert_app(&app).await.unwrap();
        app.name = "route96".to_string();
        app.display_name = "Route96".to_string();
        app.category = "Blossom media server".to_string();
        let route96 = db.insert_app(&app).await.unwrap();

        db.set_app_tags(strfry, &[nostr, relay]).await.unwrap();
        db.set_app_tags(route96, &[nostr, blossom]).await.unwrap();

        // Bulk load is keyed by app_id and ordered by (app_id, slug) — the
        // catalog listing indexes on it, so both halves matter.
        let assignments = db
            .list_app_tag_assignments(&[strfry, route96])
            .await
            .unwrap();
        let pairs: Vec<(u64, String)> = assignments
            .iter()
            .map(|(a, t)| (*a, t.slug.clone()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                (strfry, "nostr".to_string()),
                (strfry, "relay".to_string()),
                (route96, "blossom".to_string()),
                (route96, "nostr".to_string()),
            ]
        );
        // Empty input short-circuits rather than returning every row — the
        // MySQL side cannot build `IN ()` at all.
        assert!(db.list_app_tag_assignments(&[]).await.unwrap().is_empty());

        // Replace-set semantics: the new list is exact, not merged.
        db.set_app_tags(strfry, &[relay]).await.unwrap();
        let strfry_tags: Vec<String> = db
            .list_app_tag_assignments(&[strfry])
            .await
            .unwrap()
            .into_iter()
            .map(|(_, t)| t.slug)
            .collect();
        assert_eq!(strfry_tags, vec!["relay"]);
        // A repeated slug is one assignment, not a unique-key violation.
        db.set_app_tags(strfry, &[nostr, relay, nostr])
            .await
            .unwrap();
        assert_eq!(
            db.list_app_tag_assignments(&[strfry]).await.unwrap().len(),
            2
        );
        // An empty list clears.
        db.set_app_tags(strfry, &[]).await.unwrap();
        assert!(
            db.list_app_tag_assignments(&[strfry])
                .await
                .unwrap()
                .is_empty()
        );
        db.set_app_tags(strfry, &[nostr, relay]).await.unwrap();

        let counts = |v: Vec<(AppTag, u64)>| -> Vec<(String, u64)> {
            v.into_iter().map(|(t, c)| (t.slug, c)).collect()
        };
        assert_eq!(
            counts(db.list_app_tags_with_counts().await.unwrap()),
            vec![
                ("blossom".to_string(), 1),
                ("nostr".to_string(), 2),
                ("relay".to_string(), 1),
            ]
        );

        // Disabling an app drops it from the counts: the count sizes a public
        // facet bar, so counting a hidden app advertises a result a visitor
        // cannot reach. The assignment itself survives, ready for re-enabling.
        let mut r = db.get_app(route96).await.unwrap();
        r.enabled = false;
        db.update_app(&r).await.unwrap();
        assert_eq!(
            counts(db.list_app_tags_with_counts().await.unwrap()),
            vec![
                ("blossom".to_string(), 0),
                ("nostr".to_string(), 1),
                ("relay".to_string(), 1),
            ]
        );
        assert_eq!(
            db.list_app_tag_assignments(&[route96]).await.unwrap().len(),
            2
        );

        // Deleting a tag cascades its assignments and reports how many, since
        // the untagging is otherwise invisible to the admin who did it.
        assert_eq!(db.delete_app_tag(nostr).await.unwrap(), 2);
        assert!(db.get_app_tag(nostr).await.is_err());
        let strfry_tags: Vec<String> = db
            .list_app_tag_assignments(&[strfry])
            .await
            .unwrap()
            .into_iter()
            .map(|(_, t)| t.slug)
            .collect();
        assert_eq!(strfry_tags, vec!["relay"]);

        // Deleting an app cascades the other way.
        db.delete_app(strfry).await.unwrap();
        assert!(
            db.list_app_tag_assignments(&[strfry])
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(db.delete_app_tag(relay).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_app_cluster_crud() {
        let db = MockDb::default();
        let id = db
            .insert_app_cluster(&AppCluster {
                id: 0,
                name: "eu-1".to_string(),
                region_id: 1,
                ingress_domain: "apps.example.com".to_string(),
                enabled: true,
                capacity_cpu_milli: 100_000,
                capacity_memory_bytes: 100u64 * 1024 * 1024 * 1024,
                capacity_storage_bytes: 1024u64 * 1024 * 1024 * 1024,
                created: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(db.get_app_cluster(id).await.unwrap().name, "eu-1");
        assert_eq!(db.list_app_clusters(true).await.unwrap().len(), 1);

        // Disable -> excluded from enabled-only listing.
        let mut c = db.get_app_cluster(id).await.unwrap();
        c.enabled = false;
        db.update_app_cluster(&c).await.unwrap();
        assert_eq!(db.list_app_clusters(true).await.unwrap().len(), 0);
        assert_eq!(db.list_app_clusters(false).await.unwrap().len(), 1);

        db.delete_app_cluster(id).await.unwrap();
        assert!(db.get_app_cluster(id).await.is_err());
    }

    #[tokio::test]
    async fn test_app_deployment_crud() {
        let db = MockDb::default();
        let app_id = db.insert_app(&mk_app("relay")).await.unwrap();
        let cluster_id = db
            .insert_app_cluster(&AppCluster {
                id: 0,
                name: "c1".to_string(),
                region_id: 1,
                ingress_domain: "apps.example.com".to_string(),
                enabled: true,
                capacity_cpu_milli: 100_000,
                capacity_memory_bytes: 100u64 * 1024 * 1024 * 1024,
                capacity_storage_bytes: 1024u64 * 1024 * 1024 * 1024,
                created: Utc::now(),
            })
            .await
            .unwrap();

        let mk_dep = |user: u64, li: u64, name: &str| AppDeployment {
            id: 0,
            user_id: user,
            app_id,
            cluster_id,
            resource_multiplier: 1,
            subscription_line_item_id: li,
            name: name.to_string(),
            namespace: format!("app-{name}"),
            hostname: None,
            custom_domain: None,
            custom_domain_verified: false,
            config: None,
            desired_state: AppDeploymentDesiredState::Running,
            status: AppDeploymentStatus::Pending,
            status_message: None,
            usage_cpu_milli: None,
            usage_memory_bytes: None,
            usage_storage_bytes: None,
            usage_collected: None,
            created: Utc::now(),
            deleted: false,
        };

        let d1 = db.insert_app_deployment(&mk_dep(1, 10, "a")).await.unwrap();
        let _d2 = db.insert_app_deployment(&mk_dep(1, 11, "b")).await.unwrap();
        let _d3 = db.insert_app_deployment(&mk_dep(2, 12, "c")).await.unwrap();

        // Per-user listing.
        assert_eq!(db.list_user_app_deployments(1).await.unwrap().len(), 2);
        assert_eq!(db.list_user_app_deployments(2).await.unwrap().len(), 1);
        // Operator listing sees all non-deleted.
        assert_eq!(db.list_all_app_deployments().await.unwrap().len(), 3);

        // Resolve by line item.
        assert_eq!(
            db.get_app_deployment_by_line_item(11).await.unwrap().name,
            "b"
        );

        // Status write-back.
        let mut dep = db.get_app_deployment(d1).await.unwrap();
        dep.status = AppDeploymentStatus::Running;
        dep.hostname = Some("a.apps.example.com".to_string());
        db.update_app_deployment(&dep).await.unwrap();
        let reloaded = db.get_app_deployment(d1).await.unwrap();
        assert_eq!(reloaded.status, AppDeploymentStatus::Running);
        assert_eq!(reloaded.hostname.as_deref(), Some("a.apps.example.com"));

        // Soft delete removes it from both listings but the row still exists.
        db.delete_app_deployment(d1).await.unwrap();
        assert_eq!(db.list_user_app_deployments(1).await.unwrap().len(), 1);
        assert_eq!(db.list_all_app_deployments().await.unwrap().len(), 2);
        assert!(db.get_app_deployment(d1).await.unwrap().deleted);
    }

    #[tokio::test]
    async fn test_app_deployment_backup_crud() {
        let db = MockDb::default();
        let app_id = db.insert_app(&mk_app("relay")).await.unwrap();
        let cluster_a = db.insert_app_cluster(&mk_cluster("a", 1)).await.unwrap();
        let cluster_b = db.insert_app_cluster(&mk_cluster("b", 1)).await.unwrap();

        let mk_dep = |cluster_id: u64, li: u64, name: &str| AppDeployment {
            id: 0,
            user_id: 1,
            app_id,
            cluster_id,
            resource_multiplier: 1,
            subscription_line_item_id: li,
            name: name.to_string(),
            namespace: format!("app-{name}"),
            hostname: None,
            custom_domain: None,
            custom_domain_verified: false,
            config: None,
            desired_state: AppDeploymentDesiredState::Running,
            status: AppDeploymentStatus::Running,
            status_message: None,
            usage_cpu_milli: None,
            usage_memory_bytes: None,
            usage_storage_bytes: None,
            usage_collected: None,
            created: Utc::now(),
            deleted: false,
        };
        let here = db
            .insert_app_deployment(&mk_dep(cluster_a, 10, "here"))
            .await
            .unwrap();
        let elsewhere = db
            .insert_app_deployment(&mk_dep(cluster_b, 11, "elsewhere"))
            .await
            .unwrap();

        let mk_backup =
            |deployment_id: u64, service: &str, scheduled: bool, created: DateTime<Utc>| {
                AppDeploymentBackup {
                    id: 0,
                    deployment_id,
                    run_id: "run-1".to_string(),
                    service: service.to_string(),
                    method: AppBackupMethod::Command,
                    artifact: format!("{service}.sql.gz"),
                    object_key: None,
                    size_bytes: None,
                    state: AppBackupState::Pending,
                    message: None,
                    scheduled,
                    created,
                    started: None,
                    completed: None,
                    deleted: false,
                }
            };

        let older = Utc::now() - Duration::hours(2);
        let db_backup = db
            .insert_app_deployment_backup(&mk_backup(here, "db", true, older))
            .await
            .unwrap();
        let blobs = db
            .insert_app_deployment_backup(&mk_backup(here, "blobs", false, Utc::now()))
            .await
            .unwrap();
        let other = db
            .insert_app_deployment_backup(&mk_backup(elsewhere, "db", false, Utc::now()))
            .await
            .unwrap();

        // Listed newest first, and scoped to the deployment.
        let listed = db.list_app_deployment_backups(here).await.unwrap();
        assert_eq!(
            listed.iter().map(|b| b.id).collect::<Vec<_>>(),
            vec![blobs, db_backup]
        );

        // The operator only sees the backups on its own cluster.
        let active = db
            .list_active_app_deployment_backups(cluster_a)
            .await
            .unwrap();
        assert_eq!(
            active.iter().map(|b| b.id).collect::<Vec<_>>(),
            vec![db_backup, blobs]
        );
        assert_eq!(
            db.list_active_app_deployment_backups(cluster_b)
                .await
                .unwrap()
                .iter()
                .map(|b| b.id)
                .collect::<Vec<_>>(),
            vec![other]
        );

        // Progress write-back, and a completed backup drops out of the sweep.
        let mut b = db.get_app_deployment_backup(db_backup).await.unwrap();
        b.state = AppBackupState::Completed;
        b.object_key = Some("deployments/1/run-1/db.sql.gz".to_string());
        b.size_bytes = Some(4096);
        b.completed = Some(Utc::now());
        db.update_app_deployment_backup(&b).await.unwrap();
        let reloaded = db.get_app_deployment_backup(db_backup).await.unwrap();
        assert_eq!(reloaded.state, AppBackupState::Completed);
        assert_eq!(reloaded.size_bytes, Some(4096));
        assert_eq!(
            db.list_active_app_deployment_backups(cluster_a)
                .await
                .unwrap()
                .iter()
                .map(|b| b.id)
                .collect::<Vec<_>>(),
            vec![blobs]
        );

        // Only scheduled runs answer "when did the schedule last run" — an
        // on-demand backup must not push the automatic one back.
        assert_eq!(
            db.last_scheduled_app_deployment_backup(here).await.unwrap(),
            Some(older)
        );
        assert_eq!(
            db.last_scheduled_app_deployment_backup(elsewhere)
                .await
                .unwrap(),
            None
        );

        // Soft delete hides the row from both reads.
        db.delete_app_deployment_backup(blobs).await.unwrap();
        assert_eq!(
            db.list_app_deployment_backups(here)
                .await
                .unwrap()
                .iter()
                .map(|b| b.id)
                .collect::<Vec<_>>(),
            vec![db_backup]
        );
        assert!(db.get_app_deployment_backup(blobs).await.is_err());
        assert!(
            db.list_active_app_deployment_backups(cluster_a)
                .await
                .unwrap()
                .is_empty()
        );
    }

    fn mk_cluster(name: &str, region_id: u64) -> AppCluster {
        AppCluster {
            id: 0,
            name: name.to_string(),
            region_id,
            ingress_domain: format!("{name}.apps.example.com"),
            enabled: true,
            capacity_cpu_milli: 100_000,
            capacity_memory_bytes: 100u64 * 1024 * 1024 * 1024,
            capacity_storage_bytes: 1024u64 * 1024 * 1024 * 1024,
            created: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_admin_list_apps_filtered() {
        let db = MockDb::default();
        let relay = db.insert_app(&mk_app("nostr-relay")).await.unwrap();
        let mut blossom = mk_app("blossom");
        blossom.enabled = false;
        blossom.description = Some("media server".to_string());
        let blossom = db.insert_app(&blossom).await.unwrap();
        let mailer = db.insert_app(&mk_app("mailer")).await.unwrap();

        // No filters: everything, newest first, with the unfiltered total.
        let (page, total) = db
            .admin_list_apps_filtered(50, 0, None, None)
            .await
            .unwrap();
        assert_eq!(total, 3);
        assert_eq!(
            page.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![mailer, blossom, relay]
        );

        // enabled filter.
        let (page, total) = db
            .admin_list_apps_filtered(50, 0, Some(false), None)
            .await
            .unwrap();
        assert_eq!((page.len(), total), (1, 1));
        assert_eq!(page[0].id, blossom);

        // search matches name, display_name and description, case-insensitively.
        let (page, _) = db
            .admin_list_apps_filtered(50, 0, None, Some("RELAY"))
            .await
            .unwrap();
        assert_eq!(page.len(), 1, "matched by name");
        let (page, _) = db
            .admin_list_apps_filtered(50, 0, None, Some("media"))
            .await
            .unwrap();
        assert_eq!(page[0].id, blossom, "matched by description");
        let (page, _) = db
            .admin_list_apps_filtered(50, 0, None, Some("nothing-matches"))
            .await
            .unwrap();
        assert!(page.is_empty());

        // A blank search is ignored rather than matching nothing.
        let (_, total) = db
            .admin_list_apps_filtered(50, 0, None, Some("   "))
            .await
            .unwrap();
        assert_eq!(total, 3);

        // Pagination: total stays the filtered total, not the page size.
        let (page, total) = db.admin_list_apps_filtered(2, 2, None, None).await.unwrap();
        assert_eq!((page.len(), total), (1, 3));
        assert_eq!(page[0].id, relay);
    }

    #[tokio::test]
    async fn test_admin_list_app_clusters_filtered() {
        let db = MockDb::default();
        let eu = db.insert_app_cluster(&mk_cluster("eu-1", 1)).await.unwrap();
        let us = db.insert_app_cluster(&mk_cluster("us-1", 2)).await.unwrap();
        let mut disabled = mk_cluster("eu-2", 1);
        disabled.enabled = false;
        let eu2 = db.insert_app_cluster(&disabled).await.unwrap();

        let (page, total) = db
            .admin_list_app_clusters_filtered(50, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(total, 3);
        assert_eq!(page[0].id, eu2, "newest first");

        // enabled + region filters combine with AND.
        let (page, total) = db
            .admin_list_app_clusters_filtered(50, 0, Some(true), Some(1), None)
            .await
            .unwrap();
        assert_eq!((page.len(), total), (1, 1));
        assert_eq!(page[0].id, eu);

        let (page, _) = db
            .admin_list_app_clusters_filtered(50, 0, None, Some(2), None)
            .await
            .unwrap();
        assert_eq!(page[0].id, us);

        // search matches name and ingress domain.
        let (page, _) = db
            .admin_list_app_clusters_filtered(50, 0, None, None, Some("US-1"))
            .await
            .unwrap();
        assert_eq!(page[0].id, us);
        let (page, _) = db
            .admin_list_app_clusters_filtered(50, 0, None, None, Some("apps.example.com"))
            .await
            .unwrap();
        assert_eq!(page.len(), 3, "every cluster shares the ingress suffix");

        // Pagination.
        let (page, total) = db
            .admin_list_app_clusters_filtered(1, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!((page.len(), total), (1, 3));
    }

    #[tokio::test]
    async fn test_admin_list_app_deployments_filtered() {
        let db = MockDb::default();
        let relay = db.insert_app(&mk_app("relay")).await.unwrap();
        let blossom = db.insert_app(&mk_app("blossom")).await.unwrap();
        let eu = db.insert_app_cluster(&mk_cluster("eu-1", 1)).await.unwrap();
        let us = db.insert_app_cluster(&mk_cluster("us-1", 2)).await.unwrap();

        let mk_dep = |user: u64, app_id: u64, cluster_id: u64, name: &str| AppDeployment {
            id: 0,
            user_id: user,
            app_id,
            cluster_id,
            resource_multiplier: 1,
            subscription_line_item_id: 0,
            name: name.to_string(),
            namespace: format!("app-{name}"),
            hostname: Some(format!("{name}.apps.example.com")),
            custom_domain: None,
            custom_domain_verified: false,
            config: None,
            desired_state: AppDeploymentDesiredState::Running,
            status: AppDeploymentStatus::Pending,
            status_message: None,
            usage_cpu_milli: None,
            usage_memory_bytes: None,
            usage_storage_bytes: None,
            usage_collected: None,
            created: Utc::now(),
            deleted: false,
        };

        let d1 = db
            .insert_app_deployment(&mk_dep(1, relay, eu, "alpha"))
            .await
            .unwrap();
        let d2 = db
            .insert_app_deployment(&mk_dep(2, blossom, us, "beta"))
            .await
            .unwrap();
        let mut third = mk_dep(1, relay, us, "gamma");
        third.status = AppDeploymentStatus::Error;
        third.desired_state = AppDeploymentDesiredState::Stopped;
        third.custom_domain = Some("blog.example.org".to_string());
        let d3 = db.insert_app_deployment(&third).await.unwrap();

        let all = AppDeploymentFilter::default;

        // Default: all live deployments, newest first.
        let (page, total) = db
            .admin_list_app_deployments_filtered(50, 0, &all())
            .await
            .unwrap();
        assert_eq!(total, 3);
        assert_eq!(
            page.iter().map(|d| d.id).collect::<Vec<_>>(),
            vec![d3, d2, d1]
        );

        // Each filter on its own.
        let by_user = AppDeploymentFilter {
            user_id: Some(1),
            ..all()
        };
        let (page, total) = db
            .admin_list_app_deployments_filtered(50, 0, &by_user)
            .await
            .unwrap();
        assert_eq!((page.len(), total), (2, 2));

        let by_app = AppDeploymentFilter {
            app_id: Some(blossom),
            ..all()
        };
        let (page, _) = db
            .admin_list_app_deployments_filtered(50, 0, &by_app)
            .await
            .unwrap();
        assert_eq!(page[0].id, d2);

        let by_cluster = AppDeploymentFilter {
            cluster_id: Some(eu),
            ..all()
        };
        let (page, _) = db
            .admin_list_app_deployments_filtered(50, 0, &by_cluster)
            .await
            .unwrap();
        assert_eq!(page[0].id, d1);

        // region resolves through the cluster.
        let by_region = AppDeploymentFilter {
            region_id: Some(2),
            ..all()
        };
        let (page, total) = db
            .admin_list_app_deployments_filtered(50, 0, &by_region)
            .await
            .unwrap();
        assert_eq!(total, 2, "both us-1 deployments");
        assert!(page.iter().all(|d| d.cluster_id == us));

        let by_status = AppDeploymentFilter {
            status: Some(AppDeploymentStatus::Error),
            ..all()
        };
        let (page, _) = db
            .admin_list_app_deployments_filtered(50, 0, &by_status)
            .await
            .unwrap();
        assert_eq!(page[0].id, d3);

        let by_desired = AppDeploymentFilter {
            desired_state: Some(AppDeploymentDesiredState::Stopped),
            ..all()
        };
        let (page, _) = db
            .admin_list_app_deployments_filtered(50, 0, &by_desired)
            .await
            .unwrap();
        assert_eq!(page[0].id, d3);

        // search covers name, hostname and custom_domain.
        for term in ["ALPHA", "alpha.apps.example.com"] {
            let f = AppDeploymentFilter {
                search: Some(term.to_string()),
                ..all()
            };
            let (page, _) = db
                .admin_list_app_deployments_filtered(50, 0, &f)
                .await
                .unwrap();
            assert_eq!(page[0].id, d1, "search term {term}");
        }
        let f = AppDeploymentFilter {
            search: Some("blog.example.org".to_string()),
            ..all()
        };
        let (page, _) = db
            .admin_list_app_deployments_filtered(50, 0, &f)
            .await
            .unwrap();
        assert_eq!(page[0].id, d3, "matched by custom_domain");

        // Filters combine with AND.
        let combined = AppDeploymentFilter {
            user_id: Some(1),
            cluster_id: Some(us),
            ..all()
        };
        let (page, total) = db
            .admin_list_app_deployments_filtered(50, 0, &combined)
            .await
            .unwrap();
        assert_eq!((page.len(), total), (1, 1));
        assert_eq!(page[0].id, d3);

        // Soft-deleted rows are hidden by default and only surface with
        // include_deleted — the whole point of the flag.
        db.delete_app_deployment(d1).await.unwrap();
        let (_, total) = db
            .admin_list_app_deployments_filtered(50, 0, &all())
            .await
            .unwrap();
        assert_eq!(total, 2);
        let with_deleted = AppDeploymentFilter {
            include_deleted: true,
            ..all()
        };
        let (page, total) = db
            .admin_list_app_deployments_filtered(50, 0, &with_deleted)
            .await
            .unwrap();
        assert_eq!(total, 3);
        assert!(page.iter().any(|d| d.id == d1 && d.deleted));

        // Pagination.
        let (page, total) = db
            .admin_list_app_deployments_filtered(1, 1, &with_deleted)
            .await
            .unwrap();
        assert_eq!((page.len(), total), (1, 3));
        assert_eq!(page[0].id, d2);
    }

    /// Seed `subscription` + `subscription_line_item` + one paid payment for an
    /// app deployment, returning `(subscription_id, line_item_id)`.
    async fn seed_app_subscription(db: &MockDb, user_id: u64) -> (u64, u64) {
        let sub_id = db
            .insert_subscription(&Subscription {
                id: 0,
                user_id,
                company_id: 1,
                name: "app sub".to_string(),
                description: None,
                created: Utc::now(),
                expires: None,
                is_active: true,
                is_setup: true,
                currency: "EUR".to_string(),
                interval_amount: 1,
                interval_type: IntervalType::Month,
                setup_fee: 0,
                auto_renewal_enabled: true,
                external_id: None,
            })
            .await
            .unwrap();
        let li_id = db
            .insert_subscription_line_item(&SubscriptionLineItem {
                id: 0,
                subscription_id: sub_id,
                subscription_type: lnvps_db::LineItemType::App,
                name: "app".to_string(),
                description: None,
                amount: 1000,
                setup_amount: 0,
                configuration: None,
            })
            .await
            .unwrap();
        let mut payment = make_payment(sub_id, None);
        payment.user_id = user_id;
        payment.is_paid = true;
        db.insert_subscription_payment(&payment).await.unwrap();
        (sub_id, li_id)
    }

    #[tokio::test]
    async fn test_hard_delete_app_deployment() {
        let db = MockDb::default();
        // subscription_payment inserts validate the owning user exists.
        let uid = db.upsert_user(&[7u8; 32]).await.unwrap();
        let app_id = db.insert_app(&mk_app("relay")).await.unwrap();
        let cluster_id = db.insert_app_cluster(&mk_cluster("eu-1", 1)).await.unwrap();
        let (sub_id, li_id) = seed_app_subscription(&db, uid).await;

        let dep_id = db
            .insert_app_deployment(&AppDeployment {
                id: 0,
                user_id: uid,
                app_id,
                cluster_id,
                resource_multiplier: 1,
                subscription_line_item_id: li_id,
                name: "alpha".to_string(),
                namespace: "app-alpha".to_string(),
                hostname: None,
                custom_domain: None,
                custom_domain_verified: false,
                config: None,
                desired_state: AppDeploymentDesiredState::Running,
                status: AppDeploymentStatus::Running,
                status_message: None,
                usage_cpu_milli: None,
                usage_memory_bytes: None,
                usage_storage_bytes: None,
                usage_collected: None,
                created: Utc::now(),
                deleted: false,
            })
            .await
            .unwrap();

        db.hard_delete_app_deployment(dep_id).await.unwrap();

        // The row is gone, not soft-deleted, and takes its billing with it.
        assert!(db.get_app_deployment(dep_id).await.is_err());
        assert!(db.get_subscription(sub_id).await.is_err());
        assert!(db.get_subscription_line_item(li_id).await.is_err());
        assert!(
            db.list_subscription_payments(sub_id)
                .await
                .unwrap()
                .is_empty()
        );

        // Purging an unknown id is a no-op rather than an error, so a repeated
        // purge does not 500.
        db.hard_delete_app_deployment(dep_id).await.unwrap();

        // A subscription that still bills something else keeps its billing
        // rows. The default MockDb has subscription 1 with Vps line item 1,
        // which mock_vm points at; hang a deployment off the same line item.
        db.insert_vm(&Vm {
            ssh_key_id: None,
            ..MockDb::mock_vm()
        })
        .await
        .unwrap();
        let shared_sub = db.get_subscription_by_line_item_id(1).await.unwrap().id;
        let shared_dep = db
            .insert_app_deployment(&AppDeployment {
                id: 0,
                user_id: uid,
                app_id,
                cluster_id,
                resource_multiplier: 1,
                subscription_line_item_id: 1,
                name: "shared".to_string(),
                namespace: "app-shared".to_string(),
                hostname: None,
                custom_domain: None,
                custom_domain_verified: false,
                config: None,
                desired_state: AppDeploymentDesiredState::Running,
                status: AppDeploymentStatus::Running,
                status_message: None,
                usage_cpu_milli: None,
                usage_memory_bytes: None,
                usage_storage_bytes: None,
                usage_collected: None,
                created: Utc::now(),
                deleted: false,
            })
            .await
            .unwrap();

        db.hard_delete_app_deployment(shared_dep).await.unwrap();
        assert!(db.get_app_deployment(shared_dep).await.is_err());
        assert!(
            db.get_subscription(shared_sub).await.is_ok(),
            "the VM's billing survives the deployment purge"
        );
    }

    #[tokio::test]
    async fn test_hard_delete_subscription() {
        let db = MockDb::default();
        let uid = db.upsert_user(&[7u8; 32]).await.unwrap();

        // Refuses while a VM still references a line item. The default MockDb
        // has subscription 1 with Vps line item 1, which mock_vm points at.
        db.insert_vm(&Vm {
            ssh_key_id: None,
            ..MockDb::mock_vm()
        })
        .await
        .unwrap();
        let vm_sub_id = db.get_subscription_by_line_item_id(1).await.unwrap().id;
        let err = db.hard_delete_subscription(vm_sub_id).await.unwrap_err();
        assert!(
            err.to_string().contains("VM"),
            "error names the blocking resource: {err}"
        );

        // Same for an app deployment.
        let (sub_id, li_id) = seed_app_subscription(&db, uid).await;
        let app_id = db.insert_app(&mk_app("relay")).await.unwrap();
        let cluster_id = db.insert_app_cluster(&mk_cluster("eu-1", 1)).await.unwrap();
        let dep_id = db
            .insert_app_deployment(&AppDeployment {
                id: 0,
                user_id: uid,
                app_id,
                cluster_id,
                resource_multiplier: 1,
                subscription_line_item_id: li_id,
                name: "alpha".to_string(),
                namespace: "app-alpha".to_string(),
                hostname: None,
                custom_domain: None,
                custom_domain_verified: false,
                config: None,
                desired_state: AppDeploymentDesiredState::Running,
                status: AppDeploymentStatus::Running,
                status_message: None,
                usage_cpu_milli: None,
                usage_memory_bytes: None,
                usage_storage_bytes: None,
                usage_collected: None,
                created: Utc::now(),
                deleted: false,
            })
            .await
            .unwrap();
        let err = db.hard_delete_subscription(sub_id).await.unwrap_err();
        assert!(
            err.to_string().contains("app deployment"),
            "error names the blocking resource: {err}"
        );

        // With nothing attached the purge succeeds, cascading the line items and
        // paid payments that `delete_subscription` would have left behind.
        db.app_deployments.lock().await.remove(&dep_id);
        db.hard_delete_subscription(sub_id).await.unwrap();
        assert!(db.get_subscription(sub_id).await.is_err());
        assert!(db.get_subscription_line_item(li_id).await.is_err());
        assert!(
            db.list_subscription_payments(sub_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_app_cluster_capacity() {
        use crate::{AppCapacity, AppClusterCapacityService};

        let db = MockDb::default();
        // Cluster with capacity for exactly 3 of mk_app's footprint
        // (mk_app = 500m / 512Mi / 1Gi).
        let cluster_id = db
            .insert_app_cluster(&AppCluster {
                id: 0,
                name: "cap".to_string(),
                region_id: 7,
                ingress_domain: "apps.example.com".to_string(),
                enabled: true,
                capacity_cpu_milli: 1500,
                capacity_memory_bytes: 3 * 512 * 1024 * 1024,
                capacity_storage_bytes: 3 * 1024 * 1024 * 1024,
                created: Utc::now(),
            })
            .await
            .unwrap();
        let app_id = db.insert_app(&mk_app("relay")).await.unwrap();

        // Only paid deployments consume capacity (#252), so the default mock
        // subscription (`is_setup = false`) has to be marked as set up — its
        // line item id 1 is what these deployments bill through.
        {
            let mut subs = db.subscriptions.lock().await;
            subs.get_mut(&1).expect("mock subscription").is_setup = true;
        }

        let mk_dep = |name: &str| AppDeployment {
            id: 0,
            user_id: 1,
            app_id,
            cluster_id,
            resource_multiplier: 1,
            subscription_line_item_id: 1,
            name: name.to_string(),
            namespace: format!("app-{name}"),
            hostname: None,
            custom_domain: None,
            custom_domain_verified: false,
            config: None,
            desired_state: AppDeploymentDesiredState::Running,
            status: AppDeploymentStatus::Pending,
            status_message: None,
            usage_cpu_milli: None,
            usage_memory_bytes: None,
            usage_storage_bytes: None,
            usage_collected: None,
            created: Utc::now(),
            deleted: false,
        };
        db.insert_app_deployment(&mk_dep("a")).await.unwrap();
        db.insert_app_deployment(&mk_dep("b")).await.unwrap();

        let dba: Arc<dyn lnvps_db::LNVpsDb> = Arc::new(db.clone());
        let svc = AppClusterCapacityService::new(dba);

        // Two deployments used -> 1000m / 1Gi / 2Gi.
        let used = svc.used(cluster_id).await.unwrap();
        assert_eq!(used.cpu_milli, 1000);
        assert_eq!(used.storage_bytes, 2 * 1024 * 1024 * 1024);

        // Remaining capacity = room for exactly one more.
        let avail = svc.available(cluster_id).await.unwrap();
        assert_eq!(avail.cpu_milli, 500);

        let one_more = AppCapacity {
            cpu_milli: 500,
            memory_bytes: 512 * 1024 * 1024,
            storage_bytes: 1024 * 1024 * 1024,
        };
        assert!(svc.fits(cluster_id, one_more).await.unwrap());
        let two_more = AppCapacity {
            cpu_milli: 1000,
            ..one_more
        };
        assert!(!svc.fits(cluster_id, two_more).await.unwrap());

        // Region selection finds this cluster for a fitting need, none when full.
        assert_eq!(
            svc.select_in_region(7, one_more)
                .await
                .unwrap()
                .map(|c| c.id),
            Some(cluster_id)
        );
        assert!(svc.select_in_region(7, two_more).await.unwrap().is_none());
        // Wrong region -> nothing.
        assert!(svc.select_in_region(99, one_more).await.unwrap().is_none());
    }
}

use crate::dns::{BasicRecord, DnsRef, DnsZone, RecordType};
use crate::retry::{OpError, OpResult};

#[derive(Clone)]
pub struct MockDnsServer {
    pub zones: Arc<Mutex<HashMap<String, HashMap<String, MockDnsEntry>>>>,
    /// When set, `add_record` fails for records whose kind matches (e.g. "PTR",
    /// "A", "AAAA") or "*" for all. Used to simulate DNS provider failures.
    fail_kind: Arc<Mutex<Option<String>>>,
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
        // Per-test-thread state (see `MockRouter::new`): isolates parallel
        // tests while sharing within a single test.
        thread_local! {
            static TL_ZONES: Arc<Mutex<HashMap<String, HashMap<String, MockDnsEntry>>>> =
                Arc::new(Mutex::new(HashMap::new()));
            static TL_FAIL: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        }
        Self {
            zones: TL_ZONES.with(|z| z.clone()),
            fail_kind: TL_FAIL.with(|f| f.clone()),
        }
    }

    /// Make `add_record` fail for records of the given kind ("A", "AAAA",
    /// "PTR") or "*" for all kinds.
    pub async fn fail_on_kind(kind: &str) {
        *Self::new().fail_kind.lock().await = Some(kind.to_string());
    }

    /// Clear any injected DNS failure.
    pub async fn clear_failures() {
        *Self::new().fail_kind.lock().await = None;
    }

    pub async fn reset() {
        Self::new().zones.lock().await.clear();
        *Self::new().fail_kind.lock().await = None;
    }
}

#[async_trait]
impl crate::dns::DnsServer for MockDnsServer {
    async fn add_record(&self, record: &BasicRecord) -> OpResult<BasicRecord> {
        if let Some(k) = self.fail_kind.lock().await.as_ref()
            && (k == "*" || *k == record.kind.to_string())
        {
            return Err(OpError::Fatal(anyhow::anyhow!(
                "Injected DNS failure for {} record",
                record.kind
            )));
        }
        let zone_id = record
            .zone
            .as_id()
            .map(|s| s.to_string())
            .unwrap_or_else(|| record.ip.clone());
        let mut zones = self.zones.lock().await;
        let table = if let Some(t) = zones.get_mut(&zone_id) {
            t
        } else {
            zones.insert(zone_id.clone(), HashMap::new());
            zones.get_mut(&zone_id).unwrap()
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
            id: Some(DnsRef::Id(id)),
            kind: record.kind.clone(),
            ip: record.ip.clone(),
            zone: record.zone.clone(),
        })
    }

    async fn delete_record(&self, record: &BasicRecord) -> OpResult<()> {
        let zone_id = record
            .zone
            .as_id()
            .map(|s| s.to_string())
            .unwrap_or_else(|| record.ip.clone());
        let mut zones = self.zones.lock().await;
        let table = if let Some(t) = zones.get_mut(&zone_id) {
            t
        } else {
            zones.insert(zone_id.clone(), HashMap::new());
            zones.get_mut(&zone_id).unwrap()
        };
        let record_id = record
            .id
            .as_ref()
            .and_then(DnsRef::as_id)
            .ok_or_else(|| OpError::Fatal(anyhow::anyhow!("Id is missing")))?;
        table.remove(record_id);
        Ok(())
    }

    async fn update_record(&self, record: &BasicRecord) -> OpResult<BasicRecord> {
        let zone_id = record
            .zone
            .as_id()
            .map(|s| s.to_string())
            .unwrap_or_else(|| record.ip.clone());
        let mut zones = self.zones.lock().await;
        let table = if let Some(t) = zones.get_mut(&zone_id) {
            t
        } else {
            zones.insert(zone_id.clone(), HashMap::new());
            zones.get_mut(&zone_id).unwrap()
        };
        let record_id = record
            .id
            .as_ref()
            .and_then(DnsRef::as_id)
            .ok_or_else(|| OpError::Fatal(anyhow::anyhow!("Id is missing")))?;
        if let Some(r) = table.get_mut(record_id) {
            r.name = record.name.clone();
            r.value = record.value.clone();
            r.kind = record.kind.to_string();
        }
        Ok(record.clone())
    }

    async fn list_zones(&self) -> OpResult<Vec<DnsZone>> {
        Ok(vec![DnsZone {
            id: "mock-zone-id".to_string(),
            name: "mock.example.com".to_string(),
        }])
    }
}

#[cfg(test)]
mod marketplace_tests {
    use super::*;
    use lnvps_db::{
        LNVpsDbBase, LineItemType, MarketplaceTrustTier, PayoutMode, RouterTunnelKind,
        Subscription, SubscriptionLineItem, SubscriptionPayment, SubscriptionPaymentType,
    };

    /// Create a user, returning its id. The marketplace tables carry real FKs
    /// to `users`, so tests cannot invent owners.
    async fn user(db: &MockDb, n: u8) -> u64 {
        db.upsert_user(&[n; 32]).await.unwrap()
    }

    /// An operator enrolment for `user_id`, with the defaults a fresh signup has.
    fn operator(user_id: u64) -> MarketplaceOperator {
        MarketplaceOperator {
            user_id,
            address: Some("operator@example.com".to_string()),
            mode: PayoutMode::LightningAddress,
            enabled: true,
            ..Default::default()
        }
    }

    fn node(operator_id: u64, name: &str) -> MarketplaceNode {
        MarketplaceNode {
            operator_id,
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Build a subscription with the given line item amounts, plus an unpaid
    /// payment against it. `(amount, setup_amount)` per line item.
    async fn subscription_with(db: &MockDb, uid: u64, items: &[(u64, u64)]) -> (u64, Vec<u8>) {
        let sub = Subscription {
            id: 0,
            user_id: uid,
            company_id: 1,
            name: "sub".to_string(),
            description: None,
            created: Utc::now(),
            expires: None,
            is_active: false,
            is_setup: false,
            currency: "EUR".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            setup_fee: 0,
            auto_renewal_enabled: false,
            external_id: None,
        };
        let line_items = items
            .iter()
            .map(|(amount, setup_amount)| SubscriptionLineItem {
                id: 0,
                subscription_id: 0,
                subscription_type: LineItemType::MarketplaceNodeFee,
                name: "item".to_string(),
                description: None,
                amount: *amount,
                setup_amount: *setup_amount,
                configuration: None,
            })
            .collect();
        let (sub_id, _) = db
            .insert_subscription_with_line_items(&sub, line_items)
            .await
            .unwrap();

        let payment = SubscriptionPayment {
            id: vec![sub_id as u8; 32],
            subscription_id: sub_id,
            user_id: uid,
            created: Utc::now(),
            expires: Utc::now() + TimeDelta::hours(1),
            amount: 1000,
            currency: "EUR".to_string(),
            rate: 1.0,
            time_value: Some(2_592_000),
            payment_method: PaymentMethod::Lightning,
            payment_type: SubscriptionPaymentType::Purchase,
            external_data: Default::default(),
            external_id: None,
            is_paid: false,
            metadata: None,
            tax: 0,
            processing_fee: 0,
            paid_at: None,
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
            refunded_payment_id: None,
            renewal_source: None,
        };
        db.insert_subscription_payment(&payment).await.unwrap();
        (sub_id, payment.id.clone())
    }

    /// A one-off purchase must never acquire an expiry, or `check_subscriptions`
    /// mails the customer "your subscription will expire soon" about something
    /// they bought outright.
    #[tokio::test]
    async fn a_one_off_fee_never_gets_an_expiry() {
        let db = MockDb::default();
        let uid = user(&db, 1).await;
        let (sub_id, pid) = subscription_with(&db, uid, &[(0, 5000)]).await;

        let payment = db.get_subscription_payment(&pid).await.unwrap();
        db.subscription_payment_paid(&payment).await.unwrap();

        let sub = db.get_subscription(sub_id).await.unwrap();
        assert_eq!(sub.expires, None, "a one-off fee was given an expiry");
        // ...but it is still activated: the expiry UPDATE is also what sets
        // these, so skipping it wholesale would leave a paid fee looking unpaid.
        assert!(sub.is_active, "paid fee left inactive");
        assert!(sub.is_setup, "paid fee left un-set-up");
    }

    /// The narrow half of the rule. A recurring subscription must keep expiring
    /// exactly as before — this branch sits in the shared payment path.
    #[tokio::test]
    async fn a_recurring_subscription_still_expires() {
        let db = MockDb::default();
        let uid = user(&db, 1).await;
        let (sub_id, pid) = subscription_with(&db, uid, &[(1000, 500)]).await;

        let payment = db.get_subscription_payment(&pid).await.unwrap();
        db.subscription_payment_paid(&payment).await.unwrap();

        let sub = db.get_subscription(sub_id).await.unwrap();
        assert!(
            sub.expires.is_some(),
            "a recurring subscription stopped expiring — renewals would never be billed"
        );
    }

    /// The case that makes the rule "no recurring amount AND a setup fee"
    /// rather than just "no recurring amount": a free or fully-discounted
    /// subscription has neither, and must still lapse on schedule.
    #[tokio::test]
    async fn a_free_subscription_still_expires() {
        let db = MockDb::default();
        let uid = user(&db, 1).await;
        let (sub_id, pid) = subscription_with(&db, uid, &[(0, 0)]).await;

        let payment = db.get_subscription_payment(&pid).await.unwrap();
        db.subscription_payment_paid(&payment).await.unwrap();

        let sub = db.get_subscription(sub_id).await.unwrap();
        assert!(
            sub.expires.is_some(),
            "a zero-amount subscription stopped expiring — it would never be cleaned up"
        );
    }

    /// Mirrors `uk_marketplace_node_line_item`. Without it two nodes could
    /// point at one paid fee, turning the per-node gate into a per-operator one.
    #[tokio::test]
    async fn one_paid_fee_covers_one_node() {
        let db = MockDb::default();
        let uid = user(&db, 1).await;
        let op = db
            .insert_marketplace_operator(&operator(uid))
            .await
            .unwrap();
        let (_, _) = subscription_with(&db, uid, &[(0, 5000)]).await;
        let li = db.list_subscription_line_items(1).await.unwrap()[0].id;

        db.insert_marketplace_node(&MarketplaceNode {
            subscription_line_item_id: Some(li),
            ..node(op, "first")
        })
        .await
        .unwrap();

        let err = db
            .insert_marketplace_node(&MarketplaceNode {
                subscription_line_item_id: Some(li),
                ..node(op, "second")
            })
            .await
            .expect_err("two nodes shared one listing fee");
        assert!(format!("{err}").contains("already bills"), "got: {err}");

        // ...and the same must hold on update, not just insert.
        let other = db
            .insert_marketplace_node(&node(op, "third"))
            .await
            .unwrap();
        let mut steal = db.get_marketplace_node(other).await.unwrap();
        steal.subscription_line_item_id = Some(li);
        assert!(db.update_marketplace_node(&steal).await.is_err());

        // The fee resolves back to the node it paid for.
        let found = db.get_marketplace_node_by_line_item(li).await.unwrap();
        assert_eq!(found.name, "first");
    }

    /// Mirrors `uk_marketplace_node_tls_fingerprint`: two nodes serving the
    /// same certificate would each be able to answer for the other.
    #[tokio::test]
    async fn a_tls_fingerprint_belongs_to_one_node() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;
        let op = db
            .insert_marketplace_operator(&MarketplaceOperator {
                user_id: u1,
                ..Default::default()
            })
            .await
            .unwrap();

        db.insert_marketplace_node(&MarketplaceNode {
            tls_fingerprint: Some(vec![7u8; 32]),
            ..node(op, "one")
        })
        .await
        .unwrap();

        let err = db
            .insert_marketplace_node(&MarketplaceNode {
                tls_fingerprint: Some(vec![7u8; 32]),
                ..node(op, "two")
            })
            .await
            .expect_err("two nodes shared a TLS fingerprint");
        assert!(err.to_string().contains("fingerprint"), "{err}");
    }

    /// Mirrors `ck_marketplace_node_tls_fingerprint`. The real column pads a
    /// short value with zero bytes and accepts it, which stores a pin that can
    /// never match; the constraint turns that into an error at write time.
    #[tokio::test]
    async fn a_tls_fingerprint_must_be_a_full_sha256() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;
        let op = db
            .insert_marketplace_operator(&MarketplaceOperator {
                user_id: u1,
                ..Default::default()
            })
            .await
            .unwrap();

        for len in [16usize, 31, 33] {
            let err = db
                .insert_marketplace_node(&MarketplaceNode {
                    tls_fingerprint: Some(vec![1u8; len]),
                    ..node(op, "short")
                })
                .await
                .expect_err("a {len}-byte fingerprint was accepted");
            assert!(err.to_string().contains("32 bytes"), "{len}: {err}");
        }
    }

    #[tokio::test]
    async fn operator_crud_roundtrip() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;

        let id = db.insert_marketplace_operator(&operator(u1)).await.unwrap();
        let loaded = db.get_marketplace_operator(id).await.unwrap();
        assert_eq!(loaded.user_id, 1);
        assert_eq!(loaded.mode, PayoutMode::LightningAddress);
        // No override by default: the company rate applies.
        assert_eq!(loaded.rate, None);
        assert_eq!(loaded.payout_threshold, None);
        assert!(loaded.enabled);

        // Lookup by user is how the operator's own API calls will resolve.
        let by_user = db.get_marketplace_operator_by_user(1).await.unwrap();
        assert_eq!(by_user.id, id);

        let mut update = loaded.clone();
        update.rate = Some(70.0);
        update.payout_threshold = Some(10_000);
        update.mode = PayoutMode::Nwc;
        update.address = None;
        update.enabled = false;
        db.update_marketplace_operator(&update).await.unwrap();

        let reloaded = db.get_marketplace_operator(id).await.unwrap();
        assert_eq!(reloaded.rate, Some(70.0));
        assert_eq!(reloaded.payout_threshold, Some(10_000));
        assert_eq!(reloaded.mode, PayoutMode::Nwc);
        assert_eq!(reloaded.address, None);
        assert!(!reloaded.enabled);

        assert_eq!(db.list_marketplace_operators().await.unwrap().len(), 1);
        db.delete_marketplace_operator(id).await.unwrap();
        assert!(db.get_marketplace_operator(id).await.is_err());
        assert!(db.list_marketplace_operators().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn operator_enrolment_is_one_per_user() {
        let db = MockDb::default();
        let (u1, u2) = (user(&db, 1).await, user(&db, 2).await);
        db.insert_marketplace_operator(&operator(u1)).await.unwrap();
        // uk_marketplace_operator_user: a second enrolment would split one
        // user's earnings across two balances.
        assert!(db.insert_marketplace_operator(&operator(u1)).await.is_err());
        db.insert_marketplace_operator(&operator(u2)).await.unwrap();
        // FK marketplace_operator.user_id
        assert!(
            db.insert_marketplace_operator(&operator(999))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn operator_update_cannot_move_the_enrolment_to_another_user() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;
        let id = db.insert_marketplace_operator(&operator(u1)).await.unwrap();

        let mut hijack = db.get_marketplace_operator(id).await.unwrap();
        hijack.user_id = 2;
        hijack.rate = Some(50.0);
        db.update_marketplace_operator(&hijack).await.unwrap();

        // The mutable field changed; the owner did not. Otherwise an update
        // endpoint would be a way to redirect somebody else's payouts.
        let reloaded = db.get_marketplace_operator(id).await.unwrap();
        assert_eq!(reloaded.rate, Some(50.0));
        assert_eq!(reloaded.user_id, 1);
    }

    #[tokio::test]
    async fn node_crud_roundtrip() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;
        let op = db.insert_marketplace_operator(&operator(u1)).await.unwrap();

        let id = db
            .insert_marketplace_node(&node(op, "rack-1"))
            .await
            .unwrap();
        let loaded = db.get_marketplace_node(id).await.unwrap();
        assert_eq!(loaded.name, "rack-1");
        // A new node is pending and untrusted: it must not be placeable purely
        // by being registered.
        assert_eq!(loaded.status, MarketplaceNodeStatus::Pending);
        assert_eq!(loaded.trust_tier, MarketplaceTrustTier::Untrusted);
        assert!(!loaded.status.accepts_placement());
        assert_eq!(loaded.last_seen, None);
        assert_eq!(loaded.tls_fingerprint, None);
        assert_eq!(loaded.token_version, 0);

        let mut update = loaded.clone();
        update.name = "rack-1a".to_string();
        update.status = MarketplaceNodeStatus::Approved;
        update.trust_tier = MarketplaceTrustTier::Verified;
        update.tls_fingerprint = Some(vec![7u8; 32]);
        // Bumping the version is how a node's token is revoked, and it must
        // survive a write or revocation would silently not take.
        update.token_version = 1;
        db.update_marketplace_node(&update).await.unwrap();

        let reloaded = db.get_marketplace_node(id).await.unwrap();
        assert_eq!(reloaded.name, "rack-1a");
        assert!(reloaded.status.accepts_placement());
        assert_eq!(reloaded.trust_tier, MarketplaceTrustTier::Verified);
        assert_eq!(reloaded.tls_fingerprint, Some(vec![7u8; 32]));
        assert_eq!(reloaded.token_version, 1);

        // LNVPS resolves a node by the certificate it pinned.
        let by_cert = db
            .get_marketplace_node_by_tls_fingerprint(&[7u8; 32])
            .await
            .unwrap();
        assert_eq!(by_cert.id, id);
        assert!(
            db.get_marketplace_node_by_tls_fingerprint(&[9u8; 32])
                .await
                .is_err()
        );

        db.delete_marketplace_node(id).await.unwrap();
        assert!(db.get_marketplace_node(id).await.is_err());
    }

    #[tokio::test]
    async fn node_listing_filters_by_operator_and_status() {
        let db = MockDb::default();
        let (u1, u2) = (user(&db, 1).await, user(&db, 2).await);
        let op1 = db.insert_marketplace_operator(&operator(u1)).await.unwrap();
        let op2 = db.insert_marketplace_operator(&operator(u2)).await.unwrap();

        let a = db.insert_marketplace_node(&node(op1, "a")).await.unwrap();
        db.insert_marketplace_node(&node(op1, "b")).await.unwrap();
        db.insert_marketplace_node(&node(op2, "c")).await.unwrap();

        let mut approved = db.get_marketplace_node(a).await.unwrap();
        approved.status = MarketplaceNodeStatus::Approved;
        db.update_marketplace_node(&approved).await.unwrap();

        // An operator sees only their own hardware.
        let mine = db.list_marketplace_nodes(op1).await.unwrap();
        assert_eq!(mine.len(), 2);
        assert!(mine.iter().all(|n| n.operator_id == op1));
        assert_eq!(db.list_marketplace_nodes(op2).await.unwrap().len(), 1);

        assert_eq!(db.list_all_marketplace_nodes(None).await.unwrap().len(), 3);
        let pending = db
            .list_all_marketplace_nodes(Some(MarketplaceNodeStatus::Pending))
            .await
            .unwrap();
        assert_eq!(pending.len(), 2);
        let live = db
            .list_all_marketplace_nodes(Some(MarketplaceNodeStatus::Approved))
            .await
            .unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, a);
    }

    #[tokio::test]
    async fn a_certificate_identifies_exactly_one_node() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;
        let op = db.insert_marketplace_operator(&operator(u1)).await.unwrap();

        let mut first = node(op, "a");
        first.tls_fingerprint = Some(vec![1u8; 32]);
        db.insert_marketplace_node(&first).await.unwrap();

        // uk_marketplace_node_tls_fingerprint. Without this a second node could
        // present the certificate LNVPS pinned for an approved node, and answer
        // for it.
        let mut clash = node(op, "b");
        clash.tls_fingerprint = Some(vec![1u8; 32]);
        assert!(db.insert_marketplace_node(&clash).await.is_err());

        // ...and the same must hold on update, not just insert.
        clash.tls_fingerprint = None;
        let other_id = db.insert_marketplace_node(&clash).await.unwrap();
        let mut steal = db.get_marketplace_node(other_id).await.unwrap();
        steal.tls_fingerprint = Some(vec![1u8; 32]);
        assert!(db.update_marketplace_node(&steal).await.is_err());

        // Unregistered nodes do not collide with each other (SQL NULLs never do).
        db.insert_marketplace_node(&node(op, "c")).await.unwrap();
    }

    #[tokio::test]
    async fn node_cannot_be_registered_to_a_missing_operator() {
        let db = MockDb::default();
        assert!(
            db.insert_marketplace_node(&node(999, "orphan"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn node_update_cannot_move_hardware_between_operators() {
        let db = MockDb::default();
        let (u1, u2) = (user(&db, 1).await, user(&db, 2).await);
        let op1 = db.insert_marketplace_operator(&operator(u1)).await.unwrap();
        let op2 = db.insert_marketplace_operator(&operator(u2)).await.unwrap();
        let id = db.insert_marketplace_node(&node(op1, "a")).await.unwrap();

        let mut hijack = db.get_marketplace_node(id).await.unwrap();
        hijack.operator_id = op2;
        db.update_marketplace_node(&hijack).await.unwrap();

        // Reassigning a node would move its earnings history to someone else.
        assert_eq!(db.get_marketplace_node(id).await.unwrap().operator_id, op1);
        assert_eq!(db.list_marketplace_nodes(op2).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn heartbeat_updates_only_last_seen() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;
        let op = db.insert_marketplace_operator(&operator(u1)).await.unwrap();
        let id = db.insert_marketplace_node(&node(op, "a")).await.unwrap();

        let seen = Utc::now();
        db.touch_marketplace_node(id, seen).await.unwrap();
        let loaded = db.get_marketplace_node(id).await.unwrap();
        assert_eq!(loaded.last_seen, Some(seen));
        // A heartbeat must never resurrect a suspended node.
        assert_eq!(loaded.status, MarketplaceNodeStatus::Pending);

        assert!(db.touch_marketplace_node(999, seen).await.is_err());

        // Conversely, an admin edit must not clobber liveness with a stale
        // value read before the last heartbeat.
        let mut edit = loaded.clone();
        edit.last_seen = None;
        edit.status = MarketplaceNodeStatus::Approved;
        db.update_marketplace_node(&edit).await.unwrap();
        assert_eq!(
            db.get_marketplace_node(id).await.unwrap().last_seen,
            Some(seen)
        );
    }

    #[tokio::test]
    async fn live_hardware_cannot_be_deleted_out_from_under_customers() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;
        let op = db.insert_marketplace_operator(&operator(u1)).await.unwrap();
        let node_id = db.insert_marketplace_node(&node(op, "a")).await.unwrap();

        // An operator enrolment with nodes cannot be dropped...
        assert!(db.delete_marketplace_operator(op).await.is_err());

        // ...and a node backing a host cannot be dropped either.
        {
            let mut hosts = db.hosts.lock().await;
            let host = hosts.get_mut(&1).expect("seeded host");
            host.marketplace_node_id = Some(node_id);
        }
        assert!(db.delete_marketplace_node(node_id).await.is_err());

        // Detaching the host is what makes removal safe, in that order.
        {
            let mut hosts = db.hosts.lock().await;
            hosts.get_mut(&1).unwrap().marketplace_node_id = None;
        }
        db.delete_marketplace_node(node_id).await.unwrap();
        db.delete_marketplace_operator(op).await.unwrap();
    }

    // ----- Tunnels -----

    /// An allocation owned by `user_id`. What it is *for* is decided by
    /// whatever links to it, not by anything here.
    fn tunnel(user_id: u64, name: &str) -> Tunnel {
        Tunnel {
            user_id,
            name: name.to_string(),
            enabled: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn tunnel_crud_roundtrip() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;
        let op = db.insert_marketplace_operator(&operator(u1)).await.unwrap();
        let node_id = db.insert_marketplace_node(&node(op, "a")).await.unwrap();

        let mut t = tunnel(u1, "wg-node-1");
        t.peer_pubkey = Some(vec![3u8; 32]);
        t.address4 = Some("10.66.0.1/31".to_string());
        t.address6 = Some("2001:db8::1/127".to_string());
        t.keepalive = Some(25);
        let id = db.insert_tunnel(&t).await.unwrap();

        let loaded = db.get_tunnel(id).await.unwrap();
        // WireGuard is the default kind, matching the column default.
        assert_eq!(loaded.kind, RouterTunnelKind::Wireguard);
        // Every allocation has an owner; it says nothing about what it is for.
        assert_eq!(loaded.user_id, u1);
        assert_eq!(loaded.address4.as_deref(), Some("10.66.0.1/31"));
        // Not yet placed on a route server.
        assert_eq!(loaded.router_id, None);

        // A route server resolves an incoming handshake to its allocation.
        let by_key = db.get_tunnel_by_peer_pubkey(&[3u8; 32]).await.unwrap();
        assert_eq!(by_key.id, id);
        assert!(db.get_tunnel_by_peer_pubkey(&[4u8; 32]).await.is_err());

        // The node points at its tunnel, not the other way round.
        let mut with_tunnel = db.get_marketplace_node(node_id).await.unwrap();
        assert_eq!(with_tunnel.tunnel_id, None);
        with_tunnel.tunnel_id = Some(id);
        db.update_marketplace_node(&with_tunnel).await.unwrap();
        assert_eq!(
            db.get_marketplace_node(node_id).await.unwrap().tunnel_id,
            Some(id)
        );

        let mut update = loaded.clone();
        update.enabled = false;
        update.peer_endpoint = Some("198.51.100.7:51820".to_string());
        db.update_tunnel(&update).await.unwrap();
        let reloaded = db.get_tunnel(id).await.unwrap();
        assert!(!reloaded.enabled);
        assert_eq!(
            reloaded.peer_endpoint.as_deref(),
            Some("198.51.100.7:51820")
        );
    }

    #[tokio::test]
    async fn an_inner_address_belongs_to_one_tunnel() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;

        let mut first = tunnel(u1, "wg-1");
        first.address4 = Some("10.66.0.1/31".to_string());
        first.peer_pubkey = Some(vec![1u8; 32]);
        db.insert_tunnel(&first).await.unwrap();

        // Reusing an inner address routes one tenant's traffic to another.
        let mut clash = tunnel(u1, "wg-2");
        clash.address4 = Some("10.66.0.1/31".to_string());
        assert!(db.insert_tunnel(&clash).await.is_err());

        // Same for the peer key: the route server could not tell them apart.
        let mut key_clash = tunnel(u1, "wg-3");
        key_clash.peer_pubkey = Some(vec![1u8; 32]);
        assert!(db.insert_tunnel(&key_clash).await.is_err());

        // ...and neither may be stolen by an update.
        let mut ok = tunnel(u1, "wg-4");
        ok.address6 = Some("2001:db8::1/127".to_string());
        let ok_id = db.insert_tunnel(&ok).await.unwrap();
        let mut steal = db.get_tunnel(ok_id).await.unwrap();
        steal.address4 = Some("10.66.0.1/31".to_string());
        assert!(db.update_tunnel(&steal).await.is_err());

        // Unassigned tunnels do not collide with each other (SQL NULLs never do).
        db.insert_tunnel(&tunnel(u1, "wg-5")).await.unwrap();
        db.insert_tunnel(&tunnel(u1, "wg-6")).await.unwrap();
    }

    #[tokio::test]
    async fn a_tunnel_backs_exactly_one_node() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;
        let op = db.insert_marketplace_operator(&operator(u1)).await.unwrap();
        let first = db.insert_marketplace_node(&node(op, "a")).await.unwrap();
        let second = db.insert_marketplace_node(&node(op, "b")).await.unwrap();
        let t = db.insert_tunnel(&tunnel(u1, "wg-1")).await.unwrap();

        let mut a = db.get_marketplace_node(first).await.unwrap();
        a.tunnel_id = Some(t);
        db.update_marketplace_node(&a).await.unwrap();

        // uk_marketplace_node_tunnel: two machines answering to one key and
        // address is exactly the collision the unique index exists to stop.
        let mut b = db.get_marketplace_node(second).await.unwrap();
        b.tunnel_id = Some(t);
        assert!(db.update_marketplace_node(&b).await.is_err());
        assert_eq!(
            db.get_marketplace_node(second).await.unwrap().tunnel_id,
            None
        );

        // ...including at registration time.
        let mut fresh = node(op, "c");
        fresh.tunnel_id = Some(t);
        assert!(db.insert_marketplace_node(&fresh).await.is_err());

        // A node cannot point at a tunnel that does not exist.
        let mut ghost = db.get_marketplace_node(second).await.unwrap();
        ghost.tunnel_id = Some(999);
        assert!(db.update_marketplace_node(&ghost).await.is_err());
    }

    #[tokio::test]
    async fn a_tunnel_carrying_guest_traffic_cannot_be_deleted() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;
        let op = db.insert_marketplace_operator(&operator(u1)).await.unwrap();
        let node_id = db.insert_marketplace_node(&node(op, "a")).await.unwrap();
        let t = db.insert_tunnel(&tunnel(u1, "wg-1")).await.unwrap();

        let mut n = db.get_marketplace_node(node_id).await.unwrap();
        n.tunnel_id = Some(t);
        db.update_marketplace_node(&n).await.unwrap();

        // FK marketplace_node.tunnel_id — deleting it would cut a live data
        // plane and orphan the allocation.
        assert!(db.delete_tunnel(t).await.is_err());

        // Detaching first is what makes removal safe, in that order.
        n.tunnel_id = None;
        db.update_marketplace_node(&n).await.unwrap();
        db.delete_tunnel(t).await.unwrap();
        assert!(db.get_tunnel(t).await.is_err());
    }

    #[tokio::test]
    async fn a_tunnel_cannot_change_owner() {
        let db = MockDb::default();
        let (u1, u2) = (user(&db, 1).await, user(&db, 2).await);
        let id = db.insert_tunnel(&tunnel(u1, "wg-vpn")).await.unwrap();

        let mut hijack = db.get_tunnel(id).await.unwrap();
        hijack.user_id = u2;
        hijack.name = "renamed".to_string();
        db.update_tunnel(&hijack).await.unwrap();

        // The mutable field changed; ownership did not. Re-pointing an
        // allocation would hand one tenant's addresses and key to another.
        let reloaded = db.get_tunnel(id).await.unwrap();
        assert_eq!(reloaded.name, "renamed");
        assert_eq!(reloaded.user_id, u1);
    }

    #[tokio::test]
    async fn tunnels_list_by_owner() {
        let db = MockDb::default();
        let (u1, bgp_customer) = (user(&db, 1).await, user(&db, 9).await);
        let op = db.insert_marketplace_operator(&operator(u1)).await.unwrap();
        let node_id = db.insert_marketplace_node(&node(op, "a")).await.unwrap();

        // A node's data plane: owned by the operator, and marked as a node
        // tunnel only by the node pointing at it.
        let node_tunnel = db.insert_tunnel(&tunnel(u1, "wg-node")).await.unwrap();
        let mut n = db.get_marketplace_node(node_id).await.unwrap();
        n.tunnel_id = Some(node_tunnel);
        db.update_marketplace_node(&n).await.unwrap();

        // A VPN sold to the same user, linked by nothing yet.
        db.insert_tunnel(&tunnel(u1, "wg-vpn")).await.unwrap();
        // A BGP tunnel requested by a different customer.
        db.insert_tunnel(&tunnel(bgp_customer, "wg-bgp"))
            .await
            .unwrap();

        assert_eq!(db.list_tunnels().await.unwrap().len(), 3);

        // Ownership is not a type: this user owns both a node data plane and a
        // VPN, and the query returns what they own rather than what it is for.
        let mine = db.list_tunnels_for_user(u1).await.unwrap();
        assert_eq!(mine.len(), 2);
        assert_eq!(
            db.list_tunnels_for_user(bgp_customer).await.unwrap().len(),
            1
        );

        // Which of them is the node's is answered by the node, not the tunnel.
        let attached = db.get_marketplace_node(node_id).await.unwrap().tunnel_id;
        assert_eq!(attached, Some(node_tunnel));

        // A tunnel cannot be allocated to a user who does not exist.
        assert!(db.insert_tunnel(&tunnel(999, "wg-ghost")).await.is_err());
    }
}

#[cfg(test)]
mod discount_tests {
    use super::*;
    use lnvps_db::LNVpsDbBase;

    async fn user(db: &MockDb, n: u8) -> u64 {
        db.upsert_user(&[n; 32]).await.unwrap()
    }

    fn discount(code: &str) -> Discount {
        Discount {
            company_id: 1,
            code: Some(code.to_string()),
            name: "Test discount".to_string(),
            rule: "{'percent': 10}".to_string(),
            active: true,
            ..Default::default()
        }
    }

    /// Apply a discount to a payment and settle it, as a real order does.
    async fn redeem(db: &MockDb, discount_id: u64, user_id: u64, payment: u8) {
        db.insert_discount_redemption(&redemption(discount_id, user_id, payment))
            .await
            .unwrap();
        db.settle_discount_redemption(&vec![payment; 32])
            .await
            .unwrap()
            .expect("settles");
    }

    fn redemption(discount_id: u64, user_id: u64, payment: u8) -> DiscountRedemption {
        DiscountRedemption {
            discount_id,
            user_id,
            subscription_payment_id: vec![payment; 32],
            amount_off: 1_000,
            currency: "EUR".to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn crud_round_trip() {
        let db = MockDb::default();
        let id = db.insert_discount(&discount("SAVE10")).await.unwrap();

        let loaded = db.get_discount(id).await.unwrap();
        assert_eq!(loaded.code.as_deref(), Some("SAVE10"));
        assert_eq!(db.get_discount_by_code("SAVE10").await.unwrap().id, id);
        assert!(db.get_discount_by_code("NOPE").await.is_err());
        assert!(db.get_discount(999).await.is_err());

        let (listed, total) = db.list_discounts_paginated(1, 50, 0).await.unwrap();
        assert_eq!((listed.len(), total), (1, 1));
        assert!(
            db.list_discounts_paginated(2, 50, 0)
                .await
                .unwrap()
                .0
                .is_empty()
        );

        db.update_discount(&Discount {
            name: "Renamed".to_string(),
            active: false,
            ..loaded
        })
        .await
        .unwrap();
        let updated = db.get_discount(id).await.unwrap();
        assert_eq!(updated.name, "Renamed");
        assert!(!updated.active);

        db.delete_discount(id).await.unwrap();
        assert!(db.get_discount(id).await.is_err());
    }

    /// A code must identify exactly one discount, or the code a customer types
    /// is ambiguous at the moment it is used.
    #[tokio::test]
    async fn duplicate_codes_are_rejected() {
        let db = MockDb::default();
        db.insert_discount(&discount("SAVE10")).await.unwrap();
        assert!(db.insert_discount(&discount("SAVE10")).await.is_err());

        // ...but any number of code-less (phase 2 automatic) discounts coexist.
        let auto = Discount {
            code: None,
            ..discount("unused")
        };
        db.insert_discount(&auto).await.unwrap();
        db.insert_discount(&auto).await.unwrap();
    }

    /// An edit must not resurrect an exhausted campaign by writing back a stale
    /// `used_count`.
    #[tokio::test]
    async fn update_cannot_reset_used_count() {
        let db = MockDb::default();
        let u = user(&db, 1).await;
        let id = db
            .insert_discount(&Discount {
                usage_limit: Some(5),
                ..discount("SAVE10")
            })
            .await
            .unwrap();
        redeem(&db, id, u, 1).await;

        let mut edit = db.get_discount(id).await.unwrap();
        edit.used_count = 0;
        db.update_discount(&edit).await.unwrap();
        assert_eq!(db.get_discount(id).await.unwrap().used_count, 1);
    }

    #[tokio::test]
    async fn a_redemption_counts_only_once_it_settles() {
        let db = MockDb::default();
        let u = user(&db, 1).await;
        let id = db.insert_discount(&discount("SAVE10")).await.unwrap();

        // An invoice was created: the row exists but counts for nothing yet, so
        // an unpaid invoice cannot burn a campaign's stock.
        db.insert_discount_redemption(&redemption(id, u, 1))
            .await
            .unwrap();
        assert_eq!(db.get_discount(id).await.unwrap().used_count, 0);
        assert_eq!(db.count_discount_redemptions(id, u).await.unwrap(), 0);
        assert!(db.sum_discount_redemptions(id).await.unwrap().is_empty());

        let pending = db
            .get_discount_redemption_by_payment(&vec![1; 32])
            .await
            .unwrap()
            .expect("row exists");
        assert!(!pending.settled);
        assert!(pending.settled_at.is_none());

        // A payment carries one discount: a repeat insert is a no-op, which is
        // the no-stacking rule.
        db.insert_discount_redemption(&DiscountRedemption {
            amount_off: 9_999,
            ..redemption(id, u, 1)
        })
        .await
        .unwrap();
        assert_eq!(
            db.get_discount_redemption_by_payment(&vec![1; 32])
                .await
                .unwrap()
                .unwrap()
                .amount_off,
            1_000
        );

        let settled = db
            .settle_discount_redemption(&vec![1; 32])
            .await
            .unwrap()
            .expect("settles");
        assert!(settled.settled);
        assert_eq!(db.get_discount(id).await.unwrap().used_count, 1);
        assert_eq!(db.count_discount_redemptions(id, u).await.unwrap(), 1);

        // Settlement paths are replayed; only the first call counts.
        assert!(
            db.settle_discount_redemption(&vec![1; 32])
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(db.get_discount(id).await.unwrap().used_count, 1);

        // A payment that carried no discount settles to nothing.
        assert!(
            db.settle_discount_redemption(&vec![42; 32])
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_discount_redemption_by_payment(&vec![42; 32])
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The limit is enforced when a discount is *quoted*; by settlement the
    /// customer has already paid a discounted invoice, which must be honoured.
    /// The count therefore records what really happened, and every later quote
    /// is refused because the count is at (or past) the limit.
    #[tokio::test]
    async fn settlement_records_past_the_limit_rather_than_refusing() {
        let db = MockDb::default();
        let u = user(&db, 1).await;
        let id = db
            .insert_discount(&Discount {
                usage_limit: Some(1),
                ..discount("SAVE10")
            })
            .await
            .unwrap();

        for p in 1..=2u8 {
            redeem(&db, id, u, p).await;
        }
        let after = db.get_discount(id).await.unwrap();
        assert_eq!(after.used_count, 2);
        assert!(!after.has_remaining_uses(), "no further quote can succeed");
    }

    #[tokio::test]
    async fn per_user_counts_and_listing() {
        let db = MockDb::default();
        let u1 = user(&db, 1).await;
        let u2 = user(&db, 2).await;
        let id = db.insert_discount(&discount("SAVE10")).await.unwrap();

        redeem(&db, id, u1, 1).await;
        redeem(&db, id, u1, 2).await;
        redeem(&db, id, u2, 3).await;

        assert_eq!(db.count_discount_redemptions(id, u1).await.unwrap(), 2);
        assert_eq!(db.count_discount_redemptions(id, u2).await.unwrap(), 1);
        assert_eq!(db.count_discount_redemptions(id, 999).await.unwrap(), 0);

        let (listed, total) = db
            .list_discount_redemptions_paginated(id, 50, 0)
            .await
            .unwrap();
        assert_eq!((listed.len(), total), (3, 3));
        // Newest first.
        assert_eq!(listed[0].subscription_payment_id, vec![3u8; 32]);
        // Pagination is a window on that order, not a re-sort.
        let (page, total) = db
            .list_discount_redemptions_paginated(id, 1, 1)
            .await
            .unwrap();
        assert_eq!((page.len(), total), (1, 3));
        assert_eq!(page[0].subscription_payment_id, vec![2u8; 32]);
        assert!(
            db.list_discount_redemptions_paginated(999, 50, 0)
                .await
                .unwrap()
                .0
                .is_empty()
        );

        // Campaign cost, per currency, settled rows only.
        assert_eq!(
            db.sum_discount_redemptions(id).await.unwrap(),
            vec![("EUR".to_string(), 3_000)]
        );
        assert!(db.sum_discount_redemptions(999).await.unwrap().is_empty());

        // Deleting would orphan the campaign's cost record.
        assert!(db.delete_discount(id).await.is_err());
    }
}

#[cfg(test)]
mod bulk_message_tests {
    use super::*;

    /// Bulk-message targeting: each filter selects the right owners, filters
    /// union and de-duplicate, and an absent target still means "everyone with
    /// a live VM".
    #[tokio::test]
    async fn bulk_message_targets_select_and_deduplicate() {
        let db = MockDb::default();

        // Two hosts in two regions.
        {
            let mut hosts = db.hosts.lock().await;
            let mut second = hosts.get(&1).unwrap().clone();
            second.id = 2;
            second.region_id = 2;
            second.name = "mock-host-2".to_string();
            hosts.insert(2, second);
        }

        let alice = db.upsert_user(&[1u8; 32]).await.unwrap();
        let bob = db.upsert_user(&[2u8; 32]).await.unwrap();
        let carol = db.upsert_user(&[3u8; 32]).await.unwrap();
        // A user with no VM at all — only reachable by explicit user id.
        let dave = db.upsert_user(&[4u8; 32]).await.unwrap();

        {
            let mut vms = db.vms.lock().await;
            // alice owns two VMs on host 1, so a host filter must not message her twice
            vms.insert(
                1,
                Vm {
                    id: 1,
                    host_id: 1,
                    user_id: alice,
                    ..Default::default()
                },
            );
            vms.insert(
                2,
                Vm {
                    id: 2,
                    host_id: 1,
                    user_id: alice,
                    ..Default::default()
                },
            );
            // bob is on host 2 (region 2)
            vms.insert(
                3,
                Vm {
                    id: 3,
                    host_id: 2,
                    user_id: bob,
                    ..Default::default()
                },
            );
            // carol's only VM is deleted, so she is not an active customer
            vms.insert(
                4,
                Vm {
                    id: 4,
                    host_id: 1,
                    user_id: carol,
                    deleted: true,
                    ..Default::default()
                },
            );
        }

        let ids = |users: Vec<User>| users.into_iter().map(|u| u.id).collect::<Vec<_>>();
        let resolve =
            async |t: BulkMessageTarget| ids(db.get_bulk_message_recipients(&t).await.unwrap());

        // No target: every user with a live VM, deleted VMs excluded.
        assert_eq!(
            resolve(BulkMessageTarget::default()).await,
            vec![alice, bob]
        );

        // Host filter: alice appears once despite owning two VMs there.
        assert_eq!(
            resolve(BulkMessageTarget {
                host_ids: Some(vec![1]),
                ..Default::default()
            })
            .await,
            vec![alice]
        );

        // Region filter goes through the host's region.
        assert_eq!(
            resolve(BulkMessageTarget {
                region_ids: Some(vec![2]),
                ..Default::default()
            })
            .await,
            vec![bob]
        );

        // VM filter selects owners; a deleted VM selects nobody.
        assert_eq!(
            resolve(BulkMessageTarget {
                vm_ids: Some(vec![3, 4]),
                ..Default::default()
            })
            .await,
            vec![bob]
        );

        // Explicit user ids need no VM.
        assert_eq!(
            resolve(BulkMessageTarget {
                user_ids: Some(vec![dave]),
                ..Default::default()
            })
            .await,
            vec![dave]
        );

        // Filters union and de-duplicate.
        assert_eq!(
            resolve(BulkMessageTarget {
                user_ids: Some(vec![alice, dave]),
                host_ids: Some(vec![1]),
                region_ids: Some(vec![2]),
                ..Default::default()
            })
            .await,
            vec![alice, bob, dave]
        );

        // A target carrying only empty lists resolves to nobody, never to all.
        assert!(
            resolve(BulkMessageTarget {
                host_ids: Some(vec![]),
                ..Default::default()
            })
            .await
            .is_empty()
        );
    }
}

#[cfg(test)]
mod vm_traffic_tests {
    use super::*;
    use lnvps_db::LNVpsDbBase;

    fn day(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).expect("valid date")
    }

    /// Traffic is additive: the worker only ever knows the increment since its
    /// last pass, so two writes on the same day must sum rather than replace.
    #[tokio::test]
    async fn vm_traffic_accumulates_per_day() {
        let db = MockDb::default();
        let d = day(2026, 8, 24);

        db.add_vm_traffic(1, d, 100, 200).await.unwrap();
        db.add_vm_traffic(1, d, 50, 25).await.unwrap();

        let rows = db.list_vm_traffic(1, d, d).await.unwrap();
        assert_eq!(rows.len(), 1, "one row per (vm, day)");
        assert_eq!(rows[0].bytes_in, 150);
        assert_eq!(rows[0].bytes_out, 225);
    }

    /// Rows are per VM and per day, ordered oldest first, and a range excludes
    /// days outside it.
    #[tokio::test]
    async fn vm_traffic_listing_is_scoped_and_ordered() {
        let db = MockDb::default();

        db.add_vm_traffic(1, day(2026, 8, 23), 1, 10).await.unwrap();
        db.add_vm_traffic(1, day(2026, 8, 24), 2, 20).await.unwrap();
        db.add_vm_traffic(1, day(2026, 8, 25), 4, 40).await.unwrap();
        // Another VM's traffic must never leak into this VM's usage.
        db.add_vm_traffic(2, day(2026, 8, 24), 99, 99)
            .await
            .unwrap();

        let rows = db
            .list_vm_traffic(1, day(2026, 8, 23), day(2026, 8, 24))
            .await
            .unwrap();
        assert_eq!(
            rows.iter().map(|r| r.day).collect::<Vec<_>>(),
            vec![day(2026, 8, 23), day(2026, 8, 24)]
        );

        let total = db
            .get_vm_traffic_total(1, day(2026, 8, 23), day(2026, 8, 24))
            .await
            .unwrap();
        assert_eq!(total, (3, 30));
    }

    /// A VM with nothing recorded reads as zero, not as an error or a missing
    /// row: an unmetered or brand-new VM still has to render a usage figure.
    #[tokio::test]
    async fn vm_traffic_total_of_nothing_is_zero() {
        let db = MockDb::default();
        let total = db
            .get_vm_traffic_total(404, day(2026, 8, 1), day(2026, 8, 31))
            .await
            .unwrap();
        assert_eq!(total, (0, 0));
        assert!(
            db.list_vm_traffic(404, day(2026, 8, 1), day(2026, 8, 31))
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// The counter baseline is one row per VM, overwritten each pass, and
    /// absent until the first sample is taken.
    #[tokio::test]
    async fn vm_traffic_sample_is_replaced_not_appended() {
        let db = MockDb::default();
        assert!(db.get_vm_traffic_sample(1).await.unwrap().is_none());

        db.upsert_vm_traffic_sample(1, 10, 20).await.unwrap();
        db.upsert_vm_traffic_sample(1, 30, 40).await.unwrap();

        let s = db.get_vm_traffic_sample(1).await.unwrap().expect("sampled");
        assert_eq!(s.last_bytes_in, 30);
        assert_eq!(s.last_bytes_out, 40);
        assert!(db.get_vm_traffic_sample(2).await.unwrap().is_none());
    }

    /// Insert `n` VMs (ids 1..=n) so traffic rows have an owner to join to,
    /// mirroring the `vm` join the MySQL implementation does.
    async fn with_vms(db: &MockDb, n: u64) {
        // insert_vm validates the owning user exists.
        db.upsert_user(&[1u8; 32]).await.expect("user");
        for _ in 0..n {
            db.insert_vm(&Vm {
                ssh_key_id: None,
                ..MockDb::mock_vm()
            })
            .await
            .expect("insert vm");
        }
    }

    /// The fleet report answers "who is pushing the traffic", so it must rank
    /// by outbound bytes and total each VM's days into one row.
    #[tokio::test]
    async fn traffic_totals_rank_the_heaviest_senders() {
        let db = MockDb::default();
        with_vms(&db, 3).await;
        let (start, end) = (day(2026, 8, 1), day(2026, 8, 31));

        // VM 1 is the heaviest sender, but only once its two days are summed.
        db.add_vm_traffic(1, day(2026, 8, 1), 10, 600)
            .await
            .unwrap();
        db.add_vm_traffic(1, day(2026, 8, 2), 10, 600)
            .await
            .unwrap();
        db.add_vm_traffic(2, day(2026, 8, 2), 99, 900)
            .await
            .unwrap();
        // Outside the range, so it must not appear at all.
        db.add_vm_traffic(3, day(2026, 7, 30), 1, 5_000)
            .await
            .unwrap();

        let (rows, total) = db.list_vm_traffic_totals(start, end, 50, 0).await.unwrap();
        assert_eq!(total, 2, "only VMs with traffic in range are counted");
        assert_eq!(rows[0].vm_id, 1);
        assert_eq!(rows[0].bytes_out, 1_200, "a VM's days must be summed");
        assert_eq!(rows[1].vm_id, 2);
        assert_eq!(rows[1].bytes_out, 900);
    }

    /// Paging must be stable and reflect the same ordering.
    #[tokio::test]
    async fn traffic_totals_paginate() {
        let db = MockDb::default();
        with_vms(&db, 3).await;
        let (start, end) = (day(2026, 8, 1), day(2026, 8, 31));
        for (vm, out) in [(1u64, 300u64), (2, 200), (3, 100)] {
            db.add_vm_traffic(vm, day(2026, 8, 5), 1, out)
                .await
                .unwrap();
        }

        let (page1, total) = db.list_vm_traffic_totals(start, end, 2, 0).await.unwrap();
        let (page2, _) = db.list_vm_traffic_totals(start, end, 2, 2).await.unwrap();
        assert_eq!(total, 3, "total counts VMs, not the rows on this page");
        assert_eq!(
            page1.iter().map(|r| r.vm_id).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(page2.iter().map(|r| r.vm_id).collect::<Vec<_>>(), vec![3]);
    }

    /// Traffic for a VM that no longer exists cannot be attributed to anyone,
    /// matching the join the MySQL implementation uses.
    #[tokio::test]
    async fn traffic_totals_skip_vms_that_are_gone() {
        let db = MockDb::default();
        db.add_vm_traffic(999, day(2026, 8, 5), 1, 1).await.unwrap();
        let (rows, total) = db
            .list_vm_traffic_totals(day(2026, 8, 1), day(2026, 8, 31), 50, 0)
            .await
            .unwrap();
        assert!(rows.is_empty());
        assert_eq!(total, 0);
    }
}

#[cfg(test)]
mod vpn_tests {
    use super::*;
    use lnvps_db::LNVpsDbBase;

    /// Every service is sold by a company, so one has to exist first.
    async fn a_company(db: &MockDb) -> u64 {
        db.companies.lock().await.entry(1).or_insert(Company {
            id: 1,
            name: "LNVPS".to_string(),
            base_currency: "EUR".to_string(),
            ..Default::default()
        });
        1
    }

    /// A service with a block, and a paid plan on it, which is the starting
    /// point for everything below.
    async fn vpn_service(db: &MockDb) -> u64 {
        let company_id = a_company(db).await;
        db.insert_vpn_service(&VpnService {
            name: "eu".to_string(),
            company_id,
            currency: "EUR".to_string(),
            default_device_limit: 5,
            enabled: true,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    /// A subscription line item in the given billing state, for a fresh user.
    async fn billed_line_item(
        db: &MockDb,
        seed: u8,
        is_active: bool,
        is_setup: bool,
        expires: Option<DateTime<Utc>>,
    ) -> (u64, u64) {
        let uid = db.upsert_user(&[seed; 32]).await.unwrap();
        let sub = Subscription {
            id: 0,
            user_id: uid,
            company_id: 1,
            name: "vpn".to_string(),
            description: None,
            created: Utc::now(),
            expires,
            is_active,
            is_setup,
            currency: "EUR".to_string(),
            interval_amount: 1,
            interval_type: lnvps_db::IntervalType::Month,
            setup_fee: 0,
            auto_renewal_enabled: false,
            external_id: None,
        };
        let (_, items) = db
            .insert_subscription_with_line_items(
                &sub,
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: lnvps_db::LineItemType::Vps,
                    name: "vpn".to_string(),
                    description: None,
                    amount: 500,
                    setup_amount: 0,
                    configuration: None,
                }],
            )
            .await
            .unwrap();
        (uid, items[0])
    }

    /// A plan on `service` for a fresh user, paid and unexpired.
    async fn paid_plan(db: &MockDb, seed: u8, service_id: u64) -> u64 {
        let (uid, line_item) = billed_line_item(db, seed, true, true, None).await;
        db.insert_vpn_subscription(&VpnSubscription {
            vpn_service_id: service_id,
            user_id: uid,
            subscription_line_item_id: line_item,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    /// A device is a link from a plan to a peer, so a peer has to exist first.
    async fn device(db: &MockDb, plan: u64, slot: u8, seed: u8) -> VpnDevice {
        let user_id = db
            .vpn_subscriptions
            .lock()
            .await
            .get(&plan)
            .map(|p| p.user_id)
            .unwrap_or(1);
        let tunnel_id = db
            .insert_tunnel(&Tunnel {
                kind: lnvps_db::RouterTunnelKind::Wireguard,
                user_id,
                name: format!("vpn-{plan}-{slot}"),
                peer_pubkey: Some(vec![seed; 32]),
                address4: Some(format!("10.64.0.{seed}/32")),
                enabled: true,
                ..Default::default()
            })
            .await
            .unwrap();
        VpnDevice {
            vpn_subscription_id: plan,
            slot,
            name: format!("device-{seed}"),
            tunnel_id,
            ..Default::default()
        }
    }

    /// A service has no block of its own: a device is addressed from the block
    /// on the interfaces terminating it, like every other peer. What is
    /// specific to a VPN is that they all carry the same one, which is enforced
    /// when a pool is linked.
    #[tokio::test]
    async fn every_interface_on_a_service_shares_one_block() {
        let db = MockDb::default();
        let service = vpn_service(&db).await;

        let mut pools = db.tunnel_pools.lock().await;
        for (id, cidr) in [
            (1u64, "10.64.0.0/12"),
            (2, "10.64.0.0/12"),
            (3, "10.99.0.0/16"),
        ] {
            pools.insert(
                id,
                TunnelPool {
                    id,
                    cidr4: Some(cidr.to_string()),
                    ..Default::default()
                },
            );
        }
        drop(pools);

        db.link_vpn_service_pool(service, 1).await.unwrap();
        db.link_vpn_service_pool(service, 2)
            .await
            .expect("a second interface with the same block is fine");
        let err = db
            .link_vpn_service_pool(service, 3)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot terminate VPN service"), "{err}");

        // And the same from the other side: a linked pool's block cannot be
        // edited away from its siblings'.
        let mut drifting = db.get_tunnel_pool(1).await.unwrap();
        drifting.cidr4 = Some("10.99.0.0/16".to_string());
        drifting.listen_port = 51821;
        let err = db
            .update_tunnel_pool(&drifting)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("must stay the same"), "{err}");
    }

    /// Disabling a service stops sales without touching what is allocated.
    #[tokio::test]
    async fn a_service_can_be_taken_off_sale() {
        let db = MockDb::default();
        let id = vpn_service(&db).await;
        assert_eq!(db.list_vpn_services(true).await.unwrap().len(), 1);

        let mut svc = db.get_vpn_service(id).await.unwrap();
        svc.enabled = false;
        svc.name = "eu-closed".to_string();
        db.update_vpn_service(&svc).await.unwrap();
        assert!(db.list_vpn_services(true).await.unwrap().is_empty());
        assert_eq!(db.list_vpn_services(false).await.unwrap().len(), 1);
        assert_eq!(db.get_vpn_service(id).await.unwrap().name, "eu-closed");
    }

    /// Deleting a service out from under a pool or a customer would strand
    /// every device addressed from its block.
    #[tokio::test]
    async fn a_vpn_service_in_use_cannot_be_deleted() {
        let db = MockDb::default();
        let service = vpn_service(&db).await;

        let plan = paid_plan(&db, 1, service).await;
        assert!(
            db.delete_vpn_service(service).await.is_err(),
            "a service with subscriptions is still owed to somebody"
        );

        // An interface, on the other hand, does not block: the link row is pure
        // association and cascades away with the service. What is owed to
        // somebody is the subscription, not the row that says where they connect.
        db.tunnel_pools.lock().await.insert(
            1,
            TunnelPool {
                id: 1,
                ..Default::default()
            },
        );
        db.link_vpn_service_pool(service, 1).await.unwrap();
        assert!(
            db.delete_vpn_service(service).await.is_err(),
            "the subscription still blocks, and the refusal must not have unlinked anything"
        );
        assert_eq!(
            db.get_vpn_service_for_pool(1).await.unwrap().map(|s| s.id),
            Some(service),
            "a delete that was refused must not have had side effects"
        );

        db.vpn_subscriptions.lock().await.remove(&plan);
        db.delete_vpn_service(service).await.unwrap();
        assert!(db.get_vpn_service(service).await.is_err());
        assert!(
            db.get_vpn_service_for_pool(1).await.unwrap().is_none(),
            "and the link cascaded away with it"
        );
    }

    /// A pool does not record what it is for, so the link is the only thing
    /// that says an interface carries devices rather than per-node links. One
    /// interface terminates at most one service: two peer sets on one interface
    /// would reconcile against each other, each removing the other's peers.
    #[tokio::test]
    async fn an_interface_terminates_at_most_one_service() {
        let db = MockDb::default();
        let a = vpn_service(&db).await;
        let b = db
            .insert_vpn_service(&VpnService {
                name: "b".to_string(),
                company_id: a_company(&db).await,
                ..Default::default()
            })
            .await
            .unwrap();
        for id in [1u64, 2] {
            db.tunnel_pools.lock().await.insert(
                id,
                TunnelPool {
                    id,
                    ..Default::default()
                },
            );
        }

        // An unlinked pool is a marketplace pool and behaves as it always has.
        assert!(db.get_vpn_service_for_pool(1).await.unwrap().is_none());

        db.link_vpn_service_pool(a, 1).await.unwrap();
        db.link_vpn_service_pool(a, 2).await.unwrap();
        assert_eq!(
            db.get_vpn_service_for_pool(1).await.unwrap().map(|s| s.id),
            Some(a)
        );
        assert_eq!(
            db.list_vpn_service_pools(a)
                .await
                .unwrap()
                .iter()
                .map(|p| p.id)
                .collect::<Vec<_>>(),
            vec![1, 2],
            "every interface on a service carries the same device peer set"
        );

        // Repointing replaces the link rather than adding a second one.
        db.link_vpn_service_pool(b, 2).await.unwrap();
        assert_eq!(
            db.get_vpn_service_for_pool(2).await.unwrap().map(|s| s.id),
            Some(b)
        );
        assert_eq!(
            db.list_vpn_service_pools(a)
                .await
                .unwrap()
                .iter()
                .map(|p| p.id)
                .collect::<Vec<_>>(),
            vec![1]
        );

        // Neither side may be invented.
        assert!(db.link_vpn_service_pool(9999, 1).await.is_err());
        assert!(db.link_vpn_service_pool(a, 9999).await.is_err());

        // A service nothing terminates has no interfaces, not an error.
        assert!(db.list_vpn_service_pools(9999).await.unwrap().is_empty());
    }

    /// One plan per account, and a lapsed customer coming back reuses the row
    /// rather than getting a second one — which is what keeps their existing
    /// device configs working once they pay.
    #[tokio::test]
    async fn one_vpn_plan_per_account() {
        let db = MockDb::default();
        let service = vpn_service(&db).await;
        let plan = paid_plan(&db, 1, service).await;

        let stored = db.get_vpn_subscription(plan).await.unwrap();
        assert_eq!(
            db.get_vpn_subscription_for_user(stored.user_id)
                .await
                .unwrap()
                .map(|s| s.id),
            Some(plan)
        );
        assert_eq!(
            db.get_vpn_subscription_by_line_item(stored.subscription_line_item_id)
                .await
                .unwrap()
                .map(|s| s.id),
            Some(plan)
        );
        // Nobody else's account, and nobody else's line item.
        assert!(
            db.get_vpn_subscription_for_user(stored.user_id + 999)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_vpn_subscription_by_line_item(9999)
                .await
                .unwrap()
                .is_none()
        );

        // A second plan for the same account is rejected.
        let (_, other_item) = billed_line_item(&db, 2, true, true, None).await;
        assert!(
            db.insert_vpn_subscription(&VpnSubscription {
                vpn_service_id: service,
                user_id: stored.user_id,
                subscription_line_item_id: other_item,
                ..Default::default()
            })
            .await
            .is_err()
        );

        // And a second plan cannot claim a line item that already bills for one.
        let fresh = db.upsert_user(&[9u8; 32]).await.unwrap();
        assert!(
            db.insert_vpn_subscription(&VpnSubscription {
                vpn_service_id: service,
                user_id: fresh,
                subscription_line_item_id: stored.subscription_line_item_id,
                ..Default::default()
            })
            .await
            .is_err()
        );
    }

    /// Resubscribing repoints the plan at the new line item and can resize the
    /// tier, but must not be able to move it to another service: the devices'
    /// addresses are carved from the one it has.
    #[tokio::test]
    async fn a_vpn_plan_is_repointed_not_moved() {
        let db = MockDb::default();
        let service = vpn_service(&db).await;
        let other_service = db
            .insert_vpn_service(&VpnService {
                name: "other".to_string(),
                company_id: a_company(&db).await,
                ..Default::default()
            })
            .await
            .unwrap();
        let plan = paid_plan(&db, 1, service).await;
        let original = db.get_vpn_subscription(plan).await.unwrap();

        let (_, renewed_item) = billed_line_item(&db, 2, true, true, None).await;
        db.update_vpn_subscription(&VpnSubscription {
            id: plan,
            vpn_service_id: other_service,
            user_id: 4242,
            subscription_line_item_id: renewed_item,
            created: Utc::now(),
        })
        .await
        .unwrap();

        let after = db.get_vpn_subscription(plan).await.unwrap();
        assert_eq!(after.subscription_line_item_id, renewed_item);
        assert_eq!(after.vpn_service_id, original.vpn_service_id);
        assert_eq!(after.user_id, original.user_id);
        assert_eq!(after.created, original.created);

        // A renewal cannot steal another plan's line item.
        let second = paid_plan(&db, 3, service).await;
        let mut clash = db.get_vpn_subscription(second).await.unwrap();
        clash.subscription_line_item_id = renewed_item;
        assert!(db.update_vpn_subscription(&clash).await.is_err());
    }

    /// The device limit has to be unforgeable: counting rows and then inserting
    /// is a race two concurrent registrations win together, so the slot is what
    /// the cap is actually made of.
    ///
    /// Key and address uniqueness is not tested here any more: a device is a
    /// peer, a peer is a `tunnel`, and `uk_tunnel_peer_pubkey` and
    /// `uk_tunnel_address4` cover every peer LNVPS terminates rather than only
    /// the VPN ones.
    #[tokio::test]
    async fn a_device_slot_cannot_be_claimed_twice() {
        let db = MockDb::default();
        let service = vpn_service(&db).await;
        let plan = paid_plan(&db, 1, service).await;

        db.insert_vpn_device(&device(&db, plan, 0, 1).await)
            .await
            .unwrap();
        assert!(
            db.insert_vpn_device(&device(&db, plan, 0, 2).await)
                .await
                .is_err(),
            "two devices in one slot is a sixth device on a five-device plan"
        );

        // A tunnel terminates one peer, so two devices cannot share one.
        let first = db.list_vpn_devices(plan).await.unwrap()[0].clone();
        assert!(
            db.insert_vpn_device(&VpnDevice {
                slot: 1,
                tunnel_id: first.tunnel_id,
                ..device(&db, plan, 1, 3).await
            })
            .await
            .is_err()
        );

        // The slot is per plan, so another customer's slot 0 is free.
        let other = paid_plan(&db, 2, service).await;
        db.insert_vpn_device(&device(&db, other, 0, 6).await)
            .await
            .unwrap();

        // Neither a plan nor a peer may be invented.
        assert!(
            db.insert_vpn_device(&device(&db, 9999, 0, 7).await)
                .await
                .is_err()
        );
        assert!(
            db.insert_vpn_device(&VpnDevice {
                tunnel_id: 9999,
                ..device(&db, plan, 2, 8).await
            })
            .await
            .is_err()
        );
    }

    /// Suspension is not a write. A plan that is unpaid, deactivated or expired
    /// simply stops matching, so its devices leave the peer set on the next
    /// reconcile and come back when it is paid, with nothing having had to
    /// remember to toggle them.
    #[tokio::test]
    async fn only_paid_plans_are_configured() {
        let db = MockDb::default();
        let service = vpn_service(&db).await;

        let paid = paid_plan(&db, 1, service).await;
        db.insert_vpn_device(&device(&db, paid, 0, 1).await)
            .await
            .unwrap();

        // Never paid.
        let (uid, item) = billed_line_item(&db, 2, true, false, None).await;
        let unpaid = db
            .insert_vpn_subscription(&VpnSubscription {
                vpn_service_id: service,
                user_id: uid,
                subscription_line_item_id: item,
                ..Default::default()
            })
            .await
            .unwrap();
        db.insert_vpn_device(&device(&db, unpaid, 0, 2).await)
            .await
            .unwrap();

        // Paid once, then lapsed.
        let (uid, item) =
            billed_line_item(&db, 3, true, true, Some(Utc::now() - TimeDelta::days(1))).await;
        let expired = db
            .insert_vpn_subscription(&VpnSubscription {
                vpn_service_id: service,
                user_id: uid,
                subscription_line_item_id: item,
                ..Default::default()
            })
            .await
            .unwrap();
        db.insert_vpn_device(&device(&db, expired, 0, 3).await)
            .await
            .unwrap();

        // Cancelled by an admin.
        let (uid, item) = billed_line_item(&db, 4, false, true, None).await;
        let cancelled = db
            .insert_vpn_subscription(&VpnSubscription {
                vpn_service_id: service,
                user_id: uid,
                subscription_line_item_id: item,
                ..Default::default()
            })
            .await
            .unwrap();
        db.insert_vpn_device(&device(&db, cancelled, 0, 4).await)
            .await
            .unwrap();

        let active = db.list_active_vpn_tunnels(service).await.unwrap();
        assert_eq!(
            active
                .iter()
                .map(|t| t.peer_pubkey.as_ref().unwrap()[0])
                .collect::<Vec<_>>(),
            vec![1],
            "only the paid, unexpired, active plan is configured"
        );

        // A peer the customer switched off is theirs to switch off, and is
        // dropped for a different reason than non-payment.
        let mut t = active[0].clone();
        t.enabled = false;
        db.update_tunnel(&t).await.unwrap();
        assert!(
            db.list_active_vpn_tunnels(service)
                .await
                .unwrap()
                .is_empty()
        );

        // And another service's peers are not this one's.
        assert!(db.list_active_vpn_tunnels(9999).await.unwrap().is_empty());
    }

    /// A device row carries only the customer's label; its slot, its plan and
    /// the peer it points at are what their config already depends on.
    #[tokio::test]
    async fn renaming_a_device_leaves_everything_else_alone() {
        let db = MockDb::default();
        let service = vpn_service(&db).await;
        let plan = paid_plan(&db, 1, service).await;
        let id = db
            .insert_vpn_device(&device(&db, plan, 0, 1).await)
            .await
            .unwrap();
        let before = db.get_vpn_device(id).await.unwrap();

        db.update_vpn_device(&VpnDevice {
            id,
            vpn_subscription_id: 9999,
            slot: 4,
            name: "laptop".to_string(),
            tunnel_id: 9999,
            created: Utc::now(),
        })
        .await
        .unwrap();

        let after = db.get_vpn_device(id).await.unwrap();
        assert_eq!(after.name, "laptop");
        assert_eq!(after.tunnel_id, before.tunnel_id, "the peer must not move");
        assert_eq!(after.slot, before.slot);
        assert_eq!(after.vpn_subscription_id, before.vpn_subscription_id);
        assert_eq!(after.created, before.created);

        // The peer's key is how a route server's observed peer is resolved back
        // to the customer it belongs to.
        assert_eq!(
            db.get_vpn_device_by_pubkey(&[1u8; 32])
                .await
                .unwrap()
                .map(|d| d.id),
            Some(id)
        );
        assert!(
            db.get_vpn_device_by_pubkey(&[42u8; 32])
                .await
                .unwrap()
                .is_none()
        );

        // Listing is in slot order, and includes devices whose peer is disabled
        // because a disabled peer still owns its slot and its address.
        db.insert_vpn_device(&device(&db, plan, 1, 7).await)
            .await
            .unwrap();
        let listed = db.list_vpn_devices(plan).await.unwrap();
        assert_eq!(
            listed.iter().map(|d| d.slot).collect::<Vec<_>>(),
            vec![0, 1]
        );

        db.delete_vpn_device(id).await.unwrap();
        assert!(db.get_vpn_device(id).await.is_err());
        assert_eq!(db.list_vpn_devices(plan).await.unwrap().len(), 1);

        // Updating something that is gone is an error, not a silent insert.
        assert!(db.update_vpn_device(&before).await.is_err());
    }

    /// The routes behind a peer are a set, replaced wholesale, because the
    /// planner is told what should be there rather than what changed.
    #[tokio::test]
    async fn tunnel_routes_are_replaced_not_merged() {
        let db = MockDb::default();
        let service = vpn_service(&db).await;
        let plan = paid_plan(&db, 1, service).await;
        let d = device(&db, plan, 0, 1).await;
        db.insert_vpn_device(&d).await.unwrap();

        db.replace_tunnel_routes(
            d.tunnel_id,
            &["203.0.113.0/24".to_string(), "198.51.100.5/32".to_string()],
        )
        .await
        .unwrap();
        let routes = db.list_tunnel_routes(&[d.tunnel_id]).await.unwrap();
        assert_eq!(
            routes.iter().map(|r| r.prefix.as_str()).collect::<Vec<_>>(),
            vec!["198.51.100.5/32", "203.0.113.0/24"]
        );

        // Replacing with a shorter set drops what is no longer behind the peer,
        // which is what stops a released address staying routed.
        db.replace_tunnel_routes(d.tunnel_id, &["203.0.113.0/24".to_string()])
            .await
            .unwrap();
        assert_eq!(
            db.list_tunnel_routes(&[d.tunnel_id]).await.unwrap().len(),
            1
        );

        db.replace_tunnel_routes(d.tunnel_id, &[]).await.unwrap();
        assert!(
            db.list_tunnel_routes(&[d.tunnel_id])
                .await
                .unwrap()
                .is_empty()
        );

        // Nothing to fetch for a peer nobody asked about, and no such peer.
        assert!(db.list_tunnel_routes(&[]).await.unwrap().is_empty());
        assert!(db.replace_tunnel_routes(9999, &[]).await.is_err());
    }
}
