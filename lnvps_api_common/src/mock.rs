use crate::{ExchangeRateService, Ticker, TickerRate};
use anyhow::{Context, anyhow};
use chrono::{Days, Months, TimeDelta, Utc};
use lnvps_db::nostr::LNVPSNostrDb;
use lnvps_db::{
    AccessPolicy, AvailableIpSpace, Company, CpuArch, CpuMfg, DbError, DbResult, DiskInterface,
    DiskType, DnsServer, DnsServerKind, IntervalType, IpRange, IpRangeAllocationMode,
    IpRangeSubscription, IpSpacePricing, LNVpsDbBase, NostrDomain, NostrDomainHandle,
    OsDistribution, PaymentMethod, PaymentMethodConfig, Referral, ReferralCostUsage,
    ReferralPayout, Router, RouterBgpRoute, RouterBgpSession, RouterTunnel, RouterTunnelTraffic,
    Subscription, SubscriptionLineItem, SubscriptionPayment, SubscriptionPaymentWithCompany, User,
    UserPaymentMethod, UserSshKey, Vm, VmCostPlan, VmCustomPricing, VmCustomPricingDisk,
    VmCustomTemplate,
    VmFirewallPolicy, VmFirewallRule, VmHistory, VmHost, VmHostDisk, VmHostKind, VmHostRegion,
    VmIpAssignment, VmOsImage, VmPayment, VmTemplate,
};

use async_trait::async_trait;
#[cfg(feature = "admin")]
use lnvps_db::{AdminRole, AdminRoleAssignment, AdminUserInfo, AdminVmHost, RegionStats};
use std::collections::HashMap;
use std::ops::Add;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct MockDb {
    pub regions: Arc<Mutex<HashMap<u64, VmHostRegion>>>,
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
    pub payments: Arc<Mutex<Vec<VmPayment>>>,
    pub router: Arc<Mutex<HashMap<u64, Router>>>,
    pub dns_servers: Arc<Mutex<HashMap<u64, DnsServer>>>,
    pub access_policy: Arc<Mutex<HashMap<u64, AccessPolicy>>>,
    pub companies: Arc<Mutex<HashMap<u64, Company>>>,
    pub vm_history: Arc<Mutex<HashMap<u64, VmHistory>>>,
    pub subscriptions: Arc<Mutex<HashMap<u64, Subscription>>>,
    pub subscription_line_items: Arc<Mutex<HashMap<u64, SubscriptionLineItem>>>,
    pub subscription_payments: Arc<Mutex<Vec<SubscriptionPayment>>>,
    pub ip_range_subscriptions: Arc<Mutex<HashMap<u64, IpRangeSubscription>>>,
    pub payment_method_configs: Arc<Mutex<HashMap<u64, PaymentMethodConfig>>>,
    pub referrals: Arc<Mutex<HashMap<u64, Referral>>>,
    pub referral_payouts: Arc<Mutex<Vec<ReferralPayout>>>,
    pub router_tunnels: Arc<Mutex<HashMap<u64, RouterTunnel>>>,
    pub router_tunnel_traffic: Arc<Mutex<Vec<RouterTunnelTraffic>>>,
    pub router_bgp_sessions: Arc<Mutex<HashMap<u64, RouterBgpSession>>>,
    pub router_bgp_routes: Arc<Mutex<HashMap<u64, RouterBgpRoute>>>,
    pub firewall_rules: Arc<Mutex<HashMap<u64, VmFirewallRule>>>,
}

impl MockDb {
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
            disk_iops_read: None,
            disk_iops_write: None,
            disk_mbps_read: None,
            disk_mbps_write: None,
            network_mbps: None,
            cpu_limit: None,
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
            deleted: false,
            ref_code: None,
            disabled: false,
            fw_policy_in: None,
            fw_policy_out: None,
        }
    }
}

impl Default for MockDb {
    fn default() -> Self {
        let mut regions = HashMap::new();
        regions.insert(
            1,
            VmHostRegion {
                id: 1,
                name: "Mock".to_string(),
                enabled: true,
                company_id: 1, // Link to default company
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
                default_username: None,
                sha2: None,
                sha2_url: None,
            },
        );
        Self {
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
            payments: Arc::new(Default::default()),
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
                        subscription_type: lnvps_db::SubscriptionType::Vps,
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
            payment_method_configs: Arc::new(Default::default()),
            referrals: Arc::new(Default::default()),
            referral_payouts: Arc::new(Default::default()),
            router_tunnels: Arc::new(Default::default()),
            router_tunnel_traffic: Arc::new(Default::default()),
            router_bgp_sessions: Arc::new(Default::default()),
            router_bgp_routes: Arc::new(Default::default()),
            firewall_rules: Arc::new(Default::default()),
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
            u.contact_email = user.contact_email;
            u.contact_nip17 = user.contact_nip17;
            u.contact_telegram = user.contact_telegram;
            u.telegram_chat_id = user.telegram_chat_id;
            u.telegram_link_token = user.telegram_link_token.clone();
            u.contact_whatsapp = user.contact_whatsapp;
            u.whatsapp_number = user.whatsapp_number.clone();
            u.whatsapp_verified = user.whatsapp_verified;
            u.whatsapp_verify_code = user.whatsapp_verify_code.clone();
        }
        Ok(())
    }

    async fn delete_user(&self, id: u64) -> DbResult<()> {
        let mut users = self.users.lock().await;
        users.remove(&id);
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

    async fn list_host_region(&self) -> DbResult<Vec<VmHostRegion>> {
        let regions = self.regions.lock().await;
        Ok(regions.values().filter(|r| r.enabled).cloned().collect())
    }

    async fn get_host_region(&self, id: u64) -> DbResult<VmHostRegion> {
        let regions = self.regions.lock().await;
        Ok(regions.get(&id).ok_or(anyhow!("no region"))?.clone())
    }

    async fn get_host_region_by_name(&self, name: &str) -> DbResult<VmHostRegion> {
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
        Ok(hosts.values().filter(|h| h.enabled).cloned().collect())
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
    ) -> DbResult<(Vec<(VmHost, VmHostRegion)>, u64)> {
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
            h.enabled = host.enabled;
            h.cpu = host.cpu;
            h.memory = host.memory;
        }
        Ok(())
    }

    async fn create_host(&self, host: &VmHost) -> DbResult<u64> {
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

    async fn delete_vm(&self, vm_id: u64) -> DbResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(vm) = vms.get_mut(&vm_id) {
            vm.deleted = true;
            vm.ssh_key_id = None;
        }
        Ok(())
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

    async fn get_vm_by_line_item(&self, line_item_id: u64) -> DbResult<Vm> {
        let vms = self.vms.lock().await;
        vms.values()
            .find(|v| v.subscription_line_item_id == line_item_id && !v.deleted)
            .cloned()
            .ok_or_else(|| anyhow!("VM not found for line item {}", line_item_id).into())
    }

    async fn get_vm_by_subscription(&self, subscription_id: u64) -> DbResult<Vm> {
        use lnvps_db::SubscriptionType;
        let items = self.subscription_line_items.lock().await;
        let line_item_id = items
            .values()
            .find(|li| {
                li.subscription_id == subscription_id
                    && matches!(li.subscription_type, SubscriptionType::Vps)
            })
            .map(|li| li.id)
            .ok_or_else(|| {
                DbError::Other(anyhow!(
                    "No VM line item for subscription {}",
                    subscription_id
                ))
            })?;
        drop(items);
        self.get_vm_by_line_item(line_item_id).await
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

    async fn list_vm_payment(&self, vm_id: u64) -> DbResult<Vec<VmPayment>> {
        let p = self.payments.lock().await;
        Ok(p.iter().filter(|p| p.vm_id == vm_id).cloned().collect())
    }

    async fn list_vm_payment_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<Vec<VmPayment>> {
        let p = self.payments.lock().await;
        let mut filtered: Vec<_> = p.iter().filter(|p| p.vm_id == vm_id).cloned().collect();
        filtered.sort_by(|a, b| b.created.cmp(&a.created));
        Ok(filtered
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn list_vm_payment_by_method_and_type(
        &self,
        vm_id: u64,
        method: lnvps_db::PaymentMethod,
        payment_type: lnvps_db::PaymentType,
    ) -> DbResult<Vec<VmPayment>> {
        let p = self.payments.lock().await;
        let mut filtered: Vec<_> = p
            .iter()
            .filter(|p| {
                p.vm_id == vm_id
                    && p.payment_method == method
                    && p.payment_type == payment_type
                    && p.expires > Utc::now()
                    && !p.is_paid
            })
            .cloned()
            .collect();
        filtered.sort_by(|a, b| b.created.cmp(&a.created));
        Ok(filtered)
    }

    async fn insert_vm_payment(&self, vm_payment: &VmPayment) -> DbResult<()> {
        let mut p = self.payments.lock().await;
        p.push(vm_payment.clone());
        Ok(())
    }

    async fn get_vm_payment(&self, id: &Vec<u8>) -> DbResult<VmPayment> {
        let p = self.payments.lock().await;
        Ok(p.iter()
            .find(|p| p.id == *id)
            .context("no vm_payment")?
            .clone())
    }

    async fn get_vm_payment_by_ext_id(&self, id: &str) -> DbResult<VmPayment> {
        let p = self.payments.lock().await;
        Ok(p.iter()
            .find(|p| p.external_id == Some(id.to_string()))
            .context("no vm_payment")?
            .clone())
    }

    async fn update_vm_payment(&self, vm_payment: &VmPayment) -> DbResult<()> {
        let mut p = self.payments.lock().await;
        if let Some(p) = p.iter_mut().find(|p| p.id == *vm_payment.id) {
            p.is_paid = vm_payment.is_paid;
            p.paid_at = vm_payment.paid_at;
        }
        Ok(())
    }

    async fn vm_payment_paid(&self, payment: &VmPayment) -> DbResult<()> {
        let mut p = self.payments.lock().await;
        if let Some(p) = p.iter_mut().find(|p| p.id == *payment.id) {
            p.is_paid = true;
            p.paid_at = Some(Utc::now());
        }
        // vm.expires removed — expiry is managed exclusively via subscription.expires
        Ok(())
    }

    async fn last_paid_invoice(&self) -> DbResult<Option<VmPayment>> {
        let p = self.payments.lock().await;
        Ok(p.iter()
            .filter(|p| p.is_paid)
            .max_by(|a, b| a.created.cmp(&b.created))
            .cloned())
    }

    async fn count_active_vm_payments(&self, vm_id: u64) -> DbResult<u64> {
        let p = self.payments.lock().await;
        Ok(p.iter()
            .filter(|p| p.vm_id == vm_id && !p.is_paid && p.expires > Utc::now())
            .count() as u64)
    }

    async fn list_custom_pricing(&self, _tb: u64) -> DbResult<Vec<VmCustomPricing>> {
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

    async fn get_active_customers_with_contact_prefs(&self) -> DbResult<Vec<User>> {
        let users = self.users.lock().await;
        let vms = self.vms.lock().await;

        // Find users who have non-deleted VMs and contact preferences enabled
        let mut active_customers = Vec::new();

        for user in users.values() {
            // Check if user has at least one non-deleted VM
            let has_active_vm = vms.values().any(|vm| vm.user_id == user.id && !vm.deleted);

            if has_active_vm && (user.contact_email || user.contact_nip17) {
                // For email: check if they have an email address
                // For nip17: they should have a pubkey (which all users do)
                if (user.contact_email && !user.email.is_empty()) || user.contact_nip17 {
                    active_customers.push(user.clone());
                }
            }
        }

        Ok(active_customers)
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
            company_id: 0,
            company_name: String::new(),
            company_base_currency: "EUR".to_string(),
            vm_id: None,
            host_id: None,
            host_name: None,
            region_id: None,
            region_name: None,
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
            p.is_paid = payment.is_paid;
            p.paid_at = payment.paid_at;
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

        let mut subscriptions = self.subscriptions.lock().await;
        if let Some(subscription) = subscriptions.get_mut(&payment.subscription_id) {
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
        todo!()
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
        todo!()
    }

    async fn get_available_ip_space_by_cidr(&self, cidr: &str) -> DbResult<AvailableIpSpace> {
        todo!()
    }

    async fn insert_available_ip_space(&self, space: &AvailableIpSpace) -> DbResult<u64> {
        todo!()
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
            r.lightning_address = referral.lightning_address.clone();
            r.use_nwc = referral.use_nwc;
        }
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
            p.pre_image = payout.pre_image.clone();
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
                    });
                }
            }
        }
        result.sort_by(|a, b| b.created.cmp(&a.created));
        Ok(result)
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
        _search_pubkey: Option<&str>,
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

    async fn admin_find_user_by_email_hash(
        &self,
        _hash: &[u8; 32],
    ) -> DbResult<Option<AdminUserInfo>> {
        Ok(None)
    }

    async fn admin_list_regions(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<VmHostRegion>, u64)> {
        let regions = self.regions.lock().await;
        let total = regions.len() as u64;
        let paginated_regions: Vec<VmHostRegion> = regions
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
        _name: &str,
        _enabled: bool,
        _company_id: u64,
    ) -> DbResult<u64> {
        Ok(1)
    }
    async fn admin_update_region(&self, _region: &VmHostRegion) -> DbResult<()> {
        Ok(())
    }
    async fn admin_delete_region(&self, _region_id: u64) -> DbResult<()> {
        Ok(())
    }
    async fn admin_count_region_hosts(&self, _region_id: u64) -> DbResult<u64> {
        Ok(0)
    }
    async fn admin_get_region_stats(&self, _region_id: u64) -> DbResult<RegionStats> {
        todo!()
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

    async fn insert_custom_template(&self, template: &VmCustomTemplate) -> DbResult<u64> {
        let mut template_map = self.custom_template.lock().await;
        let max_id = template_map.keys().max().unwrap_or(&0) + 1;
        let mut new_template = template.clone();
        new_template.id = max_id;
        template_map.insert(max_id, new_template);
        Ok(max_id)
    }

    async fn update_custom_template(&self, template: &VmCustomTemplate) -> DbResult<()> {
        let mut template_map = self.custom_template.lock().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) = template_map.entry(template.id)
        {
            e.insert(template.clone());
            Ok(())
        } else {
            Err(anyhow!("Custom template not found: {}", template.id).into())
        }
    }

    async fn delete_custom_template(&self, id: u64) -> DbResult<()> {
        let mut template_map = self.custom_template.lock().await;
        if template_map.remove(&id).is_some() {
            Ok(())
        } else {
            Err(anyhow!("Custom template not found: {}", id).into())
        }
    }
    async fn count_vms_by_custom_template(&self, template_id: u64) -> DbResult<u64> {
        let vm_map = self.vms.lock().await;
        let count = vm_map
            .values()
            .filter(|vm| vm.custom_template_id == Some(template_id))
            .count();
        Ok(count as u64)
    }
    async fn admin_list_companies(
        &self,
        _limit: u64,
        _offset: u64,
    ) -> DbResult<(Vec<Company>, u64)> {
        Ok((vec![], 0))
    }
    async fn admin_get_company(&self, company_id: u64) -> DbResult<Company> {
        self.get_company(company_id).await
    }
    async fn admin_create_company(&self, _company: &Company) -> DbResult<u64> {
        Ok(1)
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
                    company_id: cid,
                    company_name: company.name.clone(),
                    company_base_currency: company.base_currency.clone(),
                    vm_id,
                    host_id,
                    host_name,
                    region_id,
                    region_name,
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
    use lnvps_db::{IntervalType, LNVpsDbBase, SubscriptionPaymentType};

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
        let id1 = db.insert_user_payment_method(&mk(1, "revolut", false)).await.unwrap();
        let id2 = db.insert_user_payment_method(&mk(1, "revolut", true)).await.unwrap();
        let _id3 = db.insert_user_payment_method(&mk(1, "stripe", false)).await.unwrap();
        assert_ne!(id1, id2);

        // Provider filter + default-first ordering
        let revolut = db.list_user_payment_methods(1, Some("revolut")).await.unwrap();
        assert_eq!(revolut.len(), 2);
        assert_eq!(revolut[0].id, id2, "default method should sort first");

        // All providers for the user
        let all = db.list_user_payment_methods(1, None).await.unwrap();
        assert_eq!(all.len(), 3);

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
        assert_eq!(db.list_user_payment_methods(1, Some("revolut")).await.unwrap().len(), 1);
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
        }
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
        let res = vm_to_status(&db, vm, None).await;
        assert!(res.is_err(), "expected error, not a panic");
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
}
