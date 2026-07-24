use crate::{ExchangeRateService, Ticker, TickerRate};
use anyhow::{Context, anyhow};
use chrono::{Days, Months, TimeDelta, Utc};
use lnvps_db::nostr::LNVPSNostrDb;
use lnvps_db::{
    AccessPolicy, AsnSubscription, AsnSubscriptionStatus, AvailableIpSpace, Company, CpuArch,
    CpuMfg, DbError, DbResult, DiskInterface, DiskType, DnsServer, DnsServerKind, IntervalType,
    IpRange, IpRangeAllocationMode, IpRangeSubscription, IpSpacePricing, LNVpsDbBase, NostrDomain,
    NostrDomainHandle, OsDistribution, PaymentMethod, PaymentMethodConfig, Referral,
    ReferralCostUsage, ReferralPayout, Router, RouterBgpRoute, RouterBgpSession, RouterTunnel,
    RouterTunnelTraffic, Subscription, SubscriptionLineItem, SubscriptionPayment,
    SubscriptionPaymentWithCompany, User, UserPaymentMethod, UserSshKey, Vm, VmCostPlan,
    VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate, VmFirewallPolicy, VmFirewallRule,
    VmHistory, VmHost, VmHostDisk, VmHostKind, VmHostRegion, VmIpAssignment, VmOsImage, VmTemplate,
    WebauthnCredential,
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
    pub router: Arc<Mutex<HashMap<u64, Router>>>,
    pub dns_servers: Arc<Mutex<HashMap<u64, DnsServer>>>,
    pub access_policy: Arc<Mutex<HashMap<u64, AccessPolicy>>>,
    pub companies: Arc<Mutex<HashMap<u64, Company>>>,
    pub vm_history: Arc<Mutex<HashMap<u64, VmHistory>>>,
    pub subscriptions: Arc<Mutex<HashMap<u64, Subscription>>>,
    pub subscription_line_items: Arc<Mutex<HashMap<u64, SubscriptionLineItem>>>,
    pub subscription_payments: Arc<Mutex<Vec<SubscriptionPayment>>>,
    pub ip_range_subscriptions: Arc<Mutex<HashMap<u64, IpRangeSubscription>>>,
    pub available_ip_space: Arc<Mutex<HashMap<u64, AvailableIpSpace>>>,
    pub asn_subscriptions: Arc<Mutex<HashMap<u64, AsnSubscription>>>,
    pub payment_method_configs: Arc<Mutex<HashMap<u64, PaymentMethodConfig>>>,
    pub referrals: Arc<Mutex<HashMap<u64, Referral>>>,
    pub referral_payouts: Arc<Mutex<Vec<ReferralPayout>>>,
    pub router_tunnels: Arc<Mutex<HashMap<u64, RouterTunnel>>>,
    pub router_tunnel_traffic: Arc<Mutex<Vec<RouterTunnelTraffic>>>,
    pub router_bgp_sessions: Arc<Mutex<HashMap<u64, RouterBgpSession>>>,
    pub router_bgp_routes: Arc<Mutex<HashMap<u64, RouterBgpRoute>>>,
    pub firewall_rules: Arc<Mutex<HashMap<u64, VmFirewallRule>>>,
    pub webauthn_credentials: Arc<Mutex<HashMap<u64, WebauthnCredential>>>,
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
            admin_notes: None,
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
                sunset_date: None,
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
            available_ip_space: Arc::new(Default::default()),
            asn_subscriptions: Arc::new(Default::default()),
            payment_method_configs: Arc::new(Default::default()),
            referrals: Arc::new(Default::default()),
            referral_payouts: Arc::new(Default::default()),
            router_tunnels: Arc::new(Default::default()),
            router_tunnel_traffic: Arc::new(Default::default()),
            router_bgp_sessions: Arc::new(Default::default()),
            router_bgp_routes: Arc::new(Default::default()),
            firewall_rules: Arc::new(Default::default()),
            webauthn_credentials: Arc::new(Default::default()),
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
            u.contact_email = user.contact_email;
            u.contact_nip17 = user.contact_nip17;
            u.contact_telegram = user.contact_telegram;
            u.telegram_chat_id = user.telegram_chat_id;
            u.telegram_link_token = user.telegram_link_token.clone();
            u.contact_whatsapp = user.contact_whatsapp;
            u.whatsapp_number = user.whatsapp_number.clone();
            u.whatsapp_verified = user.whatsapp_verified;
            u.whatsapp_verify_code = user.whatsapp_verify_code.clone();
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
            p.invoice = payout.invoice.clone();
            p.pre_image = payout.pre_image.clone();
            p.outpoint = payout.outpoint.clone();
            p.fee = payout.fee;
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
                    tax_rate: payment.tax_rate,
                    tax_country_code: payment.tax_country_code.clone(),
                    tax_treatment: payment.tax_treatment.clone(),
                    tax_evidence: payment.tax_evidence.clone(),
                    tax_breakdown: payment.tax_breakdown.clone(),
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
    use lnvps_db::{IntervalType, LNVpsDbBase, SubscriptionPaymentType};

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
        let res = vm_to_status(&db, vm, None, 0, 365).await;
        assert!(res.is_err(), "expected error, not a panic");
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
        let status = vm_to_status(&db, vm.clone(), None, 0, 365).await.unwrap();
        assert!(status.host_sunset_date.is_none());

        // Sunset host 1 -> field surfaces the date.
        let sunset = Utc::now() + chrono::Duration::days(30);
        mdb.hosts.lock().await.get_mut(&1).unwrap().sunset_date = Some(sunset);
        let status = vm_to_status(&db, vm, None, 0, 365).await.unwrap();
        assert_eq!(status.host_sunset_date, Some(sunset));
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
        let status = vm_to_status(&db, vm.clone(), None, 0, 365).await.unwrap();
        assert_eq!(status.max_prepay_days, 365);

        // Company override wins over the global default.
        mdb.companies
            .lock()
            .await
            .get_mut(&1)
            .unwrap()
            .max_prepay_days = 90;
        let status = vm_to_status(&db, vm, None, 0, 365).await.unwrap();
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
                subscription_type: lnvps_db::SubscriptionType::AsnSponsoring,
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
                    subscription_type: lnvps_db::SubscriptionType::Vps,
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
