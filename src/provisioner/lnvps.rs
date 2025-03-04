use crate::dns::DnsServer;
use crate::exchange::{ExchangeRateService, Ticker};
use crate::host::{get_host_client, FullVmInfo};
use crate::lightning::{AddInvoiceRequest, LightningNode};
use crate::provisioner::{NetworkProvisioner, ProvisionerMethod};
use crate::router::Router;
use crate::settings::{NetworkAccessPolicy, NetworkPolicy, ProvisionerConfig, Settings};
use anyhow::{bail, Result};
use chrono::{Days, Months, Utc};
use futures::future::join_all;
use lnvps_db::{IpRange, LNVpsDb, Vm, VmCostPlanIntervalType, VmIpAssignment, VmPayment};
use log::{info, warn};
use nostr::util::hex;
use rand::random;
use std::collections::HashSet;
use std::net::IpAddr;
use std::ops::Add;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

/// Main provisioner class for LNVPS
///
/// Does all the hard work and logic for creating / expiring VM's
pub struct LNVpsProvisioner {
    read_only: bool,

    db: Arc<dyn LNVpsDb>,
    node: Arc<dyn LightningNode>,
    rates: Arc<dyn ExchangeRateService>,

    router: Option<Arc<dyn Router>>,
    dns: Option<Arc<dyn DnsServer>>,

    network_policy: NetworkPolicy,
    provisioner_config: ProvisionerConfig,
}

impl LNVpsProvisioner {
    pub fn new(
        settings: Settings,
        db: Arc<dyn LNVpsDb>,
        node: Arc<dyn LightningNode>,
        rates: Arc<dyn ExchangeRateService>,
    ) -> Self {
        Self {
            db,
            node,
            rates,
            router: settings.get_router().expect("router config"),
            dns: settings.get_dns().expect("dns config"),
            network_policy: settings.network_policy,
            provisioner_config: settings.provisioner,
            read_only: settings.read_only,
        }
    }

    async fn delete_ip_assignment(&self, vm: &Vm) -> Result<()> {
        if let NetworkAccessPolicy::StaticArp { .. } = &self.network_policy.access {
            if let Some(r) = self.router.as_ref() {
                let ent = r.list_arp_entry().await?;
                if let Some(ent) = ent
                    .iter()
                    .find(|e| e.mac_address.eq_ignore_ascii_case(&vm.mac_address))
                {
                    r.remove_arp_entry(&ent.id).await?;
                } else {
                    warn!("ARP entry not found, skipping")
                }
            }
        }
        Ok(())
    }

    async fn save_ip_assignment(&self, vm: &Vm, assignment: &mut VmIpAssignment) -> Result<()> {
        let ip = IpAddr::from_str(&assignment.ip)?;

        // apply network policy
        if let NetworkAccessPolicy::StaticArp { interface } = &self.network_policy.access {
            if let Some(r) = self.router.as_ref() {
                r.add_arp_entry(
                    ip.clone(),
                    &vm.mac_address,
                    interface,
                    Some(&format!("VM{}", vm.id)),
                )
                .await?;
            } else {
                bail!("No router found to apply static arp entry!")
            }
        }

        // Add DNS records
        if let Some(dns) = &self.dns {
            let sub_name = format!("vm-{}", vm.id);
            let fwd = dns.add_a_record(&sub_name, ip.clone()).await?;
            assignment.dns_forward = Some(fwd.name.clone());
            assignment.dns_forward_ref = fwd.id;

            match ip {
                IpAddr::V4(ip) => {
                    let last_octet = ip.octets()[3].to_string();
                    let rev = dns.add_ptr_record(&last_octet, &fwd.name).await?;
                    assignment.dns_reverse = Some(fwd.name.clone());
                    assignment.dns_reverse_ref = rev.id;
                }
                IpAddr::V6(_) => {
                    warn!("IPv6 forward DNS not supported yet")
                }
            }
        }

        // save to db
        self.db.insert_vm_ip_assignment(&assignment).await?;
        Ok(())
    }

    async fn allocate_ips(&self, vm_id: u64) -> Result<Vec<VmIpAssignment>> {
        let vm = self.db.get_vm(vm_id).await?;
        let existing_ips = self.db.list_vm_ip_assignments(vm_id).await?;
        if !existing_ips.is_empty() {
            return Ok(existing_ips);
        }

        // Use random network provisioner
        let network = NetworkProvisioner::new(ProvisionerMethod::Random, self.db.clone());

        let template = self.db.get_vm_template(vm.template_id).await?;
        let ip = network.pick_ip_for_region(template.region_id).await?;
        let mut assignment = VmIpAssignment {
            id: 0,
            vm_id,
            ip_range_id: ip.range_id,
            ip: ip.ip.to_string(),
            deleted: false,
            arp_ref: None,
            dns_forward: None,
            dns_forward_ref: None,
            dns_reverse: None,
            dns_reverse_ref: None,
        };

        self.save_ip_assignment(&vm, &mut assignment).await?;
        Ok(vec![assignment])
    }

    /// Do any necessary initialization
    pub async fn init(&self) -> Result<()> {
        let hosts = self.db.list_hosts().await?;
        let images = self.db.list_os_image().await?;
        for host in hosts {
            let client = get_host_client(&host, &self.provisioner_config)?;
            for image in &images {
                if let Err(e) = client.download_os_image(image).await {
                    warn!(
                        "Error downloading image {} on {}: {}",
                        image.url, host.name, e
                    );
                }
            }
        }
        Ok(())
    }

    /// Provision a new VM for a user on the database
    ///
    /// Note:
    /// 1. Does not create a VM on the host machine
    /// 2. Does not assign any IP resources
    pub async fn provision(
        &self,
        user_id: u64,
        template_id: u64,
        image_id: u64,
        ssh_key_id: u64,
    ) -> Result<Vm> {
        let user = self.db.get_user(user_id).await?;
        let template = self.db.get_vm_template(template_id).await?;
        let image = self.db.get_os_image(image_id).await?;
        let ssh_key = self.db.get_user_ssh_key(ssh_key_id).await?;
        let hosts = self.db.list_hosts().await?;

        // TODO: impl resource usage based provisioning
        let pick_host = if let Some(h) = hosts.first() {
            h
        } else {
            bail!("No host found")
        };
        // TODO: impl resource usage based provisioning (disk)
        let host_disks = self.db.list_host_disks(pick_host.id).await?;
        let pick_disk = if let Some(hd) = host_disks.first() {
            hd
        } else {
            bail!("No host disk found")
        };

        let client = get_host_client(&pick_host, &self.provisioner_config)?;
        let mut new_vm = Vm {
            host_id: pick_host.id,
            user_id: user.id,
            image_id: image.id,
            template_id: template.id,
            ssh_key_id: ssh_key.id,
            created: Utc::now(),
            expires: Utc::now(),
            disk_id: pick_disk.id,
            ..Default::default()
        };

        // ask host client to generate the mac address
        new_vm.mac_address = client.generate_mac(&new_vm).await?;

        let new_id = self.db.insert_vm(&new_vm).await?;
        new_vm.id = new_id;
        Ok(new_vm)
    }

    /// Create a renewal payment
    pub async fn renew(&self, vm_id: u64) -> Result<VmPayment> {
        let vm = self.db.get_vm(vm_id).await?;
        let template = self.db.get_vm_template(vm.template_id).await?;
        let cost_plan = self.db.get_cost_plan(template.cost_plan_id).await?;

        // Reuse existing payment until expired
        let payments = self.db.list_vm_payment(vm.id).await?;
        if let Some(px) = payments
            .into_iter()
            .find(|p| p.expires > Utc::now() && !p.is_paid)
        {
            return Ok(px);
        }

        // push the expiration forward by cost plan interval amount
        let new_expire = match cost_plan.interval_type {
            VmCostPlanIntervalType::Day => vm.expires.add(Days::new(cost_plan.interval_amount)),
            VmCostPlanIntervalType::Month => vm
                .expires
                .add(Months::new(cost_plan.interval_amount as u32)),
            VmCostPlanIntervalType::Year => vm
                .expires
                .add(Months::new((12 * cost_plan.interval_amount) as u32)),
        };

        const BTC_SATS: f64 = 100_000_000.0;
        const INVOICE_EXPIRE: u32 = 3600;

        let ticker = Ticker::btc_rate(cost_plan.currency.as_str())?;
        let rate = if let Some(r) = self.rates.get_rate(ticker).await {
            r
        } else {
            bail!("No exchange rate found")
        };

        let cost_btc = cost_plan.amount as f32 / rate;
        let cost_msat = (cost_btc as f64 * BTC_SATS) as u64 * 1000;
        info!("Creating invoice for {vm_id} for {} sats", cost_msat / 1000);
        let invoice = self
            .node
            .add_invoice(AddInvoiceRequest {
                memo: Some(format!("VM renewal {vm_id} to {new_expire}")),
                amount: cost_msat,
                expire: Some(INVOICE_EXPIRE),
            })
            .await?;
        let vm_payment = VmPayment {
            id: hex::decode(invoice.payment_hash)?,
            vm_id,
            created: Utc::now(),
            expires: Utc::now().add(Duration::from_secs(INVOICE_EXPIRE as u64)),
            amount: cost_msat,
            invoice: invoice.pr,
            time_value: (new_expire - vm.expires).num_seconds() as u64,
            is_paid: false,
            rate,
            ..Default::default()
        };
        self.db.insert_vm_payment(&vm_payment).await?;

        Ok(vm_payment)
    }

    /// Create a vm on the host as configured by the template
    pub async fn spawn_vm(&self, vm_id: u64) -> Result<()> {
        if self.read_only {
            bail!("Cant spawn VM's in read-only mode")
        }
        // setup network by allocating some IP space
        self.allocate_ips(vm_id).await?;

        // load full info
        let info = FullVmInfo::load(vm_id, self.db.clone()).await?;

        // load host client
        let host = self.db.get_host(info.vm.host_id).await?;
        let client = get_host_client(&host, &self.provisioner_config)?;
        client.create_vm(&info).await?;

        Ok(())
    }

    /// Delete a VM and its associated resources
    pub async fn delete_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;

        // host client currently doesn't support delete (proxmox)
        // VM should already be stopped by [Worker]

        self.delete_ip_assignment(&vm).await?;
        self.db.delete_vm_ip_assignment(vm.id).await?;
        self.db.delete_vm(vm.id).await?;

        Ok(())
    }

    /// Stop a running VM
    pub async fn stop_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;

        let client = get_host_client(&host, &self.provisioner_config)?;
        client.stop_vm(&vm).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::DefaultRateCache;
    use crate::mocks::{MockDb, MockNode};
    use crate::settings::{DnsServerConfig, LightningConfig, QemuConfig, RouterConfig};
    use lnvps_db::UserSshKey;

    #[tokio::test]
    async fn test_basic_provisioner() -> Result<()> {
        const ROUTER_BRIDGE: &str = "bridge1";

        let settings = Settings {
            listen: None,
            db: "".to_string(),
            lightning: LightningConfig::LND {
                url: "".to_string(),
                cert: Default::default(),
                macaroon: Default::default(),
            },
            read_only: false,
            provisioner: ProvisionerConfig::Proxmox {
                qemu: QemuConfig {
                    machine: "q35".to_string(),
                    os_type: "l26".to_string(),
                    bridge: "vmbr1".to_string(),
                    cpu: "kvm64".to_string(),
                    vlan: None,
                    kvm: false,
                },
                ssh: None,
                mac_prefix: Some("ff:ff:ff".to_string()),
            },
            network_policy: NetworkPolicy {
                access: NetworkAccessPolicy::StaticArp {
                    interface: ROUTER_BRIDGE.to_string(),
                },
                ip6_slaac: None,
            },
            delete_after: 0,
            smtp: None,
            router: Some(RouterConfig::Mikrotik {
                url: "https://localhost".to_string(),
                username: "admin".to_string(),
                password: "password123".to_string(),
            }),
            dns: Some(DnsServerConfig::Cloudflare {
                token: "abc".to_string(),
                forward_zone_id: "123".to_string(),
                reverse_zone_id: "456".to_string(),
            }),
            nostr: None,
        };
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(DefaultRateCache::default());
        let router = settings.get_router().expect("router").unwrap();
        let provisioner = LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone());

        let pubkey: [u8; 32] = random();

        let user_id = db.upsert_user(&pubkey).await?;
        let new_key = UserSshKey {
            id: 0,
            name: "test-key".to_string(),
            user_id,
            created: Default::default(),
            key_data: "ssh-rsa AAA==".to_string(),
        };
        let ssh_key = db.insert_user_ssh_key(&new_key).await?;

        let vm = provisioner.provision(user_id, 1, 1, ssh_key).await?;
        println!("{:?}", vm);
        provisioner.spawn_vm(vm.id).await?;

        // check resources
        let arp = router.list_arp_entry().await?;
        assert_eq!(1, arp.len());
        let arp = arp.first().unwrap();
        assert_eq!(&vm.mac_address, &arp.mac_address);
        assert_eq!(ROUTER_BRIDGE, arp.interface.as_ref().unwrap());
        println!("{:?}", arp);

        let ips = db.list_vm_ip_assignments(vm.id).await?;
        assert_eq!(1, ips.len());
        let ip = ips.first().unwrap();
        println!("{:?}", ip);
        assert_eq!(ip.ip, arp.address);
        assert_eq!(ip.ip_range_id, 1);
        assert_eq!(ip.vm_id, vm.id);
        assert!(ip.dns_forward.is_some());
        assert!(ip.dns_reverse.is_some());
        assert!(ip.dns_reverse_ref.is_some());
        assert!(ip.dns_forward.is_some());
        assert_eq!(ip.dns_reverse, ip.dns_forward);

        // assert IP address is not CIDR
        assert!(IpAddr::from_str(&ip.ip).is_ok());
        assert!(!ip.ip.ends_with("/8"));
        assert!(!ip.ip.ends_with("/24"));

        Ok(())
    }
}
