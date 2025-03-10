use crate::data_migration::DataMigration;
use crate::dns::{BasicRecord, DnsServer};
use crate::settings::Settings;
use anyhow::Result;
use lnvps_db::LNVpsDb;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub struct DnsDataMigration {
    db: Arc<dyn LNVpsDb>,
    dns: Arc<dyn DnsServer>,
}

impl DnsDataMigration {
    pub fn new(db: Arc<dyn LNVpsDb>, settings: &Settings) -> Option<Self> {
        let dns = settings.get_dns().ok().flatten()?;
        Some(Self { db, dns })
    }
}

impl DataMigration for DnsDataMigration {
    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let db = self.db.clone();
        let dns = self.dns.clone();
        Box::pin(async move {
            let vms = db.list_vms().await?;

            for vm in vms {
                let mut ips = db.list_vm_ip_assignments(vm.id).await?;
                for mut ip in &mut ips {
                    let mut did_change = false;
                    if ip.dns_forward.is_none() {
                        let rec = BasicRecord::forward(&ip)?;
                        let r = dns.add_record(&rec).await?;
                        ip.dns_forward = Some(r.name);
                        ip.dns_forward_ref = r.id;
                        did_change = true;
                    }
                    if ip.dns_reverse.is_none() {
                        let rec = BasicRecord::reverse(&ip)?;
                        let r = dns.add_record(&rec).await?;
                        ip.dns_reverse = Some(r.name);
                        ip.dns_reverse_ref = r.id;
                        did_change = true;
                    }
                    if did_change {
                        db.update_vm_ip_assignment(ip).await?;
                    }
                }
            }
            Ok(())
        })
    }
}
