use crate::provisioner::Template;
use anyhow::{bail, Result};
use chrono::Utc;
use futures::future::join_all;
use lnvps_db::{
    DiskInterface, DiskType, LNVpsDb, VmCustomTemplate, VmHost, VmHostDisk, VmTemplate,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Simple capacity management
#[derive(Clone)]
pub struct HostCapacityService {
    /// Database
    db: Arc<dyn LNVpsDb>,
}

impl HostCapacityService {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }

    /// List templates which can be sold, based on available capacity
    pub async fn list_available_vm_templates(&self) -> Result<Vec<VmTemplate>> {
        let templates = self.db.list_vm_templates().await?;

        // TODO: list hosts in regions where templates are active?
        // use all hosts since we dont expect there to be many
        let hosts = self.db.list_hosts().await?;
        let caps: Vec<Result<HostCapacity>> =
            join_all(hosts.iter().map(|h| self.get_host_capacity(h, None, None))).await;
        let caps: Vec<HostCapacity> = caps.into_iter().filter_map(Result::ok).collect();

        Ok(templates
            .into_iter()
            .filter(|t| {
                caps.iter()
                    .filter(|c| c.host.region_id == t.region_id)
                    .any(|c| c.can_accommodate(t))
            })
            .collect())
    }

    /// Pick a host for the purposes of provisioning a new VM
    pub async fn get_host_for_template(
        &self,
        region_id: u64,
        template: &impl Template,
    ) -> Result<HostCapacity> {
        let hosts = self.db.list_hosts().await?;
        let caps: Vec<Result<HostCapacity>> =
            join_all(hosts.iter().filter(|h| h.region_id == region_id).map(|h| {
                self.get_host_capacity(
                    h,
                    Some(template.disk_type()),
                    Some(template.disk_interface()),
                )
            }))
            .await;
        let mut host_cap: Vec<HostCapacity> = caps
            .into_iter()
            .filter_map(|v| v.ok())
            .filter(|v| v.can_accommodate(template))
            .collect();

        host_cap.sort_by(|a, b| a.load().partial_cmp(&b.load()).unwrap());

        if let Some(f) = host_cap.into_iter().next() {
            Ok(f)
        } else {
            bail!("No available hosts found");
        }
    }

    /// Get available capacity of a given host
    pub async fn get_host_capacity(
        &self,
        host: &VmHost,
        disk_type: Option<DiskType>,
        disk_interface: Option<DiskInterface>,
    ) -> Result<HostCapacity> {
        let vms = self.db.list_vms_on_host(host.id).await?;
        // TODO: filter disks from DB? Should be very few disks anyway
        let storage = self.db.list_host_disks(host.id).await?;
        let templates = self.db.list_vm_templates().await?;
        let custom_templates: Vec<Result<VmCustomTemplate>> = join_all(
            vms.iter()
                .filter(|v| v.custom_template_id.is_some() && v.expires > Utc::now())
                .map(|v| {
                    self.db
                        .get_custom_vm_template(v.custom_template_id.unwrap())
                }),
        )
        .await;
        let custom_templates: HashMap<u64, VmCustomTemplate> = custom_templates
            .into_iter()
            .filter_map(|r| r.ok())
            .map(|v| (v.id, v))
            .collect();

        struct VmResources {
            vm_id: u64,
            cpu: u16,
            memory: u64,
            disk: u64,
            disk_id: u64,
        }
        // a mapping between vm_id and resources
        let vm_resources: HashMap<u64, VmResources> = vms
            .iter()
            .filter(|v| v.expires > Utc::now())
            .filter_map(|v| {
                if let Some(x) = v.template_id {
                    templates.iter().find(|t| t.id == x).map(|t| VmResources {
                        vm_id: v.id,
                        cpu: t.cpu,
                        memory: t.memory,
                        disk: t.disk_size,
                        disk_id: v.disk_id,
                    })
                } else if let Some(x) = v.custom_template_id {
                    custom_templates.get(&x).map(|t| VmResources {
                        vm_id: v.id,
                        cpu: t.cpu,
                        memory: t.memory,
                        disk: t.disk_size,
                        disk_id: v.disk_id,
                    })
                } else {
                    None
                }
            })
            .map(|m| (m.vm_id, m))
            .collect();

        let mut storage_disks: Vec<DiskCapacity> = storage
            .iter()
            .filter(|d| {
                disk_type.as_ref().map(|t| d.kind == *t).unwrap_or(true)
                    && disk_interface
                        .as_ref()
                        .map(|i| d.interface == *i)
                        .unwrap_or(true)
            })
            .map(|s| {
                let usage = vm_resources
                    .iter()
                    .filter(|(_k, v)| s.id == v.disk_id)
                    .fold(0, |acc, (_k, v)| acc + v.disk);
                DiskCapacity {
                    load_factor: host.load_factor,
                    disk: s.clone(),
                    usage,
                }
            })
            .collect();

        storage_disks.sort_by(|a, b| a.load_factor.partial_cmp(&b.load_factor).unwrap());

        let cpu_consumed = vm_resources.values().fold(0, |acc, vm| acc + vm.cpu);
        let memory_consumed = vm_resources.values().fold(0, |acc, vm| acc + vm.memory);

        Ok(HostCapacity {
            load_factor: host.load_factor,
            host: host.clone(),
            cpu: cpu_consumed,
            memory: memory_consumed,
            disks: storage_disks,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HostCapacity {
    /// Load factor applied to resource consumption
    pub load_factor: f32,
    /// The host
    pub host: VmHost,
    /// Number of consumed CPU cores
    pub cpu: u16,
    /// Number of consumed bytes of memory
    pub memory: u64,
    /// List of disks on the host and its used space
    pub disks: Vec<DiskCapacity>,
}

impl HostCapacity {
    /// Total average usage as a percentage
    pub fn load(&self) -> f32 {
        (self.cpu_load() + self.memory_load() + self.disk_load()) / 3.0
    }

    /// CPU usage as a percentage
    pub fn cpu_load(&self) -> f32 {
        self.cpu as f32 / (self.host.cpu as f32 * self.load_factor)
    }

    /// Total number of available CPUs
    pub fn available_cpu(&self) -> u16 {
        let loaded_host_cpu = (self.host.cpu as f32 * self.load_factor).floor() as u16;
        loaded_host_cpu.saturating_sub(self.cpu)
    }

    /// Memory usage as a percentage
    pub fn memory_load(&self) -> f32 {
        self.memory as f32 / (self.host.memory as f32 * self.load_factor)
    }

    /// Total available bytes of memory
    pub fn available_memory(&self) -> u64 {
        let loaded_host_memory = (self.host.memory as f64 * self.load_factor as f64).floor() as u64;
        loaded_host_memory.saturating_sub(self.memory)
    }

    /// Disk usage as a percentage (average over all disks)
    pub fn disk_load(&self) -> f32 {
        self.disks.iter().fold(0.0, |acc, disk| acc + disk.load()) / self.disks.len() as f32
    }

    /// Can this host and its available capacity accommodate the given template
    pub fn can_accommodate(&self, template: &impl Template) -> bool {
        self.available_cpu() >= template.cpu()
            && self.available_memory() >= template.memory()
            && self
                .disks
                .iter()
                .any(|d| d.available_capacity() >= template.disk_size())
    }
}

#[derive(Debug, Clone)]
pub struct DiskCapacity {
    /// Load factor applied to resource consumption
    pub load_factor: f32,
    /// Disk ID
    pub disk: VmHostDisk,
    /// Space consumed by VMs
    pub usage: u64,
}

impl DiskCapacity {
    /// Total available bytes of disk space
    pub fn available_capacity(&self) -> u64 {
        let loaded_disk_size = (self.disk.size as f64 * self.load_factor as f64).floor() as u64;
        loaded_disk_size.saturating_sub(self.usage)
    }

    /// Disk usage as percentage
    pub fn load(&self) -> f32 {
        (self.usage as f32 / self.disk.size as f32) * (1.0 / self.load_factor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::MockDb;

    #[test]
    fn loads() {
        let cap = HostCapacity {
            load_factor: 2.0,
            host: VmHost {
                cpu: 100,
                memory: 100,
                ..Default::default()
            },
            cpu: 8,
            memory: 8,
            disks: vec![DiskCapacity {
                load_factor: 2.0,
                disk: VmHostDisk {
                    size: 100,
                    ..Default::default()
                },
                usage: 8,
            }],
        };

        // load factor halves load values 8/100 * (1/load_factor)
        assert_eq!(cap.load(), 0.04);
        assert_eq!(cap.cpu_load(), 0.04);
        assert_eq!(cap.memory_load(), 0.04);
        assert_eq!(cap.disk_load(), 0.04);
        // load factor doubles memory to 200, 200 - 8
        assert_eq!(cap.available_memory(), 192);
        assert_eq!(cap.available_cpu(), 192);
    }

    #[tokio::test]
    async fn empty_available_capacity() -> Result<()> {
        let db = Arc::new(MockDb::default());

        let hc = HostCapacityService::new(db.clone());
        let host = db.get_host(1).await?;
        let cap = hc.get_host_capacity(&host, None, None).await?;
        let disks = db.list_host_disks(1).await?;
        /// check all resources are available
        assert_eq!(cap.cpu, 0);
        assert_eq!(cap.memory, 0);
        assert_eq!(cap.disks.len(), disks.len());
        assert_eq!(cap.load(), 0.0);
        for disk in cap.disks {
            assert_eq!(0, disk.usage);
            assert_eq!(disk.load(), 0.0);
        }

        let template = db.get_vm_template(1).await?;
        let host = hc
            .get_host_for_template(template.region_id, &template)
            .await?;
        assert_eq!(host.host.id, 1);

        // all templates should be available
        let templates = hc.list_available_vm_templates().await?;
        assert_eq!(templates.len(), db.list_vm_templates().await?.len());

        Ok(())
    }

    #[tokio::test]
    async fn expired_doesnt_count() -> Result<()> {
        let db = MockDb::default();
        {
            let mut v = db.vms.lock().await;
            v.insert(1, MockDb::mock_vm());
        }

        let db: Arc<dyn LNVpsDb> = Arc::new(db);
        let hc = HostCapacityService::new(db.clone());
        let host = db.get_host(1).await?;
        let cap = hc.get_host_capacity(&host, None, None).await?;

        assert_eq!(cap.load(), 0.0);
        assert_eq!(cap.cpu, 0);
        assert_eq!(cap.memory, 0);
        for disk in cap.disks {
            assert_eq!(0, disk.usage);
        }
        Ok(())
    }
}
