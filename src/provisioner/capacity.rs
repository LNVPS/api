use anyhow::Result;
use lnvps_db::{LNVpsDb, VmHost, VmHostDisk, VmTemplate};
use std::collections::HashMap;
use std::sync::Arc;

/// Simple capacity reporting per node
#[derive(Clone)]
pub struct HostCapacity {
    db: Arc<dyn LNVpsDb>,
}

impl HostCapacity {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }

    pub async fn get_available_capacity(&self, host: &VmHost) -> Result<AvailableCapacity> {
        let vms = self.db.list_vms_on_host(host.id).await?;
        let storage = self.db.list_host_disks(host.id).await?;
        let templates = self.db.list_vm_templates().await?;

        // a mapping between vm_id and template
        let vm_template: HashMap<u64, &VmTemplate> = vms
            .iter()
            .filter_map(|v| {
                templates
                    .iter()
                    .find(|t| t.id == v.template_id)
                    .and_then(|t| Some((v.id, t)))
            })
            .collect();

        let storage_disks: Vec<DiskCapacity> = storage
            .iter()
            .map(|s| {
                let usage = vm_template
                    .iter()
                    .filter(|(k, v)| v.id == s.id)
                    .fold(0, |acc, (k, v)| acc + v.disk_size);
                DiskCapacity {
                    disk: s.clone(),
                    usage,
                }
            })
            .collect();

        let cpu_consumed = vm_template.values().fold(0, |acc, vm| acc + vm.cpu);
        let memory_consumed = vm_template.values().fold(0, |acc, vm| acc + vm.memory);

        Ok(AvailableCapacity {
            cpu: host.cpu.saturating_sub(cpu_consumed),
            memory: host.memory.saturating_sub(memory_consumed),
            disks: storage_disks,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AvailableCapacity {
    /// Number of CPU cores available
    pub cpu: u16,
    /// Number of bytes of memory available
    pub memory: u64,
    /// List of disks on the host and its available space
    pub disks: Vec<DiskCapacity>,
}

#[derive(Debug, Clone)]
pub struct DiskCapacity {
    /// Disk ID
    pub disk: VmHostDisk,
    /// Space consumed by VMs
    pub usage: u64,
}

impl DiskCapacity {
    pub fn available_capacity(&self) -> u64 {
        self.disk.size.saturating_sub(self.usage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::MockDb;

    #[tokio::test]
    async fn empty_available_capacity() -> Result<()> {
        let db = Arc::new(MockDb::default());

        let hc = HostCapacity::new(db.clone());
        let host = db.get_host(1).await?;
        let cap = hc.get_available_capacity(&host).await?;
        let disks = db.list_host_disks(1).await?;
        /// check all resources are available
        assert_eq!(cap.cpu, host.cpu);
        assert_eq!(cap.memory, host.memory);
        assert_eq!(cap.disks.len(), disks.len());
        for disk in cap.disks {
            assert_eq!(0, disk.usage);
        }

        Ok(())
    }
}
