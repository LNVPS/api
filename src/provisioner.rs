use crate::db;
use crate::db::{VmHost, VmHostDisk};
use crate::host::proxmox::ProxmoxClient;
use crate::vm::VMSpec;
use anyhow::{Error, Result};
use log::{info, warn};
use sqlx::{MySqlPool, Row};

#[derive(Debug, Clone)]
pub struct Provisioner {
    db: MySqlPool,
}

impl Provisioner {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }

    /// Auto-discover resources
    pub async fn auto_discover(&self) -> Result<()> {
        let hosts = self.list_hosts().await?;
        for host in hosts {
            let api = ProxmoxClient::new(host.ip.parse()?).with_api_token(&host.api_token);

            let nodes = api.list_nodes().await?;
            if let Some(node) = nodes.iter().find(|n| n.name == host.name) {
                // Update host resources
                if node.max_cpu.unwrap_or(host.cpu) != host.cpu
                    || node.max_mem.unwrap_or(host.memory) != host.memory
                {
                    let mut host = host.clone();
                    host.cpu = node.max_cpu.unwrap_or(host.cpu);
                    host.memory = node.max_mem.unwrap_or(host.memory);
                    info!("Patching host: {:?}", host);
                    self.update_host(host).await?;
                }
                // Update disk info
                let storages = api.list_storage().await?;
                let host_disks = self.list_host_disks(host.id).await?;
                for storage in storages {
                    let host_storage =
                        if let Some(s) = host_disks.iter().find(|d| d.name == storage.storage) {
                            s
                        } else {
                            warn!("Disk not found: {} on {}", storage.storage, host.name);
                            continue;
                        };
                }
            }
            info!(
                "Discovering resources from: {} v{}",
                &host.name,
                api.version().await?.version
            );
        }

        Ok(())
    }

    /// Provision a new VM
    pub async fn provision(&self, spec: VMSpec) -> Result<db::Vm> {
        todo!()
    }

    /// Insert/Fetch user id
    pub async fn upsert_user(&self, pubkey: &[u8; 32]) -> Result<u64> {
        let res = sqlx::query("insert ignore into users(pubkey) values(?) returning id")
            .bind(pubkey.as_slice())
            .fetch_optional(&self.db)
            .await?;
        match res {
            None => sqlx::query("select id from users where pubkey = ?")
                .bind(pubkey.as_slice())
                .fetch_one(&self.db)
                .await?
                .try_get(0)
                .map_err(Error::new),
            Some(res) => res.try_get(0).map_err(Error::new),
        }
    }

    /// List VM templates
    pub async fn list_vm_templates(&self) -> Result<Vec<db::VmTemplate>> {
        sqlx::query_as("select * from vm_template where enabled = 1 and (expires is null or expires < now())")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    /// List VM's owned by a specific user
    pub async fn list_vms(&self, id: u64) -> Result<Vec<db::Vm>> {
        sqlx::query_as("select * from vm where user_id = ?")
            .bind(&id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    /// List VM's owned by a specific user
    pub async fn list_hosts(&self) -> Result<Vec<VmHost>> {
        sqlx::query_as("select * from vm_host")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    /// List VM's owned by a specific user
    pub async fn list_host_disks(&self, host_id: u64) -> Result<Vec<VmHostDisk>> {
        sqlx::query_as("select * from vm_host_disk where host_id = ?")
            .bind(&host_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    /// Update host resources (usually from [auto_discover])
    pub async fn update_host(&self, host: VmHost) -> Result<()> {
        sqlx::query("update vm_host set name = ?, cpu = ?, memory = ? where id = ?")
            .bind(&host.name)
            .bind(&host.cpu)
            .bind(&host.memory)
            .bind(&host.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }
}
