use crate::{IpRange, LNVpsDb, User, UserSshKey, Vm, VmCostPlan, VmHost, VmHostDisk, VmHostRegion, VmIpAssignment, VmOsImage, VmPayment, VmTemplate};
use anyhow::{Error, Result};
use async_trait::async_trait;
use sqlx::{Executor, MySqlPool, Row};

#[derive(Clone)]
pub struct LNVpsDbMysql {
    db: MySqlPool,
}

impl LNVpsDbMysql {
    pub async fn new(conn: &str) -> Result<Self> {
        let db = MySqlPool::connect(conn).await?;
        Ok(Self {
            db
        })
    }

    #[cfg(debug_assertions)]
    pub async fn execute(&self, sql: &str) -> Result<()> {
        self.db.execute(sql).await.map_err(Error::new)?;
        Ok(())
    }
}

#[async_trait]
impl LNVpsDb for LNVpsDbMysql {
    async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::migrate!().run(&self.db).await.map_err(Error::new)
    }

    async fn upsert_user(&self, pubkey: &[u8; 32]) -> anyhow::Result<u64> {
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

    async fn get_user(&self, id: u64) -> Result<User> {
        todo!()
    }

    async fn update_user(&self, user: &User) -> Result<()> {
        todo!()
    }

    async fn delete_user(&self, id: u64) -> Result<()> {
        todo!()
    }

    async fn insert_user_ssh_key(&self, new_key: UserSshKey) -> Result<u64> {
        todo!()
    }

    async fn get_user_ssh_key(&self, id: u64) -> Result<UserSshKey> {
        todo!()
    }

    async fn delete_user_ssh_key(&self, id: u64) -> Result<()> {
        todo!()
    }

    async fn list_user_ssh_key(&self, user_id: u64) -> Result<Vec<UserSshKey>> {
        todo!()
    }

    async fn get_host_region(&self, id: u64) -> Result<VmHostRegion> {
        todo!()
    }

    async fn list_hosts(&self) -> anyhow::Result<Vec<VmHost>> {
        sqlx::query_as("select * from vm_host")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn update_host(&self, host: VmHost) -> anyhow::Result<()> {
        sqlx::query("update vm_host set name = ?, cpu = ?, memory = ? where id = ?")
            .bind(&host.name)
            .bind(&host.cpu)
            .bind(&host.memory)
            .bind(&host.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn list_host_disks(&self, host_id: u64) -> anyhow::Result<Vec<VmHostDisk>> {
        sqlx::query_as("select * from vm_host_disk where host_id = ?")
            .bind(&host_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_os_image(&self) -> Result<Vec<VmOsImage>> {
        todo!()
    }

    async fn list_ip_range(&self) -> Result<Vec<IpRange>> {
        todo!()
    }

    async fn get_cost_plan(&self, id: u64) -> Result<VmCostPlan> {
        todo!()
    }

    async fn list_vm_templates(&self) -> anyhow::Result<Vec<VmTemplate>> {
        sqlx::query_as("select * from vm_template where enabled = 1 and (expires is null or expires > now())")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_user_vms(&self, id: u64) -> Result<Vec<Vm>> {
        sqlx::query_as("select * from vm where user_id = ?")
            .bind(&id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn insert_vm(&self, vm: Vm) -> Result<u64> {
        todo!()
    }

    async fn get_vm_ip_assignments(&self, vm_id: u64) -> Result<Vec<VmIpAssignment>> {
        todo!()
    }

    async fn list_vm_payment(&self, vm_id: u64) -> Result<Vec<VmPayment>> {
        todo!()
    }

    async fn insert_vm_payment(&self, vm_payment: VmPayment) -> Result<u64> {
        todo!()
    }

    async fn update_vm_payment(&self, vm_payment: VmPayment) -> Result<()> {
        todo!()
    }
}