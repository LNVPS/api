use crate::{
    IpRange, LNVpsDb, User, UserSshKey, Vm, VmCostPlan, VmHost, VmHostDisk, VmHostRegion,
    VmIpAssignment, VmOsImage, VmPayment, VmTemplate,
};
use anyhow::{bail, Error, Result};
use async_trait::async_trait;
use sqlx::{Executor, MySqlPool, Row};

#[derive(Clone)]
pub struct LNVpsDbMysql {
    db: MySqlPool,
}

impl LNVpsDbMysql {
    pub async fn new(conn: &str) -> Result<Self> {
        let db = MySqlPool::connect(conn).await?;
        Ok(Self { db })
    }

    #[cfg(debug_assertions)]
    pub async fn execute(&self, sql: &str) -> Result<()> {
        self.db.execute(sql).await.map_err(Error::new)?;
        Ok(())
    }
}

#[async_trait]
impl LNVpsDb for LNVpsDbMysql {
    async fn migrate(&self) -> Result<()> {
        sqlx::migrate!().run(&self.db).await.map_err(Error::new)
    }

    async fn upsert_user(&self, pubkey: &[u8; 32]) -> Result<u64> {
        let res =
            sqlx::query("insert ignore into users(pubkey,contact_nip17) values(?,1) returning id")
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
        sqlx::query_as("select * from users where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn update_user(&self, user: &User) -> Result<()> {
        sqlx::query(
            "update users set email = ?, contact_nip17 = ?, contact_email = ? where id = ?",
        )
        .bind(&user.email)
        .bind(user.contact_nip17)
        .bind(user.contact_email)
        .bind(user.id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn delete_user(&self, _id: u64) -> Result<()> {
        bail!("Deleting users is not supported")
    }

    async fn insert_user_ssh_key(&self, new_key: &UserSshKey) -> Result<u64> {
        Ok(sqlx::query(
            "insert into user_ssh_key(name,user_id,key_data) values(?, ?, ?) returning id",
        )
        .bind(&new_key.name)
        .bind(new_key.user_id)
        .bind(&new_key.key_data)
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?
        .try_get(0)?)
    }

    async fn get_user_ssh_key(&self, id: u64) -> Result<UserSshKey> {
        sqlx::query_as("select * from user_ssh_key where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn delete_user_ssh_key(&self, _id: u64) -> Result<()> {
        todo!()
    }

    async fn list_user_ssh_key(&self, user_id: u64) -> Result<Vec<UserSshKey>> {
        sqlx::query_as("select * from user_ssh_key where user_id = ?")
            .bind(user_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_host_region(&self, id: u64) -> Result<VmHostRegion> {
        sqlx::query_as("select * from vm_host_region where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_hosts(&self) -> Result<Vec<VmHost>> {
        sqlx::query_as("select * from vm_host where enabled = 1")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_host(&self, id: u64) -> Result<VmHost> {
        sqlx::query_as("select * from vm_host where id = ?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn update_host(&self, host: &VmHost) -> Result<()> {
        sqlx::query("update vm_host set name = ?, cpu = ?, memory = ? where id = ?")
            .bind(&host.name)
            .bind(host.cpu)
            .bind(host.memory)
            .bind(host.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn list_host_disks(&self, host_id: u64) -> Result<Vec<VmHostDisk>> {
        sqlx::query_as("select * from vm_host_disk where host_id = ? and enabled = 1")
            .bind(host_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_host_disk(&self, disk_id: u64) -> Result<VmHostDisk> {
        sqlx::query_as("select * from vm_host_disk where id = ?")
            .bind(disk_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_os_image(&self, id: u64) -> Result<VmOsImage> {
        sqlx::query_as("select * from vm_os_image where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_os_image(&self) -> Result<Vec<VmOsImage>> {
        sqlx::query_as("select * from vm_os_image")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_ip_range(&self, id: u64) -> Result<IpRange> {
        sqlx::query_as("select * from ip_range where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_ip_range(&self) -> Result<Vec<IpRange>> {
        sqlx::query_as("select * from ip_range where enabled = 1")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_ip_range_in_region(&self, region_id: u64) -> Result<Vec<IpRange>> {
        sqlx::query_as("select * from ip_range where region_id = ? and enabled = 1")
            .bind(region_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_cost_plan(&self, id: u64) -> Result<VmCostPlan> {
        sqlx::query_as("select * from vm_cost_plan where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_vm_template(&self, id: u64) -> Result<VmTemplate> {
        sqlx::query_as("select * from vm_template where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_vm_templates(&self) -> Result<Vec<VmTemplate>> {
        sqlx::query_as("select * from vm_template")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn insert_vm_template(&self, template: &VmTemplate) -> Result<u64> {
        Ok(sqlx::query("insert into vm_template(name,enabled,created,expires,cpu,memory,disk_size,disk_type,disk_interface,cost_plan_id,region_id) values(?,?,?,?,?,?,?,?,?,?,?) returning id")
            .bind(&template.name)
            .bind(&template.enabled)
            .bind(&template.created)
            .bind(&template.expires)
            .bind(template.cpu)
            .bind(template.memory)
            .bind(template.disk_size)
            .bind(&template.disk_type)
            .bind(&template.disk_interface)
            .bind(template.cost_plan_id)
            .bind(template.region_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?
            .try_get(0)?)
    }

    async fn list_vms(&self) -> Result<Vec<Vm>> {
        sqlx::query_as("select * from vm where deleted = 0")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_vms_on_host(&self, host_id: u64) -> Result<Vec<Vm>> {
        sqlx::query_as("select * from vm where deleted = 0 and host_id = ?")
            .bind(host_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_expired_vms(&self) -> Result<Vec<Vm>> {
        sqlx::query_as("select * from vm where expires > current_timestamp()  and deleted = 0")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_user_vms(&self, id: u64) -> Result<Vec<Vm>> {
        sqlx::query_as("select * from vm where user_id = ? and deleted = 0")
            .bind(id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_vm(&self, vm_id: u64) -> Result<Vm> {
        sqlx::query_as("select * from vm where id = ?")
            .bind(vm_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn insert_vm(&self, vm: &Vm) -> Result<u64> {
        Ok(sqlx::query("insert into vm(host_id,user_id,image_id,template_id,ssh_key_id,created,expires,disk_id,mac_address,ref_code) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) returning id")
            .bind(vm.host_id)
            .bind(vm.user_id)
            .bind(vm.image_id)
            .bind(vm.template_id)
            .bind(vm.ssh_key_id)
            .bind(vm.created)
            .bind(vm.expires)
            .bind(vm.disk_id)
            .bind(&vm.mac_address)
            .bind(&vm.ref_code)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?
            .try_get(0)?)
    }

    async fn delete_vm(&self, vm_id: u64) -> Result<()> {
        sqlx::query("update vm set deleted = 1 where id = ?")
            .bind(vm_id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(())
    }

    async fn update_vm(&self, vm: &Vm) -> Result<()> {
        sqlx::query(
            "update vm set image_id=?,template_id=?,ssh_key_id=?,expires=?,disk_id=? where id=?",
        )
        .bind(vm.image_id)
        .bind(vm.template_id)
        .bind(vm.ssh_key_id)
        .bind(vm.expires)
        .bind(vm.disk_id)
        .bind(vm.id)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;
        Ok(())
    }

    async fn insert_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> Result<u64> {
        Ok(sqlx::query(
            "insert into vm_ip_assignment(vm_id,ip_range_id,ip,arp_ref,dns_forward,dns_forward_ref,dns_reverse,dns_reverse_ref) values(?,?,?,?,?,?,?,?) returning id",
        )
        .bind(ip_assignment.vm_id)
        .bind(ip_assignment.ip_range_id)
        .bind(&ip_assignment.ip)
        .bind(&ip_assignment.arp_ref)
        .bind(&ip_assignment.dns_forward)
        .bind(&ip_assignment.dns_forward_ref)
        .bind(&ip_assignment.dns_reverse)
        .bind(&ip_assignment.dns_reverse_ref)
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?
        .try_get(0)?)
    }

    async fn update_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> Result<()> {
        sqlx::query(
            "update vm_ip_assignment set arp_ref = ?, dns_forward = ?, dns_forward_ref = ?, dns_reverse = ?, dns_reverse_ref = ? where id = ?",
        )
            .bind(&ip_assignment.arp_ref)
            .bind(&ip_assignment.dns_forward)
            .bind(&ip_assignment.dns_forward_ref)
            .bind(&ip_assignment.dns_reverse)
            .bind(&ip_assignment.dns_reverse_ref)
            .bind(&ip_assignment.id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(())
    }

    async fn list_vm_ip_assignments(&self, vm_id: u64) -> Result<Vec<VmIpAssignment>> {
        sqlx::query_as("select * from vm_ip_assignment where vm_id = ? and deleted = 0")
            .bind(vm_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_vm_ip_assignments_in_range(&self, range_id: u64) -> Result<Vec<VmIpAssignment>> {
        sqlx::query_as("select * from vm_ip_assignment where ip_range_id = ? and deleted = 0")
            .bind(range_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn delete_vm_ip_assignment(&self, vm_id: u64) -> Result<()> {
        sqlx::query("update vm_ip_assignment set deleted = 1 where vm_id = ?")
            .bind(&vm_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn list_vm_payment(&self, vm_id: u64) -> Result<Vec<VmPayment>> {
        sqlx::query_as("select * from vm_payment where vm_id = ?")
            .bind(vm_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn insert_vm_payment(&self, vm_payment: &VmPayment) -> Result<()> {
        sqlx::query("insert into vm_payment(id,vm_id,created,expires,amount,invoice,time_value,is_paid,rate) values(?,?,?,?,?,?,?,?,?)")
            .bind(&vm_payment.id)
            .bind(vm_payment.vm_id)
            .bind(vm_payment.created)
            .bind(vm_payment.expires)
            .bind(vm_payment.amount)
            .bind(&vm_payment.invoice)
            .bind(vm_payment.time_value)
            .bind(vm_payment.is_paid)
            .bind(vm_payment.rate)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(())
    }

    async fn get_vm_payment(&self, id: &Vec<u8>) -> Result<VmPayment> {
        sqlx::query_as("select * from vm_payment where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn update_vm_payment(&self, vm_payment: &VmPayment) -> Result<()> {
        sqlx::query("update vm_payment set is_paid = ? where id = ?")
            .bind(vm_payment.is_paid)
            .bind(&vm_payment.id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(())
    }

    async fn vm_payment_paid(&self, vm_payment: &VmPayment) -> Result<()> {
        if vm_payment.is_paid {
            bail!("Invoice already paid");
        }

        let mut tx = self.db.begin().await?;

        sqlx::query("update vm_payment set is_paid = true, settle_index = ? where id = ?")
            .bind(vm_payment.settle_index)
            .bind(&vm_payment.id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("update vm set expires = TIMESTAMPADD(SECOND, ?, expires) where id = ?")
            .bind(vm_payment.time_value)
            .bind(vm_payment.vm_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn last_paid_invoice(&self) -> Result<Option<VmPayment>> {
        sqlx::query_as(
            "select * from vm_payment where is_paid = true order by settle_index desc limit 1",
        )
        .fetch_optional(&self.db)
        .await
        .map_err(Error::new)
    }
}
