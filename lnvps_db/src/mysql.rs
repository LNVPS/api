use crate::{
    AccessPolicy, Company, IpRange, LNVpsDbBase, PaymentMethod, PaymentType, RegionStats, Router,
    User, UserSshKey, Vm, VmCostPlan, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate,
    VmHistory, VmHost, VmHostDisk, VmHostRegion, VmIpAssignment, VmOsImage, VmPayment,
    VmPaymentWithCompany, VmTemplate,
};
#[cfg(feature = "admin")]
use crate::{AdminDb, AdminRole, AdminRoleAssignment};
#[cfg(feature = "nostr-domain")]
use crate::{LNVPSNostrDb, NostrDomain, NostrDomainHandle};
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
impl LNVpsDbBase for LNVpsDbMysql {
    async fn migrate(&self) -> Result<()> {
        let migrator = sqlx::migrate!();
        migrator.run(&self.db).await.map_err(Error::new)?;
        Ok(())
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
            "update users set email=?, contact_nip17=?, contact_email=?, country_code=?, billing_name=?, billing_address_1=?, billing_address_2=?, billing_city=?, billing_state=?, billing_postcode=?, billing_tax_id=? where id = ?",
        )
            .bind(&user.email)
            .bind(user.contact_nip17)
            .bind(user.contact_email)
            .bind(&user.country_code)
            .bind(&user.billing_name)
            .bind(&user.billing_address_1)
            .bind(&user.billing_address_2)
            .bind(&user.billing_city)
            .bind(&user.billing_state)
            .bind(&user.billing_postcode)
            .bind(&user.billing_tax_id)
            .bind(user.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn delete_user(&self, _id: u64) -> Result<()> {
        bail!("Deleting users is not supported")
    }

    async fn list_users(&self) -> Result<Vec<User>> {
        sqlx::query_as("select * from users")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_users_paginated(&self, limit: u64, offset: u64) -> Result<Vec<User>> {
        sqlx::query_as("select * from users order by id limit ? offset ?")
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn count_users(&self) -> Result<u64> {
        sqlx::query("select count(*) as count from users")
            .fetch_one(&self.db)
            .await?
            .try_get(0)
            .map_err(Error::new)
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

    async fn list_host_region(&self) -> Result<Vec<VmHostRegion>> {
        sqlx::query_as("select * from vm_host_region where enabled=1")
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

    async fn get_host_region_by_name(&self, name: &str) -> Result<VmHostRegion> {
        sqlx::query_as("select * from vm_host_region where name like ?")
            .bind(name)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_hosts(&self) -> Result<Vec<VmHost>> {
        sqlx::query_as("select h.* from vm_host h,vm_host_region hr where h.enabled = 1 and h.region_id = hr.id and hr.enabled = 1")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_hosts_paginated(&self, limit: u64, offset: u64) -> Result<(Vec<VmHost>, u64)> {
        // Get total count
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vm_host h, vm_host_region hr WHERE h.enabled = 1 AND h.region_id = hr.id AND hr.enabled = 1"
        )
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;

        // Get paginated results
        let hosts = sqlx::query_as(
            "SELECT h.* FROM vm_host h, vm_host_region hr WHERE h.enabled = 1 AND h.region_id = hr.id AND hr.enabled = 1 ORDER BY h.name LIMIT ? OFFSET ?"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)?;

        Ok((hosts, total as u64))
    }

    async fn list_hosts_with_regions_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<(VmHost, VmHostRegion)>, u64)> {
        // Get total count
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vm_host h, vm_host_region hr WHERE h.enabled = 1 AND h.region_id = hr.id AND hr.enabled = 1"
        )
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;

        // Get paginated results with region info
        let rows = sqlx::query(
            "SELECT h.*, hr.id as region_id, hr.name as region_name, hr.enabled as region_enabled, hr.company_id as region_company_id 
             FROM vm_host h, vm_host_region hr 
             WHERE h.enabled = 1 AND h.region_id = hr.id AND hr.enabled = 1 
             ORDER BY h.name LIMIT ? OFFSET ?"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)?;

        let mut results = Vec::new();
        for row in rows {
            let host = VmHost {
                id: row.get("id"),
                kind: row.get("kind"),
                region_id: row.get("region_id"),
                name: row.get("name"),
                ip: row.get("ip"),
                cpu: row.get("cpu"),
                memory: row.get("memory"),
                enabled: row.get("enabled"),
                api_token: row.get("api_token"),
                load_cpu: row.get("load_cpu"),
                load_memory: row.get("load_memory"),
                load_disk: row.get("load_disk"),
                vlan_id: row.get("vlan_id"),
            };

            let region = VmHostRegion {
                id: row.get("region_id"),
                name: row.get("region_name"),
                enabled: row.get("region_enabled"),
                company_id: row.get("region_company_id"),
            };

            results.push((host, region));
        }

        Ok((results, total as u64))
    }

    async fn get_host(&self, id: u64) -> Result<VmHost> {
        sqlx::query_as("select * from vm_host where id = ?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn update_host(&self, host: &VmHost) -> Result<()> {
        sqlx::query("update vm_host set kind = ?, region_id = ?, name = ?, ip = ?, cpu = ?, memory = ?, enabled = ?, api_token = ?, load_cpu = ?, load_memory = ?, load_disk = ?, vlan_id = ? where id = ?")
            .bind(&host.kind)
            .bind(host.region_id)
            .bind(&host.name)
            .bind(&host.ip)
            .bind(host.cpu)
            .bind(host.memory)
            .bind(host.enabled)
            .bind(&host.api_token)
            .bind(host.load_cpu)
            .bind(host.load_memory)
            .bind(host.load_disk)
            .bind(host.vlan_id)
            .bind(host.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn create_host(&self, host: &VmHost) -> Result<u64> {
        let result = sqlx::query("insert into vm_host (kind, region_id, name, ip, cpu, memory, enabled, api_token, load_cpu, load_memory, load_disk, vlan_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&host.kind)
            .bind(host.region_id)
            .bind(&host.name)
            .bind(&host.ip)
            .bind(host.cpu)
            .bind(host.memory)
            .bind(host.enabled)
            .bind(&host.api_token)
            .bind(host.load_cpu)
            .bind(host.load_memory)
            .bind(host.load_disk)
            .bind(host.vlan_id)
            .execute(&self.db)
            .await?;
        Ok(result.last_insert_id())
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

    async fn update_host_disk(&self, disk: &VmHostDisk) -> Result<()> {
        sqlx::query("update vm_host_disk set size=?,kind=?,interface=? where id=?")
            .bind(disk.size)
            .bind(disk.kind)
            .bind(disk.interface)
            .bind(disk.id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(())
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

    async fn list_cost_plans(&self) -> Result<Vec<VmCostPlan>> {
        sqlx::query_as("select * from vm_cost_plan order by created desc")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn insert_cost_plan(&self, cost_plan: &VmCostPlan) -> Result<u64> {
        Ok(sqlx::query("insert into vm_cost_plan(name,created,amount,currency,interval_amount,interval_type) values(?,?,?,?,?,?) returning id")
            .bind(&cost_plan.name)
            .bind(cost_plan.created)
            .bind(cost_plan.amount)
            .bind(&cost_plan.currency)
            .bind(cost_plan.interval_amount)
            .bind(cost_plan.interval_type)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?
            .try_get(0)?)
    }

    async fn update_cost_plan(&self, cost_plan: &VmCostPlan) -> Result<()> {
        sqlx::query("update vm_cost_plan set name=?,amount=?,currency=?,interval_amount=?,interval_type=? where id=?")
            .bind(&cost_plan.name)
            .bind(cost_plan.amount)
            .bind(&cost_plan.currency)
            .bind(cost_plan.interval_amount)
            .bind(cost_plan.interval_type)
            .bind(cost_plan.id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(())
    }

    async fn delete_cost_plan(&self, id: u64) -> Result<()> {
        sqlx::query("delete from vm_cost_plan where id=?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(())
    }

    async fn get_vm_template(&self, id: u64) -> Result<VmTemplate> {
        sqlx::query_as("select * from vm_template where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_vm_templates(&self) -> Result<Vec<VmTemplate>> {
        sqlx::query_as("select * from vm_template where enabled = 1")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn insert_vm_template(&self, template: &VmTemplate) -> Result<u64> {
        Ok(sqlx::query("insert into vm_template(name,enabled,created,expires,cpu,memory,disk_size,disk_type,disk_interface,cost_plan_id,region_id) values(?,?,?,?,?,?,?,?,?,?,?) returning id")
            .bind(&template.name)
            .bind(template.enabled)
            .bind(template.created)
            .bind(template.expires)
            .bind(template.cpu)
            .bind(template.memory)
            .bind(template.disk_size)
            .bind(template.disk_type)
            .bind(template.disk_interface)
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

    async fn count_active_vms_on_host(&self, host_id: u64) -> Result<u64> {
        let result: (i64,) =
            sqlx::query_as("select count(*) from vm where deleted = 0 and host_id = ?")
                .bind(host_id)
                .fetch_one(&self.db)
                .await
                .map_err(Error::new)?;
        Ok(result.0 as u64)
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
        Ok(sqlx::query("insert into vm(host_id,user_id,image_id,template_id,custom_template_id,ssh_key_id,created,expires,disk_id,mac_address,ref_code) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?) returning id")
            .bind(vm.host_id)
            .bind(vm.user_id)
            .bind(vm.image_id)
            .bind(vm.template_id)
            .bind(vm.custom_template_id)
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
            "update vm set image_id=?,template_id=?,custom_template_id=?,ssh_key_id=?,expires=?,disk_id=?,mac_address=? where id=?",
        )
            .bind(vm.image_id)
            .bind(vm.template_id)
            .bind(vm.custom_template_id)
            .bind(vm.ssh_key_id)
            .bind(vm.expires)
            .bind(vm.disk_id)
            .bind(&vm.mac_address)
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
            .bind(ip_assignment.id)
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
            .bind(vm_id)
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

    async fn list_vm_payment_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<VmPayment>> {
        sqlx::query_as(
            "select * from vm_payment where vm_id = ? order by created desc limit ? offset ?",
        )
        .bind(vm_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)
    }

    async fn list_vm_payment_by_method_and_type(
        &self,
        vm_id: u64,
        method: PaymentMethod,
        payment_type: PaymentType,
    ) -> Result<Vec<VmPayment>> {
        sqlx::query_as(
            "select * from vm_payment where vm_id = ? and payment_method = ? and payment_type = ? and expires > NOW() and is_paid = false order by created desc",
        )
        .bind(vm_id)
        .bind(method)
        .bind(payment_type)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)
    }

    async fn insert_vm_payment(&self, vm_payment: &VmPayment) -> Result<()> {
        sqlx::query("insert into vm_payment(id,vm_id,created,expires,amount,tax,currency,payment_method,payment_type,time_value,is_paid,rate,external_id,external_data,upgrade_params) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(&vm_payment.id)
            .bind(vm_payment.vm_id)
            .bind(vm_payment.created)
            .bind(vm_payment.expires)
            .bind(vm_payment.amount)
            .bind(vm_payment.tax)
            .bind(&vm_payment.currency)
            .bind(vm_payment.payment_method)
            .bind(vm_payment.payment_type)
            .bind(vm_payment.time_value)
            .bind(vm_payment.is_paid)
            .bind(vm_payment.rate)
            .bind(&vm_payment.external_id)
            .bind(&vm_payment.external_data)
            .bind(&vm_payment.upgrade_params)
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

    async fn get_vm_payment_by_ext_id(&self, id: &str) -> Result<VmPayment> {
        sqlx::query_as("select * from vm_payment where external_id=?")
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

        sqlx::query("update vm_payment set is_paid = true, external_data = ? where id = ?")
            .bind(&vm_payment.external_data)
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
            "select * from vm_payment where is_paid = true order by created desc limit 1",
        )
        .fetch_optional(&self.db)
        .await
        .map_err(Error::new)
    }

    async fn list_custom_pricing(&self, region_id: u64) -> Result<Vec<VmCustomPricing>> {
        sqlx::query_as("select * from vm_custom_pricing where region_id = ? and enabled = 1")
            .bind(region_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_custom_pricing(&self, id: u64) -> Result<VmCustomPricing> {
        sqlx::query_as("select * from vm_custom_pricing where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_custom_vm_template(&self, id: u64) -> Result<VmCustomTemplate> {
        sqlx::query_as("select * from vm_custom_template where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn insert_custom_vm_template(&self, template: &VmCustomTemplate) -> Result<u64> {
        Ok(sqlx::query("insert into vm_custom_template(cpu,memory,disk_size,disk_type,disk_interface,pricing_id) values(?,?,?,?,?,?) returning id")
            .bind(template.cpu)
            .bind(template.memory)
            .bind(template.disk_size)
            .bind(template.disk_type)
            .bind(template.disk_interface)
            .bind(template.pricing_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?
            .try_get(0)?)
    }

    async fn update_custom_vm_template(&self, template: &VmCustomTemplate) -> Result<()> {
        sqlx::query("update vm_custom_template set cpu=?, memory=?, disk_size=?, disk_type=?, disk_interface=?, pricing_id=? where id=?")
            .bind(template.cpu)
            .bind(template.memory)
            .bind(template.disk_size)
            .bind(template.disk_type)
            .bind(template.disk_interface)
            .bind(template.pricing_id)
            .bind(template.id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(())
    }

    async fn list_custom_pricing_disk(&self, pricing_id: u64) -> Result<Vec<VmCustomPricingDisk>> {
        sqlx::query_as("select * from vm_custom_pricing_disk where pricing_id=?")
            .bind(pricing_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_router(&self, router_id: u64) -> Result<Router> {
        sqlx::query_as("select * from router where id=?")
            .bind(router_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_routers(&self) -> Result<Vec<Router>> {
        sqlx::query_as("select * from router")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_vm_ip_assignment_by_ip(&self, ip: &str) -> Result<VmIpAssignment> {
        sqlx::query_as("select * from vm_ip_assignment where ip=? and deleted=0")
            .bind(ip)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_access_policy(&self, access_policy_id: u64) -> Result<AccessPolicy> {
        sqlx::query_as("select * from access_policy where id=?")
            .bind(access_policy_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_company(&self, company_id: u64) -> Result<Company> {
        sqlx::query_as("select * from company where id=?")
            .bind(company_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_vm_base_currency(&self, vm_id: u64) -> Result<String> {
        let currency = sqlx::query_scalar::<_, String>(
            "SELECT COALESCE(c.base_currency, 'EUR') as base_currency 
             FROM vm v
             JOIN vm_host vh ON v.host_id = vh.id  
             JOIN vm_host_region vhr ON vh.region_id = vhr.id
             LEFT JOIN company c ON vhr.company_id = c.id
             WHERE v.id = ?",
        )
        .bind(vm_id)
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;
        Ok(currency)
    }

    async fn insert_vm_history(&self, history: &VmHistory) -> Result<u64> {
        Ok(sqlx::query("insert into vm_history(vm_id,action_type,initiated_by_user,previous_state,new_state,metadata,description) values(?,?,?,?,?,?,?) returning id")
            .bind(history.vm_id)
            .bind(&history.action_type)
            .bind(history.initiated_by_user)
            .bind(&history.previous_state)
            .bind(&history.new_state)
            .bind(&history.metadata)
            .bind(&history.description)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?
            .try_get(0)?)
    }

    async fn list_vm_history(&self, vm_id: u64) -> Result<Vec<VmHistory>> {
        sqlx::query_as("select * from vm_history where vm_id = ? order by timestamp desc")
            .bind(vm_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_vm_history_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<VmHistory>> {
        sqlx::query_as(
            "select * from vm_history where vm_id = ? order by timestamp desc limit ? offset ?",
        )
        .bind(vm_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)
    }

    async fn get_vm_history(&self, id: u64) -> Result<VmHistory> {
        sqlx::query_as("select * from vm_history where id = ?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn execute_query(&self, query: &str) -> Result<u64> {
        let result = sqlx::query(query)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(result.rows_affected())
    }

    async fn execute_query_with_string_params(&self, query: &str, params: Vec<String>) -> Result<u64> {
        let mut query_builder = sqlx::query(query);
        for param in params {
            query_builder = query_builder.bind(param);
        }
        let result = query_builder
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(result.rows_affected())
    }

    async fn fetch_raw_strings(&self, query: &str) -> Result<Vec<(u64, String)>> {
        let rows = sqlx::query(query)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)?;
        
        let mut results = Vec::new();
        for row in rows {
            let id: u64 = row.try_get(0).map_err(Error::new)?;
            let value: String = row.try_get(1).map_err(Error::new)?;
            results.push((id, value));
        }
        Ok(results)
    }
}


#[cfg(feature = "nostr-domain")]
#[async_trait]
impl LNVPSNostrDb for LNVpsDbMysql {
    async fn get_handle(&self, handle_id: u64) -> Result<NostrDomainHandle> {
        sqlx::query_as("select * from nostr_domain_handle where id=?")
            .bind(handle_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_handle_by_name(&self, domain_id: u64, handle: &str) -> Result<NostrDomainHandle> {
        sqlx::query_as("select * from nostr_domain_handle where domain_id=? and handle=?")
            .bind(domain_id)
            .bind(handle)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn insert_handle(&self, handle: &NostrDomainHandle) -> Result<u64> {
        Ok(
            sqlx::query(
                "insert into nostr_domain_handle(domain_id,handle,pubkey,relays) values(?,?,?,?) returning id",
            )
                .bind(handle.domain_id)
                .bind(&handle.handle)
                .bind(&handle.pubkey)
                .bind(&handle.relays)
                .fetch_one(&self.db)
                .await
                .map_err(Error::new)?
                .try_get(0)?,
        )
    }

    async fn update_handle(&self, handle: &NostrDomainHandle) -> Result<()> {
        sqlx::query("update nostr_domain_handle set handle=?,pubkey=?,relays=? where id=?")
            .bind(&handle.handle)
            .bind(&handle.pubkey)
            .bind(&handle.relays)
            .bind(handle.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn delete_handle(&self, handle_id: u64) -> Result<()> {
        sqlx::query("delete from nostr_domain_handle where id=?")
            .bind(handle_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn list_handles(&self, domain_id: u64) -> Result<Vec<NostrDomainHandle>> {
        sqlx::query_as("select * from nostr_domain_handle where domain_id=?")
            .bind(domain_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_domain(&self, id: u64) -> Result<NostrDomain> {
        sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn get_domain_by_name(&self, name: &str) -> Result<NostrDomain> {
        sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain where name=?")
            .bind(name)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_domains(&self, owner_id: u64) -> Result<Vec<NostrDomain>> {
        sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain where owner_id=?")
            .bind(owner_id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn insert_domain(&self, domain: &NostrDomain) -> Result<u64> {
        Ok(
            sqlx::query(
                "insert into nostr_domain(owner_id,name,relays) values(?,?,?) returning id",
            )
            .bind(domain.owner_id)
            .bind(&domain.name)
            .bind(&domain.relays)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?
            .try_get(0)?,
        )
    }

    async fn delete_domain(&self, domain_id: u64) -> Result<()> {
        sqlx::query("delete from nostr_domain where id = ?")
            .bind(domain_id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(())
    }

    async fn list_all_domains(&self) -> Result<Vec<NostrDomain>> {
        sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_active_domains(&self) -> Result<Vec<NostrDomain>> {
        sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain where enabled=1")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn list_disabled_domains(&self) -> Result<Vec<NostrDomain>> {
        sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain where enabled=0")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn enable_domain(&self, domain_id: u64) -> Result<()> {
        sqlx::query(
            "update nostr_domain set enabled=1, last_status_change=CURRENT_TIMESTAMP where id=?",
        )
        .bind(domain_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn disable_domain(&self, domain_id: u64) -> Result<()> {
        sqlx::query(
            "update nostr_domain set enabled=0, last_status_change=CURRENT_TIMESTAMP where id=?",
        )
        .bind(domain_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }
}

#[cfg(feature = "admin")]
#[async_trait]
impl AdminDb for LNVpsDbMysql {
    async fn get_user_permissions(
        &self,
        user_id: u64,
    ) -> Result<std::collections::HashSet<(u16, u16)>> {
        let query = r#"
            SELECT DISTINCT rp.resource, rp.action
            FROM admin_role_assignments ara
            JOIN admin_role_permissions rp ON ara.role_id = rp.role_id
            WHERE ara.user_id = ?
            AND (ara.expires_at IS NULL OR ara.expires_at > NOW())
        "#;

        let rows = sqlx::query_as::<_, (u16, u16)>(query)
            .bind(user_id)
            .fetch_all(&self.db)
            .await?;

        Ok(rows.into_iter().collect())
    }

    async fn get_user_roles(&self, user_id: u64) -> Result<Vec<u64>> {
        let query = r#"
            SELECT role_id
            FROM admin_role_assignments
            WHERE user_id = ?
            AND (expires_at IS NULL OR expires_at > NOW())
        "#;

        let rows = sqlx::query_scalar::<_, u64>(query)
            .bind(user_id)
            .fetch_all(&self.db)
            .await?;

        Ok(rows)
    }

    async fn is_admin_user(&self, user_id: u64) -> Result<bool> {
        let query = r#"
            SELECT COUNT(*) > 0
            FROM admin_role_assignments
            WHERE user_id = ?
            AND (expires_at IS NULL OR expires_at > NOW())
        "#;

        let has_role = sqlx::query_scalar::<_, bool>(query)
            .bind(user_id)
            .fetch_one(&self.db)
            .await?;

        Ok(has_role)
    }

    async fn assign_user_role(&self, user_id: u64, role_id: u64, assigned_by: u64) -> Result<()> {
        let query = r#"
            INSERT INTO admin_role_assignments (user_id, role_id, assigned_by)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                assigned_by = VALUES(assigned_by),
                assigned_at = CURRENT_TIMESTAMP,
                expires_at = NULL
        "#;

        sqlx::query(query)
            .bind(user_id)
            .bind(role_id)
            .bind(assigned_by)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn revoke_user_role(&self, user_id: u64, role_id: u64) -> Result<()> {
        let query = r#"
            DELETE FROM admin_role_assignments
            WHERE user_id = ? AND role_id = ?
        "#;

        sqlx::query(query)
            .bind(user_id)
            .bind(role_id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn create_role(&self, name: &str, description: Option<&str>) -> Result<u64> {
        let query = r#"
            INSERT INTO admin_roles (name, description, is_system_role)
            VALUES (?, ?, false)
        "#;

        let result = sqlx::query(query)
            .bind(name)
            .bind(description)
            .execute(&self.db)
            .await?;

        Ok(result.last_insert_id())
    }

    async fn get_role(&self, role_id: u64) -> Result<AdminRole> {
        let query = r#"
            SELECT *
            FROM admin_roles
            WHERE id = ?
        "#;

        let role = sqlx::query_as::<_, AdminRole>(query)
            .bind(role_id)
            .fetch_one(&self.db)
            .await?;

        Ok(role)
    }

    async fn get_role_by_name(&self, name: &str) -> Result<AdminRole> {
        let query = r#"
            SELECT *
            FROM admin_roles
            WHERE name = ?
        "#;

        let role = sqlx::query_as::<_, AdminRole>(query)
            .bind(name)
            .fetch_one(&self.db)
            .await?;

        Ok(role)
    }

    async fn list_roles(&self) -> Result<Vec<AdminRole>> {
        let query = r#"
            SELECT *
            FROM admin_roles
            ORDER BY is_system_role DESC, name ASC
        "#;

        let roles = sqlx::query_as::<_, AdminRole>(query)
            .fetch_all(&self.db)
            .await?;

        Ok(roles)
    }

    async fn update_role(&self, role: &AdminRole) -> Result<()> {
        let query = r#"
            UPDATE admin_roles
            SET name = ?, description = ?
            WHERE id = ? AND is_system_role = false
        "#;

        let result = sqlx::query(query)
            .bind(&role.name)
            .bind(&role.description)
            .bind(role.id)
            .execute(&self.db)
            .await?;

        if result.rows_affected() == 0 {
            bail!("Role not found or is a system role (cannot be updated)");
        }

        Ok(())
    }

    async fn delete_role(&self, role_id: u64) -> Result<()> {
        // First check if role has any assignments
        let assignments_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM admin_role_assignments WHERE role_id = ?",
        )
        .bind(role_id)
        .fetch_one(&self.db)
        .await?;

        if assignments_count > 0 {
            bail!(
                "Cannot delete role: {} active user assignments exist",
                assignments_count
            );
        }

        let query = r#"
            DELETE FROM admin_roles
            WHERE id = ? AND is_system_role = false
        "#;

        let result = sqlx::query(query).bind(role_id).execute(&self.db).await?;

        if result.rows_affected() == 0 {
            bail!("Role not found or is a system role (cannot be deleted)");
        }

        Ok(())
    }

    async fn add_role_permission(&self, role_id: u64, resource: u16, action: u16) -> Result<()> {
        let query = r#"
            INSERT IGNORE INTO admin_role_permissions (role_id, resource, action)
            VALUES (?, ?, ?)
        "#;

        sqlx::query(query)
            .bind(role_id)
            .bind(resource)
            .bind(action)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn remove_role_permission(&self, role_id: u64, resource: u16, action: u16) -> Result<()> {
        let query = r#"
            DELETE FROM admin_role_permissions
            WHERE role_id = ? AND resource = ? AND action = ?
        "#;

        sqlx::query(query)
            .bind(role_id)
            .bind(resource)
            .bind(action)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn get_role_permissions(&self, role_id: u64) -> Result<Vec<(u16, u16)>> {
        let query = r#"
            SELECT resource, action
            FROM admin_role_permissions
            WHERE role_id = ?
            ORDER BY resource, action
        "#;

        let permissions = sqlx::query_as::<_, (u16, u16)>(query)
            .bind(role_id)
            .fetch_all(&self.db)
            .await?;

        Ok(permissions)
    }

    async fn get_user_role_assignments(&self, user_id: u64) -> Result<Vec<AdminRoleAssignment>> {
        let query = r#"
            SELECT *
            FROM admin_role_assignments
            WHERE user_id = ?
            ORDER BY assigned_at DESC
        "#;

        let assignments = sqlx::query_as::<_, AdminRoleAssignment>(query)
            .bind(user_id)
            .fetch_all(&self.db)
            .await?;

        Ok(assignments)
    }

    async fn count_role_users(&self, role_id: u64) -> Result<u64> {
        let query = r#"
            SELECT COUNT(*)
            FROM admin_role_assignments
            WHERE role_id = ?
            AND (expires_at IS NULL OR expires_at > NOW())
        "#;

        let count = sqlx::query_scalar::<_, i64>(query)
            .bind(role_id)
            .fetch_one(&self.db)
            .await?;

        Ok(count as u64)
    }

    async fn admin_list_users(
        &self,
        limit: u64,
        offset: u64,
        search_pubkey: Option<&str>,
    ) -> Result<(Vec<crate::AdminUserInfo>, u64)> {
        let (where_clause, search_param) = if let Some(pubkey) = search_pubkey {
            if pubkey.len() == 64 {
                (" WHERE HEX(u.pubkey) = ? ", Some(pubkey.to_uppercase()))
            } else {
                return Err(anyhow::anyhow!(
                    "Search only supports 64-character hex pubkeys"
                ));
            }
        } else {
            ("", None)
        };

        // Single query to get all user data with stats
        let query = format!(
            r#"
            SELECT 
                u.id,
                u.pubkey,
                u.created,
                u.email,
                u.contact_nip17,
                u.contact_email,
                u.country_code,
                u.billing_name,
                u.billing_address_1,
                u.billing_address_2,
                u.billing_city,
                u.billing_state,
                u.billing_postcode,
                u.billing_tax_id,
                COALESCE(vm_stats.vm_count, 0) as vm_count,
                CASE WHEN admin_roles.user_id IS NOT NULL THEN 1 ELSE 0 END as is_admin
            FROM users u
            LEFT JOIN (
                SELECT 
                    user_id, 
                    COUNT(*) as vm_count
                FROM vm 
                WHERE deleted = 0 
                GROUP BY user_id
            ) vm_stats ON u.id = vm_stats.user_id
            LEFT JOIN (
                SELECT DISTINCT user_id
                FROM admin_role_assignments
                WHERE expires_at IS NULL OR expires_at > NOW()
            ) admin_roles ON u.id = admin_roles.user_id
            {}
            ORDER BY u.id
            LIMIT ? OFFSET ?
        "#,
            where_clause
        );

        let mut query_builder = sqlx::query_as::<_, crate::AdminUserInfo>(&query);

        if let Some(ref pubkey_hex) = search_param {
            query_builder = query_builder.bind(pubkey_hex);
        }

        let users = query_builder
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await?;

        // Get total count
        let count_query = format!("SELECT COUNT(*) FROM users u {}", where_clause);
        let mut count_query_builder = sqlx::query_scalar::<_, i64>(&count_query);

        if let Some(ref pubkey_hex) = search_param {
            count_query_builder = count_query_builder.bind(pubkey_hex);
        }

        let total = count_query_builder.fetch_one(&self.db).await? as u64;

        Ok((users, total))
    }

    async fn admin_list_regions(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<VmHostRegion>, u64)> {
        // Get total count
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vm_host_region")
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?;

        // Get paginated results
        let regions = sqlx::query_as::<_, VmHostRegion>(
            "SELECT * FROM vm_host_region ORDER BY name LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)?;

        Ok((regions, total as u64))
    }

    async fn admin_create_region(&self, name: &str, company_id: Option<u64>) -> Result<u64> {
        let id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO vm_host_region (name, enabled, company_id) VALUES (?, ?, ?) RETURNING id",
        )
        .bind(name)
        .bind(true) // New regions are enabled by default
        .bind(company_id)
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(id as u64)
    }

    async fn admin_update_region(&self, region: &VmHostRegion) -> Result<()> {
        sqlx::query("UPDATE vm_host_region SET name = ?, enabled = ?, company_id = ? WHERE id = ?")
            .bind(&region.name)
            .bind(region.enabled)
            .bind(region.company_id)
            .bind(region.id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        Ok(())
    }

    async fn admin_delete_region(&self, region_id: u64) -> Result<()> {
        // First check if any hosts are assigned to this region
        let host_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM vm_host WHERE region_id = ?")
                .bind(region_id)
                .fetch_one(&self.db)
                .await
                .map_err(Error::new)?;

        if host_count > 0 {
            return Err(anyhow::anyhow!(
                "Cannot delete region with {} assigned hosts",
                host_count
            ));
        }

        // Disable the region instead of deleting to preserve referential integrity
        sqlx::query("UPDATE vm_host_region SET enabled = ? WHERE id = ?")
            .bind(false)
            .bind(region_id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        Ok(())
    }

    async fn admin_count_region_hosts(&self, region_id: u64) -> Result<u64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vm_host WHERE region_id = ?")
            .bind(region_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?;

        Ok(count as u64)
    }

    async fn admin_get_region_stats(&self, region_id: u64) -> Result<RegionStats> {
        // Get comprehensive region statistics with a single efficient query
        // Use CAST to ensure we get the right SQL types for Rust compatibility
        let row: (i64, i64, Option<u64>, Option<u64>, i64) = sqlx::query_as(
            r#"
            SELECT 
                COUNT(DISTINCT h.id) as host_count,
                COUNT(DISTINCT CASE WHEN v.deleted = 0 THEN v.id END) as total_vms,
                CAST(COALESCE(SUM(DISTINCT h.cpu), 0) AS UNSIGNED) as total_cpu_cores,
                CAST(COALESCE(SUM(DISTINCT h.memory), 0) AS UNSIGNED) as total_memory_bytes,
                COUNT(DISTINCT CASE WHEN v.deleted = 0 THEN ip.id END) as total_ip_assignments
            FROM vm_host h
            LEFT JOIN vm v ON v.host_id = h.id
            LEFT JOIN vm_ip_assignment ip ON ip.vm_id = v.id AND ip.deleted = 0
            WHERE h.region_id = ?
            "#,
        )
        .bind(region_id)
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(RegionStats {
            host_count: row.0 as u64,
            total_vms: row.1 as u64,
            total_cpu_cores: row.2.unwrap_or(0),
            total_memory_bytes: row.3.unwrap_or(0),
            total_ip_assignments: row.4 as u64,
        })
    }

    async fn admin_list_vm_os_images(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<VmOsImage>, u64)> {
        // Get paginated list of VM OS images
        let images = sqlx::query_as::<_, VmOsImage>(
            "SELECT * FROM vm_os_image ORDER BY id LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)?;

        // Get total count
        let total_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vm_os_image")
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?;

        Ok((images, total_count.0 as u64))
    }

    async fn admin_get_vm_os_image(&self, image_id: u64) -> Result<VmOsImage> {
        sqlx::query_as("SELECT * FROM vm_os_image WHERE id = ?")
            .bind(image_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn admin_create_vm_os_image(&self, image: &VmOsImage) -> Result<u64> {
        let result = sqlx::query(
            r#"
            INSERT INTO vm_os_image (distribution, flavour, version, enabled, release_date, url, default_username)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(image.distribution as u16)
        .bind(&image.flavour)
        .bind(&image.version)
        .bind(image.enabled)
        .bind(image.release_date)
        .bind(&image.url)
        .bind(&image.default_username)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(result.last_insert_id())
    }

    async fn admin_update_vm_os_image(&self, image: &VmOsImage) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE vm_os_image 
            SET distribution = ?, flavour = ?, version = ?, enabled = ?, release_date = ?, url = ?, default_username = ?
            WHERE id = ?
            "#
        )
        .bind(image.distribution as u16)
        .bind(&image.flavour)
        .bind(&image.version)
        .bind(image.enabled)
        .bind(image.release_date)
        .bind(&image.url)
        .bind(&image.default_username)
        .bind(image.id)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(())
    }

    async fn admin_delete_vm_os_image(&self, image_id: u64) -> Result<()> {
        // Check if the image is referenced by any VMs
        let vm_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vm WHERE image_id = ?")
            .bind(image_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?;

        if vm_count.0 > 0 {
            bail!(
                "Cannot delete VM OS image: {} VMs are using this image",
                vm_count.0
            );
        }

        sqlx::query("DELETE FROM vm_os_image WHERE id = ?")
            .bind(image_id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        Ok(())
    }

    async fn list_vm_templates_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<VmTemplate>, i64)> {
        // Get paginated list of VM templates
        let templates = sqlx::query_as::<_, VmTemplate>(
            "SELECT * FROM vm_template ORDER BY id LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)?;

        // Get total count
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vm_template")
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?;

        Ok((templates, total.0))
    }

    async fn update_vm_template(&self, template: &VmTemplate) -> Result<()> {
        sqlx::query(
            r#"UPDATE vm_template SET 
               name = ?, enabled = ?, expires = ?, cpu = ?, memory = ?, 
               disk_size = ?, disk_type = ?, disk_interface = ?, 
               cost_plan_id = ?, region_id = ?
               WHERE id = ?"#,
        )
        .bind(&template.name)
        .bind(template.enabled)
        .bind(template.expires)
        .bind(template.cpu)
        .bind(template.memory)
        .bind(template.disk_size)
        .bind(template.disk_type)
        .bind(template.disk_interface)
        .bind(template.cost_plan_id)
        .bind(template.region_id)
        .bind(template.id)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;
        Ok(())
    }

    async fn delete_vm_template(&self, template_id: u64) -> Result<()> {
        sqlx::query("DELETE FROM vm_template WHERE id = ?")
            .bind(template_id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(())
    }

    async fn check_vm_template_usage(&self, template_id: u64) -> Result<i64> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vm WHERE template_id = ?")
            .bind(template_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(count.0)
    }

    async fn admin_list_hosts_with_regions_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<(VmHost, VmHostRegion)>, u64)> {
        // Get total count (including disabled hosts)
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vm_host h, vm_host_region hr WHERE h.region_id = hr.id",
        )
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;

        // Get paginated results with region info (including disabled hosts)
        let rows = sqlx::query(
            "SELECT h.*, hr.id as region_id, hr.name as region_name, hr.enabled as region_enabled, hr.company_id as region_company_id 
             FROM vm_host h, vm_host_region hr 
             WHERE h.region_id = hr.id 
             ORDER BY h.name LIMIT ? OFFSET ?"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)?;

        let mut results = Vec::new();
        for row in rows {
            let host = VmHost {
                id: row.get("id"),
                kind: row.get("kind"),
                region_id: row.get("region_id"),
                name: row.get("name"),
                ip: row.get("ip"),
                cpu: row.get("cpu"),
                memory: row.get("memory"),
                enabled: row.get("enabled"),
                api_token: row.get("api_token"),
                load_cpu: row.get("load_cpu"),
                load_memory: row.get("load_memory"),
                load_disk: row.get("load_disk"),
                vlan_id: row.get("vlan_id"),
            };

            let region = VmHostRegion {
                id: row.get("region_id"),
                name: row.get("region_name"),
                enabled: row.get("region_enabled"),
                company_id: row.get("region_company_id"),
            };

            results.push((host, region));
        }

        Ok((results, total as u64))
    }

    async fn insert_custom_pricing(&self, pricing: &VmCustomPricing) -> Result<u64> {
        let query = r#"
            INSERT INTO vm_custom_pricing (name, enabled, created, expires, region_id, currency, cpu_cost, memory_cost, ip4_cost, ip6_cost)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        let result = sqlx::query(query)
            .bind(&pricing.name)
            .bind(pricing.enabled)
            .bind(pricing.created)
            .bind(pricing.expires)
            .bind(pricing.region_id)
            .bind(&pricing.currency)
            .bind(pricing.cpu_cost)
            .bind(pricing.memory_cost)
            .bind(pricing.ip4_cost)
            .bind(pricing.ip6_cost)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        Ok(result.last_insert_id())
    }

    async fn update_custom_pricing(&self, pricing: &VmCustomPricing) -> Result<()> {
        let query = r#"
            UPDATE vm_custom_pricing 
            SET name = ?, enabled = ?, expires = ?, region_id = ?, currency = ?, 
                cpu_cost = ?, memory_cost = ?, ip4_cost = ?, ip6_cost = ?
            WHERE id = ?
        "#;

        let result = sqlx::query(query)
            .bind(&pricing.name)
            .bind(pricing.enabled)
            .bind(pricing.expires)
            .bind(pricing.region_id)
            .bind(&pricing.currency)
            .bind(pricing.cpu_cost)
            .bind(pricing.memory_cost)
            .bind(pricing.ip4_cost)
            .bind(pricing.ip6_cost)
            .bind(pricing.id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        if result.rows_affected() == 0 {
            bail!("Custom pricing model not found");
        }

        Ok(())
    }

    async fn delete_custom_pricing(&self, id: u64) -> Result<()> {
        let query = "DELETE FROM vm_custom_pricing WHERE id = ?";
        let result = sqlx::query(query)
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        if result.rows_affected() == 0 {
            bail!("Custom pricing model not found");
        }

        Ok(())
    }

    async fn insert_custom_pricing_disk(&self, disk: &VmCustomPricingDisk) -> Result<u64> {
        let query = r#"
            INSERT INTO vm_custom_pricing_disk (pricing_id, kind, interface, cost)
            VALUES (?, ?, ?, ?)
        "#;

        let result = sqlx::query(query)
            .bind(disk.pricing_id)
            .bind(disk.kind as u16)
            .bind(disk.interface as u16)
            .bind(disk.cost)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        Ok(result.last_insert_id())
    }

    async fn delete_custom_pricing_disks(&self, pricing_id: u64) -> Result<()> {
        let query = "DELETE FROM vm_custom_pricing_disk WHERE pricing_id = ?";
        sqlx::query(query)
            .bind(pricing_id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;
        Ok(())
    }

    async fn count_custom_templates_by_pricing(&self, pricing_id: u64) -> Result<u64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vm_custom_template WHERE pricing_id = ?",
        )
        .bind(pricing_id)
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(count as u64)
    }

    async fn list_custom_templates_by_pricing_paginated(
        &self,
        pricing_id: u64,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<VmCustomTemplate>, u64)> {
        let total = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vm_custom_template WHERE pricing_id = ?",
        )
        .bind(pricing_id)
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;

        let templates = sqlx::query_as::<_, VmCustomTemplate>(
            "SELECT * FROM vm_custom_template WHERE pricing_id = ? ORDER BY id LIMIT ? OFFSET ?",
        )
        .bind(pricing_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)?;

        Ok((templates, total as u64))
    }

    async fn insert_custom_template(&self, template: &VmCustomTemplate) -> Result<u64> {
        let query = r#"
            INSERT INTO vm_custom_template (cpu, memory, disk_size, disk_type, disk_interface, pricing_id)
            VALUES (?, ?, ?, ?, ?, ?)
        "#;

        let result = sqlx::query(query)
            .bind(template.cpu)
            .bind(template.memory)
            .bind(template.disk_size)
            .bind(template.disk_type as u16)
            .bind(template.disk_interface as u16)
            .bind(template.pricing_id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        Ok(result.last_insert_id())
    }

    async fn get_custom_template(&self, id: u64) -> Result<VmCustomTemplate> {
        let template =
            sqlx::query_as::<_, VmCustomTemplate>("SELECT * FROM vm_custom_template WHERE id = ?")
                .bind(id)
                .fetch_one(&self.db)
                .await
                .map_err(Error::new)?;

        Ok(template)
    }

    async fn update_custom_template(&self, template: &VmCustomTemplate) -> Result<()> {
        let query = r#"
            UPDATE vm_custom_template 
            SET cpu = ?, memory = ?, disk_size = ?, disk_type = ?, disk_interface = ?, pricing_id = ?
            WHERE id = ?
        "#;

        let result = sqlx::query(query)
            .bind(template.cpu)
            .bind(template.memory)
            .bind(template.disk_size)
            .bind(template.disk_type as u16)
            .bind(template.disk_interface as u16)
            .bind(template.pricing_id)
            .bind(template.id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        if result.rows_affected() == 0 {
            bail!("Custom template not found");
        }

        Ok(())
    }

    async fn delete_custom_template(&self, id: u64) -> Result<()> {
        let query = "DELETE FROM vm_custom_template WHERE id = ?";
        let result = sqlx::query(query)
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        if result.rows_affected() == 0 {
            bail!("Custom template not found");
        }

        Ok(())
    }

    async fn count_vms_by_custom_template(&self, template_id: u64) -> Result<u64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vm WHERE custom_template_id = ? AND deleted = false",
        )
        .bind(template_id)
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(count as u64)
    }

    async fn admin_list_companies(&self, limit: u64, offset: u64) -> Result<(Vec<Company>, u64)> {
        let companies = sqlx::query_as::<_, Company>(
            "SELECT * FROM company ORDER BY created DESC LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)?;

        let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM company")
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?;

        Ok((companies, total as u64))
    }

    async fn admin_get_company(&self, company_id: u64) -> Result<Company> {
        sqlx::query_as::<_, Company>("SELECT * FROM company WHERE id = ?")
            .bind(company_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn admin_create_company(&self, company: &Company) -> Result<u64> {
        let result = sqlx::query(
            r#"INSERT INTO company (name, address_1, address_2, city, state, country_code, tax_id, postcode, phone, email, created)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())"#,
        )
        .bind(&company.name)
        .bind(&company.address_1)
        .bind(&company.address_2)
        .bind(&company.city)
        .bind(&company.state)
        .bind(&company.country_code)
        .bind(&company.tax_id)
        .bind(&company.postcode)
        .bind(&company.phone)
        .bind(&company.email)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(result.last_insert_id())
    }

    async fn admin_update_company(&self, company: &Company) -> Result<()> {
        sqlx::query(
            r#"UPDATE company SET 
               name = ?, address_1 = ?, address_2 = ?, city = ?, state = ?, 
               country_code = ?, tax_id = ?, postcode = ?, phone = ?, email = ?
               WHERE id = ?"#,
        )
        .bind(&company.name)
        .bind(&company.address_1)
        .bind(&company.address_2)
        .bind(&company.city)
        .bind(&company.state)
        .bind(&company.country_code)
        .bind(&company.tax_id)
        .bind(&company.postcode)
        .bind(&company.phone)
        .bind(&company.email)
        .bind(company.id)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(())
    }

    async fn admin_delete_company(&self, company_id: u64) -> Result<()> {
        // Check if company has any regions assigned
        let region_count = self.admin_count_company_regions(company_id).await?;
        if region_count > 0 {
            return Err(anyhow::anyhow!(
                "Cannot delete company with {} assigned regions",
                region_count
            ));
        }

        sqlx::query("DELETE FROM company WHERE id = ?")
            .bind(company_id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        Ok(())
    }

    async fn admin_count_company_regions(&self, company_id: u64) -> Result<u64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vm_host_region WHERE company_id = ?",
        )
        .bind(company_id)
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(count as u64)
    }

    async fn admin_get_payments_by_date_range(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<VmPayment>> {
        sqlx::query_as(
            "SELECT * FROM vm_payment WHERE created >= ? AND created < ? AND is_paid = true ORDER BY created",
        )
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)
    }

    async fn admin_get_payments_by_date_range_and_company(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
    ) -> Result<Vec<VmPayment>> {
        sqlx::query_as(
            "SELECT vp.* FROM vm_payment vp
             JOIN vm v ON vp.vm_id = v.id
             JOIN vm_host vh ON v.host_id = vh.id
             JOIN vm_host_region vhr ON vh.region_id = vhr.id
             WHERE vp.created >= ? AND vp.created < ? AND vp.is_paid = true AND vhr.company_id = ?
             ORDER BY vp.created",
        )
        .bind(start_date)
        .bind(end_date)
        .bind(company_id)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)
    }

    async fn admin_get_payments_with_company_info(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
        currency: Option<&str>,
    ) -> Result<Vec<VmPaymentWithCompany>> {
        match currency {
            Some(currency) => {
                sqlx::query_as(
                    "SELECT vp.*, c.id as company_id, c.name as company_name, c.base_currency as company_base_currency
                     FROM vm_payment vp
                     JOIN vm v ON vp.vm_id = v.id
                     JOIN vm_host vh ON v.host_id = vh.id
                     JOIN vm_host_region vhr ON vh.region_id = vhr.id
                     JOIN company c ON vhr.company_id = c.id
                     WHERE vp.created >= ? AND vp.created < ? AND vp.is_paid = true AND c.id = ? AND vp.currency = ?
                     ORDER BY vp.created"
                )
                .bind(start_date)
                .bind(end_date)
                .bind(company_id)
                .bind(currency)
                .fetch_all(&self.db).await.map_err(Error::new)
            },
            None => {
                sqlx::query_as(
                    "SELECT vp.*, c.id as company_id, c.name as company_name, c.base_currency as company_base_currency
                     FROM vm_payment vp
                     JOIN vm v ON vp.vm_id = v.id
                     JOIN vm_host vh ON v.host_id = vh.id
                     JOIN vm_host_region vhr ON vh.region_id = vhr.id
                     JOIN company c ON vhr.company_id = c.id
                     WHERE vp.created >= ? AND vp.created < ? AND vp.is_paid = true AND c.id = ?
                     ORDER BY vp.created"
                )
                .bind(start_date)
                .bind(end_date)
                .bind(company_id)
                .fetch_all(&self.db).await.map_err(Error::new)
            }
        }
    }

    async fn admin_list_ip_ranges(
        &self,
        limit: u64,
        offset: u64,
        region_id: Option<u64>,
    ) -> Result<(Vec<IpRange>, u64)> {
        let (ip_ranges, total) = if let Some(region_id) = region_id {
            // Filter by region
            let ip_ranges = sqlx::query_as::<_, IpRange>(
                "SELECT * FROM ip_range WHERE region_id = ? ORDER BY cidr LIMIT ? OFFSET ?",
            )
            .bind(region_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)?;

            let total =
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ip_range WHERE region_id = ?")
                    .bind(region_id)
                    .fetch_one(&self.db)
                    .await
                    .map_err(Error::new)?;

            (ip_ranges, total)
        } else {
            // Get all IP ranges
            let ip_ranges = sqlx::query_as::<_, IpRange>(
                "SELECT * FROM ip_range ORDER BY cidr LIMIT ? OFFSET ?",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)?;

            let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ip_range")
                .fetch_one(&self.db)
                .await
                .map_err(Error::new)?;

            (ip_ranges, total)
        };

        Ok((ip_ranges, total as u64))
    }

    async fn admin_get_ip_range(&self, ip_range_id: u64) -> Result<IpRange> {
        sqlx::query_as::<_, IpRange>("SELECT * FROM ip_range WHERE id = ?")
            .bind(ip_range_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn admin_create_ip_range(&self, ip_range: &IpRange) -> Result<u64> {
        let result = sqlx::query(
            r#"INSERT INTO ip_range (cidr, gateway, enabled, region_id, reverse_zone_id, access_policy_id, allocation_mode, use_full_range)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&ip_range.cidr)
        .bind(&ip_range.gateway)
        .bind(ip_range.enabled)
        .bind(ip_range.region_id)
        .bind(&ip_range.reverse_zone_id)
        .bind(ip_range.access_policy_id)
        .bind(ip_range.allocation_mode as u16)
        .bind(ip_range.use_full_range)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(result.last_insert_id())
    }

    async fn admin_update_ip_range(&self, ip_range: &IpRange) -> Result<()> {
        sqlx::query(
            r#"UPDATE ip_range SET 
               cidr = ?, gateway = ?, enabled = ?, region_id = ?, 
               reverse_zone_id = ?, access_policy_id = ?, allocation_mode = ?, use_full_range = ?
               WHERE id = ?"#,
        )
        .bind(&ip_range.cidr)
        .bind(&ip_range.gateway)
        .bind(ip_range.enabled)
        .bind(ip_range.region_id)
        .bind(&ip_range.reverse_zone_id)
        .bind(ip_range.access_policy_id)
        .bind(ip_range.allocation_mode as u16)
        .bind(ip_range.use_full_range)
        .bind(ip_range.id)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(())
    }

    async fn admin_delete_ip_range(&self, ip_range_id: u64) -> Result<()> {
        // Check if IP range has any assignments
        let assignment_count = self.admin_count_ip_range_assignments(ip_range_id).await?;
        if assignment_count > 0 {
            return Err(anyhow::anyhow!(
                "Cannot delete IP range with {} active IP assignments",
                assignment_count
            ));
        }

        sqlx::query("DELETE FROM ip_range WHERE id = ?")
            .bind(ip_range_id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        Ok(())
    }

    async fn admin_count_ip_range_assignments(&self, ip_range_id: u64) -> Result<u64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vm_ip_assignment WHERE ip_range_id = ? AND deleted = false",
        )
        .bind(ip_range_id)
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(count as u64)
    }

    async fn admin_list_access_policies(&self) -> Result<Vec<AccessPolicy>> {
        sqlx::query_as::<_, AccessPolicy>("SELECT * FROM access_policy ORDER BY name")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn admin_list_access_policies_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<AccessPolicy>, u64)> {
        let access_policies = sqlx::query_as::<_, AccessPolicy>(
            "SELECT * FROM access_policy ORDER BY name LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(Error::new)?;

        let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM access_policy")
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?;

        Ok((access_policies, total as u64))
    }

    async fn admin_get_access_policy(&self, access_policy_id: u64) -> Result<AccessPolicy> {
        sqlx::query_as::<_, AccessPolicy>("SELECT * FROM access_policy WHERE id = ?")
            .bind(access_policy_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn admin_create_access_policy(&self, access_policy: &AccessPolicy) -> Result<u64> {
        let result = sqlx::query(
            r#"INSERT INTO access_policy (name, kind, router_id, interface)
               VALUES (?, ?, ?, ?)"#,
        )
        .bind(&access_policy.name)
        .bind(access_policy.kind as u16)
        .bind(access_policy.router_id)
        .bind(&access_policy.interface)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(result.last_insert_id())
    }

    async fn admin_update_access_policy(&self, access_policy: &AccessPolicy) -> Result<()> {
        sqlx::query(
            r#"UPDATE access_policy SET 
               name = ?, kind = ?, router_id = ?, interface = ?
               WHERE id = ?"#,
        )
        .bind(&access_policy.name)
        .bind(access_policy.kind as u16)
        .bind(access_policy.router_id)
        .bind(&access_policy.interface)
        .bind(access_policy.id)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(())
    }

    async fn admin_delete_access_policy(&self, access_policy_id: u64) -> Result<()> {
        // Check if access policy is used by any IP ranges
        let usage_count = self
            .admin_count_access_policy_ip_ranges(access_policy_id)
            .await?;
        if usage_count > 0 {
            return Err(anyhow::anyhow!(
                "Cannot delete access policy used by {} IP ranges",
                usage_count
            ));
        }

        sqlx::query("DELETE FROM access_policy WHERE id = ?")
            .bind(access_policy_id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        Ok(())
    }

    async fn admin_count_access_policy_ip_ranges(&self, access_policy_id: u64) -> Result<u64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM ip_range WHERE access_policy_id = ?",
        )
        .bind(access_policy_id)
        .fetch_one(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(count as u64)
    }

    async fn admin_list_routers(&self) -> Result<Vec<Router>> {
        sqlx::query_as::<_, Router>("SELECT * FROM router ORDER BY name")
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn admin_list_routers_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<Router>, u64)> {
        let routers =
            sqlx::query_as::<_, Router>("SELECT * FROM router ORDER BY name LIMIT ? OFFSET ?")
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.db)
                .await
                .map_err(Error::new)?;

        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM router")
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?;

        Ok((routers, total.0 as u64))
    }

    async fn admin_get_router(&self, router_id: u64) -> Result<Router> {
        sqlx::query_as::<_, Router>("SELECT * FROM router WHERE id = ?")
            .bind(router_id)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }

    async fn admin_create_router(&self, router: &Router) -> Result<u64> {
        let result = sqlx::query(
            "INSERT INTO router (name, enabled, kind, url, token) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&router.name)
        .bind(router.enabled)
        .bind(router.kind.clone())
        .bind(&router.url)
        .bind(&router.token)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(result.last_insert_id())
    }

    async fn admin_update_router(&self, router: &Router) -> Result<()> {
        sqlx::query(
            "UPDATE router SET name = ?, enabled = ?, kind = ?, url = ?, token = ? WHERE id = ?",
        )
        .bind(&router.name)
        .bind(router.enabled)
        .bind(router.kind.clone())
        .bind(&router.url)
        .bind(&router.token)
        .bind(router.id)
        .execute(&self.db)
        .await
        .map_err(Error::new)?;

        Ok(())
    }

    async fn admin_delete_router(&self, router_id: u64) -> Result<()> {
        // Check if router is used by any access policies
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM access_policy WHERE router_id = ?")
                .bind(router_id)
                .fetch_one(&self.db)
                .await
                .map_err(Error::new)?;

        if count.0 > 0 {
            return Err(anyhow::anyhow!(
                "Cannot delete router: {} access policies are using this router",
                count.0
            ));
        }

        sqlx::query("DELETE FROM router WHERE id = ?")
            .bind(router_id)
            .execute(&self.db)
            .await
            .map_err(Error::new)?;

        Ok(())
    }

    async fn admin_count_router_access_policies(&self, router_id: u64) -> Result<u64> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM access_policy WHERE router_id = ?")
                .bind(router_id)
                .fetch_one(&self.db)
                .await
                .map_err(Error::new)?;

        Ok(count.0 as u64)
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
    ) -> Result<(Vec<crate::Vm>, u64)> {
        // Resolve user_id from pubkey if provided
        let resolved_user_id = if let Some(pk) = pubkey {
            // Use SQL UNHEX to decode the pubkey and find the user
            let user_result: Result<(u64,), _> =
                sqlx::query_as("SELECT id FROM users WHERE pubkey = UNHEX(?)")
                    .bind(pk)
                    .fetch_one(&self.db)
                    .await;

            match user_result {
                Ok((user_id,)) => Some(user_id),
                Err(_) => return Ok((vec![], 0)), // No user found, return empty
            }
        } else {
            user_id
        };

        // Build queries using query builder
        let base_from = "vm v LEFT JOIN vm_host h ON v.host_id = h.id";

        // Start with the base query
        let mut count_query = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM ");
        count_query.push(base_from);

        let mut data_query = sqlx::QueryBuilder::new("SELECT v.* FROM ");
        data_query.push(base_from);

        // Add WHERE conditions
        let mut has_conditions = false;

        if let Some(uid) = resolved_user_id {
            if !has_conditions {
                count_query.push(" WHERE ");
                data_query.push(" WHERE ");
                has_conditions = true;
            } else {
                count_query.push(" AND ");
                data_query.push(" AND ");
            }
            count_query.push("v.user_id = ").push_bind(uid);
            data_query.push("v.user_id = ").push_bind(uid);
        }

        if let Some(hid) = host_id {
            if !has_conditions {
                count_query.push(" WHERE ");
                data_query.push(" WHERE ");
                has_conditions = true;
            } else {
                count_query.push(" AND ");
                data_query.push(" AND ");
            }
            count_query.push("v.host_id = ").push_bind(hid);
            data_query.push("v.host_id = ").push_bind(hid);
        }

        if let Some(rid) = region_id {
            if !has_conditions {
                count_query.push(" WHERE ");
                data_query.push(" WHERE ");
                has_conditions = true;
            } else {
                count_query.push(" AND ");
                data_query.push(" AND ");
            }
            count_query.push("h.region_id = ").push_bind(rid);
            data_query.push("h.region_id = ").push_bind(rid);
        }

        // Handle deleted filter
        match include_deleted {
            Some(false) | None => {
                // Exclude deleted VMs (default behavior or explicitly requested)
                if !has_conditions {
                    count_query.push(" WHERE ");
                    data_query.push(" WHERE ");
                } else {
                    count_query.push(" AND ");
                    data_query.push(" AND ");
                }
                count_query.push("v.deleted = FALSE");
                data_query.push("v.deleted = FALSE");
            }
            Some(true) => {
                // Include both deleted and non-deleted VMs - no additional filter needed
            }
        }

        // Execute count query
        let total: i64 = count_query
            .build_query_scalar()
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)?;

        // Add ordering and pagination to data query
        data_query
            .push(" ORDER BY v.id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);

        // Execute data query
        let vms: Vec<Vm> = data_query
            .build_query_as()
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)?;

        Ok((vms, total as u64))
    }

    async fn get_user_by_pubkey(&self, pubkey: &[u8]) -> Result<crate::User> {
        sqlx::query_as("SELECT * FROM users WHERE pubkey = ?")
            .bind(pubkey)
            .fetch_one(&self.db)
            .await
            .map_err(Error::new)
    }
}
