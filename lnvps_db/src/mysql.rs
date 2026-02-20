use crate::{
    AccessPolicy, AvailableIpSpace, Company, DbError, DbResult, IpRange, IpRangeSubscription,
    IpSpacePricing, LNVpsDbBase, PaymentMethod, PaymentMethodConfig, PaymentType, Referral,
    ReferralCostUsage, ReferralPayout, RegionStats, Router, Subscription, SubscriptionLineItem,
    SubscriptionPayment, SubscriptionPaymentWithCompany, User, UserSshKey, Vm, VmCostPlan,
    VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate, VmHistory, VmHost, VmHostDisk,
    VmHostRegion, VmIpAssignment, VmOsImage, VmPayment, VmPaymentWithCompany, VmTemplate,
};
#[cfg(feature = "admin")]
use crate::{AdminDb, AdminRole, AdminRoleAssignment, AdminVmHost};
#[cfg(feature = "nostr-domain")]
use crate::{LNVPSNostrDb, NostrDomain, NostrDomainHandle};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use sqlx::{Executor, MySqlPool, QueryBuilder, Row};

#[derive(Clone)]
pub struct LNVpsDbMysql {
    db: MySqlPool,
}

impl LNVpsDbMysql {
    pub async fn new(conn: &str) -> DbResult<Self> {
        let db = MySqlPool::connect(conn).await?;
        Ok(Self { db })
    }

    pub async fn execute(&self, sql: &str) -> DbResult<()> {
        self.db.execute(sql).await?;
        Ok(())
    }
}

#[async_trait]
impl LNVpsDbBase for LNVpsDbMysql {
    async fn migrate(&self) -> DbResult<()> {
        let migrator = sqlx::migrate!();
        migrator.run(&self.db).await?;
        Ok(())
    }

    async fn upsert_user(&self, pubkey: &[u8; 32]) -> DbResult<u64> {
        let res =
            sqlx::query("insert ignore into users(pubkey,contact_nip17) values(?,1) returning id")
                .bind(pubkey.as_slice())
                .fetch_optional(&self.db)
                .await?;
        Ok(match res {
            None => sqlx::query("select id from users where pubkey = ?")
                .bind(pubkey.as_slice())
                .fetch_one(&self.db)
                .await?
                .try_get(0)?,
            Some(res) => res.try_get(0)?,
        })
    }

    async fn get_user(&self, id: u64) -> DbResult<User> {
        Ok(sqlx::query_as("select * from users where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn update_user(&self, user: &User) -> DbResult<()> {
        sqlx::query(
            "update users set email=?, email_verified=?, email_verify_token=?, contact_nip17=?, contact_email=?, country_code=?, billing_name=?, billing_address_1=?, billing_address_2=?, billing_city=?, billing_state=?, billing_postcode=?, billing_tax_id=?, nwc_connection_string=? where id = ?",
        )
            .bind(&user.email)
            .bind(user.email_verified)
            .bind(&user.email_verify_token)
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
            .bind(&user.nwc_connection_string)
            .bind(user.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn delete_user(&self, _id: u64) -> DbResult<()> {
        Err(DbError::Source(
            anyhow!("Deleting users is not supported").into_boxed_dyn_error(),
        ))
    }

    async fn get_user_by_email_verify_token(&self, token: &str) -> DbResult<User> {
        Ok(
            sqlx::query_as(
                "select * from users where email_verify_token = ? and email_verify_token != ''",
            )
            .bind(token)
            .fetch_one(&self.db)
            .await?,
        )
    }

    async fn list_users(&self) -> DbResult<Vec<User>> {
        Ok(sqlx::query_as("select * from users")
            .fetch_all(&self.db)
            .await?)
    }

    async fn list_users_paginated(&self, limit: u64, offset: u64) -> DbResult<Vec<User>> {
        Ok(
            sqlx::query_as("select * from users order by id limit ? offset ?")
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn count_users(&self) -> DbResult<u64> {
        Ok(sqlx::query("select count(*) as count from users")
            .fetch_one(&self.db)
            .await?
            .try_get(0)?)
    }

    async fn insert_user_ssh_key(&self, new_key: &UserSshKey) -> DbResult<u64> {
        Ok(sqlx::query(
            "insert into user_ssh_key(name,user_id,key_data) values(?, ?, ?) returning id",
        )
        .bind(&new_key.name)
        .bind(new_key.user_id)
        .bind(&new_key.key_data)
        .fetch_one(&self.db)
        .await?
        .try_get(0)?)
    }

    async fn get_user_ssh_key(&self, id: u64) -> DbResult<UserSshKey> {
        Ok(sqlx::query_as("select * from user_ssh_key where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn delete_user_ssh_key(&self, _id: u64) -> DbResult<()> {
        todo!()
    }

    async fn list_user_ssh_key(&self, user_id: u64) -> DbResult<Vec<UserSshKey>> {
        Ok(
            sqlx::query_as("select * from user_ssh_key where user_id = ?")
                .bind(user_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn list_host_region(&self) -> DbResult<Vec<VmHostRegion>> {
        Ok(
            sqlx::query_as("select * from vm_host_region where enabled=1")
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_host_region(&self, id: u64) -> DbResult<VmHostRegion> {
        Ok(sqlx::query_as("select * from vm_host_region where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn get_host_region_by_name(&self, name: &str) -> DbResult<VmHostRegion> {
        Ok(
            sqlx::query_as("select * from vm_host_region where name like ?")
                .bind(name)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn list_hosts(&self) -> DbResult<Vec<VmHost>> {
        Ok(sqlx::query_as("select h.* from vm_host h,vm_host_region hr where h.enabled = 1 and h.region_id = hr.id and hr.enabled = 1")
            .fetch_all(&self.db)
            .await?)
    }

    async fn list_hosts_paginated(&self, limit: u64, offset: u64) -> DbResult<(Vec<VmHost>, u64)> {
        // Get total count
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vm_host h, vm_host_region hr WHERE h.enabled = 1 AND h.region_id = hr.id AND hr.enabled = 1"
        )
        .fetch_one(&self.db)
        .await?;

        // Get paginated results
        let hosts = sqlx::query_as(
            "SELECT h.* FROM vm_host h, vm_host_region hr WHERE h.enabled = 1 AND h.region_id = hr.id AND hr.enabled = 1 ORDER BY h.name LIMIT ? OFFSET ?"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?;

        Ok((hosts, total as u64))
    }

    async fn list_hosts_with_regions_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<(VmHost, VmHostRegion)>, u64)> {
        // Get total count
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vm_host h, vm_host_region hr WHERE h.enabled = 1 AND h.region_id = hr.id AND hr.enabled = 1"
        )
        .fetch_one(&self.db)
        .await?;

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
        .await?;

        let mut results = Vec::new();
        for row in rows {
            let host = VmHost {
                id: row.get("id"),
                kind: row.get("kind"),
                region_id: row.get("region_id"),
                name: row.get("name"),
                ip: row.get("ip"),
                cpu: row.get("cpu"),
                cpu_mfg: row.get("cpu_mfg"),
                cpu_arch: row.get("cpu_arch"),
                cpu_features: row.get("cpu_features"),
                memory: row.get("memory"),
                enabled: row.get("enabled"),
                api_token: row.get("api_token"),
                load_cpu: row.get("load_cpu"),
                load_memory: row.get("load_memory"),
                load_disk: row.get("load_disk"),
                vlan_id: row.get("vlan_id"),
                ssh_user: row.get("ssh_user"),
                ssh_key: row.get("ssh_key"),
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

    async fn get_host(&self, id: u64) -> DbResult<VmHost> {
        Ok(sqlx::query_as("select * from vm_host where id = ?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn update_host(&self, host: &VmHost) -> DbResult<()> {
        sqlx::query(
            "UPDATE vm_host SET kind = ?, region_id = ?, name = ?, ip = ?, cpu = ?, \
             cpu_mfg = ?, cpu_arch = ?, cpu_features = ?, memory = ?, enabled = ?, \
             api_token = ?, load_cpu = ?, load_memory = ?, load_disk = ?, vlan_id = ?, \
             ssh_user = ?, ssh_key = ? WHERE id = ?",
        )
        .bind(&host.kind)
        .bind(host.region_id)
        .bind(&host.name)
        .bind(&host.ip)
        .bind(host.cpu)
        .bind(&host.cpu_mfg)
        .bind(&host.cpu_arch)
        .bind(&host.cpu_features)
        .bind(host.memory)
        .bind(host.enabled)
        .bind(&host.api_token)
        .bind(host.load_cpu)
        .bind(host.load_memory)
        .bind(host.load_disk)
        .bind(host.vlan_id)
        .bind(&host.ssh_user)
        .bind(&host.ssh_key)
        .bind(host.id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn create_host(&self, host: &VmHost) -> DbResult<u64> {
        let result = sqlx::query(
            "INSERT INTO vm_host (kind, region_id, name, ip, cpu, cpu_mfg, cpu_arch, \
             cpu_features, memory, enabled, api_token, load_cpu, load_memory, load_disk, \
             vlan_id, ssh_user, ssh_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&host.kind)
        .bind(host.region_id)
        .bind(&host.name)
        .bind(&host.ip)
        .bind(host.cpu)
        .bind(&host.cpu_mfg)
        .bind(&host.cpu_arch)
        .bind(&host.cpu_features)
        .bind(host.memory)
        .bind(host.enabled)
        .bind(&host.api_token)
        .bind(host.load_cpu)
        .bind(host.load_memory)
        .bind(host.load_disk)
        .bind(host.vlan_id)
        .bind(&host.ssh_user)
        .bind(&host.ssh_key)
        .execute(&self.db)
        .await?;
        Ok(result.last_insert_id())
    }

    async fn list_host_disks(&self, host_id: u64) -> DbResult<Vec<VmHostDisk>> {
        Ok(
            sqlx::query_as("select * from vm_host_disk where host_id = ? and enabled = 1")
                .bind(host_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_host_disk(&self, disk_id: u64) -> DbResult<VmHostDisk> {
        Ok(sqlx::query_as("select * from vm_host_disk where id = ?")
            .bind(disk_id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn update_host_disk(&self, disk: &VmHostDisk) -> DbResult<()> {
        sqlx::query(
            "update vm_host_disk set name=?,size=?,kind=?,interface=?,enabled=? where id=?",
        )
        .bind(&disk.name)
        .bind(disk.size)
        .bind(disk.kind)
        .bind(disk.interface)
        .bind(disk.enabled)
        .bind(disk.id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn create_host_disk(&self, disk: &VmHostDisk) -> DbResult<u64> {
        let result = sqlx::query("insert into vm_host_disk (host_id,name,size,kind,interface,enabled) values (?,?,?,?,?,?)")
            .bind(disk.host_id)
            .bind(&disk.name)
            .bind(disk.size)
            .bind(disk.kind)
            .bind(disk.interface)
            .bind(disk.enabled)
            .execute(&self.db)
            .await?;
        Ok(result.last_insert_id())
    }

    async fn get_os_image(&self, id: u64) -> DbResult<VmOsImage> {
        Ok(sqlx::query_as("select * from vm_os_image where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn list_os_image(&self) -> DbResult<Vec<VmOsImage>> {
        Ok(sqlx::query_as("select * from vm_os_image")
            .fetch_all(&self.db)
            .await?)
    }

    async fn get_ip_range(&self, id: u64) -> DbResult<IpRange> {
        Ok(sqlx::query_as("select * from ip_range where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn list_ip_range(&self) -> DbResult<Vec<IpRange>> {
        Ok(sqlx::query_as("select * from ip_range where enabled = 1")
            .fetch_all(&self.db)
            .await?)
    }

    async fn list_ip_range_in_region(&self, region_id: u64) -> DbResult<Vec<IpRange>> {
        Ok(
            sqlx::query_as("select * from ip_range where region_id = ? and enabled = 1")
                .bind(region_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_cost_plan(&self, id: u64) -> DbResult<VmCostPlan> {
        Ok(sqlx::query_as("select * from vm_cost_plan where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn list_cost_plans(&self) -> DbResult<Vec<VmCostPlan>> {
        Ok(
            sqlx::query_as("select * from vm_cost_plan order by created desc")
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn insert_cost_plan(&self, cost_plan: &VmCostPlan) -> DbResult<u64> {
        Ok(sqlx::query("insert into vm_cost_plan(name,created,amount,currency,interval_amount,interval_type) values(?,?,?,?,?,?) returning id")
            .bind(&cost_plan.name)
            .bind(cost_plan.created)
            .bind(cost_plan.amount)
            .bind(&cost_plan.currency)
            .bind(cost_plan.interval_amount)
            .bind(cost_plan.interval_type)
            .fetch_one(&self.db)
            .await?
            .try_get(0)?)
    }

    async fn update_cost_plan(&self, cost_plan: &VmCostPlan) -> DbResult<()> {
        sqlx::query("update vm_cost_plan set name=?,amount=?,currency=?,interval_amount=?,interval_type=? where id=?")
            .bind(&cost_plan.name)
            .bind(cost_plan.amount)
            .bind(&cost_plan.currency)
            .bind(cost_plan.interval_amount)
            .bind(cost_plan.interval_type)
            .bind(cost_plan.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn delete_cost_plan(&self, id: u64) -> DbResult<()> {
        sqlx::query("delete from vm_cost_plan where id=?")
            .bind(id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn get_vm_template(&self, id: u64) -> DbResult<VmTemplate> {
        Ok(sqlx::query_as("select * from vm_template where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn list_vm_templates(&self) -> DbResult<Vec<VmTemplate>> {
        Ok(
            sqlx::query_as("select * from vm_template where enabled = 1")
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn insert_vm_template(&self, template: &VmTemplate) -> DbResult<u64> {
        Ok(sqlx::query("insert into vm_template(name,enabled,created,expires,cpu,cpu_mfg,cpu_arch,cpu_features,memory,disk_size,disk_type,disk_interface,cost_plan_id,region_id) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?) returning id")
            .bind(&template.name)
            .bind(template.enabled)
            .bind(template.created)
            .bind(template.expires)
            .bind(template.cpu)
            .bind(&template.cpu_mfg)
            .bind(&template.cpu_arch)
            .bind(&template.cpu_features)
            .bind(template.memory)
            .bind(template.disk_size)
            .bind(template.disk_type)
            .bind(template.disk_interface)
            .bind(template.cost_plan_id)
            .bind(template.region_id)
            .fetch_one(&self.db)
            .await?
            .try_get(0)?)
    }

    async fn list_vms(&self) -> DbResult<Vec<Vm>> {
        Ok(sqlx::query_as("select * from vm where deleted = 0")
            .fetch_all(&self.db)
            .await?)
    }

    async fn list_vms_on_host(&self, host_id: u64) -> DbResult<Vec<Vm>> {
        Ok(
            sqlx::query_as("select * from vm where deleted = 0 and host_id = ?")
                .bind(host_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn count_active_vms_on_host(&self, host_id: u64) -> DbResult<u64> {
        let result: (i64,) =
            sqlx::query_as("select count(*) from vm where deleted = 0 and host_id = ?")
                .bind(host_id)
                .fetch_one(&self.db)
                .await?;
        Ok(result.0 as u64)
    }

    async fn list_expired_vms(&self) -> DbResult<Vec<Vm>> {
        Ok(
            sqlx::query_as("select * from vm where expires > current_timestamp()  and deleted = 0")
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn list_user_vms(&self, id: u64) -> DbResult<Vec<Vm>> {
        Ok(
            sqlx::query_as("select * from vm where user_id = ? and deleted = 0")
                .bind(id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_vm(&self, vm_id: u64) -> DbResult<Vm> {
        Ok(sqlx::query_as("select * from vm where id = ?")
            .bind(vm_id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn insert_vm(&self, vm: &Vm) -> DbResult<u64> {
        Ok(sqlx::query("insert into vm(host_id,user_id,image_id,template_id,custom_template_id,ssh_key_id,created,expires,disk_id,mac_address,ref_code,auto_renewal_enabled) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) returning id")
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
            .bind(vm.auto_renewal_enabled)
            .fetch_one(&self.db)
            .await?
            .try_get(0)?)
    }

    async fn delete_vm(&self, vm_id: u64) -> DbResult<()> {
        sqlx::query("update vm set deleted = 1 where id = ?")
            .bind(vm_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn update_vm(&self, vm: &Vm) -> DbResult<()> {
        sqlx::query(
            "update vm set image_id=?,template_id=?,custom_template_id=?,ssh_key_id=?,expires=?,disk_id=?,mac_address=?,auto_renewal_enabled=? where id=?",
        )
            .bind(vm.image_id)
            .bind(vm.template_id)
            .bind(vm.custom_template_id)
            .bind(vm.ssh_key_id)
            .bind(vm.expires)
            .bind(vm.disk_id)
            .bind(&vm.mac_address)
            .bind(vm.auto_renewal_enabled)
            .bind(vm.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn insert_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> DbResult<u64> {
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
            .await?
            .try_get(0)?)
    }

    async fn update_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> DbResult<()> {
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
            .await?;
        Ok(())
    }

    async fn list_vm_ip_assignments(&self, vm_id: u64) -> DbResult<Vec<VmIpAssignment>> {
        Ok(
            sqlx::query_as("select * from vm_ip_assignment where vm_id = ? and deleted = 0")
                .bind(vm_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn list_vm_ip_assignments_in_range(
        &self,
        range_id: u64,
    ) -> DbResult<Vec<VmIpAssignment>> {
        Ok(
            sqlx::query_as("select * from vm_ip_assignment where ip_range_id = ? and deleted = 0")
                .bind(range_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn delete_vm_ip_assignments_by_vm_id(&self, vm_id: u64) -> DbResult<()> {
        sqlx::query("update vm_ip_assignment set deleted = 1 where vm_id = ?")
            .bind(vm_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn hard_delete_vm_ip_assignments_by_vm_id(&self, vm_id: u64) -> DbResult<()> {
        sqlx::query("delete from vm_ip_assignment where vm_id = ?")
            .bind(vm_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn delete_vm_ip_assignment(&self, assignment_id: u64) -> DbResult<()> {
        sqlx::query("update vm_ip_assignment set deleted = 1 where id = ?")
            .bind(assignment_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn list_vm_payment(&self, vm_id: u64) -> DbResult<Vec<VmPayment>> {
        Ok(sqlx::query_as("select * from vm_payment where vm_id = ?")
            .bind(vm_id)
            .fetch_all(&self.db)
            .await?)
    }

    async fn list_vm_payment_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<Vec<VmPayment>> {
        Ok(sqlx::query_as(
            "select * from vm_payment where vm_id = ? order by created desc limit ? offset ?",
        )
        .bind(vm_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?)
    }

    async fn list_vm_payment_by_method_and_type(
        &self,
        vm_id: u64,
        method: PaymentMethod,
        payment_type: PaymentType,
    ) -> DbResult<Vec<VmPayment>> {
        Ok(sqlx::query_as(
            "select * from vm_payment where vm_id = ? and payment_method = ? and payment_type = ? and expires > NOW() and is_paid = false order by created desc",
        )
        .bind(vm_id)
        .bind(method)
        .bind(payment_type)
        .fetch_all(&self.db)
        .await?)
    }

    async fn insert_vm_payment(&self, vm_payment: &VmPayment) -> DbResult<()> {
        sqlx::query("insert into vm_payment(id,vm_id,created,expires,amount,tax,processing_fee,currency,payment_method,payment_type,time_value,is_paid,rate,external_id,external_data,upgrade_params) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(&vm_payment.id)
            .bind(vm_payment.vm_id)
            .bind(vm_payment.created)
            .bind(vm_payment.expires)
            .bind(vm_payment.amount)
            .bind(vm_payment.tax)
            .bind(vm_payment.processing_fee)
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
            .await?;
        Ok(())
    }

    async fn get_vm_payment(&self, id: &Vec<u8>) -> DbResult<VmPayment> {
        Ok(sqlx::query_as("select * from vm_payment where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn get_vm_payment_by_ext_id(&self, id: &str) -> DbResult<VmPayment> {
        Ok(
            sqlx::query_as("select * from vm_payment where external_id=?")
                .bind(id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn update_vm_payment(&self, vm_payment: &VmPayment) -> DbResult<()> {
        sqlx::query("update vm_payment set is_paid = ? where id = ?")
            .bind(vm_payment.is_paid)
            .bind(&vm_payment.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn vm_payment_paid(&self, vm_payment: &VmPayment) -> DbResult<()> {
        if vm_payment.is_paid {
            return Err(DbError::Source(
                anyhow!("Invoice already paid").into_boxed_dyn_error(),
            ));
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

    async fn last_paid_invoice(&self) -> DbResult<Option<VmPayment>> {
        Ok(sqlx::query_as(
            "select * from vm_payment where is_paid = true order by created desc limit 1",
        )
        .fetch_optional(&self.db)
        .await?)
    }

    async fn list_custom_pricing(&self, region_id: u64) -> DbResult<Vec<VmCustomPricing>> {
        Ok(
            sqlx::query_as("select * from vm_custom_pricing where region_id = ? and enabled = 1")
                .bind(region_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_custom_pricing(&self, id: u64) -> DbResult<VmCustomPricing> {
        Ok(sqlx::query_as("select * from vm_custom_pricing where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn get_custom_vm_template(&self, id: u64) -> DbResult<VmCustomTemplate> {
        Ok(
            sqlx::query_as("select * from vm_custom_template where id=?")
                .bind(id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn insert_custom_vm_template(&self, template: &VmCustomTemplate) -> DbResult<u64> {
        Ok(sqlx::query("insert into vm_custom_template(cpu,memory,disk_size,disk_type,disk_interface,pricing_id,cpu_mfg,cpu_arch,cpu_features) values(?,?,?,?,?,?,?,?,?) returning id")
            .bind(template.cpu)
            .bind(template.memory)
            .bind(template.disk_size)
            .bind(template.disk_type)
            .bind(template.disk_interface)
            .bind(template.pricing_id)
            .bind(&template.cpu_mfg)
            .bind(&template.cpu_arch)
            .bind(&template.cpu_features)
            .fetch_one(&self.db)
            .await?
            .try_get(0)?)
    }

    async fn update_custom_vm_template(&self, template: &VmCustomTemplate) -> DbResult<()> {
        sqlx::query("update vm_custom_template set cpu=?, memory=?, disk_size=?, disk_type=?, disk_interface=?, pricing_id=?, cpu_mfg=?, cpu_arch=?, cpu_features=? where id=?")
            .bind(template.cpu)
            .bind(template.memory)
            .bind(template.disk_size)
            .bind(template.disk_type)
            .bind(template.disk_interface)
            .bind(template.pricing_id)
            .bind(&template.cpu_mfg)
            .bind(&template.cpu_arch)
            .bind(&template.cpu_features)
            .bind(template.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn list_custom_pricing_disk(
        &self,
        pricing_id: u64,
    ) -> DbResult<Vec<VmCustomPricingDisk>> {
        Ok(
            sqlx::query_as("select * from vm_custom_pricing_disk where pricing_id=?")
                .bind(pricing_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_router(&self, router_id: u64) -> DbResult<Router> {
        Ok(sqlx::query_as("select * from router where id=?")
            .bind(router_id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn list_routers(&self) -> DbResult<Vec<Router>> {
        Ok(sqlx::query_as("select * from router")
            .fetch_all(&self.db)
            .await?)
    }

    async fn get_vm_ip_assignment(&self, id: u64) -> DbResult<VmIpAssignment> {
        Ok(sqlx::query_as("select * from vm_ip_assignment where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn get_vm_ip_assignment_by_ip(&self, ip: &str) -> DbResult<VmIpAssignment> {
        Ok(
            sqlx::query_as("select * from vm_ip_assignment where ip=? and deleted=0")
                .bind(ip)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn get_access_policy(&self, access_policy_id: u64) -> DbResult<AccessPolicy> {
        Ok(sqlx::query_as("select * from access_policy where id=?")
            .bind(access_policy_id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn get_company(&self, company_id: u64) -> DbResult<Company> {
        Ok(sqlx::query_as("select * from company where id=?")
            .bind(company_id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn list_companies(&self) -> DbResult<Vec<Company>> {
        Ok(sqlx::query_as("select * from company order by id")
            .fetch_all(&self.db)
            .await?)
    }

    async fn get_vm_base_currency(&self, vm_id: u64) -> DbResult<String> {
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
        .await?;
        Ok(currency)
    }

    async fn get_vm_company_id(&self, vm_id: u64) -> DbResult<u64> {
        let company_id = sqlx::query_scalar::<_, u64>(
            "SELECT vhr.company_id 
             FROM vm v
             JOIN vm_host vh ON v.host_id = vh.id  
             JOIN vm_host_region vhr ON vh.region_id = vhr.id
             WHERE v.id = ?",
        )
        .bind(vm_id)
        .fetch_one(&self.db)
        .await?;
        Ok(company_id)
    }

    async fn insert_vm_history(&self, history: &VmHistory) -> DbResult<u64> {
        Ok(sqlx::query("insert into vm_history(vm_id,action_type,initiated_by_user,previous_state,new_state,metadata,description) values(?,?,?,?,?,?,?) returning id")
            .bind(history.vm_id)
            .bind(&history.action_type)
            .bind(history.initiated_by_user)
            .bind(&history.previous_state)
            .bind(&history.new_state)
            .bind(&history.metadata)
            .bind(&history.description)
            .fetch_one(&self.db)
            .await?
            .try_get(0)?)
    }

    async fn list_vm_history(&self, vm_id: u64) -> DbResult<Vec<VmHistory>> {
        Ok(
            sqlx::query_as("select * from vm_history where vm_id = ? order by timestamp desc")
                .bind(vm_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn list_vm_history_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<Vec<VmHistory>> {
        Ok(sqlx::query_as(
            "select * from vm_history where vm_id = ? order by timestamp desc limit ? offset ?",
        )
        .bind(vm_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?)
    }

    async fn get_vm_history(&self, id: u64) -> DbResult<VmHistory> {
        Ok(sqlx::query_as("select * from vm_history where id = ?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn execute_query(&self, query: &str) -> DbResult<u64> {
        let result = sqlx::query(query).execute(&self.db).await?;
        Ok(result.rows_affected())
    }

    async fn execute_query_with_string_params(
        &self,
        query: &str,
        params: Vec<String>,
    ) -> DbResult<u64> {
        let mut query_builder = sqlx::query(query);
        for param in params {
            query_builder = query_builder.bind(param);
        }
        let result = query_builder.execute(&self.db).await?;
        Ok(result.rows_affected())
    }

    async fn fetch_raw_strings(&self, query: &str) -> DbResult<Vec<(u64, String)>> {
        let rows = sqlx::query(query).fetch_all(&self.db).await?;

        let mut results = Vec::new();
        for row in rows {
            let id: u64 = row.try_get(0)?;
            let value: String = row.try_get(1)?;
            results.push((id, value));
        }
        Ok(results)
    }

    async fn get_active_customers_with_contact_prefs(&self) -> DbResult<Vec<User>> {
        let query = r#"
            SELECT DISTINCT 
                u.id,
                u.pubkey,
                u.created,
                u.email,
                u.email_verified,
                u.email_verify_token,
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
                u.nwc_connection_string
            FROM users u
            INNER JOIN vm ON u.id = vm.user_id
            WHERE vm.deleted = 0 
            AND (
                (u.contact_email = 1 AND u.email != '') 
                OR 
                u.contact_nip17 = 1
            )
            ORDER BY u.id
        "#;

        let users = sqlx::query_as(query).fetch_all(&self.db).await?;

        Ok(users)
    }

    async fn list_admin_user_ids(&self) -> DbResult<Vec<u64>> {
        let query = r#"
            SELECT DISTINCT user_id
            FROM admin_role_assignments
            WHERE expires_at IS NULL OR expires_at > NOW()
            ORDER BY user_id
        "#;

        let user_ids = sqlx::query_scalar::<_, u64>(query)
            .fetch_all(&self.db)
            .await?;

        Ok(user_ids)
    }

    // ========================================================================
    // Subscription Billing System Implementations
    // ========================================================================

    // Subscriptions
    async fn list_subscriptions(&self) -> DbResult<Vec<Subscription>> {
        Ok(sqlx::query_as("SELECT * FROM subscription")
            .fetch_all(&self.db)
            .await?)
    }

    async fn list_subscriptions_by_user(&self, user_id: u64) -> DbResult<Vec<Subscription>> {
        Ok(
            sqlx::query_as("SELECT * FROM subscription WHERE user_id = ?")
                .bind(user_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn list_subscriptions_active(&self, user_id: u64) -> DbResult<Vec<Subscription>> {
        Ok(
            sqlx::query_as("SELECT * FROM subscription WHERE user_id = ? AND is_active = 1")
                .bind(user_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_subscription(&self, id: u64) -> DbResult<Subscription> {
        Ok(sqlx::query_as("SELECT * FROM subscription WHERE id = ?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn get_subscription_by_ext_id(&self, external_id: &str) -> DbResult<Subscription> {
        Ok(
            sqlx::query_as("SELECT * FROM subscription WHERE external_id = ?")
                .bind(external_id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn insert_subscription(&self, subscription: &Subscription) -> DbResult<u64> {
        let res = sqlx::query(
            "INSERT INTO subscription (user_id, company_id, name, description, created, expires, is_active, currency, setup_fee, auto_renewal_enabled, external_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(subscription.user_id)
        .bind(subscription.company_id)
        .bind(&subscription.name)
        .bind(&subscription.description)
        .bind(subscription.created)
        .bind(subscription.expires)
        .bind(subscription.is_active)
        .bind(&subscription.currency)
        .bind(subscription.setup_fee)
        .bind(subscription.auto_renewal_enabled)
        .bind(&subscription.external_id)
        .execute(&self.db)
        .await?;

        Ok(res.last_insert_id())
    }

    async fn insert_subscription_with_line_items(
        &self,
        subscription: &Subscription,
        mut line_items: Vec<SubscriptionLineItem>,
    ) -> DbResult<u64> {
        let mut tx = self.db.begin().await?;

        // Insert subscription
        let res = sqlx::query(
            "INSERT INTO subscription (user_id, company_id, name, description, created, expires, is_active, currency, setup_fee, auto_renewal_enabled, external_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(subscription.user_id)
        .bind(subscription.company_id)
        .bind(&subscription.name)
        .bind(&subscription.description)
        .bind(subscription.created)
        .bind(subscription.expires)
        .bind(subscription.is_active)
        .bind(&subscription.currency)
        .bind(subscription.setup_fee)
        .bind(subscription.auto_renewal_enabled)
        .bind(&subscription.external_id)
        .execute(&mut *tx)
        .await?;

        let subscription_id = res.last_insert_id();

        // Insert all line items with the subscription_id
        for line_item in &mut line_items {
            line_item.subscription_id = subscription_id;

            sqlx::query(
                "INSERT INTO subscription_line_item (subscription_id, subscription_type, name, description, amount, setup_amount, configuration) VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(line_item.subscription_id)
            .bind(line_item.subscription_type)
            .bind(&line_item.name)
            .bind(&line_item.description)
            .bind(line_item.amount)
            .bind(line_item.setup_amount)
            .bind(&line_item.configuration)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(subscription_id)
    }

    async fn update_subscription(&self, subscription: &Subscription) -> DbResult<()> {
        sqlx::query(
            "UPDATE subscription SET user_id = ?, company_id = ?, name = ?, description = ?, expires = ?, is_active = ?, currency = ?, setup_fee = ?, auto_renewal_enabled = ?, external_id = ? WHERE id = ?"
        )
        .bind(subscription.user_id)
        .bind(subscription.company_id)
        .bind(&subscription.name)
        .bind(&subscription.description)
        .bind(subscription.expires)
        .bind(subscription.is_active)
        .bind(&subscription.currency)
        .bind(subscription.setup_fee)
        .bind(subscription.auto_renewal_enabled)
        .bind(&subscription.external_id)
        .bind(subscription.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn delete_subscription(&self, id: u64) -> DbResult<()> {
        sqlx::query("DELETE FROM subscription WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn get_subscription_base_currency(&self, subscription_id: u64) -> DbResult<String> {
        let result: (String,) = sqlx::query_as(
            "SELECT c.base_currency 
             FROM subscription s
             JOIN users u ON s.user_id = u.id
             JOIN company c ON u.id = c.id
             WHERE s.id = ?",
        )
        .bind(subscription_id)
        .fetch_one(&self.db)
        .await?;

        Ok(result.0)
    }

    // Subscription Line Items
    async fn list_subscription_line_items(
        &self,
        subscription_id: u64,
    ) -> DbResult<Vec<SubscriptionLineItem>> {
        Ok(
            sqlx::query_as("SELECT * FROM subscription_line_item WHERE subscription_id = ?")
                .bind(subscription_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_subscription_line_item(&self, id: u64) -> DbResult<SubscriptionLineItem> {
        Ok(
            sqlx::query_as("SELECT * FROM subscription_line_item WHERE id = ?")
                .bind(id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn insert_subscription_line_item(
        &self,
        line_item: &SubscriptionLineItem,
    ) -> DbResult<u64> {
        let res = sqlx::query(
            "INSERT INTO subscription_line_item (subscription_id, subscription_type, name, description, amount, setup_amount, configuration) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(line_item.subscription_id)
        .bind(line_item.subscription_type)
        .bind(&line_item.name)
        .bind(&line_item.description)
        .bind(line_item.amount)
        .bind(line_item.setup_amount)
        .bind(&line_item.configuration)
        .execute(&self.db)
        .await?;

        Ok(res.last_insert_id())
    }

    async fn update_subscription_line_item(
        &self,
        line_item: &SubscriptionLineItem,
    ) -> DbResult<()> {
        sqlx::query(
            "UPDATE subscription_line_item SET subscription_id = ?, subscription_type = ?, name = ?, description = ?, amount = ?, setup_amount = ?, configuration = ? WHERE id = ?"
        )
        .bind(line_item.subscription_id)
        .bind(line_item.subscription_type)
        .bind(&line_item.name)
        .bind(&line_item.description)
        .bind(line_item.amount)
        .bind(line_item.setup_amount)
        .bind(&line_item.configuration)
        .bind(line_item.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn delete_subscription_line_item(&self, id: u64) -> DbResult<()> {
        sqlx::query("DELETE FROM subscription_line_item WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    // Subscription Payments
    async fn list_subscription_payments(
        &self,
        subscription_id: u64,
    ) -> DbResult<Vec<SubscriptionPayment>> {
        Ok(
            sqlx::query_as("SELECT * FROM subscription_payment WHERE subscription_id = ?")
                .bind(subscription_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn list_subscription_payments_by_user(
        &self,
        user_id: u64,
    ) -> DbResult<Vec<SubscriptionPayment>> {
        Ok(
            sqlx::query_as("SELECT * FROM subscription_payment WHERE user_id = ?")
                .bind(user_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_subscription_payment(&self, id: &Vec<u8>) -> DbResult<SubscriptionPayment> {
        Ok(
            sqlx::query_as("SELECT * FROM subscription_payment WHERE id = ?")
                .bind(id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn get_subscription_payment_by_ext_id(
        &self,
        external_id: &str,
    ) -> DbResult<SubscriptionPayment> {
        Ok(
            sqlx::query_as("SELECT * FROM subscription_payment WHERE external_id = ?")
                .bind(external_id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn get_subscription_payment_with_company(
        &self,
        id: &Vec<u8>,
    ) -> DbResult<SubscriptionPaymentWithCompany> {
        Ok(sqlx::query_as(
            "SELECT sp.*, c.base_currency as company_base_currency
             FROM subscription_payment sp
             JOIN subscription s ON sp.subscription_id = s.id
             JOIN users u ON s.user_id = u.id
             JOIN company c ON u.id = c.id
             WHERE sp.id = ?",
        )
        .bind(id)
        .fetch_one(&self.db)
        .await?)
    }

    async fn insert_subscription_payment(&self, payment: &SubscriptionPayment) -> DbResult<()> {
        sqlx::query(
            "INSERT INTO subscription_payment (id, subscription_id, user_id, created, expires, amount, currency, payment_method, payment_type, external_data, external_id, is_paid, rate, tax) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&payment.id)
        .bind(payment.subscription_id)
        .bind(payment.user_id)
        .bind(payment.created)
        .bind(payment.expires)
        .bind(payment.amount)
        .bind(&payment.currency)
        .bind(payment.payment_method)
        .bind(payment.payment_type)
        .bind(&payment.external_data)
        .bind(&payment.external_id)
        .bind(payment.is_paid)
        .bind(payment.rate)
        .bind(payment.tax)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn update_subscription_payment(&self, payment: &SubscriptionPayment) -> DbResult<()> {
        sqlx::query(
            "UPDATE subscription_payment SET subscription_id = ?, user_id = ?, created = ?, expires = ?, amount = ?, currency = ?, payment_method = ?, payment_type = ?, external_data = ?, external_id = ?, is_paid = ?, rate = ?, tax = ? WHERE id = ?"
        )
        .bind(payment.subscription_id)
        .bind(payment.user_id)
        .bind(payment.created)
        .bind(payment.expires)
        .bind(payment.amount)
        .bind(&payment.currency)
        .bind(payment.payment_method)
        .bind(payment.payment_type)
        .bind(&payment.external_data)
        .bind(&payment.external_id)
        .bind(payment.is_paid)
        .bind(payment.rate)
        .bind(payment.tax)
        .bind(&payment.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn subscription_payment_paid(&self, payment: &SubscriptionPayment) -> DbResult<()> {
        let mut tx = self.db.begin().await?;

        // Mark payment as paid
        sqlx::query("UPDATE subscription_payment SET is_paid = 1 WHERE id = ?")
            .bind(&payment.id)
            .execute(tx.as_mut())
            .await?;

        // Subscriptions are always monthly - extend by 30 days and activate
        sqlx::query(
            "UPDATE subscription SET expires = DATE_ADD(GREATEST(COALESCE(expires, NOW()), NOW()), INTERVAL 30 DAY), is_active = 1 WHERE id = ?"
        )
        .bind(payment.subscription_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn last_paid_subscription_invoice(&self) -> DbResult<Option<SubscriptionPayment>> {
        Ok(sqlx::query_as(
            "SELECT * FROM subscription_payment WHERE is_paid = 1 ORDER BY created DESC LIMIT 1",
        )
        .fetch_optional(&self.db)
        .await?)
    }

    // Available IP Space
    async fn list_available_ip_space(&self) -> DbResult<Vec<AvailableIpSpace>> {
        Ok(
            sqlx::query_as("SELECT * FROM available_ip_space ORDER BY created DESC")
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_available_ip_space(&self, id: u64) -> DbResult<AvailableIpSpace> {
        Ok(
            sqlx::query_as("SELECT * FROM available_ip_space WHERE id = ?")
                .bind(id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn get_available_ip_space_by_cidr(&self, cidr: &str) -> DbResult<AvailableIpSpace> {
        Ok(
            sqlx::query_as("SELECT * FROM available_ip_space WHERE cidr = ?")
                .bind(cidr)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn insert_available_ip_space(&self, space: &AvailableIpSpace) -> DbResult<u64> {
        let result = sqlx::query(
            "INSERT INTO available_ip_space (cidr, min_prefix_size, max_prefix_size, registry, external_id, is_available, is_reserved, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&space.cidr)
        .bind(space.min_prefix_size)
        .bind(space.max_prefix_size)
        .bind(space.registry)
        .bind(&space.external_id)
        .bind(space.is_available)
        .bind(space.is_reserved)
        .bind(&space.metadata)
        .execute(&self.db)
        .await?;

        Ok(result.last_insert_id())
    }

    async fn update_available_ip_space(&self, space: &AvailableIpSpace) -> DbResult<()> {
        sqlx::query(
            "UPDATE available_ip_space SET cidr = ?, min_prefix_size = ?, max_prefix_size = ?, registry = ?, external_id = ?, is_available = ?, is_reserved = ?, metadata = ? WHERE id = ?"
        )
        .bind(&space.cidr)
        .bind(space.min_prefix_size)
        .bind(space.max_prefix_size)
        .bind(space.registry)
        .bind(&space.external_id)
        .bind(space.is_available)
        .bind(space.is_reserved)
        .bind(&space.metadata)
        .bind(space.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn delete_available_ip_space(&self, id: u64) -> DbResult<()> {
        sqlx::query("DELETE FROM available_ip_space WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    // IP Space Pricing
    async fn list_ip_space_pricing_by_space(
        &self,
        available_ip_space_id: u64,
    ) -> DbResult<Vec<IpSpacePricing>> {
        Ok(
            sqlx::query_as("SELECT * FROM ip_space_pricing WHERE available_ip_space_id = ?")
                .bind(available_ip_space_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_ip_space_pricing(&self, id: u64) -> DbResult<IpSpacePricing> {
        Ok(
            sqlx::query_as("SELECT * FROM ip_space_pricing WHERE id = ?")
                .bind(id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn get_ip_space_pricing_by_prefix(
        &self,
        available_ip_space_id: u64,
        prefix_size: u16,
    ) -> DbResult<IpSpacePricing> {
        Ok(sqlx::query_as(
            "SELECT * FROM ip_space_pricing WHERE available_ip_space_id = ? AND prefix_size = ?",
        )
        .bind(available_ip_space_id)
        .bind(prefix_size)
        .fetch_one(&self.db)
        .await?)
    }

    async fn insert_ip_space_pricing(&self, pricing: &IpSpacePricing) -> DbResult<u64> {
        let result = sqlx::query(
            "INSERT INTO ip_space_pricing (available_ip_space_id, prefix_size, price_per_month, currency, setup_fee) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(pricing.available_ip_space_id)
        .bind(pricing.prefix_size)
        .bind(pricing.price_per_month)
        .bind(&pricing.currency)
        .bind(pricing.setup_fee)
        .execute(&self.db)
        .await?;

        Ok(result.last_insert_id())
    }

    async fn update_ip_space_pricing(&self, pricing: &IpSpacePricing) -> DbResult<()> {
        sqlx::query(
            "UPDATE ip_space_pricing SET available_ip_space_id = ?, prefix_size = ?, price_per_month = ?, currency = ?, setup_fee = ? WHERE id = ?"
        )
        .bind(pricing.available_ip_space_id)
        .bind(pricing.prefix_size)
        .bind(pricing.price_per_month)
        .bind(&pricing.currency)
        .bind(pricing.setup_fee)
        .bind(pricing.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn delete_ip_space_pricing(&self, id: u64) -> DbResult<()> {
        sqlx::query("DELETE FROM ip_space_pricing WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    // IP Range Subscriptions
    async fn list_ip_range_subscriptions_by_line_item(
        &self,
        subscription_line_item_id: u64,
    ) -> DbResult<Vec<IpRangeSubscription>> {
        Ok(sqlx::query_as(
            "SELECT * FROM ip_range_subscription WHERE subscription_line_item_id = ?",
        )
        .bind(subscription_line_item_id)
        .fetch_all(&self.db)
        .await?)
    }

    async fn list_ip_range_subscriptions_by_subscription(
        &self,
        subscription_id: u64,
    ) -> DbResult<Vec<IpRangeSubscription>> {
        Ok(sqlx::query_as(
            "SELECT ips.* FROM ip_range_subscription ips
             INNER JOIN subscription_line_item sli ON ips.subscription_line_item_id = sli.id
             WHERE sli.subscription_id = ?",
        )
        .bind(subscription_id)
        .fetch_all(&self.db)
        .await?)
    }

    async fn list_ip_range_subscriptions_by_user(
        &self,
        user_id: u64,
    ) -> DbResult<Vec<IpRangeSubscription>> {
        Ok(sqlx::query_as(
            "SELECT ips.* FROM ip_range_subscription ips
             INNER JOIN subscription_line_item sli ON ips.subscription_line_item_id = sli.id
             INNER JOIN subscription s ON sli.subscription_id = s.id
             WHERE s.user_id = ?",
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await?)
    }

    async fn get_ip_range_subscription(&self, id: u64) -> DbResult<IpRangeSubscription> {
        Ok(
            sqlx::query_as("SELECT * FROM ip_range_subscription WHERE id = ?")
                .bind(id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn get_ip_range_subscription_by_cidr(&self, cidr: &str) -> DbResult<IpRangeSubscription> {
        Ok(
            sqlx::query_as("SELECT * FROM ip_range_subscription WHERE cidr = ?")
                .bind(cidr)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn insert_ip_range_subscription(
        &self,
        subscription: &IpRangeSubscription,
    ) -> DbResult<u64> {
        let result = sqlx::query(
            "INSERT INTO ip_range_subscription (subscription_line_item_id, available_ip_space_id, cidr, is_active, started_at, ended_at, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(subscription.subscription_line_item_id)
        .bind(subscription.available_ip_space_id)
        .bind(&subscription.cidr)
        .bind(subscription.is_active)
        .bind(subscription.started_at)
        .bind(subscription.ended_at)
        .bind(&subscription.metadata)
        .execute(&self.db)
        .await?;

        Ok(result.last_insert_id())
    }

    async fn update_ip_range_subscription(
        &self,
        subscription: &IpRangeSubscription,
    ) -> DbResult<()> {
        sqlx::query(
            "UPDATE ip_range_subscription SET subscription_line_item_id = ?, available_ip_space_id = ?, cidr = ?, is_active = ?, started_at = ?, ended_at = ?, metadata = ? WHERE id = ?"
        )
        .bind(subscription.subscription_line_item_id)
        .bind(subscription.available_ip_space_id)
        .bind(&subscription.cidr)
        .bind(subscription.is_active)
        .bind(subscription.started_at)
        .bind(subscription.ended_at)
        .bind(&subscription.metadata)
        .bind(subscription.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn delete_ip_range_subscription(&self, id: u64) -> DbResult<()> {
        sqlx::query("DELETE FROM ip_range_subscription WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    // ========================================================================
    // Payment Method Configuration
    // ========================================================================

    async fn list_payment_method_configs(&self) -> DbResult<Vec<PaymentMethodConfig>> {
        Ok(sqlx::query_as(
            "SELECT * FROM payment_method_config ORDER BY company_id, payment_method, name",
        )
        .fetch_all(&self.db)
        .await?)
    }

    async fn list_payment_method_configs_for_company(
        &self,
        company_id: u64,
    ) -> DbResult<Vec<PaymentMethodConfig>> {
        Ok(sqlx::query_as(
            "SELECT * FROM payment_method_config WHERE company_id = ? ORDER BY payment_method, name",
        )
        .bind(company_id)
        .fetch_all(&self.db)
        .await?)
    }

    async fn list_enabled_payment_method_configs_for_company(
        &self,
        company_id: u64,
    ) -> DbResult<Vec<PaymentMethodConfig>> {
        Ok(sqlx::query_as(
            "SELECT * FROM payment_method_config WHERE company_id = ? AND enabled = TRUE ORDER BY payment_method, name",
        )
        .bind(company_id)
        .fetch_all(&self.db)
        .await?)
    }

    async fn get_payment_method_config(&self, id: u64) -> DbResult<PaymentMethodConfig> {
        Ok(
            sqlx::query_as("SELECT * FROM payment_method_config WHERE id = ?")
                .bind(id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn get_payment_method_config_for_company(
        &self,
        company_id: u64,
        method: PaymentMethod,
    ) -> DbResult<PaymentMethodConfig> {
        Ok(sqlx::query_as(
            "SELECT * FROM payment_method_config WHERE company_id = ? AND payment_method = ?",
        )
        .bind(company_id)
        .bind(method)
        .fetch_one(&self.db)
        .await?)
    }

    async fn insert_payment_method_config(&self, config: &PaymentMethodConfig) -> DbResult<u64> {
        let result = sqlx::query(
            r#"
            INSERT INTO payment_method_config 
            (company_id, payment_method, name, enabled, provider_type, config, 
             processing_fee_rate, processing_fee_base, processing_fee_currency)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(config.company_id)
        .bind(config.payment_method)
        .bind(&config.name)
        .bind(config.enabled)
        .bind(&config.provider_type)
        .bind(&config.config)
        .bind(config.processing_fee_rate)
        .bind(config.processing_fee_base)
        .bind(&config.processing_fee_currency)
        .execute(&self.db)
        .await?;

        Ok(result.last_insert_id())
    }

    async fn update_payment_method_config(&self, config: &PaymentMethodConfig) -> DbResult<()> {
        sqlx::query(
            r#"
            UPDATE payment_method_config 
            SET company_id = ?, payment_method = ?, name = ?, enabled = ?, provider_type = ?, config = ?,
                processing_fee_rate = ?, processing_fee_base = ?, processing_fee_currency = ?
            WHERE id = ?
            "#,
        )
        .bind(config.company_id)
        .bind(config.payment_method)
        .bind(&config.name)
        .bind(config.enabled)
        .bind(&config.provider_type)
        .bind(&config.config)
        .bind(config.processing_fee_rate)
        .bind(config.processing_fee_base)
        .bind(&config.processing_fee_currency)
        .bind(config.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn delete_payment_method_config(&self, id: u64) -> DbResult<()> {
        sqlx::query("DELETE FROM payment_method_config WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn get_referral_by_user(&self, user_id: u64) -> DbResult<Referral> {
        Ok(sqlx::query_as("SELECT * FROM referral WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn get_referral_by_code(&self, code: &str) -> DbResult<Referral> {
        Ok(sqlx::query_as("SELECT * FROM referral WHERE code = ?")
            .bind(code)
            .fetch_one(&self.db)
            .await?)
    }

    async fn insert_referral(&self, referral: &Referral) -> DbResult<u64> {
        let res = sqlx::query(
            "INSERT INTO referral (user_id, code, lightning_address, use_nwc) VALUES (?, ?, ?, ?) returning id",
        )
        .bind(referral.user_id)
        .bind(&referral.code)
        .bind(&referral.lightning_address)
        .bind(referral.use_nwc)
        .fetch_one(&self.db)
        .await?;
        Ok(res.try_get(0)?)
    }

    async fn update_referral(&self, referral: &Referral) -> DbResult<()> {
        sqlx::query(
            "UPDATE referral SET lightning_address = ?, use_nwc = ? WHERE id = ?",
        )
        .bind(&referral.lightning_address)
        .bind(referral.use_nwc)
        .bind(referral.id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn insert_referral_payout(&self, payout: &ReferralPayout) -> DbResult<u64> {
        let res = sqlx::query(
            "INSERT INTO referral_payout (referral_id, amount, currency, invoice) VALUES (?, ?, ?, ?) returning id",
        )
        .bind(payout.referral_id)
        .bind(payout.amount)
        .bind(&payout.currency)
        .bind(&payout.invoice)
        .fetch_one(&self.db)
        .await?;
        Ok(res.try_get(0)?)
    }

    async fn update_referral_payout(&self, payout: &ReferralPayout) -> DbResult<()> {
        sqlx::query("UPDATE referral_payout SET is_paid = ?, pre_image = ? WHERE id = ?")
            .bind(payout.is_paid)
            .bind(&payout.pre_image)
            .bind(payout.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn list_referral_payouts(&self, referral_id: u64) -> DbResult<Vec<ReferralPayout>> {
        Ok(
            sqlx::query_as("SELECT * FROM referral_payout WHERE referral_id = ? ORDER BY created DESC")
                .bind(referral_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn list_referral_usage(&self, code: &str) -> DbResult<Vec<ReferralCostUsage>> {
        Ok(sqlx::query_as(
            "SELECT v.id as vm_id,
                    v.ref_code,
                    vp.created,
                    vp.amount,
                    vp.currency,
                    vp.rate,
                    c.base_currency
             FROM vm v
             JOIN (
                 SELECT vm_id, currency, amount, created, rate,
                        ROW_NUMBER() OVER (PARTITION BY vm_id ORDER BY created ASC) AS rn
                 FROM vm_payment
                 WHERE is_paid = 1
             ) vp ON v.id = vp.vm_id AND vp.rn = 1
             JOIN vm_host vh ON v.host_id = vh.id
             JOIN vm_host_region vhr ON vh.region_id = vhr.id
             JOIN company c ON vhr.company_id = c.id
             WHERE v.ref_code = ?
             ORDER BY vp.created DESC",
        )
        .bind(code)
        .fetch_all(&self.db)
        .await?)
    }

    async fn count_failed_referrals(&self, code: &str) -> DbResult<u64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vm v
             WHERE v.ref_code = ?
               AND NOT EXISTS (
                   SELECT 1 FROM vm_payment vp WHERE vp.vm_id = v.id AND vp.is_paid = 1
               )",
        )
        .bind(code)
        .fetch_one(&self.db)
        .await?;
        Ok(count as u64)
    }
}

#[cfg(feature = "nostr-domain")]
#[async_trait]
impl LNVPSNostrDb for LNVpsDbMysql {
    async fn get_handle(&self, handle_id: u64) -> DbResult<NostrDomainHandle> {
        Ok(
            sqlx::query_as("select * from nostr_domain_handle where id=?")
                .bind(handle_id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn get_handle_by_name(
        &self,
        domain_id: u64,
        handle: &str,
    ) -> DbResult<NostrDomainHandle> {
        Ok(
            sqlx::query_as("select * from nostr_domain_handle where domain_id=? and handle=?")
                .bind(domain_id)
                .bind(handle)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn insert_handle(&self, handle: &NostrDomainHandle) -> DbResult<u64> {
        Ok(
            sqlx::query(
                "insert into nostr_domain_handle(domain_id,handle,pubkey,relays) values(?,?,?,?) returning id",
            )
                .bind(handle.domain_id)
                .bind(&handle.handle)
                .bind(&handle.pubkey)
                .bind(&handle.relays)
                .fetch_one(&self.db)
                .await?
                .try_get(0)?,
        )
    }

    async fn update_handle(&self, handle: &NostrDomainHandle) -> DbResult<()> {
        sqlx::query("update nostr_domain_handle set handle=?,pubkey=?,relays=? where id=?")
            .bind(&handle.handle)
            .bind(&handle.pubkey)
            .bind(&handle.relays)
            .bind(handle.id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn delete_handle(&self, handle_id: u64) -> DbResult<()> {
        sqlx::query("delete from nostr_domain_handle where id=?")
            .bind(handle_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn list_handles(&self, domain_id: u64) -> DbResult<Vec<NostrDomainHandle>> {
        Ok(
            sqlx::query_as("select * from nostr_domain_handle where domain_id=?")
                .bind(domain_id)
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn get_domain(&self, id: u64) -> DbResult<NostrDomain> {
        Ok(sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain where id=?")
            .bind(id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn get_domain_by_name(&self, name: &str) -> DbResult<NostrDomain> {
        Ok(sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain where name=?")
            .bind(name)
            .fetch_one(&self.db)
            .await?)
    }

    async fn get_domain_by_activation_hash(&self, hash: &str) -> DbResult<NostrDomain> {
        Ok(sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain where activation_hash=?")
            .bind(hash)
            .fetch_one(&self.db)
            .await?)
    }

    async fn list_domains(&self, owner_id: u64) -> DbResult<Vec<NostrDomain>> {
        Ok(sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain where owner_id=?")
            .bind(owner_id)
            .fetch_all(&self.db)
            .await?)
    }

    async fn insert_domain(&self, domain: &NostrDomain) -> DbResult<u64> {
        Ok(
            sqlx::query(
                "insert into nostr_domain(owner_id,name,relays,activation_hash,http_only) values(?,?,?,?,?) returning id",
            )
            .bind(domain.owner_id)
            .bind(&domain.name)
            .bind(&domain.relays)
            .bind(&domain.activation_hash)
            .bind(domain.http_only)
            .fetch_one(&self.db)
            .await?
            .try_get(0)?,
        )
    }

    async fn delete_domain(&self, domain_id: u64) -> DbResult<()> {
        sqlx::query("delete from nostr_domain where id = ?")
            .bind(domain_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn list_all_domains(&self) -> DbResult<Vec<NostrDomain>> {
        Ok(sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain")
            .fetch_all(&self.db)
            .await?)
    }

    async fn list_active_domains(&self) -> DbResult<Vec<NostrDomain>> {
        Ok(sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain where enabled=1")
            .fetch_all(&self.db)
            .await?)
    }

    async fn list_disabled_domains(&self) -> DbResult<Vec<NostrDomain>> {
        Ok(sqlx::query_as("select *,(select count(1) from nostr_domain_handle where domain_id=nostr_domain.id) handles from nostr_domain where enabled=0")
            .fetch_all(&self.db)
            .await?)
    }

    async fn enable_domain_with_https(&self, domain_id: u64) -> DbResult<()> {
        sqlx::query(
            "update nostr_domain set enabled=1, http_only=0, last_status_change=CURRENT_TIMESTAMP where id=?",
        )
        .bind(domain_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn enable_domain_http_only(&self, domain_id: u64) -> DbResult<()> {
        sqlx::query(
            "update nostr_domain set enabled=1, http_only=1, last_status_change=CURRENT_TIMESTAMP where id=?",
        )
        .bind(domain_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn disable_domain(&self, domain_id: u64) -> DbResult<()> {
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
    ) -> DbResult<std::collections::HashSet<(u16, u16)>> {
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

    async fn get_user_roles(&self, user_id: u64) -> DbResult<Vec<u64>> {
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

    async fn is_admin_user(&self, user_id: u64) -> DbResult<bool> {
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

    async fn assign_user_role(&self, user_id: u64, role_id: u64, assigned_by: u64) -> DbResult<()> {
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

    async fn revoke_user_role(&self, user_id: u64, role_id: u64) -> DbResult<()> {
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

    async fn create_role(&self, name: &str, description: Option<&str>) -> DbResult<u64> {
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

    async fn get_role(&self, role_id: u64) -> DbResult<AdminRole> {
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

    async fn get_role_by_name(&self, name: &str) -> DbResult<AdminRole> {
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

    async fn list_roles(&self) -> DbResult<Vec<AdminRole>> {
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

    async fn update_role(&self, role: &AdminRole) -> DbResult<()> {
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
            return Err(DbError::Source(
                anyhow!("Role not found or is a system role (cannot be updated)")
                    .into_boxed_dyn_error(),
            ));
        }

        Ok(())
    }

    async fn delete_role(&self, role_id: u64) -> DbResult<()> {
        // First check if role has any assignments
        let assignments_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM admin_role_assignments WHERE role_id = ?",
        )
        .bind(role_id)
        .fetch_one(&self.db)
        .await?;

        if assignments_count > 0 {
            return Err(DbError::Source(
                anyhow!(
                    "Cannot delete role: {} active user assignments exist",
                    assignments_count
                )
                .into_boxed_dyn_error(),
            ));
        }

        let query = r#"
            DELETE FROM admin_roles
            WHERE id = ? AND is_system_role = false
        "#;

        let result = sqlx::query(query).bind(role_id).execute(&self.db).await?;

        if result.rows_affected() == 0 {
            return Err(DbError::Source(
                anyhow!("Role not found or is a system role (cannot be deleted)")
                    .into_boxed_dyn_error(),
            ));
        }

        Ok(())
    }

    async fn add_role_permission(&self, role_id: u64, resource: u16, action: u16) -> DbResult<()> {
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

    async fn remove_role_permission(
        &self,
        role_id: u64,
        resource: u16,
        action: u16,
    ) -> DbResult<()> {
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

    async fn get_role_permissions(&self, role_id: u64) -> DbResult<Vec<(u16, u16)>> {
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

    async fn get_user_role_assignments(&self, user_id: u64) -> DbResult<Vec<AdminRoleAssignment>> {
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

    async fn count_role_users(&self, role_id: u64) -> DbResult<u64> {
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
    ) -> DbResult<(Vec<crate::AdminUserInfo>, u64)> {
        let (where_clause, search_param) = if let Some(pubkey) = search_pubkey {
            if pubkey.len() == 64 {
                (" WHERE HEX(u.pubkey) = ? ", Some(pubkey.to_uppercase()))
            } else {
                return Err(DbError::Source(
                    anyhow::anyhow!("Search only supports 64-character hex pubkeys")
                        .into_boxed_dyn_error(),
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
                u.email_verified,
                u.email_verify_token,
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
                u.nwc_connection_string,
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
    ) -> DbResult<(Vec<VmHostRegion>, u64)> {
        // Get total count
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vm_host_region")
            .fetch_one(&self.db)
            .await?;

        // Get paginated results
        let regions = sqlx::query_as::<_, VmHostRegion>(
            "SELECT * FROM vm_host_region ORDER BY name LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?;

        Ok((regions, total as u64))
    }

    async fn admin_create_region(
        &self,
        name: &str,
        enabled: bool,
        company_id: u64,
    ) -> DbResult<u64> {
        let id = sqlx::query_scalar::<_, u64>(
            "INSERT INTO vm_host_region (name, enabled, company_id) VALUES (?, ?, ?) RETURNING id",
        )
        .bind(name)
        .bind(enabled)
        .bind(company_id)
        .fetch_one(&self.db)
        .await?;

        Ok(id)
    }

    async fn admin_update_region(&self, region: &VmHostRegion) -> DbResult<()> {
        sqlx::query("UPDATE vm_host_region SET name = ?, enabled = ?, company_id = ? WHERE id = ?")
            .bind(&region.name)
            .bind(region.enabled)
            .bind(region.company_id)
            .bind(region.id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn admin_delete_region(&self, region_id: u64) -> DbResult<()> {
        // First check if any hosts are assigned to this region
        let host_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM vm_host WHERE region_id = ?")
                .bind(region_id)
                .fetch_one(&self.db)
                .await?;

        if host_count > 0 {
            return Err(DbError::Source(
                anyhow!("Cannot delete region with {} assigned hosts", host_count)
                    .into_boxed_dyn_error(),
            ));
        }

        // Disable the region instead of deleting to preserve referential integrity
        sqlx::query("UPDATE vm_host_region SET enabled = ? WHERE id = ?")
            .bind(false)
            .bind(region_id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn admin_count_region_hosts(&self, region_id: u64) -> DbResult<u64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vm_host WHERE region_id = ?")
            .bind(region_id)
            .fetch_one(&self.db)
            .await?;

        Ok(count as u64)
    }

    async fn admin_get_region_stats(&self, region_id: u64) -> DbResult<RegionStats> {
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
        .await?;

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
    ) -> DbResult<(Vec<VmOsImage>, u64)> {
        // Get paginated list of VM OS images
        let images = sqlx::query_as::<_, VmOsImage>(
            "SELECT * FROM vm_os_image ORDER BY id LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?;

        // Get total count
        let total_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vm_os_image")
            .fetch_one(&self.db)
            .await?;

        Ok((images, total_count.0 as u64))
    }

    async fn admin_get_vm_os_image(&self, image_id: u64) -> DbResult<VmOsImage> {
        Ok(sqlx::query_as("SELECT * FROM vm_os_image WHERE id = ?")
            .bind(image_id)
            .fetch_one(&self.db)
            .await?)
    }

    async fn admin_create_vm_os_image(&self, image: &VmOsImage) -> DbResult<u64> {
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
        .await?;

        Ok(result.last_insert_id())
    }

    async fn admin_update_vm_os_image(&self, image: &VmOsImage) -> DbResult<()> {
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
        .await?;

        Ok(())
    }

    async fn admin_delete_vm_os_image(&self, image_id: u64) -> DbResult<()> {
        // Check if the image is referenced by any VMs
        let vm_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vm WHERE image_id = ?")
            .bind(image_id)
            .fetch_one(&self.db)
            .await?;

        if vm_count.0 > 0 {
            return Err(DbError::Source(
                anyhow!(
                    "Cannot delete VM OS image: {} VMs are using this image",
                    vm_count.0
                )
                .into_boxed_dyn_error(),
            ));
        }

        sqlx::query("DELETE FROM vm_os_image WHERE id = ?")
            .bind(image_id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn list_vm_templates_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> DbResult<(Vec<VmTemplate>, i64)> {
        // Get paginated list of VM templates
        let templates = sqlx::query_as::<_, VmTemplate>(
            "SELECT * FROM vm_template ORDER BY id LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?;

        // Get total count
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vm_template")
            .fetch_one(&self.db)
            .await?;

        Ok((templates, total.0))
    }

    async fn update_vm_template(&self, template: &VmTemplate) -> DbResult<()> {
        sqlx::query(
            r#"UPDATE vm_template SET 
               name = ?, enabled = ?, expires = ?, cpu = ?, cpu_mfg = ?, cpu_arch = ?, cpu_features = ?, memory = ?,
               disk_size = ?, disk_type = ?, disk_interface = ?, 
               cost_plan_id = ?, region_id = ?
               WHERE id = ?"#,
        )
        .bind(&template.name)
        .bind(template.enabled)
        .bind(template.expires)
        .bind(template.cpu)
        .bind(&template.cpu_mfg)
        .bind(&template.cpu_arch)
        .bind(&template.cpu_features)
        .bind(template.memory)
        .bind(template.disk_size)
        .bind(template.disk_type)
        .bind(template.disk_interface)
        .bind(template.cost_plan_id)
        .bind(template.region_id)
        .bind(template.id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn delete_vm_template(&self, template_id: u64) -> DbResult<()> {
        sqlx::query("DELETE FROM vm_template WHERE id = ?")
            .bind(template_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn check_vm_template_usage(&self, template_id: u64) -> DbResult<i64> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vm WHERE template_id = ?")
            .bind(template_id)
            .fetch_one(&self.db)
            .await?;
        Ok(count.0)
    }

    async fn admin_list_hosts_with_regions_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<AdminVmHost>, u64)> {
        // Get total count (including disabled hosts)
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vm_host h JOIN vm_host_region hr ON h.region_id = hr.id",
        )
        .fetch_one(&self.db)
        .await?;

        // Get paginated results with region info and active VM count (including disabled hosts)
        let mut hosts: Vec<AdminVmHost> = sqlx::query_as(
            "SELECT h.*, 
                    hr.id as region_id, 
                    hr.name as region_name, 
                    hr.enabled as region_enabled, 
                    hr.company_id as region_company_id,
                    COALESCE(vm_counts.active_vm_count, 0) as active_vm_count
             FROM vm_host h 
             JOIN vm_host_region hr ON h.region_id = hr.id 
             LEFT JOIN (
                 SELECT host_id, COUNT(*) as active_vm_count 
                 FROM vm 
                 WHERE deleted = 0 
                 GROUP BY host_id
             ) vm_counts ON h.id = vm_counts.host_id
             ORDER BY h.name 
             LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?;

        // Fetch disk information for each host
        for host in &mut hosts {
            let disks: Vec<VmHostDisk> =
                sqlx::query_as("SELECT * FROM vm_host_disk WHERE host_id = ? ORDER BY name")
                    .bind(host.host.id)
                    .fetch_all(&self.db)
                    .await?;

            host.disks = disks;
        }

        Ok((hosts, total as u64))
    }

    async fn insert_custom_pricing(&self, pricing: &VmCustomPricing) -> DbResult<u64> {
        let query = r#"
            INSERT INTO vm_custom_pricing (name, enabled, created, expires, region_id, currency, cpu_mfg, cpu_arch, cpu_features, cpu_cost, memory_cost, ip4_cost, ip6_cost, min_cpu, max_cpu, min_memory, max_memory)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        let result = sqlx::query(query)
            .bind(&pricing.name)
            .bind(pricing.enabled)
            .bind(pricing.created)
            .bind(pricing.expires)
            .bind(pricing.region_id)
            .bind(&pricing.currency)
            .bind(&pricing.cpu_mfg)
            .bind(&pricing.cpu_arch)
            .bind(&pricing.cpu_features)
            .bind(pricing.cpu_cost)
            .bind(pricing.memory_cost)
            .bind(pricing.ip4_cost)
            .bind(pricing.ip6_cost)
            .bind(pricing.min_cpu)
            .bind(pricing.max_cpu)
            .bind(pricing.min_memory)
            .bind(pricing.max_memory)
            .execute(&self.db)
            .await?;

        Ok(result.last_insert_id())
    }

    async fn update_custom_pricing(&self, pricing: &VmCustomPricing) -> DbResult<()> {
        let query = r#"
            UPDATE vm_custom_pricing 
            SET name = ?, enabled = ?, expires = ?, region_id = ?, currency = ?, 
                cpu_mfg = ?, cpu_arch = ?, cpu_features = ?, cpu_cost = ?, memory_cost = ?, ip4_cost = ?, ip6_cost = ?, 
                min_cpu = ?, max_cpu = ?, min_memory = ?, max_memory = ?
            WHERE id = ?
        "#;

        let result = sqlx::query(query)
            .bind(&pricing.name)
            .bind(pricing.enabled)
            .bind(pricing.expires)
            .bind(pricing.region_id)
            .bind(&pricing.currency)
            .bind(&pricing.cpu_mfg)
            .bind(&pricing.cpu_arch)
            .bind(&pricing.cpu_features)
            .bind(pricing.cpu_cost)
            .bind(pricing.memory_cost)
            .bind(pricing.ip4_cost)
            .bind(pricing.ip6_cost)
            .bind(pricing.min_cpu)
            .bind(pricing.max_cpu)
            .bind(pricing.min_memory)
            .bind(pricing.max_memory)
            .bind(pricing.id)
            .execute(&self.db)
            .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::Source(
                anyhow!("Custom pricing model not found").into_boxed_dyn_error(),
            ));
        }

        Ok(())
    }

    async fn delete_custom_pricing(&self, id: u64) -> DbResult<()> {
        let query = "DELETE FROM vm_custom_pricing WHERE id = ?";
        let result = sqlx::query(query).bind(id).execute(&self.db).await?;

        if result.rows_affected() == 0 {
            return Err(DbError::Source(
                anyhow!("Custom pricing model not found").into_boxed_dyn_error(),
            ));
        }

        Ok(())
    }

    async fn insert_custom_pricing_disk(&self, disk: &VmCustomPricingDisk) -> DbResult<u64> {
        let query = r#"
            INSERT INTO vm_custom_pricing_disk (pricing_id, kind, interface, cost, min_disk_size, max_disk_size)
            VALUES (?, ?, ?, ?, ?, ?)
        "#;

        let result = sqlx::query(query)
            .bind(disk.pricing_id)
            .bind(disk.kind as u16)
            .bind(disk.interface as u16)
            .bind(disk.cost)
            .bind(disk.min_disk_size)
            .bind(disk.max_disk_size)
            .execute(&self.db)
            .await?;

        Ok(result.last_insert_id())
    }

    async fn delete_custom_pricing_disks(&self, pricing_id: u64) -> DbResult<()> {
        let query = "DELETE FROM vm_custom_pricing_disk WHERE pricing_id = ?";
        sqlx::query(query)
            .bind(pricing_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn count_custom_templates_by_pricing(&self, pricing_id: u64) -> DbResult<u64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vm_custom_template WHERE pricing_id = ?",
        )
        .bind(pricing_id)
        .fetch_one(&self.db)
        .await?;

        Ok(count as u64)
    }

    async fn list_custom_templates_by_pricing_paginated(
        &self,
        pricing_id: u64,
        limit: i64,
        offset: i64,
    ) -> DbResult<(Vec<VmCustomTemplate>, u64)> {
        let total = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vm_custom_template WHERE pricing_id = ?",
        )
        .bind(pricing_id)
        .fetch_one(&self.db)
        .await?;

        let templates = sqlx::query_as::<_, VmCustomTemplate>(
            "SELECT * FROM vm_custom_template WHERE pricing_id = ? ORDER BY id LIMIT ? OFFSET ?",
        )
        .bind(pricing_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?;

        Ok((templates, total as u64))
    }

    async fn insert_custom_template(&self, template: &VmCustomTemplate) -> DbResult<u64> {
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
            .await?;

        Ok(result.last_insert_id())
    }

    async fn update_custom_template(&self, template: &VmCustomTemplate) -> DbResult<()> {
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
            .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::Source(
                anyhow!("Custom template not found").into_boxed_dyn_error(),
            ));
        }

        Ok(())
    }

    async fn delete_custom_template(&self, id: u64) -> DbResult<()> {
        let query = "DELETE FROM vm_custom_template WHERE id = ?";
        let result = sqlx::query(query).bind(id).execute(&self.db).await?;

        if result.rows_affected() == 0 {
            return Err(DbError::Source(
                anyhow!("Custom template not found").into_boxed_dyn_error(),
            ));
        }

        Ok(())
    }

    async fn count_vms_by_custom_template(&self, template_id: u64) -> DbResult<u64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vm WHERE custom_template_id = ? AND deleted = false",
        )
        .bind(template_id)
        .fetch_one(&self.db)
        .await?;

        Ok(count as u64)
    }

    async fn admin_list_companies(&self, limit: u64, offset: u64) -> DbResult<(Vec<Company>, u64)> {
        let companies = sqlx::query_as::<_, Company>(
            "SELECT * FROM company ORDER BY created DESC LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?;

        let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM company")
            .fetch_one(&self.db)
            .await?;

        Ok((companies, total as u64))
    }

    async fn admin_get_company(&self, company_id: u64) -> DbResult<Company> {
        Ok(
            sqlx::query_as::<_, Company>("SELECT * FROM company WHERE id = ?")
                .bind(company_id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn admin_create_company(&self, company: &Company) -> DbResult<u64> {
        let result = sqlx::query(
            r#"INSERT INTO company (name, address_1, address_2, city, state, country_code, tax_id, postcode, phone, email, created, base_currency)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?)"#,
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
            .bind(&company.base_currency)
        .execute(&self.db)
        .await?;

        Ok(result.last_insert_id())
    }

    async fn admin_update_company(&self, company: &Company) -> DbResult<()> {
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
        .await?;

        Ok(())
    }

    async fn admin_delete_company(&self, company_id: u64) -> DbResult<()> {
        // Check if company has any regions assigned
        let region_count = self.admin_count_company_regions(company_id).await?;
        if region_count > 0 {
            return Err(DbError::Source(
                anyhow!(
                    "Cannot delete company with {} assigned regions",
                    region_count
                )
                .into_boxed_dyn_error(),
            ));
        }

        sqlx::query("DELETE FROM company WHERE id = ?")
            .bind(company_id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn admin_count_company_regions(&self, company_id: u64) -> DbResult<u64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vm_host_region WHERE company_id = ?",
        )
        .bind(company_id)
        .fetch_one(&self.db)
        .await?;

        Ok(count as u64)
    }

    async fn admin_get_payments_by_date_range(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
    ) -> DbResult<Vec<VmPayment>> {
        Ok(sqlx::query_as(
            "SELECT * FROM vm_payment WHERE created >= ? AND created < ? AND is_paid = true ORDER BY created",
        )
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.db)
        .await?)
    }

    async fn admin_get_payments_by_date_range_and_company(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
    ) -> DbResult<Vec<VmPayment>> {
        Ok(sqlx::query_as(
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
        .await?)
    }

    async fn admin_get_payments_with_company_info(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
        currency: Option<&str>,
    ) -> DbResult<Vec<VmPaymentWithCompany>> {
        match currency {
            Some(currency) => {
                Ok(sqlx::query_as(
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
                .fetch_all(&self.db).await?)
            },
            None => {
                Ok(sqlx::query_as(
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
                .fetch_all(&self.db).await?)
            }
        }
    }

    async fn admin_get_referral_usage_by_date_range(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
        ref_code: Option<&str>,
    ) -> DbResult<Vec<ReferralCostUsage>> {
        let mut query = "SELECT v.id as vm_id,
                                v.ref_code,
                                vp.created,
                                vp.amount,
                                vp.currency,
                                vp.rate,
                                c.base_currency
                         FROM vm v
                         JOIN (
                             SELECT vm_id, currency, amount, created, rate,
                                    ROW_NUMBER() OVER (PARTITION BY vm_id ORDER BY created ASC) as rn
                             FROM vm_payment
                             WHERE is_paid = 1
                         ) vp ON v.id = vp.vm_id AND vp.rn = 1
                         JOIN vm_host vh ON v.host_id = vh.id
                         JOIN vm_host_region vhr ON vh.region_id = vhr.id
                         JOIN company c ON vhr.company_id = c.id
                         WHERE v.ref_code IS NOT NULL 
                           AND vp.created >= ? 
                           AND vp.created <= ?
                           AND c.id = ?".to_string();

        if ref_code.is_some() {
            query.push_str(" AND v.ref_code = ?");
        }

        query.push_str(" ORDER BY vp.created DESC");

        let mut db_query = sqlx::query_as(&query)
            .bind(start_date)
            .bind(end_date)
            .bind(company_id);

        if let Some(code) = ref_code {
            db_query = db_query.bind(code);
        }

        Ok(db_query.fetch_all(&self.db).await?)
    }

    async fn admin_list_ip_ranges(
        &self,
        limit: u64,
        offset: u64,
        region_id: Option<u64>,
    ) -> DbResult<(Vec<IpRange>, u64)> {
        let (ip_ranges, total) = if let Some(region_id) = region_id {
            // Filter by region
            let ip_ranges = sqlx::query_as::<_, IpRange>(
                "SELECT * FROM ip_range WHERE region_id = ? ORDER BY cidr LIMIT ? OFFSET ?",
            )
            .bind(region_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await?;

            let total =
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ip_range WHERE region_id = ?")
                    .bind(region_id)
                    .fetch_one(&self.db)
                    .await?;

            (ip_ranges, total)
        } else {
            // Get all IP ranges
            let ip_ranges = sqlx::query_as::<_, IpRange>(
                "SELECT * FROM ip_range ORDER BY cidr LIMIT ? OFFSET ?",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await?;

            let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ip_range")
                .fetch_one(&self.db)
                .await?;

            (ip_ranges, total)
        };

        Ok((ip_ranges, total as u64))
    }

    async fn admin_get_ip_range(&self, ip_range_id: u64) -> DbResult<IpRange> {
        Ok(
            sqlx::query_as::<_, IpRange>("SELECT * FROM ip_range WHERE id = ?")
                .bind(ip_range_id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn admin_create_ip_range(&self, ip_range: &IpRange) -> DbResult<u64> {
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
        .await?;

        Ok(result.last_insert_id())
    }

    async fn admin_update_ip_range(&self, ip_range: &IpRange) -> DbResult<()> {
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
        .await?;

        Ok(())
    }

    async fn admin_delete_ip_range(&self, ip_range_id: u64) -> DbResult<()> {
        // Check if IP range has any assignments
        let assignment_count = self.admin_count_ip_range_assignments(ip_range_id).await?;
        if assignment_count > 0 {
            return Err(DbError::Source(
                anyhow!(
                    "Cannot delete IP range with {} active IP assignments",
                    assignment_count
                )
                .into_boxed_dyn_error(),
            ));
        }

        sqlx::query("DELETE FROM ip_range WHERE id = ?")
            .bind(ip_range_id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn admin_count_ip_range_assignments(&self, ip_range_id: u64) -> DbResult<u64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vm_ip_assignment WHERE ip_range_id = ? AND deleted = false",
        )
        .bind(ip_range_id)
        .fetch_one(&self.db)
        .await?;

        Ok(count as u64)
    }

    async fn admin_list_access_policies(&self) -> DbResult<Vec<AccessPolicy>> {
        Ok(
            sqlx::query_as::<_, AccessPolicy>("SELECT * FROM access_policy ORDER BY name")
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn admin_list_access_policies_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<AccessPolicy>, u64)> {
        let access_policies = sqlx::query_as::<_, AccessPolicy>(
            "SELECT * FROM access_policy ORDER BY name LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?;

        let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM access_policy")
            .fetch_one(&self.db)
            .await?;

        Ok((access_policies, total as u64))
    }

    async fn admin_get_access_policy(&self, access_policy_id: u64) -> DbResult<AccessPolicy> {
        Ok(
            sqlx::query_as::<_, AccessPolicy>("SELECT * FROM access_policy WHERE id = ?")
                .bind(access_policy_id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn admin_create_access_policy(&self, access_policy: &AccessPolicy) -> DbResult<u64> {
        let result = sqlx::query(
            r#"INSERT INTO access_policy (name, kind, router_id, interface)
               VALUES (?, ?, ?, ?)"#,
        )
        .bind(&access_policy.name)
        .bind(access_policy.kind as u16)
        .bind(access_policy.router_id)
        .bind(&access_policy.interface)
        .execute(&self.db)
        .await?;

        Ok(result.last_insert_id())
    }

    async fn admin_update_access_policy(&self, access_policy: &AccessPolicy) -> DbResult<()> {
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
        .await?;

        Ok(())
    }

    async fn admin_delete_access_policy(&self, access_policy_id: u64) -> DbResult<()> {
        // Check if access policy is used by any IP ranges
        let usage_count = self
            .admin_count_access_policy_ip_ranges(access_policy_id)
            .await?;
        if usage_count > 0 {
            return Err(DbError::Source(
                anyhow!(
                    "Cannot delete access policy used by {} IP ranges",
                    usage_count
                )
                .into_boxed_dyn_error(),
            ));
        }

        sqlx::query("DELETE FROM access_policy WHERE id = ?")
            .bind(access_policy_id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn admin_count_access_policy_ip_ranges(&self, access_policy_id: u64) -> DbResult<u64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM ip_range WHERE access_policy_id = ?",
        )
        .bind(access_policy_id)
        .fetch_one(&self.db)
        .await?;

        Ok(count as u64)
    }

    async fn admin_list_routers(&self) -> DbResult<Vec<Router>> {
        Ok(
            sqlx::query_as::<_, Router>("SELECT * FROM router ORDER BY name")
                .fetch_all(&self.db)
                .await?,
        )
    }

    async fn admin_list_routers_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<Router>, u64)> {
        let routers =
            sqlx::query_as::<_, Router>("SELECT * FROM router ORDER BY name LIMIT ? OFFSET ?")
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.db)
                .await?;

        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM router")
            .fetch_one(&self.db)
            .await?;

        Ok((routers, total.0 as u64))
    }

    async fn admin_get_router(&self, router_id: u64) -> DbResult<Router> {
        Ok(
            sqlx::query_as::<_, Router>("SELECT * FROM router WHERE id = ?")
                .bind(router_id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn admin_create_router(&self, router: &Router) -> DbResult<u64> {
        let result = sqlx::query(
            "INSERT INTO router (name, enabled, kind, url, token) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&router.name)
        .bind(router.enabled)
        .bind(router.kind.clone())
        .bind(&router.url)
        .bind(&router.token)
        .execute(&self.db)
        .await?;

        Ok(result.last_insert_id())
    }

    async fn admin_update_router(&self, router: &Router) -> DbResult<()> {
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
        .await?;

        Ok(())
    }

    async fn admin_delete_router(&self, router_id: u64) -> DbResult<()> {
        // Check if router is used by any access policies
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM access_policy WHERE router_id = ?")
                .bind(router_id)
                .fetch_one(&self.db)
                .await?;

        if count.0 > 0 {
            return Err(DbError::Source(
                anyhow!(
                    "Cannot delete router: {} access policies are using this router",
                    count.0
                )
                .into_boxed_dyn_error(),
            ));
        }

        sqlx::query("DELETE FROM router WHERE id = ?")
            .bind(router_id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn admin_count_router_access_policies(&self, router_id: u64) -> DbResult<u64> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM access_policy WHERE router_id = ?")
                .bind(router_id)
                .fetch_one(&self.db)
                .await?;

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
    ) -> DbResult<(Vec<crate::Vm>, u64)> {
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
        let total: i64 = count_query.build_query_scalar().fetch_one(&self.db).await?;

        // Add ordering and pagination to data query
        data_query
            .push(" ORDER BY v.id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);

        // Execute data query
        let vms: Vec<Vm> = data_query.build_query_as().fetch_all(&self.db).await?;

        Ok((vms, total as u64))
    }

    async fn get_user_by_pubkey(&self, pubkey: &[u8]) -> DbResult<crate::User> {
        Ok(sqlx::query_as("SELECT * FROM users WHERE pubkey = ?")
            .bind(pubkey)
            .fetch_one(&self.db)
            .await?)
    }

    async fn admin_list_vm_ip_assignments(
        &self,
        limit: u64,
        offset: u64,
        vm_id: Option<u64>,
        ip_range_id: Option<u64>,
        ip: Option<&str>,
        include_deleted: Option<bool>,
    ) -> DbResult<(Vec<VmIpAssignment>, u64)> {
        let mut count_query = QueryBuilder::new("SELECT COUNT(*) FROM vm_ip_assignment");
        let mut data_query = QueryBuilder::new("SELECT * FROM vm_ip_assignment");

        let mut has_conditions = false;

        // Apply filters
        if let Some(vm_id) = vm_id {
            if !has_conditions {
                count_query.push(" WHERE ");
                data_query.push(" WHERE ");
                has_conditions = true;
            } else {
                count_query.push(" AND ");
                data_query.push(" AND ");
            }
            count_query.push("vm_id = ").push_bind(vm_id);
            data_query.push("vm_id = ").push_bind(vm_id);
        }

        if let Some(ip_range_id) = ip_range_id {
            if !has_conditions {
                count_query.push(" WHERE ");
                data_query.push(" WHERE ");
                has_conditions = true;
            } else {
                count_query.push(" AND ");
                data_query.push(" AND ");
            }
            count_query.push("ip_range_id = ").push_bind(ip_range_id);
            data_query.push("ip_range_id = ").push_bind(ip_range_id);
        }

        if let Some(ip) = ip {
            if !has_conditions {
                count_query.push(" WHERE ");
                data_query.push(" WHERE ");
                has_conditions = true;
            } else {
                count_query.push(" AND ");
                data_query.push(" AND ");
            }
            count_query.push("ip = ").push_bind(ip);
            data_query.push("ip = ").push_bind(ip);
        }

        // Handle deleted filter
        match include_deleted {
            Some(false) | None => {
                // Exclude deleted assignments (default behavior)
                if !has_conditions {
                    count_query.push(" WHERE ");
                    data_query.push(" WHERE ");
                } else {
                    count_query.push(" AND ");
                    data_query.push(" AND ");
                }
                count_query.push("deleted = FALSE");
                data_query.push("deleted = FALSE");
            }
            Some(true) => {
                // Include both deleted and non-deleted assignments
            }
        }

        // Execute count query
        let total: i64 = count_query.build_query_scalar().fetch_one(&self.db).await?;

        // Add ordering and pagination to data query
        data_query
            .push(" ORDER BY id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);

        // Execute data query
        let assignments: Vec<VmIpAssignment> =
            data_query.build_query_as().fetch_all(&self.db).await?;

        Ok((assignments, total as u64))
    }

    async fn admin_get_vm_ip_assignment(&self, assignment_id: u64) -> DbResult<VmIpAssignment> {
        Ok(
            sqlx::query_as::<_, VmIpAssignment>("SELECT * FROM vm_ip_assignment WHERE id = ?")
                .bind(assignment_id)
                .fetch_one(&self.db)
                .await?,
        )
    }

    async fn admin_create_vm_ip_assignment(&self, assignment: &VmIpAssignment) -> DbResult<u64> {
        // Check if IP already exists and is not deleted
        if let Ok(_existing) = sqlx::query_as::<_, VmIpAssignment>(
            "SELECT * FROM vm_ip_assignment WHERE ip = ? AND deleted = FALSE",
        )
        .bind(&assignment.ip)
        .fetch_one(&self.db)
        .await
        {
            return Err(DbError::Source(
                anyhow!("IP address {} is already assigned", assignment.ip).into_boxed_dyn_error(),
            ));
        }

        let result = sqlx::query(
            "INSERT INTO vm_ip_assignment (vm_id, ip_range_id, ip, deleted, arp_ref, dns_forward, dns_forward_ref, dns_reverse, dns_reverse_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(assignment.vm_id)
        .bind(assignment.ip_range_id)
        .bind(&assignment.ip)
        .bind(assignment.deleted)
        .bind(&assignment.arp_ref)
        .bind(&assignment.dns_forward)
        .bind(&assignment.dns_forward_ref)
        .bind(&assignment.dns_reverse)
        .bind(&assignment.dns_reverse_ref)
        .execute(&self.db)
        .await?;

        Ok(result.last_insert_id())
    }

    async fn admin_update_vm_ip_assignment(&self, assignment: &VmIpAssignment) -> DbResult<()> {
        // Check if IP already exists for a different assignment
        if let Ok(existing) = sqlx::query_as::<_, VmIpAssignment>(
            "SELECT * FROM vm_ip_assignment WHERE ip = ? AND deleted = FALSE AND id != ?",
        )
        .bind(&assignment.ip)
        .bind(assignment.id)
        .fetch_one(&self.db)
        .await
        {
            return Err(DbError::Source(
                anyhow!(
                    "IP address {} is already assigned to assignment {}",
                    assignment.ip,
                    existing.id
                )
                .into_boxed_dyn_error(),
            ));
        }

        sqlx::query(
            "UPDATE vm_ip_assignment SET vm_id = ?, ip_range_id = ?, ip = ?, arp_ref = ?, dns_forward = ?, dns_forward_ref = ?, dns_reverse = ?, dns_reverse_ref = ? WHERE id = ?"
        )
        .bind(assignment.vm_id)
        .bind(assignment.ip_range_id)
        .bind(&assignment.ip)
        .bind(&assignment.arp_ref)
        .bind(&assignment.dns_forward)
        .bind(&assignment.dns_forward_ref)
        .bind(&assignment.dns_reverse)
        .bind(&assignment.dns_reverse_ref)
        .bind(assignment.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn admin_delete_vm_ip_assignment(&self, assignment_id: u64) -> DbResult<()> {
        sqlx::query("UPDATE vm_ip_assignment SET deleted = TRUE WHERE id = ?")
            .bind(assignment_id)
            .execute(&self.db)
            .await?;

        Ok(())
    }
}
