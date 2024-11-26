use crate::{LNVpsDb, Vm, VmTemplate};
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Hydrate {
    /// Load parent resources
    async fn hydrate_up(&mut self, db: &Box<dyn LNVpsDb>) -> Result<()>;

    /// Load child resources
    async fn hydrate_down(&mut self, db: &Box<dyn LNVpsDb>) -> Result<()>;
}

#[async_trait]
impl Hydrate for Vm {
    async fn hydrate_up(&mut self, db: &Box<dyn LNVpsDb>) -> Result<()> {
        let image = db.get_os_image(self.image_id).await?;
        let template = db.get_vm_template(self.template_id).await?;
        let ssh_key = db.get_user_ssh_key(self.ssh_key_id).await?;

        self.image = Some(image);
        self.template = Some(template);
        self.ssh_key = Some(ssh_key);
        Ok(())
    }

    async fn hydrate_down(&mut self, db: &Box<dyn LNVpsDb>) -> Result<()> {
        //let payments = db.list_vm_payment(self.id).await?;
        let ips = db.list_vm_ip_assignments(self.id).await?;

        //self.payments = Some(payments);
        self.ip_assignments = Some(ips);
        Ok(())
    }
}

#[async_trait]
impl Hydrate for VmTemplate {
    async fn hydrate_up(&mut self, db: &Box<dyn LNVpsDb>) -> Result<()> {
        let cost_plan = db.get_cost_plan(self.cost_plan_id).await?;
        let region = db.get_host_region(self.region_id).await?;
        self.cost_plan = Some(cost_plan);
        self.region = Some(region);
        Ok(())
    }

    async fn hydrate_down(&mut self, db: &Box<dyn LNVpsDb>) -> Result<()> {
        todo!()
    }
}