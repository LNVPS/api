use crate::dvm::{build_status_for_job, DVMHandler, DVMJobRequest};
use crate::provisioner::LNVpsProvisioner;
use anyhow::Context;
use lnvps_db::{DiskInterface, DiskType, LNVpsDb, PaymentMethod, UserSshKey, VmCustomTemplate};
use nostr::prelude::DataVendingMachineStatus;
use nostr::Tag;
use nostr_sdk::Client;
use ssh_key::PublicKey;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

pub struct LnvpsDvm {
    client: Client,
    provisioner: Arc<LNVpsProvisioner>,
}

impl LnvpsDvm {
    pub fn new(provisioner: Arc<LNVpsProvisioner>, client: Client) -> LnvpsDvm {
        Self {
            provisioner,
            client,
        }
    }
}

impl DVMHandler for LnvpsDvm {
    fn handle_request(
        &mut self,
        request: DVMJobRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> {
        let provisioner = self.provisioner.clone();
        let client = self.client.clone();
        Box::pin(async move {
            let default_disk = "ssd".to_string();
            let default_interface = "pcie".to_string();
            let cpu = request.params.get("cpu").context("missing cpu parameter")?;
            let memory = request
                .params
                .get("memory")
                .context("missing memory parameter")?;
            let disk = request
                .params
                .get("disk")
                .context("missing disk parameter")?;
            let disk_type = request.params.get("disk_type").unwrap_or(&default_disk);
            let disk_interface = request
                .params
                .get("disk_interface")
                .unwrap_or(&default_interface);
            let ssh_key = request
                .params
                .get("ssh_key")
                .context("missing ssh_key parameter")?;
            let ssh_key_name = request.params.get("ssh_key_name");
            let region = request.params.get("region");

            let db = provisioner.get_db();
            let host_region = if let Some(r) = region {
                db.get_host_region_by_name(r).await?
            } else {
                db.list_host_region()
                    .await?
                    .into_iter()
                    .next()
                    .context("no host region")?
            };
            let pricing = db.list_custom_pricing(host_region.id).await?;

            // we expect only 1 pricing per region
            let pricing = pricing
                .first()
                .context("no custom pricing found in region")?;

            let template = VmCustomTemplate {
                id: 0,
                cpu: cpu.parse()?,
                memory: memory.parse()?,
                disk_size: disk.parse()?,
                disk_type: DiskType::from_str(disk_type)?,
                disk_interface: DiskInterface::from_str(disk_interface)?,
                pricing_id: pricing.id,
            };
            let uid = db.upsert_user(request.event.pubkey.as_bytes()).await?;

            let pk: PublicKey = ssh_key.parse()?;
            let key_name = if let Some(n) = ssh_key_name {
                n.clone()
            } else {
                pk.comment().to_string()
            };
            let new_key = UserSshKey {
                name: key_name,
                user_id: uid,
                key_data: pk.to_openssh()?,
                ..Default::default()
            };

            // report as started if params are valid
            let processing =
                build_status_for_job(&request, DataVendingMachineStatus::Processing, None, None);
            client.send_event_builder(processing).await?;

            let existing_keys = db.list_user_ssh_key(uid).await?;
            let ssh_key_id = if let Some(k) = existing_keys.iter().find(|k| {
                let ek: PublicKey = k.key_data.parse().unwrap();
                ek.eq(&pk)
            }) {
                k.id
            } else {
                db.insert_user_ssh_key(&new_key).await?
            };

            let vm = provisioner
                .provision_custom(uid, template, 0, ssh_key_id, None)
                .await?;
            let invoice = provisioner.renew(vm.id, PaymentMethod::Lightning).await?;

            let mut payment = build_status_for_job(
                &request,
                DataVendingMachineStatus::PaymentRequired,
                None,
                None,
            );
            payment = payment.tag(Tag::parse([
                "amount",
                invoice.amount.to_string().as_str(),
                &invoice.external_data,
            ])?);
            client.send_event_builder(payment).await?;

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dvm::parse_job_request;
    use crate::exchange::{ExchangeRateService, Ticker};
    use crate::mocks::{MockDb, MockExchangeRate, MockNode};
    use crate::settings::mock_settings;
    use lnvps_db::{VmCustomPricing, VmCustomPricingDisk};
    use nostr::{EventBuilder, Keys, Kind};

    #[tokio::test]
    async fn test_dvm() -> anyhow::Result<()> {
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::new());
        let exch = Arc::new(MockExchangeRate::new());
        exch.set_rate(Ticker::btc_rate("EUR")?, 69_420.0).await;

        {
            let mut cp = db.custom_pricing.lock().await;
            cp.insert(
                1,
                VmCustomPricing {
                    id: 1,
                    name: "mock".to_string(),
                    enabled: true,
                    created: Default::default(),
                    expires: None,
                    region_id: 1,
                    currency: "EUR".to_string(),
                    cpu_cost: 1.5,
                    memory_cost: 0.5,
                    ip4_cost: 1.5,
                    ip6_cost: 0.05,
                },
            );
            let mut cpd = db.custom_pricing_disk.lock().await;
            cpd.insert(
                1,
                VmCustomPricingDisk {
                    id: 1,
                    pricing_id: 1,
                    kind: DiskType::SSD,
                    interface: DiskInterface::PCIe,
                    cost: 0.05,
                },
            );
        }

        let settings = mock_settings();
        let provisioner = Arc::new(LNVpsProvisioner::new(
            settings,
            db.clone(),
            node.clone(),
            exch.clone(),
        ));
        let keys = Keys::generate();
        let empty_client = Client::new(keys.clone());
        empty_client.add_relay("wss://nos.lol").await?;
        empty_client.connect().await;

        let mut dvm = LnvpsDvm::new(provisioner.clone(), empty_client.clone());

        let ev = EventBuilder::new(Kind::from_u16(5999), "")
            .tags([
                Tag::parse(["param", "cpu", "1"])?,
                Tag::parse(["param", "memory", "1024"])?,
                Tag::parse(["param", "disk", "50"])?,
                Tag::parse(["param", "disk_type", "ssd"])?,
                Tag::parse(["param", "ssh_key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGUSrwzZfbjqY81RRC7eg3zRvg0D53HOhjbG6h0SY3f3"])?,
            ])
            .sign(&keys)
            .await?;
        let req = parse_job_request(&ev)?;
        dvm.handle_request(req).await?;

        Ok(())
    }
}
