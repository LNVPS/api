use crate::dvm::{DVMHandler, DVMJobRequest, build_status_for_job};
use crate::provisioner::VmProvisioner;
use crate::subscription::SubscriptionHandler;
use anyhow::Context;
use lnvps_api_common::VmStateCache;
use lnvps_db::{
    DiskInterface, DiskType, OsDistribution, PaymentMethod, SubscriptionPayment, UserSshKey,
    VmCustomTemplate,
};
use nostr_sdk::prelude::DataVendingMachineStatus;
use nostr_sdk::{Client, EventBuilder, Tag};
use ssh_key::PublicKey;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

pub struct LnvpsDvm {
    client: Client,
    sub_handler: SubscriptionHandler,
}

impl LnvpsDvm {
    pub fn new(sub_handler: SubscriptionHandler, client: Client) -> LnvpsDvm {
        Self {
            sub_handler,
            client,
        }
    }
}

impl DVMHandler for LnvpsDvm {
    fn handle_request(
        &mut self,
        request: DVMJobRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> {
        let sub_handler = self.sub_handler.clone();
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
            let os_image = request.params.get("os").context("missing os parameter")?;
            let os_version = request
                .params
                .get("os_version")
                .context("missing os_version parameter")?;
            let region = request.params.get("region");

            let db = sub_handler.db();
            let host_region = if let Some(r) = region {
                db.get_host_region_by_name(r).await?
            } else {
                db.list_host_region()
                    .await?
                    .into_iter()
                    .next()
                    .context("no host region")?
            };
            let mut pricing = db.list_custom_pricing(host_region.id).await?;

            // Filter to only enabled pricing. Hourly models are paid from account
            // credit only, which a DVM order paid by Lightning invoice can't use,
            // so they are never picked here.
            pricing.retain(|p| p.enabled && p.interval_type != lnvps_db::IntervalType::Hour);

            // we expect only 1 pricing per region
            let pricing = pricing
                .first()
                .context("no custom pricing found in region")?;

            let template = VmCustomTemplate {
                id: 0,
                cpu: cpu.parse()?,
                memory: crate::MB * memory.parse::<u64>()?,
                disk_size: crate::GB * disk.parse::<u64>()?,
                disk_type: DiskType::from_str(disk_type)?,
                disk_interface: DiskInterface::from_str(disk_interface)?,
                pricing_id: pricing.id,
                ..Default::default()
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
                key_data: pk.to_openssh()?.into(),
                ..Default::default()
            };

            // report as started if params are valid
            let processing =
                build_status_for_job(&request, DataVendingMachineStatus::Processing, None, None);
            client.send_event_builder(processing).await?;

            let existing_keys = db.list_user_ssh_key(uid).await?;
            let ssh_key_id = if let Some(k) = existing_keys.iter().find(|k| {
                let ek: PublicKey = k.key_data.as_str().parse().unwrap();
                ek.eq(&pk)
            }) {
                k.id
            } else {
                db.insert_user_ssh_key(&new_key).await?
            };

            let image = OsDistribution::from_str(os_image)?;
            let image = db
                .list_os_image()
                .await?
                .into_iter()
                .find(|i| i.distribution == image && i.version == *os_version)
                .context("no os image found")?;

            let vm = sub_handler
                .vm_provisioner()
                .provision_custom(uid, template, image.id, ssh_key_id, None)
                .await?;
            let line_item = db
                .get_subscription_line_item(vm.subscription_line_item_id)
                .await?;
            let invoice = sub_handler
                .renew_subscription(line_item.subscription_id, PaymentMethod::Lightning, 1)
                .await?;
            client
                .send_event_builder(payment_feedback(&request, &invoice)?)
                .await?;

            Ok(())
        })
    }
}

fn payment_feedback(
    request: &DVMJobRequest,
    invoice: &SubscriptionPayment,
) -> anyhow::Result<EventBuilder> {
    if invoice.is_paid {
        return Ok(build_status_for_job(
            request,
            DataVendingMachineStatus::Success,
            None,
            None,
        ));
    }
    Ok(build_status_for_job(
        request,
        DataVendingMachineStatus::PaymentRequired,
        None,
        None,
    )
    .tag(Tag::parse([
        "amount",
        invoice.amount.to_string().as_str(),
        invoice.external_data.as_str(),
    ])?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dvm::parse_job_request;
    use crate::mocks::{MockNode, MockOnChainProvider};
    use crate::settings::mock_settings;
    use lnvps_api_common::{
        ChannelWorkCommander, ExchangeRateService, MockDb, MockExchangeRate, Ticker,
    };
    use lnvps_db::{VmCustomPricing, VmCustomPricingDisk};
    use nostr_sdk::{EventBuilder, Keys, Kind};
    use std::sync::Arc;

    async fn job_request(keys: &Keys) -> DVMJobRequest {
        let ev = EventBuilder::new(Kind::from_u16(5999), "")
            .sign(keys)
            .await
            .unwrap();
        parse_job_request(&ev).unwrap()
    }

    fn renewal(is_paid: bool, external_data: &str) -> SubscriptionPayment {
        SubscriptionPayment {
            id: vec![1u8; 32],
            subscription_id: 1,
            user_id: 1,
            created: chrono::Utc::now(),
            expires: chrono::Utc::now(),
            amount: 21_000,
            currency: "BTC".to_string(),
            payment_method: PaymentMethod::Lightning,
            payment_type: lnvps_db::SubscriptionPaymentType::Purchase,
            external_data: external_data.to_string().into(),
            external_id: None,
            is_paid,
            rate: 1.0,
            time_value: None,
            metadata: None,
            tax: 0,
            processing_fee: 0,
            paid_at: None,
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
            refunded_payment_id: None,
            renewal_source: None,
        }
    }

    fn tag_values(ev: &nostr_sdk::Event, name: &str) -> Vec<String> {
        ev.tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some(name))
            .map(|t| t.as_slice()[1..].to_vec())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn a_credit_funded_job_reports_success() {
        let keys = Keys::generate();
        let req = job_request(&keys).await;
        let ev = payment_feedback(&req, &renewal(true, "credit"))
            .unwrap()
            .sign(&keys)
            .await
            .unwrap();
        assert_eq!(tag_values(&ev, "status")[0], "success");
        assert!(tag_values(&ev, "amount").is_empty());
    }

    #[tokio::test]
    async fn an_unpaid_job_asks_for_payment() {
        let keys = Keys::generate();
        let req = job_request(&keys).await;
        let ev = payment_feedback(&req, &renewal(false, "lnbc1"))
            .unwrap()
            .sign(&keys)
            .await
            .unwrap();
        assert_eq!(tag_values(&ev, "status")[0], "payment-required");
        assert_eq!(tag_values(&ev, "amount"), vec!["21000", "lnbc1"]);
    }

    #[tokio::test]
    #[ignore]
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
                    cpu_mfg: Default::default(),
                    cpu_arch: Default::default(),
                    cpu_features: Default::default(),
                    cpu_cost: 150,   // €1.50 in cents per CPU
                    memory_cost: 50, // €0.50 in cents per GB
                    ip4_cost: 150,   // €1.50 in cents per IPv4
                    ip6_cost: 5,     // €0.05 in cents per IPv6
                    min_cpu: 0,
                    max_cpu: 0,
                    min_memory: 0,
                    max_memory: 0,
                    ..Default::default()
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
                    cost: 5, // €0.05 in cents per GB
                    min_disk_size: 5 * crate::GB,
                    max_disk_size: 1 * crate::TB,
                },
            );
        }

        let settings = mock_settings();
        let provisioner = SubscriptionHandler::new(
            settings,
            db.clone(),
            node.clone(),
            Arc::new(MockOnChainProvider::default()),
            None,
            exch.clone(),
            lnvps_api_common::VatClient::new(),
            Arc::new(ChannelWorkCommander::new()),
            VmStateCache::new(),
        )?;
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
