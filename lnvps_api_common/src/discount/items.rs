//! The order's line items, as a discount rule sees them.
//!
//! An order is a set of line items, and what a rule most often wants to say is
//! "this offer is for *that* product": a plan, a region, a machine size, a
//! managed app. Reducing that to a single `template_id` plus a product name
//! could only express the simplest of those, and every new product shape would
//! have needed another scalar bolted onto the context.
//!
//! Each item is a typed variant carrying the properties of its own product, so
//! a rule can ask about exactly the thing it cares about:
//!
//! ```text
//! order.items.exists(i, i.type == 'vm' && i.template_id == 3)
//! order.items.all(i, i.type == 'vm' && i.cpu >= 8)
//! order.items.exists(i, i.type == 'ip_range')
//! size(order.items) > 1
//! ```
//!
//! # Type is certain, detail is best-effort
//!
//! The line item itself says what kind of product it bills for, so `i.type` is
//! always right. The detail fields come from the product row behind it, which
//! may not exist yet: an IP range or a sponsored ASN is allocated when the
//! *first payment settles*, so on a purchase order there is nothing to read.
//! Those fields are therefore null rather than the line being dropped — a
//! dropped line would make `i.type == 'ip_range'` silently false on exactly the
//! order that is buying one. A comparison against a null detail fails the rule,
//! which applies no discount, so "unknown" never costs LNVPS money.
//!
//! # Per-item money
//!
//! `amount` is the line's recurring price for **one interval** and
//! `setup_amount` its one-off fee, both converted into the order's payment
//! currency by [`crate::PricingEngine::quote_discount`] so that everything a
//! rule sees is in one currency.
//!
//! They are the line's **list price** — what the invoice shows for that line —
//! not necessarily what is charged for it. For non-VPS lines the two are the
//! same figure: the renewal sums `amount * intervals` directly. For a VPS line
//! the stored amount is the base price recorded when the VM was ordered (and
//! rewritten on upgrade), while the actual charge is recomputed at payment time
//! by the pricing engine from the cost plan or custom pricing, including the
//! machine's IP assignments; a later change to the cost plan does not rewrite
//! it. So compare `i.amount` when a rule wants "this line is worth about X",
//! and use `order.amount` — the actual net being charged — for a minimum-spend
//! threshold.

use lnvps_db::{LNVpsDb, LineItemType, SubscriptionLineItem};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// One line of the order being priced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
///
/// Every field except the product carries a serde default, so the admin rule
/// preview can post a partial line (`{"type": "vm", "cpu": 8}`) to try a rule
/// without inventing an invoice.
pub struct OrderLineItem {
    /// Id of the `subscription_line_item` row.
    #[serde(default)]
    pub line_item_id: i64,
    /// The line's display name, as it appears on the invoice.
    #[serde(default)]
    pub name: String,
    /// Recurring price of this line for one interval, in the order's payment
    /// currency and minor units. See the module docs: this is the line's list
    /// price, not necessarily what is charged for it.
    #[serde(default)]
    pub amount: i64,
    /// One-off setup fee for this line, in the same units. Charged on the first
    /// payment only.
    #[serde(default)]
    pub setup_amount: i64,
    /// The product this line bills for, and its properties. Flattened, so a
    /// rule reads `i.type` and `i.cpu` rather than `i.product.cpu`.
    #[serde(flatten)]
    pub product: OrderProduct,
}

/// What a line item bills for.
///
/// Serialized with a `type` tag, so `i.type == 'vm'` selects the variant and
/// the variant's own fields are readable alongside it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OrderProduct {
    /// A virtual machine, standard plan or custom build.
    Vm {
        #[serde(default)]
        vm_id: Option<i64>,
        /// The standard plan being billed; null for a custom build, which is
        /// how a rule tells the two apart.
        #[serde(default)]
        template_id: Option<i64>,
        /// Region the machine runs in.
        #[serde(default)]
        region_id: Option<i64>,
        /// vCPU cores.
        #[serde(default)]
        cpu: Option<i64>,
        /// Memory in bytes.
        #[serde(default)]
        memory: Option<i64>,
        /// Disk size in bytes.
        #[serde(default)]
        disk_size: Option<i64>,
        /// `ssd` or `hdd`.
        #[serde(default)]
        disk_type: Option<String>,
        /// Included IPv4 addresses.
        #[serde(default)]
        ip4_count: Option<i64>,
        /// Included IPv6 addresses.
        #[serde(default)]
        ip6_count: Option<i64>,
    },
    /// A managed app deployment.
    App {
        #[serde(default)]
        deployment_id: Option<i64>,
        /// The catalog app being deployed.
        #[serde(default)]
        app_id: Option<i64>,
        /// The cluster it runs on.
        #[serde(default)]
        cluster_id: Option<i64>,
        /// Resource sizing multiplier applied to the app's base resources.
        #[serde(default)]
        resource_multiplier: Option<i64>,
    },
    /// A leased IP range. Allocated when the first payment settles, so the
    /// detail is null on the order that buys it.
    IpRange {
        #[serde(default)]
        subscription_id: Option<i64>,
        /// The range in CIDR notation.
        #[serde(default)]
        cidr: Option<String>,
    },
    /// A sponsored ASN. Assigned by the registry after purchase, so the detail
    /// is null on the order that buys it.
    AsnSponsoring {
        #[serde(default)]
        subscription_id: Option<i64>,
        /// The assigned AS number.
        #[serde(default)]
        asn: Option<i64>,
        /// The registry the ASN is held with, e.g. `ripe`.
        #[serde(default)]
        registry: Option<String>,
    },
    /// DNS hosting. Has no product row of its own — the line item is the whole
    /// record — so it carries only the common fields.
    DnsHosting,
    /// A one-off marketplace node listing fee.
    MarketplaceNodeFee { node_id: Option<i64> },
    /// A consumer VPN plan.
    Vpn {
        #[serde(default)]
        vpn_subscription_id: Option<i64>,
        /// Which service, and therefore which regions and address space.
        #[serde(default)]
        vpn_service_id: Option<i64>,
    },
}

impl OrderLineItem {
    /// Build the rule's view of `line_item`, resolving the product row behind
    /// it where one exists.
    ///
    /// Never fails: the type comes from the line item and is always reported,
    /// and any detail that cannot be read is left null. See the module docs for
    /// why a missing product row must not remove the line.
    pub async fn resolve(db: &Arc<dyn LNVpsDb>, line_item: &SubscriptionLineItem) -> Self {
        let product = match line_item.subscription_type {
            LineItemType::Vps => Self::vm_product(db, line_item.id).await,
            LineItemType::App => {
                let d = db.get_app_deployment_by_line_item(line_item.id).await.ok();
                OrderProduct::App {
                    deployment_id: d.as_ref().map(|d| d.id as i64),
                    app_id: d.as_ref().map(|d| d.app_id as i64),
                    cluster_id: d.as_ref().map(|d| d.cluster_id as i64),
                    resource_multiplier: d.as_ref().map(|d| d.resource_multiplier as i64),
                }
            }
            LineItemType::IpRange => {
                let r = db
                    .list_ip_range_subscriptions_by_line_item(line_item.id)
                    .await
                    .ok()
                    .and_then(|rows| rows.into_iter().next());
                OrderProduct::IpRange {
                    subscription_id: r.as_ref().map(|r| r.id as i64),
                    cidr: r.map(|r| r.cidr),
                }
            }
            LineItemType::AsnSponsoring => {
                let a = db
                    .list_asn_subscriptions_by_line_item(line_item.id)
                    .await
                    .ok()
                    .and_then(|rows| rows.into_iter().next());
                OrderProduct::AsnSponsoring {
                    subscription_id: a.as_ref().map(|a| a.id as i64),
                    asn: a.as_ref().and_then(|a| a.asn).map(|n| n as i64),
                    registry: a.map(|a| a.registry.to_string().to_lowercase()),
                }
            }
            LineItemType::Vpn => {
                let p = db
                    .get_vpn_subscription_by_line_item(line_item.id)
                    .await
                    .ok()
                    .flatten();
                OrderProduct::Vpn {
                    vpn_subscription_id: p.as_ref().map(|p| p.id as i64),
                    vpn_service_id: p.as_ref().map(|p| p.vpn_service_id as i64),
                }
            }
            LineItemType::DnsHosting => OrderProduct::DnsHosting,
            LineItemType::MarketplaceNodeFee => OrderProduct::MarketplaceNodeFee {
                node_id: db
                    .get_marketplace_node_by_line_item(line_item.id)
                    .await
                    .ok()
                    .map(|n| n.id as i64),
            },
        };

        Self {
            line_item_id: line_item.id as i64,
            name: line_item.name.clone(),
            // Resolved in the subscription's base currency; the pricing engine
            // converts it into the payment currency when it builds the context,
            // because only it holds an exchange-rate service.
            amount: line_item.amount as i64,
            setup_amount: line_item.setup_amount as i64,
            product,
        }
    }

    /// This line with its money converted by `convert`, used by the pricing
    /// engine to put every figure in the context in the payment currency.
    pub(crate) fn with_converted_money(self, amount: i64, setup_amount: i64) -> Self {
        Self {
            amount,
            setup_amount,
            ..self
        }
    }

    /// Resolve a VM line item's specs from its template or custom build.
    async fn vm_product(db: &Arc<dyn LNVpsDb>, line_item_id: u64) -> OrderProduct {
        let Ok(vm) = db.get_vm_by_line_item(line_item_id).await else {
            return OrderProduct::Vm {
                vm_id: None,
                template_id: None,
                region_id: None,
                cpu: None,
                memory: None,
                disk_size: None,
                disk_type: None,
                ip4_count: None,
                ip6_count: None,
            };
        };

        // A standard plan carries its own region; a custom build's region is
        // the region of the host it was placed on.
        let specs = match vm.template_id {
            Some(id) => db.get_vm_template(id).await.ok().map(|t| {
                (
                    t.cpu as i64,
                    t.memory as i64,
                    t.disk_size as i64,
                    t.disk_type.to_string(),
                    t.ip4_count as i64,
                    t.ip6_count as i64,
                    Some(t.region_id as i64),
                )
            }),
            None => match vm.custom_template_id {
                Some(id) => {
                    let region = db
                        .get_host(vm.host_id)
                        .await
                        .ok()
                        .map(|h| h.region_id as i64);
                    db.get_custom_vm_template(id).await.ok().map(|t| {
                        (
                            t.cpu as i64,
                            t.memory as i64,
                            t.disk_size as i64,
                            t.disk_type.to_string(),
                            t.ip4_count as i64,
                            t.ip6_count as i64,
                            region,
                        )
                    })
                }
                None => None,
            },
        };

        OrderProduct::Vm {
            vm_id: Some(vm.id as i64),
            template_id: vm.template_id.map(|t| t as i64),
            region_id: specs.as_ref().and_then(|s| s.6),
            cpu: specs.as_ref().map(|s| s.0),
            memory: specs.as_ref().map(|s| s.1),
            disk_size: specs.as_ref().map(|s| s.2),
            disk_type: specs.as_ref().map(|s| s.3.clone()),
            ip4_count: specs.as_ref().map(|s| s.4),
            ip6_count: specs.as_ref().map(|s| s.5),
        }
    }

    /// Build the rule's view of a whole order. Every line is reported.
    pub async fn resolve_all(
        db: &Arc<dyn LNVpsDb>,
        line_items: &[SubscriptionLineItem],
    ) -> Vec<Self> {
        let mut out = Vec::with_capacity(line_items.len());
        for li in line_items {
            out.push(Self::resolve(db, li).await);
        }
        out
    }

    /// A representative VM line, used by the admin rule preview and by tests.
    pub fn sample_vm() -> Self {
        Self {
            line_item_id: 1,
            name: "VPS".to_string(),
            amount: 10_000,
            setup_amount: 0,
            product: OrderProduct::Vm {
                vm_id: Some(1),
                template_id: Some(1),
                region_id: Some(1),
                cpu: Some(2),
                memory: Some(4 * crate::GB as i64),
                disk_size: Some(80 * crate::GB as i64),
                disk_type: Some("ssd".to_string()),
                ip4_count: Some(1),
                ip6_count: Some(1),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockDb;
    use lnvps_db::{
        AsnSubscription, LNVpsDbBase, LineItemType, Subscription, Vm, VmCustomTemplate,
    };

    async fn db_with_user() -> (Arc<dyn LNVpsDb>, u64) {
        let mock = MockDb::default();
        let user_id = mock.upsert_user(&[4; 32]).await.unwrap();
        (Arc::new(mock), user_id)
    }

    /// Create a subscription with one line item of `kind`, returning the line.
    async fn line(
        db: &Arc<dyn LNVpsDb>,
        user_id: u64,
        kind: LineItemType,
        name: &str,
    ) -> SubscriptionLineItem {
        let (_sub_id, ids) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id,
                    company_id: 1,
                    name: "s".to_string(),
                    description: None,
                    created: chrono::Utc::now(),
                    expires: None,
                    is_active: true,
                    is_setup: true,
                    currency: "EUR".to_string(),
                    interval_amount: 1,
                    interval_type: lnvps_db::IntervalType::Month,
                    setup_fee: 0,
                    auto_renewal_enabled: false,
                    external_id: None,
                },
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: kind,
                    name: name.to_string(),
                    description: None,
                    amount: 1_000,
                    setup_amount: 0,
                    configuration: None,
                }],
            )
            .await
            .unwrap();
        db.get_subscription_line_item(ids[0]).await.unwrap()
    }

    fn vm(user_id: u64, line_item_id: u64, template_id: Option<u64>) -> Vm {
        Vm {
            id: 0,
            host_id: 1,
            user_id,
            image_id: 1,
            template_id,
            custom_template_id: None,
            subscription_line_item_id: line_item_id,
            // The mock enforces lazy FKs; no key or disk row is needed for
            // what this test resolves.
            ssh_key_id: None,
            disk_id: 1,
            mac_address: "ff:ff:ff:ff:ff:ff".to_string(),
            ..Default::default()
        }
    }

    /// A standard-plan VM reports the plan's specs, so a rule can target a
    /// plan, a size or a region without the engine choosing for it.
    #[tokio::test]
    async fn a_template_vm_reports_its_plan() {
        let (db, user_id) = db_with_user().await;
        let li = line(&db, user_id, LineItemType::Vps, "VPS").await;
        let vm_id = db.insert_vm(&vm(user_id, li.id, Some(1))).await.unwrap();

        let item = OrderLineItem::resolve(&db, &li).await;
        assert_eq!(item.line_item_id, li.id as i64);
        assert_eq!(item.name, "VPS");
        match item.product {
            OrderProduct::Vm {
                vm_id: id,
                template_id,
                region_id,
                cpu,
                memory,
                disk_size,
                disk_type,
                ip4_count,
                ip6_count,
            } => {
                assert_eq!(id, Some(vm_id as i64));
                assert_eq!(template_id, Some(1));
                assert_eq!(region_id, Some(1));
                assert_eq!(cpu, Some(2));
                assert_eq!(memory, Some((crate::GB * 2) as i64));
                assert_eq!(disk_size, Some((crate::GB * 64) as i64));
                assert_eq!(disk_type.as_deref(), Some("ssd"));
                assert_eq!((ip4_count, ip6_count), (Some(1), Some(1)));
            }
            other => panic!("expected a vm, got {other:?}"),
        }
    }

    /// A custom build has no plan: `template_id` is null, which is how a rule
    /// tells the two apart, and its specs come from the custom template with
    /// the region taken from the host it was placed on.
    #[tokio::test]
    async fn a_custom_vm_reports_its_build_and_has_no_template() {
        let (db, user_id) = db_with_user().await;
        let li = line(&db, user_id, LineItemType::Vps, "Custom VPS").await;
        let custom_id = db
            .insert_custom_vm_template(&VmCustomTemplate {
                id: 0,
                cpu: 8,
                memory: crate::GB * 16,
                disk_size: crate::GB * 500,
                disk_type: lnvps_db::DiskType::SSD,
                disk_interface: lnvps_db::DiskInterface::PCIe,
                pricing_id: 1,
                ip4_count: 2,
                ip6_count: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        db.insert_vm(&Vm {
            custom_template_id: Some(custom_id),
            ..vm(user_id, li.id, None)
        })
        .await
        .unwrap();

        match OrderLineItem::resolve(&db, &li).await.product {
            OrderProduct::Vm {
                template_id,
                region_id,
                cpu,
                ip4_count,
                ..
            } => {
                assert_eq!(template_id, None, "a custom build has no plan");
                assert_eq!(region_id, Some(1), "taken from the host");
                assert_eq!(cpu, Some(8));
                assert_eq!(ip4_count, Some(2));
            }
            other => panic!("expected a vm, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_vm_products_report_their_own_rows() {
        let (db, user_id) = db_with_user().await;

        // DNS hosting has no product row at all — the line item is the record.
        let dns = line(&db, user_id, LineItemType::DnsHosting, "DNS").await;
        let item = OrderLineItem::resolve(&db, &dns).await;
        assert_eq!(item.product, OrderProduct::DnsHosting);
        assert_eq!(item.name, "DNS");

        let asn_line = line(&db, user_id, LineItemType::AsnSponsoring, "ASN").await;
        db.insert_asn_subscription(&AsnSubscription {
            id: 0,
            subscription_line_item_id: asn_line.id,
            registry: lnvps_db::InternetRegistry::RIPE,
            asn: Some(212_805),
            status: lnvps_db::AsnSubscriptionStatus::Assigned,
            created: chrono::Utc::now(),
            assigned_at: None,
            is_active: true,
            ended_at: None,
            aut_num_ref: None,
            metadata: None,
        })
        .await
        .unwrap();
        match OrderLineItem::resolve(&db, &asn_line).await.product {
            OrderProduct::AsnSponsoring { asn, registry, .. } => {
                assert_eq!(asn, Some(212_805));
                assert_eq!(registry.as_deref(), Some("ripe"));
            }
            other => panic!("expected an asn, got {other:?}"),
        }
    }

    /// A product row that does not exist yet — an IP range or ASN is allocated
    /// only once the first payment settles — must still report its *type*, or
    /// `i.type == 'ip_range'` would be false on the very order buying one.
    #[tokio::test]
    async fn a_line_with_no_product_row_yet_still_reports_its_type() {
        let (db, user_id) = db_with_user().await;
        let ip = line(&db, user_id, LineItemType::IpRange, "IPv4 /24").await;
        let item = OrderLineItem::resolve(&db, &ip).await;
        assert_eq!(item.name, "IPv4 /24");
        assert_eq!(
            item.product,
            OrderProduct::IpRange {
                subscription_id: None,
                cidr: None
            },
            "type known, detail not yet"
        );

        // Same for a VPS line whose VM row cannot be read.
        let orphan = line(&db, user_id, LineItemType::Vps, "VPS with no VM").await;
        let items = OrderLineItem::resolve_all(&db, &[orphan, ip]).await;
        assert_eq!(items.len(), 2, "no line is ever dropped");
        assert!(matches!(
            items[0].product,
            OrderProduct::Vm {
                vm_id: None,
                cpu: None,
                ..
            }
        ));
    }

    /// The remaining product types report their own rows when those rows do
    /// exist.
    #[tokio::test]
    async fn resolved_products_carry_their_detail() {
        let (db, user_id) = db_with_user().await;

        let ip = line(&db, user_id, LineItemType::IpRange, "IPv4 /24").await;
        db.insert_ip_range_subscription(&lnvps_db::IpRangeSubscription {
            id: 0,
            subscription_line_item_id: ip.id,
            available_ip_space_id: 1,
            created: chrono::Utc::now(),
            cidr: "203.0.113.0/24".to_string(),
            origin_asn: Some(212_805),
            is_active: true,
            started_at: chrono::Utc::now(),
            ended_at: None,
            metadata: None,
        })
        .await
        .unwrap();
        match OrderLineItem::resolve(&db, &ip).await.product {
            OrderProduct::IpRange {
                cidr,
                subscription_id,
            } => {
                assert_eq!(cidr.as_deref(), Some("203.0.113.0/24"));
                assert!(subscription_id.is_some());
            }
            other => panic!("expected an ip range, got {other:?}"),
        }

        let app_line = line(&db, user_id, LineItemType::App, "Managed app").await;
        db.insert_app_deployment(&lnvps_db::AppDeployment {
            id: 0,
            user_id,
            app_id: 1,
            cluster_id: 1,
            resource_multiplier: 2,
            subscription_line_item_id: app_line.id,
            name: "inst".to_string(),
            namespace: "app-1".to_string(),
            hostname: None,
            custom_domain: None,
            custom_domain_verified: false,
            config: None,
            desired_state: lnvps_db::AppDeploymentDesiredState::Running,
            status: lnvps_db::AppDeploymentStatus::Running,
            status_message: None,
            usage_cpu_milli: None,
            usage_memory_bytes: None,
            usage_storage_bytes: None,
            usage_collected: None,
            created: chrono::Utc::now(),
            deleted: false,
        })
        .await
        .unwrap();
        match OrderLineItem::resolve(&db, &app_line).await.product {
            OrderProduct::App {
                app_id,
                cluster_id,
                resource_multiplier,
                deployment_id,
            } => {
                assert_eq!(app_id, Some(1));
                assert_eq!(cluster_id, Some(1));
                assert_eq!(resource_multiplier, Some(2));
                assert!(deployment_id.is_some());
            }
            other => panic!("expected an app, got {other:?}"),
        }

        let fee = line(
            &db,
            user_id,
            LineItemType::MarketplaceNodeFee,
            "Node listing",
        )
        .await;
        let operator_id = db
            .insert_marketplace_operator(&lnvps_db::MarketplaceOperator {
                user_id,
                enabled: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let node_id = db
            .insert_marketplace_node(&lnvps_db::MarketplaceNode {
                operator_id,
                name: "node-1".to_string(),
                subscription_line_item_id: Some(fee.id),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            OrderLineItem::resolve(&db, &fee).await.product,
            OrderProduct::MarketplaceNodeFee {
                node_id: Some(node_id as i64)
            }
        );
    }

    /// The sample is what the admin preview evaluates against, so it has to be
    /// a real, complete line.
    #[test]
    fn the_sample_is_a_standard_vm() {
        let sample = OrderLineItem::sample_vm();
        assert!(matches!(
            sample.product,
            OrderProduct::Vm {
                template_id: Some(1),
                ..
            }
        ));
        // Round-trips, so the admin API can accept one as input.
        let json = serde_json::to_string(&sample).unwrap();
        assert!(json.contains(r#""type":"vm""#));
        assert_eq!(
            serde_json::from_str::<OrderLineItem>(&json).unwrap(),
            sample
        );
    }
}
