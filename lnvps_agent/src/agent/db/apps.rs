//! Managed app tools: the public catalogue and the customer's deployments.
//!
//! The catalogue half needs no account (it is a shop window); the deployment
//! half resolves through [`DbToolExecutor::owned_deployment`]. Start/stop set
//! the desired state exactly as the REST endpoints do and let the operator
//! reconcile — reversible, which is why live chat may call them.

use std::collections::HashMap;

use anyhow::{Result, bail};
use serde_json::{Value, json};

use lnvps_api_common::{AppCapacity, AppClusterCapacityService};
use lnvps_db::{App, AppDeployment, AppDeploymentDesiredState};
use payments_rs::currency::{Currency, CurrencyAmount};

use super::{DbToolExecutor, money, required_u64, tag};

impl DbToolExecutor {
    /// A catalogue app, with price and resource footprint.
    ///
    /// `compose` is deliberately not included: it is a large YAML document that
    /// answers no support question and would crowd out the rest of the context.
    pub(super) async fn app_view(&self, app: &App, tags: &[String]) -> Value {
        let currency = app.currency.parse::<Currency>().ok();
        json!({
            "id": app.id,
            "name": app.name,
            "display_name": app.display_name,
            "description": app.description,
            "category": app.category,
            "repo_url": app.repo_url,
            "tags": tags,
            "price": match currency {
                Some(c) => json!({
                    "per_interval": self.priced(CurrencyAmount::from_u64(c, app.amount)).await,
                    "interval": format!("{} {}", app.interval_amount, tag(app.interval_type)),
                    "setup_fee": money(CurrencyAmount::from_u64(c, app.setup_amount)),
                }),
                None => Value::Null,
            },
            "footprint": {
                "cpu_milli": app.cpu_milli,
                "memory_bytes": app.memory_bytes,
                "storage_bytes": app.storage_bytes,
            },
        })
    }

    /// Tag slugs per app id, for the catalogue listing.
    pub(super) async fn app_tag_map(&self, app_ids: &[u64]) -> HashMap<u64, Vec<String>> {
        let mut map: HashMap<u64, Vec<String>> = HashMap::new();
        for (app_id, tag) in self
            .db
            .list_app_tag_assignments(app_ids)
            .await
            .unwrap_or_default()
        {
            map.entry(app_id).or_default().push(tag.slug);
        }
        map
    }

    pub(super) async fn apps(&self) -> Result<Value> {
        let apps = self.db.list_apps(true).await?;
        let ids: Vec<u64> = apps.iter().map(|a| a.id).collect();
        let tags = self.app_tag_map(&ids).await;
        let mut out = Vec::with_capacity(apps.len());
        for app in &apps {
            out.push(
                self.app_view(
                    app,
                    tags.get(&app.id).cloned().unwrap_or_default().as_slice(),
                )
                .await,
            );
        }
        Ok(Value::Array(out))
    }

    /// One app, plus where it can actually be deployed right now.
    ///
    /// Availability is computed from real cluster capacity, so the agent does
    /// not offer a region that would reject the order.
    pub(super) async fn app_details(&self, args: &HashMap<String, Value>) -> Result<Value> {
        let app = match (
            args.get("app_id").and_then(|v| v.as_u64()),
            args.get("name").and_then(|v| v.as_str()),
        ) {
            (Some(id), _) => self.db.get_app(id).await?,
            (None, Some(name)) => self.db.get_app_by_name(name).await?,
            (None, None) => bail!("app_id or name required"),
        };
        if !app.enabled {
            bail!("App '{}' is not currently offered", app.name);
        }

        let tags = self.app_tag_map(&[app.id]).await;
        let mut out = self
            .app_view(
                &app,
                tags.get(&app.id).cloned().unwrap_or_default().as_slice(),
            )
            .await;

        let capacity = AppClusterCapacityService::new(self.db.clone());
        let regions = capacity
            .regions_availability(AppCapacity {
                cpu_milli: app.cpu_milli,
                memory_bytes: app.memory_bytes,
                storage_bytes: app.storage_bytes,
            })
            .await
            .unwrap_or_default();
        let mut available = Vec::new();
        for r in regions {
            if let Ok(region) = self.db.get_host_region(r.region_id).await
                && region.enabled
            {
                available.push(json!({
                    "id": region.id,
                    "name": region.name,
                    "available": r.available,
                    "ingress_domain": r.ingress_domain,
                }));
            }
        }
        if let Some(object) = out.as_object_mut() {
            object.insert("regions".to_string(), Value::Array(available));
        }
        Ok(out)
    }

    pub(super) async fn app_tags(&self) -> Result<Value> {
        Ok(Value::Array(
            self.db
                .list_app_tags_with_counts()
                .await?
                .into_iter()
                .map(|(tag, count)| {
                    json!({
                        "slug": tag.slug,
                        "display_name": tag.display_name,
                        "description": tag.description,
                        "app_count": count,
                    })
                })
                .collect(),
        ))
    }

    /// Load an app deployment, confirming the scoped user owns it.
    pub(super) async fn owned_deployment(
        &self,
        args: &HashMap<String, Value>,
    ) -> Result<AppDeployment> {
        let user_id = self.require_user()?;
        let id = required_u64(args, "deployment_id")?;
        let deployment = self.db.get_app_deployment(id).await?;
        if deployment.user_id != user_id {
            bail!("Deployment {} does not belong to you", id);
        }
        Ok(deployment)
    }

    /// A deployment as the customer sees it.
    ///
    /// `config` is omitted: it is an encrypted blob of resolved configuration
    /// which routinely holds the app's own secrets (API keys, passwords).
    /// `desired_state` and `status` are both reported because they answer
    /// different questions — what the customer asked for, and what the cluster
    /// actually did.
    pub(super) async fn deployment_view(&self, d: &AppDeployment) -> Value {
        let app = self.db.get_app(d.app_id).await.ok();
        let cluster = self.db.get_app_cluster(d.cluster_id).await.ok();
        let region = match cluster.as_ref() {
            Some(c) => self.db.get_host_region(c.region_id).await.ok(),
            None => None,
        };
        let subscription = self
            .db
            .get_subscription_by_line_item_id(d.subscription_line_item_id)
            .await
            .ok();

        json!({
            "id": d.id,
            "name": d.name,
            "app": app.map(|a| json!({ "id": a.id, "name": a.name, "display_name": a.display_name })),
            "region": region.map(|r| json!({ "id": r.id, "name": r.name })),
            "hostname": d.hostname,
            "custom_domain": d.custom_domain,
            "custom_domain_verified": d.custom_domain_verified,
            "desired_state": d.desired_state.to_string(),
            "status": d.status.to_string(),
            "status_message": d.status_message,
            "resource_multiplier": d.resource_multiplier.max(1),
            "usage": {
                "cpu_milli": d.usage_cpu_milli,
                "memory_bytes": d.usage_memory_bytes,
                "storage_bytes": d.usage_storage_bytes,
                "collected": d.usage_collected,
            },
            "subscription": subscription.as_ref().map(|s| json!({
                "id": s.id,
                "expires": s.expires,
                "billing_state": s.billing_state(chrono::Utc::now()).to_string(),
                "auto_renewal_enabled": s.auto_renewal_enabled,
            })),
            "created": d.created,
            "deleted": d.deleted,
        })
    }

    pub(super) async fn deployments(&self) -> Result<Value> {
        let deployments = self
            .db
            .list_user_app_deployments(self.require_user()?)
            .await?;
        let mut out = Vec::with_capacity(deployments.len());
        for d in deployments.iter().filter(|d| !d.deleted) {
            out.push(self.deployment_view(d).await);
        }
        Ok(Value::Array(out))
    }

    /// Start or stop a deployment by setting its desired state, exactly as the
    /// REST endpoint does; the operator reconciles from there (scaling to zero
    /// replicas when stopped). Reversible, and already available to the
    /// customer through the API, which is why live chat may do it.
    pub(super) async fn set_deployment_state(
        &self,
        deployment: &AppDeployment,
        state: AppDeploymentDesiredState,
    ) -> Result<Value> {
        if deployment.deleted {
            bail!("Deployment {} has been deleted", deployment.id);
        }
        let mut updated = deployment.clone();
        updated.desired_state = state;
        self.db.update_app_deployment(&updated).await?;
        Ok(json!({
            "deployment_id": deployment.id,
            "desired_state": state.to_string(),
            "result": format!("Deployment {} set to {}", deployment.name, state),
            "note": "The cluster reconciles asynchronously; status may take a minute to follow.",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::agent::ToolExecutor;
    use chrono::Utc;
    use lnvps_api_common::{GB, MockDb};
    use lnvps_db::{AppCluster, AppDeploymentStatus, AppTag, IntervalType, SubscriptionType};
    use std::sync::Arc;

    /// Seed one catalogue app (`nostr-relay`, €5/month) with a tag and a
    /// cluster in region 1.
    async fn seed_catalogue(db: &Arc<MockDb>) {
        db.apps.lock().await.insert(
            1,
            App {
                id: 1,
                name: "nostr-relay".to_string(),
                display_name: "Nostr Relay".to_string(),
                description: Some("A relay".to_string()),
                icon: None,
                repo_url: Some("https://github.com/example/relay".to_string()),
                category: "Nostr relay".to_string(),
                seo_title: None,
                seo_description: None,
                compose: "services: {}".to_string(),
                amount: 500,
                currency: "EUR".to_string(),
                interval_amount: 1,
                interval_type: IntervalType::Month,
                setup_amount: 100,
                enabled: true,
                cpu_milli: 500,
                memory_bytes: GB,
                storage_bytes: 10 * GB,
                created: Utc::now(),
            },
        );
        db.app_tags.lock().await.insert(
            1,
            AppTag {
                id: 1,
                slug: "nostr".to_string(),
                display_name: "Nostr".to_string(),
                description: None,
                created: Utc::now(),
            },
        );
        db.app_tag_assignments.lock().await.push((1, 1));
        db.app_clusters.lock().await.insert(
            1,
            AppCluster {
                id: 1,
                name: "cluster-1".to_string(),
                region_id: 1,
                ingress_domain: "apps.lnvps.tld".to_string(),
                enabled: true,
                capacity_cpu_milli: 100_000,
                capacity_memory_bytes: 1024 * GB,
                capacity_storage_bytes: 10_000 * GB,
                created: Utc::now(),
            },
        );
    }

    /// Seed a deployment of app 1 owned by `user_id`.
    async fn seed_deployment(db: &Arc<MockDb>, id: u64, user_id: u64) {
        db.subscription_line_items.lock().await.insert(
            100 + id,
            lnvps_db::SubscriptionLineItem {
                id: 100 + id,
                subscription_id: 1,
                subscription_type: SubscriptionType::App,
                name: "App".to_string(),
                description: None,
                amount: 500,
                setup_amount: 0,
                configuration: None,
            },
        );
        db.app_deployments.lock().await.insert(
            id,
            AppDeployment {
                id,
                user_id,
                app_id: 1,
                cluster_id: 1,
                resource_multiplier: 1,
                subscription_line_item_id: 100 + id,
                name: "my-relay".to_string(),
                namespace: "ns".to_string(),
                hostname: Some("my-relay.apps.lnvps.tld".to_string()),
                custom_domain: None,
                custom_domain_verified: false,
                config: Some("SECRET-APP-CONFIG".to_string().into()),
                desired_state: AppDeploymentDesiredState::Running,
                status: AppDeploymentStatus::Running,
                status_message: None,
                usage_cpu_milli: Some(120),
                usage_memory_bytes: Some(GB / 2),
                usage_storage_bytes: None,
                usage_collected: Some(Utc::now()),
                created: Utc::now(),
                deleted: false,
            },
        );
    }

    #[tokio::test]
    async fn catalogue_lists_apps_with_price_and_footprint() {
        let db = Arc::new(MockDb::default());
        seed_catalogue(&db).await;
        let exec = public_executor(&db);

        let out = exec
            .execute("list_apps", "{}")
            .await
            .expect("no account needed");
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let app = &parsed[0];
        assert_eq!(app["name"], "nostr-relay");
        assert_eq!(app["price"]["per_interval"]["amount"], 500);
        assert_eq!(app["price"]["interval"], "1 month");
        assert_eq!(app["price"]["setup_fee"]["amount"], 100);
        assert_eq!(app["tags"][0], "nostr");
        assert_eq!(app["footprint"]["cpu_milli"], 500);
        // The compose document answers no support question and would crowd the
        // context out.
        assert!(!out.contains("compose"), "{out}");
    }

    #[tokio::test]
    async fn app_details_resolve_by_id_or_name_and_carry_regions() {
        let db = Arc::new(MockDb::default());
        seed_catalogue(&db).await;
        let exec = public_executor(&db);

        for args in [r#"{"app_id":1}"#, r#"{"name":"nostr-relay"}"#] {
            let out = exec.execute("get_app_details", args).await.unwrap();
            let parsed: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(parsed["name"], "nostr-relay");
            assert_eq!(parsed["regions"][0]["name"], "Mock");
            assert_eq!(parsed["regions"][0]["available"], true);
        }

        let err = exec.execute("get_app_details", "{}").await.unwrap_err();
        assert!(err.to_string().contains("app_id or name required"));
    }

    /// A disabled app is not for sale, so the agent must not describe it as
    /// though it were.
    #[tokio::test]
    async fn app_details_refuse_a_withdrawn_app() {
        let db = Arc::new(MockDb::default());
        seed_catalogue(&db).await;
        db.apps.lock().await.get_mut(&1).unwrap().enabled = false;
        let exec = public_executor(&db);

        let err = exec
            .execute("get_app_details", r#"{"app_id":1}"#)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not currently offered"));

        // ...and it disappears from the listing.
        let out = exec.execute("list_apps", "{}").await.unwrap();
        assert_eq!(out.trim(), "[]");
    }

    #[tokio::test]
    async fn lists_tags_with_counts() {
        let db = Arc::new(MockDb::default());
        seed_catalogue(&db).await;
        let out = public_executor(&db)
            .execute("list_app_tags", "{}")
            .await
            .unwrap();
        assert!(out.contains("\"slug\": \"nostr\""), "{out}");
    }

    /// The deployment projection must never carry the app's own configuration:
    /// it is an encrypted blob that routinely holds the app's secrets.
    #[tokio::test]
    async fn deployment_projection_omits_configuration() {
        let (db, exec) = executor(1).await;
        seed_catalogue(&db).await;
        seed_deployment(&db, 3, 1).await;

        let out = exec
            .execute("get_app_deployment_details", r#"{"deployment_id":3}"#)
            .await
            .unwrap();
        assert!(out.contains("my-relay.apps.lnvps.tld"));
        assert!(out.contains("\"desired_state\": \"running\""));
        assert!(out.contains("\"status\": \"running\""));
        for leaked in ["SECRET-APP-CONFIG", "config", "namespace"] {
            assert!(!out.contains(leaked), "leaked {leaked}");
        }
    }

    #[tokio::test]
    async fn lists_only_the_scoped_users_deployments() {
        let (db, exec) = executor(1).await;
        seed_catalogue(&db).await;
        seed_deployment(&db, 3, 1).await;
        seed_deployment(&db, 4, 2).await;

        let out = exec.execute("list_my_app_deployments", "{}").await.unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let ids: Vec<u64> = parsed
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_u64().unwrap())
            .collect();
        assert_eq!(ids, vec![3]);
    }

    #[tokio::test]
    async fn rejects_deployments_owned_by_another_user() {
        let (db, exec) = executor(1).await;
        seed_catalogue(&db).await;
        seed_deployment(&db, 4, 2).await;

        for tool in [
            "get_app_deployment_details",
            "start_app_deployment",
            "stop_app_deployment",
        ] {
            let err = exec
                .execute(tool, r#"{"deployment_id":4}"#)
                .await
                .expect_err(&format!("{tool} must reject another user's deployment"));
            assert!(err.to_string().contains("does not belong to you"), "{err}");
        }

        let err = exec
            .execute("start_app_deployment", "{}")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("deployment_id required"));
    }

    /// Start/stop must actually persist the desired state — the operator
    /// reconciles from the database, so a reply that claims success without a
    /// write would be a lie the customer discovers later.
    #[tokio::test]
    async fn start_and_stop_persist_the_desired_state() {
        let (db, exec) = executor(1).await;
        seed_catalogue(&db).await;
        seed_deployment(&db, 3, 1).await;

        let out = exec
            .execute("stop_app_deployment", r#"{"deployment_id":3}"#)
            .await
            .unwrap();
        assert!(out.contains("\"desired_state\": \"stopped\""), "{out}");
        assert_eq!(
            db.app_deployments.lock().await[&3].desired_state,
            AppDeploymentDesiredState::Stopped
        );

        exec.execute("start_app_deployment", r#"{"deployment_id":3}"#)
            .await
            .unwrap();
        assert_eq!(
            db.app_deployments.lock().await[&3].desired_state,
            AppDeploymentDesiredState::Running
        );
    }

    /// A torn-down deployment cannot be restarted, and saying otherwise would
    /// send the customer to wait for something that will never come up.
    #[tokio::test]
    async fn a_deleted_deployment_cannot_be_started() {
        let (db, exec) = executor(1).await;
        seed_catalogue(&db).await;
        seed_deployment(&db, 3, 1).await;
        db.app_deployments.lock().await.get_mut(&3).unwrap().deleted = true;

        let err = exec
            .execute("start_app_deployment", r#"{"deployment_id":3}"#)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("has been deleted"));

        // It is also absent from the listing.
        let out = exec.execute("list_my_app_deployments", "{}").await.unwrap();
        assert_eq!(out.trim(), "[]");
    }
}
