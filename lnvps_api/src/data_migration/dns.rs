use crate::data_migration::DataMigration;
use lnvps_api_common::{BasicRecord, DnsRef, get_dns_server};
use crate::settings::Settings;
use anyhow::Result;
use lnvps_db::{DnsServer, DnsServerKind, LNVpsDb, RouterKind};
use log::warn;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Legacy Cloudflare DNS config (from `settings.dns`) to migrate into the DB.
#[derive(Clone)]
struct LegacyCloudflare {
    kind: DnsServerKind,
    token: String,
    forward_zone_id: String,
}

/// One-shot migration that moves DNS provider config into the `dns_server` table:
/// - the legacy `settings.dns` (Cloudflare) block, and
/// - OVH additional-IP routers (which share the same `url` + `app_key:app_secret:consumer_key`
///   token as OVH reverse DNS) are imported as `Ovh` DNS servers, auto-mapping reverse DNS
///   on the ranges they route.
///
/// Then it backfills any missing forward/reverse records (best-effort). Idempotent —
/// safe to run on every startup.
pub struct DnsDataMigration {
    db: Arc<dyn LNVpsDb>,
    cloudflare: Option<LegacyCloudflare>,
}

impl DnsDataMigration {
    pub fn new(db: Arc<dyn LNVpsDb>, settings: &Settings) -> Option<Self> {
        let cloudflare = settings.dns.as_ref().map(|cfg| {
            let (kind, token) = cfg.to_db_kind_token();
            LegacyCloudflare {
                kind,
                token,
                forward_zone_id: cfg.forward_zone_id.clone(),
            }
        });
        Some(Self { db, cloudflare })
    }

    /// Find an existing DNS server by name, or create it, returning its id.
    async fn ensure_dns_server(
        db: &Arc<dyn LNVpsDb>,
        name: &str,
        kind: DnsServerKind,
        url: &str,
        token: lnvps_db::EncryptedString,
    ) -> Result<u64> {
        let existing = db.list_dns_servers().await?;
        if let Some(row) = existing.iter().find(|r| r.name == name) {
            return Ok(row.id);
        }
        let id = db
            .insert_dns_server(&DnsServer {
                id: 0,
                name: name.to_string(),
                enabled: true,
                kind,
                url: url.to_string(),
                token,
            })
            .await?;
        Ok(id)
    }

    /// Import the legacy Cloudflare config and point ranges at it (where unset).
    async fn migrate_cloudflare(db: &Arc<dyn LNVpsDb>, cf: &LegacyCloudflare) -> Result<()> {
        let dns_server_id =
            Self::ensure_dns_server(db, "migrated-dns", cf.kind, "", cf.token.clone().into())
                .await?;

        let ranges = db.list_ip_range().await?;
        for mut range in ranges {
            let mut changed = false;
            if range.forward_dns_server_id.is_none() {
                range.forward_dns_server_id = Some(dns_server_id);
                range.forward_zone_id = Some(cf.forward_zone_id.clone());
                changed = true;
            }
            if range.reverse_zone_id.is_some() && range.reverse_dns_server_id.is_none() {
                range.reverse_dns_server_id = Some(dns_server_id);
                changed = true;
            }
            if changed {
                db.update_ip_range_dns(&range).await?;
            }
        }
        Ok(())
    }

    /// Import OVH additional-IP routers as `Ovh` DNS servers and auto-map reverse DNS
    /// on the ranges those routers serve (via their access policy).
    async fn migrate_ovh(db: &Arc<dyn LNVpsDb>) -> Result<()> {
        let routers = db.list_routers().await?;
        // router_id -> dns_server_id for each OVH additional-IP router
        let mut ovh_map: std::collections::HashMap<u64, u64> = Default::default();
        for router in routers
            .into_iter()
            .filter(|r| matches!(r.kind, RouterKind::OvhAdditionalIp))
        {
            let name = format!("ovh-reverse-{}", router.name);
            let dns_id = Self::ensure_dns_server(
                db,
                &name,
                DnsServerKind::Ovh,
                &router.url,
                router.token.clone(),
            )
            .await?;
            ovh_map.insert(router.id, dns_id);
        }

        if ovh_map.is_empty() {
            return Ok(());
        }

        // Map ranges whose access policy points at an OVH router to that OVH DNS server
        // for reverse DNS (only where reverse is not already configured).
        let ovh_ids: std::collections::HashSet<u64> = ovh_map.values().copied().collect();
        let ranges = db.list_ip_range().await?;
        for mut range in ranges {
            // OVH keys reverse DNS on the IP block (CIDR), which is exactly the
            // range's own CIDR. Store it as the reverse zone so DNS calls target
            // `/ip/{block}/reverse` rather than a bare `/ip/{ip}` (404).
            let ensure_zone = |range: &mut lnvps_db::IpRange| -> bool {
                if range.reverse_zone_id.is_none() {
                    range.reverse_zone_id = Some(range.cidr.clone());
                    true
                } else {
                    false
                }
            };

            // Already pointed at an OVH DNS server (e.g. by a prior run): make
            // sure the block zone is backfilled.
            if let Some(rev_id) = range.reverse_dns_server_id {
                if ovh_ids.contains(&rev_id) && ensure_zone(&mut range) {
                    db.update_ip_range_dns(&range).await?;
                }
                continue;
            }
            let Some(policy_id) = range.access_policy_id else {
                continue;
            };
            let Ok(policy) = db.get_access_policy(policy_id).await else {
                continue;
            };
            let Some(router_id) = policy.router_id else {
                continue;
            };
            if let Some(dns_id) = ovh_map.get(&router_id) {
                range.reverse_dns_server_id = Some(*dns_id);
                ensure_zone(&mut range);
                db.update_ip_range_dns(&range).await?;
            }
        }
        Ok(())
    }

    /// Whether an IP's reverse record needs to be (re)created.
    ///
    /// - Missing reverse (and a name exists to point at) → create.
    /// - Existing reverse: only OVH records whose stored ref isn't yet the OVH
    ///   implicit key (the IP itself) are force-refreshed — this replaces the
    ///   stale Cloudflare PTRs that OVH-routed IPs carried before this change.
    ///   Working Cloudflare reverse records are left untouched.
    fn reverse_needs_create_or_refresh(ip: &lnvps_db::VmIpAssignment, is_ovh: bool) -> bool {
        let has_name = ip.dns_forward.is_some() || ip.dns_reverse.is_some();
        if !has_name {
            return false;
        }
        if ip.dns_reverse.is_none() {
            return true;
        }
        is_ovh && ip.dns_reverse_ref.as_deref() != Some(ip.ip.as_str())
    }

    /// Best-effort backfill/refresh of forward/reverse records for existing IPs.
    /// Failures are logged and skipped so a DNS/permission problem never aborts startup.
    async fn backfill_records(db: &Arc<dyn LNVpsDb>) -> Result<()> {
        let vms = db.list_vms().await?;
        for vm in vms {
            let mut ips = db.list_vm_ip_assignments(vm.id).await?;
            for ip in &mut ips {
                let range = db.get_ip_range(ip.ip_range_id).await?;
                let mut did_change = false;

                if ip.dns_forward.is_none()
                    && let Some(fwd_id) = range.forward_dns_server_id
                {
                    let rec =
                        BasicRecord::forward(ip, DnsRef::from_opt(range.forward_zone_id.clone()))?;
                    match get_dns_server(db, fwd_id).await {
                        Ok(dns) => match dns.add_record(&rec).await {
                            Ok(r) => {
                                ip.dns_forward = Some(r.name.clone());
                                ip.dns_forward_ref = r.stored_ref();
                                did_change = true;
                            }
                            Err(e) => warn!(
                                "[dns-migration] forward backfill failed for {}: {}",
                                ip.ip, e
                            ),
                        },
                        Err(e) => warn!(
                            "[dns-migration] forward dns server {} unavailable: {}",
                            fwd_id, e
                        ),
                    }
                }

                if let Some(rev_id) = range.reverse_dns_server_id {
                    // Determine the provider kind to decide whether to force-refresh.
                    let is_ovh = matches!(
                        db.get_dns_server(rev_id).await.map(|s| s.kind),
                        Ok(DnsServerKind::Ovh)
                    );
                    if Self::reverse_needs_create_or_refresh(ip, is_ovh) {
                        let rec = BasicRecord::reverse_to_fwd(
                            ip,
                            DnsRef::from_opt(range.reverse_zone_id.clone()),
                        )?;
                        match get_dns_server(db, rev_id).await {
                            Ok(dns) => match dns.add_record(&rec).await {
                                Ok(r) => {
                                    ip.dns_reverse = Some(r.value.clone());
                                    ip.dns_reverse_ref = r.stored_ref();
                                    did_change = true;
                                }
                                Err(e) => warn!(
                                    "[dns-migration] reverse backfill failed for {}: {}",
                                    ip.ip, e
                                ),
                            },
                            Err(e) => warn!(
                                "[dns-migration] reverse dns server {} unavailable: {}",
                                rev_id, e
                            ),
                        }
                    }
                }

                if did_change {
                    db.update_vm_ip_assignment(ip).await?;
                }
            }
        }
        Ok(())
    }
}

impl DataMigration for DnsDataMigration {
    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let db = self.db.clone();
        let cloudflare = self.cloudflare.clone();
        Box::pin(async move {
            if let Some(cf) = &cloudflare {
                Self::migrate_cloudflare(&db, cf).await?;
            }
            Self::migrate_ovh(&db).await?;
            Self::backfill_records(&db).await?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::mock_settings;
    use lnvps_api_common::MockDb;

    fn ip_with(
        dns_forward: Option<&str>,
        dns_reverse: Option<&str>,
        rev_ref: Option<&str>,
    ) -> lnvps_db::VmIpAssignment {
        lnvps_db::VmIpAssignment {
            ip: "15.235.3.225".to_string(),
            dns_forward: dns_forward.map(|s| s.to_string()),
            dns_reverse: dns_reverse.map(|s| s.to_string()),
            dns_reverse_ref: rev_ref.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_reverse_needs_create_or_refresh() {
        // No name at all -> nothing to do
        assert!(!DnsDataMigration::reverse_needs_create_or_refresh(
            &ip_with(None, None, None),
            true
        ));
        // Missing reverse but has a forward name -> create
        assert!(DnsDataMigration::reverse_needs_create_or_refresh(
            &ip_with(Some("vm-1.lnvps.cloud"), None, None),
            false
        ));
        // Cloudflare reverse already set -> leave untouched
        assert!(!DnsDataMigration::reverse_needs_create_or_refresh(
            &ip_with(
                Some("vm-1.lnvps.cloud"),
                Some("vm-1.lnvps.cloud"),
                Some("cf-abc")
            ),
            false
        ));
        // OVH range with a stale Cloudflare ref -> force refresh
        assert!(DnsDataMigration::reverse_needs_create_or_refresh(
            &ip_with(
                Some("vm-1.lnvps.cloud"),
                Some("vm-1.lnvps.cloud"),
                Some("cf-abc")
            ),
            true
        ));
        // OVH range already keyed on the IP -> idempotent, skip
        assert!(!DnsDataMigration::reverse_needs_create_or_refresh(
            &ip_with(
                Some("vm-1.lnvps.cloud"),
                Some("vm-1.lnvps.cloud"),
                Some("15.235.3.225")
            ),
            true
        ));
    }

    #[tokio::test]
    async fn test_dns_migration_bootstraps_and_is_idempotent() -> anyhow::Result<()> {
        let db_impl = Arc::new(MockDb::default());
        // Start from a clean slate: no dns servers, ranges without forward dns config.
        db_impl.dns_servers.lock().await.clear();
        {
            let mut ranges = db_impl.ip_range.lock().await;
            for r in ranges.values_mut() {
                r.forward_dns_server_id = None;
                r.reverse_dns_server_id = None;
                r.forward_zone_id = None;
                r.reverse_zone_id = Some("rev-zone".to_string());
            }
        }

        let db: Arc<dyn LNVpsDb> = db_impl.clone();
        let settings = mock_settings();
        let migration = DnsDataMigration::new(db.clone(), &settings).expect("migration enabled");

        migration.migrate().await?;

        // A dns_server row was created and ranges were pointed at it.
        let servers = db.list_dns_servers().await?;
        assert_eq!(servers.len(), 1);
        let sid = servers[0].id;
        for r in db.list_ip_range().await? {
            assert_eq!(r.forward_dns_server_id, Some(sid));
            assert_eq!(r.reverse_dns_server_id, Some(sid));
            assert_eq!(r.forward_zone_id.as_deref(), Some("mock-forward-zone-id"));
        }

        // Running again must not create a second dns_server row.
        migration.migrate().await?;
        assert_eq!(db.list_dns_servers().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_dns_migration_imports_ovh_router() -> anyhow::Result<()> {
        let db_impl = Arc::new(MockDb::default());
        db_impl.dns_servers.lock().await.clear();

        // An OVH additional-IP router
        db_impl.router.lock().await.insert(
            5,
            lnvps_db::Router {
                id: 5,
                name: "ns1234.ovh.net".to_string(),
                enabled: true,
                kind: RouterKind::OvhAdditionalIp,
                url: "https://eu.api.ovh.com".to_string(),
                token: "ak:as:ck".into(),
            },
        );
        // An access policy using that router
        db_impl.access_policy.lock().await.insert(
            9,
            lnvps_db::AccessPolicy {
                id: 9,
                name: "ovh".to_string(),
                kind: lnvps_db::NetworkAccessPolicy::StaticArp,
                router_id: Some(5),
                interface: None,
            },
        );
        // Point range 1 at that access policy, clear its DNS config
        {
            let mut ranges = db_impl.ip_range.lock().await;
            let r = ranges.get_mut(&1).unwrap();
            r.access_policy_id = Some(9);
            r.forward_dns_server_id = None;
            r.reverse_dns_server_id = None;
            r.reverse_zone_id = None;
        }

        let db: Arc<dyn LNVpsDb> = db_impl.clone();
        // No legacy cloudflare config for this deployment
        let mut settings = mock_settings();
        settings.dns = None;
        let migration = DnsDataMigration::new(db.clone(), &settings).expect("migration enabled");

        migration.migrate().await?;

        let servers = db.list_dns_servers().await?;
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].kind, DnsServerKind::Ovh);
        assert_eq!(servers[0].name, "ovh-reverse-ns1234.ovh.net");
        let ovh_id = servers[0].id;

        let range = db.get_ip_range(1).await?;
        assert_eq!(range.reverse_dns_server_id, Some(ovh_id));

        // Idempotent
        migration.migrate().await?;
        assert_eq!(db.list_dns_servers().await?.len(), 1);
        Ok(())
    }
}
