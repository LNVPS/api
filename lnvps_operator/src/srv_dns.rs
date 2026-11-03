use anyhow::Result;
use lnvps_api_common::{BasicRecord, DnsRef, DnsServer, RecordType};
use lnvps_compose::Compose;

use crate::app_deployments::deployment_hostname;

pub fn desired_srv(
    compose: &Compose,
    name: &str,
    public_port: Option<u16>,
    ingress_domain: &str,
    zone: &DnsRef,
) -> Option<BasicRecord> {
    let port = public_port?;
    let l4 = compose.l4_port()?;
    if l4.port.container == port {
        return None;
    }
    let host = deployment_hostname(name, ingress_domain);
    let name = l4.srv_name(&host)?;
    Some(BasicRecord::srv(name, port, &host, zone.clone()))
}

fn is_ours(record: &BasicRecord, ingress_domain: &str) -> bool {
    let suffix = format!(".{}", ingress_domain.trim_end_matches('.'));
    let name = record.name.trim_end_matches('.');
    if !matches!(record.kind, RecordType::SRV) || !name.starts_with('_') {
        return false;
    }
    let Some(prefix) = name.strip_suffix(&suffix) else {
        return false;
    };
    let mut labels = prefix.split('.');
    let (Some(service), Some(proto), Some(host), None) =
        (labels.next(), labels.next(), labels.next(), labels.next())
    else {
        return false;
    };
    service.starts_with('_') && matches!(proto, "_tcp" | "_udp") && !host.is_empty()
}

#[derive(Default, Debug)]
pub struct SrvPlan {
    pub add: Vec<BasicRecord>,
    pub delete: Vec<BasicRecord>,
}

pub fn plan_srv(
    existing: &[BasicRecord],
    desired: &[BasicRecord],
    ingress_domain: &str,
) -> SrvPlan {
    let mut plan = SrvPlan::default();
    let ours: Vec<&BasicRecord> = existing
        .iter()
        .filter(|r| is_ours(r, ingress_domain))
        .collect();
    for have in &ours {
        let kept = desired
            .iter()
            .any(|d| d.name == have.name && d.value == have.value);
        if !kept {
            plan.delete.push((*have).clone());
        }
    }
    for want in desired {
        let present = ours
            .iter()
            .any(|h| h.name == want.name && h.value == want.value);
        if !present {
            plan.add.push(want.clone());
        }
    }
    plan
}

pub async fn sync_srv(
    dns: &dyn DnsServer,
    zone: &DnsRef,
    ingress_domain: &str,
    desired: &[BasicRecord],
) -> Result<SrvPlan> {
    let existing = dns
        .list_records(zone)
        .await
        .map_err(|e| anyhow::anyhow!("list SRV records: {}", e.inner()))?;
    let plan = plan_srv(&existing, desired, ingress_domain);
    for rec in &plan.delete {
        dns.delete_record(rec)
            .await
            .map_err(|e| anyhow::anyhow!("delete SRV {}: {}", rec.name, e.inner()))?;
    }
    for rec in &plan.add {
        dns.add_record(rec)
            .await
            .map_err(|e| anyhow::anyhow!("add SRV {}: {}", rec.name, e.inner()))?;
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDnsServer;

    const DOMAIN: &str = "ie.apps.lnvps.cloud";
    const MC: &str = "services:\n  s:\n    image: x\n    ports:\n      - { name: g, container: 25565, protocol: tcp, expose: tcp, srv: minecraft }\n";
    const NO_SRV: &str = "services:\n  s:\n    image: x\n    ports:\n      - { name: g, container: 7777, protocol: tcp, expose: tcp }\n";

    fn zone() -> DnsRef {
        DnsRef::Id("zone".to_string())
    }

    fn desired(compose: &str, port: Option<u16>) -> Option<BasicRecord> {
        desired_srv(
            &Compose::parse(compose).unwrap(),
            "mctest",
            port,
            DOMAIN,
            &zone(),
        )
    }

    #[test]
    fn default_port_needs_no_srv_record() {
        assert!(desired(MC, Some(25565)).is_none());
    }

    #[test]
    fn app_without_srv_label_needs_no_srv_record() {
        assert!(desired(NO_SRV, Some(25570)).is_none());
    }

    #[test]
    fn unallocated_port_needs_no_srv_record() {
        assert!(desired(MC, None).is_none());
    }

    #[test]
    fn non_default_port_publishes_srv_to_the_hostname() {
        let rec = desired(MC, Some(25570)).unwrap();
        assert_eq!(rec.name, "_minecraft._tcp.mctest.ie.apps.lnvps.cloud");
        assert_eq!(rec.value, "0 5 25570 mctest.ie.apps.lnvps.cloud");
    }

    #[tokio::test]
    async fn srv_is_created_then_left_alone_then_deleted_on_teardown() {
        let dns = MockDnsServer::new();
        let want = desired(MC, Some(25570)).unwrap();

        let plan = sync_srv(&dns, &zone(), DOMAIN, &[want.clone()])
            .await
            .unwrap();
        assert_eq!(plan.add.len(), 1);
        assert_eq!(dns.list_records(&zone()).await.unwrap().len(), 1);

        let plan = sync_srv(&dns, &zone(), DOMAIN, &[want.clone()])
            .await
            .unwrap();
        assert!(plan.add.is_empty() && plan.delete.is_empty());
        assert_eq!(dns.list_records(&zone()).await.unwrap().len(), 1);

        let plan = sync_srv(&dns, &zone(), DOMAIN, &[]).await.unwrap();
        assert_eq!(plan.delete.len(), 1);
        assert!(dns.list_records(&zone()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_moved_port_replaces_the_record() {
        let dns = MockDnsServer::new();
        sync_srv(&dns, &zone(), DOMAIN, &[desired(MC, Some(25570)).unwrap()])
            .await
            .unwrap();
        sync_srv(&dns, &zone(), DOMAIN, &[desired(MC, Some(25571)).unwrap()])
            .await
            .unwrap();
        let records = dns.list_records(&zone()).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "0 5 25571 mctest.ie.apps.lnvps.cloud");
    }

    #[test]
    fn records_outside_the_ingress_domain_are_never_deleted() {
        let foreign = BasicRecord::srv(
            "_sip._tcp.voip.example.com".to_string(),
            5060,
            "voip.example.com",
            zone(),
        );
        let nested = BasicRecord::srv(
            "_minecraft._tcp.a.b.ie.apps.lnvps.cloud".to_string(),
            1,
            "a.b.ie.apps.lnvps.cloud",
            zone(),
        );
        let plan = plan_srv(&[foreign, nested], &[], DOMAIN);
        assert!(plan.delete.is_empty());
    }
}
