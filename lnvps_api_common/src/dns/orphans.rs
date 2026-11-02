use crate::dns::{BasicRecord, DnsRef, RecordType, get_dns_server};
use crate::retry::OpResult;
use ipnetwork::IpNetwork;
use lnvps_db::{IpRange, LNVpsDb};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrphanDnsRecord {
    pub dns_server_id: u64,
    pub zone_id: String,
    pub record_id: String,
    pub kind: String,
    pub name: String,
    pub value: String,
}

#[derive(Default)]
struct ZoneGroup {
    cidrs: Vec<IpNetwork>,
    live_refs: HashSet<String>,
}

pub async fn find_orphan_dns_records(db: &Arc<dyn LNVpsDb>) -> OpResult<Vec<OrphanDnsRecord>> {
    let ranges = db.list_ip_range().await?;
    let mut forward: HashMap<(u64, String), ZoneGroup> = HashMap::new();
    let mut reverse: HashMap<(u64, String), ZoneGroup> = HashMap::new();

    for range in &ranges {
        let assignments = db.list_vm_ip_assignments_in_range(range.id).await?;
        add_to_group(
            &mut forward,
            range,
            range.forward_dns_server_id,
            &range.forward_zone_id,
            |a| a.dns_forward_ref.clone(),
            &assignments,
        );
        add_to_group(
            &mut reverse,
            range,
            range.reverse_dns_server_id,
            &range.reverse_zone_id,
            |a| a.dns_reverse_ref.clone(),
            &assignments,
        );
    }

    let mut orphans = Vec::new();
    for ((server_id, zone_id), group) in &forward {
        let dns = get_dns_server(db, *server_id).await?;
        for rec in dns.list_records(&DnsRef::Id(zone_id.clone())).await? {
            if !matches!(rec.kind, RecordType::A | RecordType::AAAA) {
                continue;
            }
            let in_range = IpAddr::from_str(&rec.value)
                .map(|ip| group.cidrs.iter().any(|c| c.contains(ip)))
                .unwrap_or(false);
            if in_range {
                push_if_orphan(&mut orphans, *server_id, zone_id, group, rec);
            }
        }
    }
    for ((server_id, zone_id), group) in &reverse {
        let dns = get_dns_server(db, *server_id).await?;
        for rec in dns.list_records(&DnsRef::Id(zone_id.clone())).await? {
            if matches!(rec.kind, RecordType::PTR) {
                push_if_orphan(&mut orphans, *server_id, zone_id, group, rec);
            }
        }
    }
    orphans.sort_by(|a, b| {
        (a.dns_server_id, &a.zone_id, &a.record_id).cmp(&(
            b.dns_server_id,
            &b.zone_id,
            &b.record_id,
        ))
    });
    Ok(orphans)
}

fn add_to_group(
    groups: &mut HashMap<(u64, String), ZoneGroup>,
    range: &IpRange,
    server_id: Option<u64>,
    zone_id: &Option<String>,
    dns_ref: impl Fn(&lnvps_db::VmIpAssignment) -> Option<String>,
    assignments: &[lnvps_db::VmIpAssignment],
) {
    let (Some(server_id), Some(zone_id)) = (server_id, zone_id) else {
        return;
    };
    let group = groups.entry((server_id, zone_id.clone())).or_default();
    if let Ok(cidr) = IpNetwork::from_str(&range.cidr) {
        group.cidrs.push(cidr);
    }
    group
        .live_refs
        .extend(assignments.iter().filter_map(dns_ref));
}

fn push_if_orphan(
    orphans: &mut Vec<OrphanDnsRecord>,
    server_id: u64,
    zone_id: &str,
    group: &ZoneGroup,
    rec: BasicRecord,
) {
    let Some(record_id) = rec.id.as_ref().and_then(DnsRef::as_id).map(str::to_string) else {
        return;
    };
    if group.live_refs.contains(&record_id) {
        return;
    }
    orphans.push(OrphanDnsRecord {
        dns_server_id: server_id,
        zone_id: zone_id.to_string(),
        record_id,
        kind: rec.kind.to_string(),
        name: rec.name,
        value: rec.value,
    });
}
