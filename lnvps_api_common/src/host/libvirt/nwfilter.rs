//! Translation of LNVPS firewall rules into libvirt nwfilter documents.
//!
//! Each VM gets its own filter (`lnvps-vm-<id>`) referenced from its interface.
//! Rules are emitted in database priority order; libvirt evaluates by the
//! `priority` attribute, so the two are kept aligned explicitly rather than
//! relying on document order.

use anyhow::{Result, bail};
use lnvps_db::{VmFirewallDirection, VmFirewallProtocol, VmFirewallRule, VmFirewallRuleAction};
use serde::Serialize;

/// Name of the per-VM filter.
pub fn filter_name(vm_id: u64) -> String {
    format!("lnvps-vm-{vm_id}")
}

/// libvirt's rule priority range. Database priorities are mapped into it so a
/// rule's relative order is preserved without ever colliding with libvirt's
/// own built-in filters.
const PRIORITY_BASE: i32 = 400;

/// Build the nwfilter XML for a VM's rules.
///
/// Disabled rules are skipped entirely rather than emitted as no-ops, so what
/// is on the host always matches what is enabled in the database.
/// `existing_uuid` must be the UUID of the filter already defined on the host,
/// when there is one. libvirt does **not** replace an nwfilter by name: a
/// define without the existing UUID fails with "filter already exists with
/// uuid ...", so re-applying a VM's rules would break. Undefining first is not
/// an option either — that would leave the VM briefly unfiltered.
pub fn build(vm_id: u64, rules: &[VmFirewallRule], existing_uuid: Option<&str>) -> Result<String> {
    let mut ordered: Vec<&VmFirewallRule> = rules.iter().filter(|r| r.enabled).collect();
    ordered.sort_by_key(|r| (r.priority, r.id));

    let mut entries = Vec::new();
    for (index, rule) in ordered.iter().enumerate() {
        entries.push(rule_element(rule, index)?);
    }

    let filter = NwFilter {
        name: filter_name(vm_id),
        uuid: existing_uuid.map(|u| u.to_string()),
        // MAC spoofing protection applies regardless of customer rules: a guest
        // that can forge its MAC can impersonate another tenant on the bridge.
        filterrefs: vec![FilterRef {
            filter: "no-mac-spoofing".to_string(),
        }],
        rules: entries,
    };

    Ok(quick_xml::se::to_string(&filter)?)
}

fn rule_element(rule: &VmFirewallRule, index: usize) -> Result<Rule> {
    if let (Some(start), Some(end)) = (rule.dst_port_start, rule.dst_port_end)
        && start > end
    {
        bail!(
            "firewall rule {} has an inverted port range ({}-{})",
            rule.id,
            start,
            end
        );
    }
    if matches!(rule.protocol, VmFirewallProtocol::Icmp)
        && (rule.dst_port_start.is_some() || rule.dst_port_end.is_some())
    {
        bail!("firewall rule {} sets ports on ICMP", rule.id);
    }

    let ports = Ports {
        // libvirt wants explicit start/end; an open-ended range in the database
        // means "from here up" / "up to here".
        dstportstart: rule.dst_port_start,
        dstportend: rule.dst_port_end.or(rule.dst_port_start),
    };
    let has_ports = ports.dstportstart.is_some() || ports.dstportend.is_some();

    let src = rule.src_cidr.as_ref().and_then(|c| split_cidr(c));
    let matcher = Matcher {
        srcipaddr: src.as_ref().map(|(addr, _)| addr.clone()),
        srcipmask: src.as_ref().map(|(_, mask)| mask.clone()),
        dstportstart: has_ports.then_some(ports.dstportstart).flatten(),
        dstportend: has_ports.then_some(ports.dstportend).flatten(),
    };

    let body = match rule.protocol {
        VmFirewallProtocol::Tcp => RuleBody::Tcp(matcher),
        VmFirewallProtocol::Udp => RuleBody::Udp(matcher),
        VmFirewallProtocol::Icmp => RuleBody::Icmp(Matcher {
            dstportstart: None,
            dstportend: None,
            ..matcher
        }),
        VmFirewallProtocol::Any => {
            if has_ports {
                bail!(
                    "firewall rule {} sets ports without a protocol; libvirt has no \
                     protocol-agnostic port match",
                    rule.id
                );
            }
            RuleBody::All(Matcher {
                dstportstart: None,
                dstportend: None,
                ..matcher
            })
        }
    };

    Ok(Rule {
        action: match rule.action {
            VmFirewallRuleAction::Accept => "accept",
            VmFirewallRuleAction::Drop => "drop",
            VmFirewallRuleAction::Reject => "reject",
        }
        .to_string(),
        // libvirt's directions are named from the guest's point of view: `in`
        // is traffic arriving at the VM.
        direction: match rule.direction {
            VmFirewallDirection::Inbound => "in",
            VmFirewallDirection::Outbound => "out",
        }
        .to_string(),
        priority: PRIORITY_BASE + index as i32,
        body,
    })
}

/// Split `a.b.c.d/nn` into an address and a mask, which is how nwfilter
/// expresses a network (it has no CIDR attribute).
fn split_cidr(cidr: &str) -> Option<(String, String)> {
    let net: ipnetwork::IpNetwork = cidr.parse().ok()?;
    Some((net.network().to_string(), net.mask().to_string()))
}

#[derive(Debug, Serialize)]
#[serde(rename = "filter")]
struct NwFilter {
    #[serde(rename = "@name")]
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uuid: Option<String>,
    #[serde(rename = "filterref")]
    filterrefs: Vec<FilterRef>,
    #[serde(rename = "rule")]
    rules: Vec<Rule>,
}

#[derive(Debug, Serialize)]
struct FilterRef {
    #[serde(rename = "@filter")]
    filter: String,
}

#[derive(Debug, Serialize)]
struct Rule {
    #[serde(rename = "@action")]
    action: String,
    #[serde(rename = "@direction")]
    direction: String,
    #[serde(rename = "@priority")]
    priority: i32,
    #[serde(rename = "$value")]
    body: RuleBody,
}

#[derive(Debug, Serialize)]
enum RuleBody {
    #[serde(rename = "tcp")]
    Tcp(Matcher),
    #[serde(rename = "udp")]
    Udp(Matcher),
    #[serde(rename = "icmp")]
    Icmp(Matcher),
    #[serde(rename = "all")]
    All(Matcher),
}

#[derive(Debug, Serialize, Default, Clone)]
struct Matcher {
    #[serde(rename = "@srcipaddr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    srcipaddr: Option<String>,
    #[serde(rename = "@srcipmask")]
    #[serde(skip_serializing_if = "Option::is_none")]
    srcipmask: Option<String>,
    #[serde(rename = "@dstportstart")]
    #[serde(skip_serializing_if = "Option::is_none")]
    dstportstart: Option<u32>,
    #[serde(rename = "@dstportend")]
    #[serde(skip_serializing_if = "Option::is_none")]
    dstportend: Option<u32>,
}

struct Ports {
    dstportstart: Option<u32>,
    dstportend: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn rule(id: u64) -> VmFirewallRule {
        VmFirewallRule {
            id,
            vm_id: 1,
            priority: 0,
            direction: VmFirewallDirection::Inbound,
            protocol: VmFirewallProtocol::Tcp,
            action: VmFirewallRuleAction::Accept,
            src_cidr: None,
            dst_port_start: None,
            dst_port_end: None,
            enabled: true,
            created: Utc::now(),
            updated: Utc::now(),
        }
    }

    #[test]
    fn filter_is_named_per_vm() {
        assert_eq!(filter_name(7), "lnvps-vm-7");
    }

    #[test]
    fn existing_uuid_is_reused_so_redefine_works() -> Result<()> {
        // Regression: libvirt refuses `define` for a filter name that already
        // exists unless the UUID matches, so re-applying rules to a VM would
        // fail with "already exists with uuid ...".
        let uuid = "7c4c7525-5ad0-4962-8adf-9a30d5570fd7";
        let xml = build(1, &[], Some(uuid))?;
        assert!(xml.contains(uuid), "got {xml}");

        // A brand new filter must not invent one.
        assert!(!build(1, &[], None)?.contains("<uuid>"));
        Ok(())
    }

    #[test]
    fn empty_ruleset_still_blocks_mac_spoofing() -> Result<()> {
        let xml = build(1, &[], None)?;
        assert!(xml.contains(r#"<filter name="lnvps-vm-1">"#), "got {xml}");
        // A guest that can forge its MAC can impersonate another tenant.
        assert!(xml.contains(r#"filter="no-mac-spoofing""#), "got {xml}");
        Ok(())
    }

    #[test]
    fn tcp_port_rule() -> Result<()> {
        let mut r = rule(1);
        r.dst_port_start = Some(22);
        r.dst_port_end = Some(22);
        let xml = build(1, &[r], None)?;

        assert!(xml.contains(r#"action="accept""#), "got {xml}");
        assert!(xml.contains(r#"direction="in""#), "got {xml}");
        assert!(xml.contains(r#"dstportstart="22""#), "got {xml}");
        assert!(xml.contains(r#"dstportend="22""#), "got {xml}");
        assert!(xml.contains("<tcp"), "got {xml}");
        Ok(())
    }

    #[test]
    fn source_cidr_becomes_address_and_mask() -> Result<()> {
        let mut r = rule(1);
        r.src_cidr = Some("10.1.2.0/24".to_string());
        let xml = build(1, &[r], None)?;

        // nwfilter has no CIDR attribute, only address + mask.
        assert!(xml.contains(r#"srcipaddr="10.1.2.0""#), "got {xml}");
        assert!(xml.contains(r#"srcipmask="255.255.255.0""#), "got {xml}");
        Ok(())
    }

    #[test]
    fn direction_and_action_mapping() -> Result<()> {
        let mut r = rule(1);
        r.direction = VmFirewallDirection::Outbound;
        r.action = VmFirewallRuleAction::Drop;
        let xml = build(1, &[r], None)?;
        assert!(xml.contains(r#"direction="out""#), "got {xml}");
        assert!(xml.contains(r#"action="drop""#), "got {xml}");

        let mut r = rule(1);
        r.action = VmFirewallRuleAction::Reject;
        assert!(build(1, &[r], None)?.contains(r#"action="reject""#));
        Ok(())
    }

    #[test]
    fn protocols_map_to_elements() -> Result<()> {
        let mut udp = rule(1);
        udp.protocol = VmFirewallProtocol::Udp;
        udp.dst_port_start = Some(53);
        assert!(build(1, &[udp], None)?.contains("<udp"));

        let mut icmp = rule(2);
        icmp.protocol = VmFirewallProtocol::Icmp;
        assert!(build(1, &[icmp], None)?.contains("<icmp"));

        let mut any = rule(3);
        any.protocol = VmFirewallProtocol::Any;
        assert!(build(1, &[any], None)?.contains("<all"));
        Ok(())
    }

    #[test]
    fn disabled_rules_are_not_emitted() -> Result<()> {
        let mut r = rule(1);
        r.enabled = false;
        r.dst_port_start = Some(8080);
        let xml = build(1, &[r], None)?;
        // Leaving a disabled rule in place would enforce something the operator
        // switched off.
        assert!(!xml.contains("8080"), "got {xml}");
        Ok(())
    }

    #[test]
    fn rules_keep_database_priority_order() -> Result<()> {
        let mut first = rule(2);
        first.priority = 1;
        first.dst_port_start = Some(80);
        let mut second = rule(1);
        second.priority = 5;
        second.dst_port_start = Some(443);

        let xml = build(1, &[second, first], None)?;
        let p80 = xml.find("80").expect("port 80");
        let p443 = xml.find("443").expect("port 443");
        assert!(p80 < p443, "lower priority must be evaluated first: {xml}");
        Ok(())
    }

    #[test]
    fn inverted_port_range_is_rejected() {
        let mut r = rule(1);
        r.dst_port_start = Some(100);
        r.dst_port_end = Some(50);
        // Silently swapping these would enforce a range the operator did not
        // ask for.
        assert!(build(1, &[r], None).is_err());
    }

    #[test]
    fn ports_without_a_protocol_are_rejected() {
        let mut r = rule(1);
        r.protocol = VmFirewallProtocol::Any;
        r.dst_port_start = Some(22);
        // libvirt cannot express this; emitting <all/> would silently open
        // every port instead of just 22.
        assert!(build(1, &[r], None).is_err());
    }

    #[test]
    fn icmp_with_ports_is_rejected() {
        let mut r = rule(1);
        r.protocol = VmFirewallProtocol::Icmp;
        r.dst_port_start = Some(22);
        assert!(build(1, &[r], None).is_err());
    }

    #[test]
    fn open_ended_range_is_closed_for_libvirt() -> Result<()> {
        let mut r = rule(1);
        r.dst_port_start = Some(8000);
        let xml = build(1, &[r], None)?;
        // A start with no end must not become "all ports".
        assert!(xml.contains(r#"dstportstart="8000""#), "got {xml}");
        assert!(xml.contains(r#"dstportend="8000""#), "got {xml}");
        Ok(())
    }
}
