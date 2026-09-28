use super::*;

fn tunnel(address4: Option<&str>) -> Tunnel {
    Tunnel {
        id: 1,
        address4: address4.map(str::to_string),
        address6: Some("fd00:66::2/128".to_string()),
        ..Default::default()
    }
}

fn pool(cidr4: Option<&str>) -> TunnelPool {
    TunnelPool {
        cidr4: cidr4.map(str::to_string),
        cidr6: Some("fd00:66::/64".to_string()),
        ..Default::default()
    }
}

#[test]
fn a_probe_address_mirrors_the_node_from_the_top_of_the_block() {
    let p = pool(Some("10.95.0.0/16"));
    assert_eq!(
        probe_address(&tunnel(Some("10.95.0.2/32")), &p).as_deref(),
        Some("10.95.255.254/32")
    );
    assert_eq!(
        probe_address(&tunnel(Some("10.95.0.3/32")), &p).as_deref(),
        Some("10.95.255.253/32")
    );
}

#[test]
fn a_probe_address_is_derived_not_allocated() {
    let t = tunnel(Some("10.66.0.2/32"));
    let p = pool(Some("10.66.0.0/24"));
    assert_eq!(probe_address(&t, &p), probe_address(&t, &p));
}

#[test]
fn no_two_addresses_in_a_full_pool_collide() {
    let p = pool(Some("10.66.0.0/24"));
    let mut taken = vec![
        "10.66.0.0/32".to_string(),
        "10.66.0.1/32".to_string(),
        "10.66.0.255/32".to_string(),
    ];
    for n in 2..128u32 {
        let node = format!("10.66.0.{n}/32");
        let probe = probe_address(&tunnel(Some(&node)), &p).unwrap();
        taken.push(node);
        taken.push(probe);
    }
    let mut sorted = taken.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), taken.len(), "two addresses collided");
}

#[test]
fn every_probe_lies_in_the_half_the_allocator_keeps_back() {
    let p = pool(Some("10.66.0.0/24"));
    let half = probe_half(&p).unwrap();
    assert_eq!(half.to_string(), "10.66.0.128/25");
    for n in 2..128u32 {
        let probe = probe_address(&tunnel(Some(&format!("10.66.0.{n}/32"))), &p).unwrap();
        let ip: IpAddr = probe.split('/').next().unwrap().parse().unwrap();
        assert!(half.contains(ip), "{probe} is outside {half}");
    }
}

#[test]
fn a_node_in_the_upper_half_has_no_probe() {
    let p = pool(Some("10.66.0.0/24"));
    assert!(probe_address(&tunnel(Some("10.66.0.128/32")), &p).is_none());
    assert!(probe_address(&tunnel(Some("10.66.0.200/32")), &p).is_none());
}

#[test]
fn no_v4_block_means_no_probe() {
    assert!(probe_address(&tunnel(Some("10.66.0.2/32")), &pool(None)).is_none());
    assert!(probe_address(&tunnel(None), &pool(Some("10.66.0.0/24"))).is_none());
    assert!(probe_half(&pool(None)).is_none());
}

#[test]
fn a_broken_or_foreign_address_is_not_guessed_at() {
    let p = pool(Some("10.66.0.0/24"));
    assert!(probe_address(&tunnel(Some("not-an-address")), &p).is_none());
    assert!(probe_address(&tunnel(Some("fd00:66::2/128")), &p).is_none());
    assert!(probe_address(&tunnel(Some("10.67.0.2/32")), &p).is_none());
    assert!(probe_address(&tunnel(Some("10.66.0.1/32")), &p).is_none());
}

#[test]
fn a_block_too_small_to_split_has_no_probe_half() {
    assert!(probe_half(&pool(Some("10.66.0.0/31"))).is_none());
    assert!(probe_half(&pool(Some("10.66.0.0/32"))).is_none());
}

#[test]
fn a_probes_mac_is_stable_and_its_own() {
    assert_eq!(probe_mac(7), probe_mac(7));
    assert_ne!(probe_mac(7), probe_mac(8));
    assert!(probe_mac(7).starts_with("52:54:"), "{}", probe_mac(7));
}

#[test]
fn a_probes_gateway_is_not_in_any_pool() {
    assert!(PROBE_GATEWAY.is_link_local());
}
