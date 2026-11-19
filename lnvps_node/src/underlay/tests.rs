use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;

#[test]
fn the_search_finds_the_largest_size_that_fits() {
    for limit in [576, 1280, 1312, 1420, 1499, 1500] {
        let mut asked = 0;
        let found = largest_that_fits(576, 1500, |size| {
            asked += 1;
            Ok(size <= limit)
        })
        .unwrap();
        assert_eq!(found, limit);
        assert!(asked <= 12, "{asked} probes for {limit}");
    }
}

#[test]
fn a_v4_echo_is_sized_to_the_whole_packet_and_checksummed() {
    let packet = echo_request(IpAddr::V4(Ipv4Addr::LOCALHOST), 7, 9, 1312).unwrap();
    assert_eq!(packet.len() + 20, 1312);
    assert_eq!(packet[0], 8);
    assert_eq!(checksum(&packet), 0);
}

#[test]
fn a_v6_echo_is_sized_to_the_whole_packet() {
    let packet = echo_request(IpAddr::V6(Ipv6Addr::LOCALHOST), 7, 9, 1280).unwrap();
    assert_eq!(packet.len() + 40, 1280);
    assert_eq!(packet[0], 128);
}

#[test]
fn a_size_below_the_headers_is_refused() {
    assert!(echo_request(IpAddr::V4(Ipv4Addr::LOCALHOST), 1, 1, 20).is_err());
}

#[test]
fn only_the_reply_to_this_probe_counts() {
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut reply = vec![0x45; 20];
    reply.extend_from_slice(&[0, 0, 0, 0, 0, 7, 0, 9]);
    assert!(is_our_reply(v4, &reply, 7, 9));
    assert!(!is_our_reply(v4, &reply, 7, 10));
    assert!(!is_our_reply(v4, &reply, 8, 9));
    reply[20] = 8;
    assert!(
        !is_our_reply(v4, &reply, 7, 9),
        "our own request echoed back"
    );

    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert!(is_our_reply(v6, &[129, 0, 0, 0, 0, 7, 0, 9], 7, 9));
    assert!(!is_our_reply(v6, &[128, 0, 0, 0, 0, 7, 0, 9], 7, 9));
    assert!(!is_our_reply(v6, &[129, 0], 7, 9));
}
