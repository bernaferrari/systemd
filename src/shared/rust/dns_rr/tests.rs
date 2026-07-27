// SPDX-License-Identifier: LGPL-2.1-or-later

use super::*;
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;

fn hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn key_equality_is_case_insensitive() {
    let a = DnsResourceKey::new(1, DnsType::A as u16, "Example.COM").unwrap();
    let b = DnsResourceKey::new(1, DnsType::A as u16, "example.com.").unwrap();
    assert_eq!(a, b);
    assert_eq!(hash(&a), hash(&b));
}

#[test]
fn key_matching_helpers_work() {
    let key = DnsResourceKey::new(1, DnsType::Ptr as u16, "_ipp._tcp.local").unwrap();
    assert!(key.is_dnssd_ptr());
    assert!(key.is_dnssd_two_label_ptr());
    assert_eq!(dns_name_count_labels(&key.name), 3);
    assert!(!DnsResourceKey::new(1, DnsType::A as u16, "host.local")
        .unwrap()
        .is_dnssd_ptr());
}

#[test]
fn a_roundtrip_wire_format() {
    let mut rr = DnsResourceRecord::new_full(
        1,
        DnsType::A as u16,
        "host.example",
        Rdata::A {
            address: Ipv4Addr::new(192, 0, 2, 1),
        },
    )
    .unwrap();
    rr.ttl = 60;
    let wire = rr.to_wire(false).unwrap().to_vec();
    let (parsed, end) = DnsResourceRecord::from_wire(&wire, 0).unwrap();
    assert_eq!(end, wire.len());
    assert!(rr.equal(&parsed));
    assert_eq!(
        dns_resource_record_payload(&parsed),
        Some(vec![192, 0, 2, 1])
    );
}

#[test]
fn complex_records_roundtrip() {
    let records = vec![
        DnsResourceRecord::new_full(
            1,
            DnsType::Mx as u16,
            "example.com",
            Rdata::Mx {
                priority: 10,
                exchange: "mail.example.com".into(),
            },
        )
        .unwrap(),
        DnsResourceRecord::new_full(
            1,
            DnsType::Txt as u16,
            "example.com",
            Rdata::Txt {
                items: vec![
                    DnsTxtItem {
                        data: b"v=spf1".to_vec(),
                    },
                    DnsTxtItem {
                        data: b"-all".to_vec(),
                    },
                ],
            },
        )
        .unwrap(),
        DnsResourceRecord::new_full(
            1,
            DnsType::Soa as u16,
            "example.com",
            Rdata::Soa {
                mname: "ns1.example.com".into(),
                rname: "hostmaster.example.com".into(),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 5,
            },
        )
        .unwrap(),
        DnsResourceRecord::new_full(
            1,
            DnsType::Ds as u16,
            "example.com",
            Rdata::Ds {
                key_tag: 60485,
                algorithm: 8,
                digest_type: 2,
                digest: vec![0xde, 0xad, 0xbe, 0xef],
            },
        )
        .unwrap(),
        DnsResourceRecord::new_full(
            1,
            DnsType::Dnskey as u16,
            "example.com",
            Rdata::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 8,
                key: vec![1, 2, 3, 4, 5, 6],
            },
        )
        .unwrap(),
        DnsResourceRecord::new_full(
            1,
            DnsType::Caa as u16,
            "example.com",
            Rdata::Caa {
                flags: CAA_FLAG_CRITICAL,
                tag: "issue".into(),
                value: b"letsencrypt.org".to_vec(),
            },
        )
        .unwrap(),
        DnsResourceRecord::new_full(
            1,
            DnsType::Naptr as u16,
            "example.com",
            Rdata::Naptr {
                order: 1,
                preference: 2,
                flags: "u".into(),
                services: "E2U+sip".into(),
                regexp: "!^.*$!sip:info@example.com!".into(),
                replacement: ".".into(),
            },
        )
        .unwrap(),
    ];

    for mut rr in records {
        rr.ttl = 300;
        let wire = rr.to_wire(true).unwrap().to_vec();
        let parsed = DnsResourceRecord::new_from_raw(&wire).unwrap();
        assert!(rr.equal(&parsed), "{}", rr.to_string_cached());
    }
}

#[test]
fn nsec_bitmap_roundtrip() {
    let mut types = BTreeSet::new();
    types.insert(DnsType::A as u16);
    types.insert(DnsType::Aaaa as u16);
    types.insert(DnsType::Rrsig as u16);
    let mut rr = DnsResourceRecord::new_full(
        1,
        DnsType::Nsec as u16,
        "example.com",
        Rdata::Nsec {
            next_domain_name: "next.example.com".into(),
            types: types.clone(),
        },
    )
    .unwrap();
    let wire = rr.to_wire(true).unwrap().to_vec();
    let parsed = DnsResourceRecord::new_from_raw(&wire).unwrap();
    match parsed.rdata {
        Rdata::Nsec {
            types: parsed_types,
            ..
        } => assert_eq!(parsed_types, types),
        _ => panic!("wrong type"),
    }
}

#[test]
fn cname_and_dname_targets_work() {
    let key = DnsResourceKey::new(1, DnsType::A as u16, "www.example.com").unwrap();
    let cname = DnsResourceRecord::new_full(
        1,
        DnsType::Cname as u16,
        "www.example.com",
        Rdata::Cname {
            name: "alias.example.net".into(),
        },
    )
    .unwrap();
    assert_eq!(
        DnsResourceRecord::get_cname_target(&key, &cname).unwrap(),
        "alias.example.net"
    );

    let dkey = DnsResourceKey::new(1, DnsType::A as u16, "foo.sub.example.com").unwrap();
    let dname = DnsResourceRecord::new_full(
        1,
        DnsType::Dname as u16,
        "example.com",
        Rdata::Dname {
            name: "example.net".into(),
        },
    )
    .unwrap();
    assert_eq!(
        DnsResourceRecord::get_cname_target(&dkey, &dname).unwrap(),
        "foo.sub.example.net"
    );

    let redirected = DnsResourceKey::new_redirect(&dkey, &dname).unwrap();
    assert_eq!(redirected.dns_class, dkey.dns_class);
    assert_eq!(redirected.rr_type, dkey.rr_type);
    assert_eq!(redirected.name, "foo.sub.example.net");
}

#[test]
fn reverse_and_address_constructors_work() {
    let reverse =
        DnsResourceRecord::new_reverse(AF_INET, &[192, 0, 2, 1], "host.example.com").unwrap();
    assert_eq!(reverse.key.name, "1.2.0.192.in-addr.arpa");
    let aaaa = DnsResourceRecord::new_address(
        AF_INET6,
        &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        "host.example.com",
    )
    .unwrap();
    assert!(aaaa.is_link_local_address());
}

#[test]
fn dnskey_keytag_matches_rfc_algorithm() {
    let rr = DnsResourceRecord::new_full(
        1,
        DnsType::Dnskey as u16,
        "example.com",
        Rdata::Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 8,
            key: vec![1, 2, 3, 4, 5],
        },
    )
    .unwrap();
    assert_eq!(dnssec_keytag(&rr, false).unwrap(), 3343);
}

#[test]
fn signer_source_and_synthetic_helpers_work() {
    let mut rr = DnsResourceRecord::new_full(
        1,
        DnsType::A as u16,
        "foo.example.com",
        Rdata::A {
            address: Ipv4Addr::new(1, 2, 3, 4),
        },
    )
    .unwrap();
    rr.signer_skip_labels = Some(2);
    rr.source_skip_labels = Some(1);
    assert_eq!(rr.signer().unwrap(), Some("com"));
    assert_eq!(rr.source().unwrap(), Some("example.com"));
    assert_eq!(rr.is_signer("COM").unwrap(), Some(true));
    assert_eq!(rr.is_synthetic().unwrap(), Some(true));
}

#[test]
fn compare_and_hash_follow_payload() {
    let a = DnsResourceRecord::new_full(
        1,
        DnsType::A as u16,
        "host.example",
        Rdata::A {
            address: Ipv4Addr::new(1, 1, 1, 1),
        },
    )
    .unwrap();
    let b = DnsResourceRecord::new_full(
        1,
        DnsType::A as u16,
        "host.example",
        Rdata::A {
            address: Ipv4Addr::new(1, 1, 1, 1),
        },
    )
    .unwrap();
    let c = DnsResourceRecord::new_full(
        1,
        DnsType::A as u16,
        "host.example",
        Rdata::A {
            address: Ipv4Addr::new(1, 1, 1, 2),
        },
    )
    .unwrap();
    assert_eq!(dns_resource_record_compare_func(&a, &b), Ordering::Equal);
    assert_ne!(dns_resource_record_compare_func(&a, &c), Ordering::Equal);

    let mut ha = DefaultHasher::new();
    let mut hb = DefaultHasher::new();
    dns_resource_record_hash_func(&a, &mut ha);
    dns_resource_record_hash_func(&b, &mut hb);
    assert_eq!(ha.finish(), hb.finish());
}

#[test]
fn formatting_helpers_cover_known_records() {
    let txt = format_txt(&[DnsTxtItem {
        data: b"hello world".to_vec(),
    }]);
    assert_eq!(txt, "\"hello world\"");
    assert_eq!(dnssec_algorithm_to_string(8), "RSASHA256");
    assert_eq!(dnssec_digest_to_string(2), "SHA-256");
    assert_eq!(sshfp_algorithm_to_string(1), "RSA");
    assert_eq!(sshfp_key_type_to_string(2), "SHA-256");
    assert_eq!(format_timestamp_dns(0), "19700101000000");
    assert!(format_location(1 << 31, 1 << 31, 10_000_000, 0x12, 0x13, 0x14, 0).contains('N'));
}
