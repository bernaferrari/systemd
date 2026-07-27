// SPDX-License-Identifier: LGPL-2.1-or-later
//
// DNS resource-record formatting and IANA mnemonic lookup.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use super::model::{
    DnsSvcParam, DnsSvcParamKey, DnsTxtItem, DnsType, DnssecAlgorithm, DnssecDigest, Rdata,
    SshfpAlgorithm, SshfpKeyType,
};
use super::record::DnsResourceRecord;

impl DnsResourceRecord {
    pub fn to_string_cached(&self) -> String {
        let mut out = self.key.to_rr_string();
        match &self.rdata {
            Rdata::Srv {
                priority,
                weight,
                port,
                name,
            } => {
                write!(&mut out, " {priority} {weight} {port} {name}").ok();
            }
            Rdata::Ptr { name }
            | Rdata::Ns { name }
            | Rdata::Cname { name }
            | Rdata::Dname { name } => {
                write!(&mut out, " {name}").ok();
            }
            Rdata::Hinfo { cpu, os } => {
                write!(&mut out, " {cpu} {os}").ok();
            }
            Rdata::Txt { items } | Rdata::Spf { items } => {
                write!(&mut out, " {}", format_txt(items)).ok();
            }
            Rdata::A { address } => {
                write!(&mut out, " {address}").ok();
            }
            Rdata::Aaaa { address } => {
                write!(&mut out, " {address}").ok();
            }
            Rdata::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                write!(
                    &mut out,
                    " {mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
                )
                .ok();
            }
            Rdata::Mx { priority, exchange } => {
                write!(&mut out, " {priority} {exchange}").ok();
            }
            Rdata::Loc {
                version,
                size,
                horiz_pre,
                vert_pre,
                latitude,
                longitude,
                altitude,
            } => {
                write!(
                    &mut out,
                    " {}",
                    format_location(
                        *latitude, *longitude, *altitude, *size, *horiz_pre, *vert_pre, *version
                    )
                )
                .ok();
            }
            Rdata::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                write!(
                    &mut out,
                    " {key_tag} {algorithm} {digest_type} {}",
                    hex(digest)
                )
                .ok();
            }
            Rdata::Sshfp {
                algorithm,
                fptype,
                fingerprint,
            } => {
                write!(&mut out, " {algorithm} {fptype} {}", hex(fingerprint)).ok();
            }
            Rdata::Dnskey {
                key,
                flags,
                protocol,
                algorithm,
            } => {
                write!(
                    &mut out,
                    " {flags} {protocol} {algorithm} {}",
                    base64_encode(key)
                )
                .ok();
            }
            Rdata::Rrsig {
                signer,
                signature,
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
            } => {
                write!(&mut out, " {type_covered} {algorithm} {labels} {original_ttl} {} {} {key_tag} {signer} {}", format_timestamp_dns(*expiration), format_timestamp_dns(*inception), base64_encode(signature)).ok();
            }
            Rdata::Nsec {
                next_domain_name,
                types,
            } => {
                write!(&mut out, " {next_domain_name} {}", format_types(types)).ok();
            }
            Rdata::Nsec3 {
                algorithm,
                flags,
                iterations,
                salt,
                next_hashed_name,
                types,
            } => {
                write!(
                    &mut out,
                    " {algorithm} {flags} {iterations} {} {} {}",
                    if salt.is_empty() {
                        "-".into()
                    } else {
                        hex(salt)
                    },
                    base32hex(next_hashed_name),
                    format_types(types)
                )
                .ok();
            }
            Rdata::Tlsa {
                cert_usage,
                selector,
                matching_type,
                data,
            } => {
                write!(
                    &mut out,
                    " {cert_usage} {selector} {matching_type} {}",
                    hex(data)
                )
                .ok();
            }
            Rdata::Svcb {
                priority,
                target_name,
                params,
            }
            | Rdata::Https {
                priority,
                target_name,
                params,
            } => {
                write!(
                    &mut out,
                    " {priority} {} {}",
                    if target_name.is_empty() {
                        "."
                    } else {
                        target_name
                    },
                    format_svc_params(params)
                )
                .ok();
            }
            Rdata::Caa { tag, value, flags } => {
                write!(&mut out, " {flags} {tag} \"{}\"", octescape(value)).ok();
            }
            Rdata::Naptr {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => {
                write!(
                    &mut out,
                    " {order} {preference} \"{}\" \"{}\" \"{}\" {replacement}.",
                    octescape(flags.as_bytes()),
                    octescape(services.as_bytes()),
                    octescape(regexp.as_bytes())
                )
                .ok();
            }
            Rdata::Generic(data) | Rdata::Opt(data) => {
                write!(&mut out, " \\# {} {}", data.len(), hex(data)).ok();
            }
        }
        out
    }
}

pub fn dnssec_algorithm_to_string(value: u8) -> String {
    match value {
        1 => "RSAMD5",
        2 => "DH",
        3 => "DSA",
        4 => "ECC",
        5 => "RSASHA1",
        6 => "DSA-NSEC3-SHA1",
        7 => "RSASHA1-NSEC3-SHA1",
        8 => "RSASHA256",
        10 => "RSASHA512",
        12 => "ECC-GOST",
        13 => "ECDSAP256SHA256",
        14 => "ECDSAP384SHA384",
        15 => "ED25519",
        16 => "ED448",
        252 => "INDIRECT",
        253 => "PRIVATEDNS",
        254 => "PRIVATEOID",
        other => return other.to_string(),
    }
    .to_owned()
}

pub fn dnssec_digest_to_string(value: u8) -> String {
    match value {
        1 => "SHA-1",
        2 => "SHA-256",
        3 => "GOST_R_34.11-94",
        4 => "SHA-384",
        other => return other.to_string(),
    }
    .to_owned()
}

pub fn sshfp_algorithm_to_string(value: u8) -> String {
    match value {
        1 => "RSA",
        2 => "DSA",
        3 => "ECDSA",
        4 => "Ed25519",
        6 => "Ed448",
        other => return other.to_string(),
    }
    .to_owned()
}

pub fn sshfp_key_type_to_string(value: u8) -> String {
    match value {
        1 => "SHA-1",
        2 => "SHA-256",
        other => return other.to_string(),
    }
    .to_owned()
}

pub fn format_timestamp_dns(sec: u32) -> String {
    let timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(sec));
    let datetime: chrono_like::DateTime = timestamp.into();
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        datetime.year,
        datetime.month,
        datetime.day,
        datetime.hour,
        datetime.minute,
        datetime.second
    )
}

pub fn format_types(types: &BTreeSet<u16>) -> String {
    let parts = types
        .iter()
        .map(|t| {
            dns_type_to_string(*t)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("TYPE{t}"))
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("( {parts} )")
}

pub fn format_txt(items: &[DnsTxtItem]) -> String {
    items
        .iter()
        .map(|item| {
            let mut s = String::from("\"");
            for &b in &item.data {
                if b < b' ' || b == b'\"' || b >= 127 {
                    write!(&mut s, "\\{:03}", b).ok();
                } else {
                    s.push(char::from(b));
                }
            }
            s.push('\"');
            s
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn format_svc_param_value(param: &DnsSvcParam) -> String {
    match param.key {
        x if x == DnsSvcParamKey::Alpn as u16 => {
            let mut offset = 0usize;
            let mut values = Vec::new();
            while offset < param.value.len() {
                let len = param.value[offset] as usize;
                offset += 1;
                let end = offset + len;
                values.push(String::from_utf8_lossy(&param.value[offset..end]).into_owned());
                offset = end;
            }
            format!("\"{}\"", values.join(","))
        }
        x if x == DnsSvcParamKey::Port as u16 && param.value.len() == 2 => {
            u16::from_be_bytes([param.value[0], param.value[1]]).to_string()
        }
        x if x == DnsSvcParamKey::Ipv4Hint as u16 => {
            let addrs = param
                .value
                .chunks_exact(4)
                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string())
                .collect::<Vec<_>>()
                .join(",");
            format!("\"{addrs}\"")
        }
        x if x == DnsSvcParamKey::Ipv6Hint as u16 => {
            let addrs = param
                .value
                .chunks_exact(16)
                .map(|c| Ipv6Addr::from(<[u8; 16]>::try_from(c).unwrap_or([0; 16])).to_string())
                .collect::<Vec<_>>()
                .join(",");
            format!("\"{addrs}\"")
        }
        _ => format!("\"{}\"", octescape(&param.value)),
    }
}

pub fn format_svc_param(param: &DnsSvcParam) -> String {
    let key = svc_param_key_name(param.key);
    if param.value.is_empty() {
        return key.to_owned();
    }
    format!("{key}={}", format_svc_param_value(param))
}

pub fn format_svc_params(params: &[DnsSvcParam]) -> String {
    params
        .iter()
        .map(format_svc_param)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn format_location(
    latitude: u32,
    longitude: u32,
    altitude: u32,
    size: u8,
    horiz_pre: u8,
    vert_pre: u8,
    version: u8,
) -> String {
    let _ = version;
    let ns = if latitude >= 1u32 << 31 { 'N' } else { 'S' };
    let ew = if longitude >= 1u32 << 31 { 'E' } else { 'W' };
    let lat = if latitude >= 1u32 << 31 {
        latitude - (1u32 << 31)
    } else {
        (1u32 << 31) - latitude
    };
    let lon = if longitude >= 1u32 << 31 {
        longitude - (1u32 << 31)
    } else {
        (1u32 << 31) - longitude
    };
    let alt = if altitude >= 10_000_000 {
        f64::from(altitude - 10_000_000)
    } else {
        -f64::from(10_000_000 - altitude)
    };
    let siz = f64::from(size >> 4) * 10f64.powi((size & 0x0f) as i32);
    let hor = f64::from(horiz_pre >> 4) * 10f64.powi((horiz_pre & 0x0f) as i32);
    let ver = f64::from(vert_pre >> 4) * 10f64.powi((vert_pre & 0x0f) as i32);
    format!(
        "{} {} {:.3} {} {} {} {:.3} {} {:.2}m {:.2}m {:.2}m {:.2}m",
        lat / 60000 / 60,
        (lat / 60000) % 60,
        f64::from(lat % 60000) / 1000.0,
        ns,
        lon / 60000 / 60,
        (lon / 60000) % 60,
        f64::from(lon % 60000) / 1000.0,
        ew,
        alt / 100.0,
        siz / 100.0,
        hor / 100.0,
        ver / 100.0,
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

fn octescape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if b.is_ascii_graphic() && b != b'\\' && b != b'\"' {
            out.push(char::from(b));
        } else {
            write!(&mut out, "\\{:03}", b).ok();
        }
    }
    out
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = *bytes.get(i + 1).unwrap_or(&0);
        let b2 = *bytes.get(i + 2).unwrap_or(&0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[((b0 & 0x03) << 4 | (b1 >> 4)) as usize] as char);
        out.push(if i + 1 < bytes.len() {
            TABLE[((b1 & 0x0f) << 2 | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if i + 2 < bytes.len() {
            TABLE[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
        i += 3;
    }
    out
}

fn base32hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(TABLE[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(TABLE[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn svc_param_key_name(key: u16) -> &'static str {
    match key {
        x if x == DnsSvcParamKey::Mandatory as u16 => "mandatory",
        x if x == DnsSvcParamKey::Alpn as u16 => "alpn",
        x if x == DnsSvcParamKey::NoDefaultAlpn as u16 => "no-default-alpn",
        x if x == DnsSvcParamKey::Port as u16 => "port",
        x if x == DnsSvcParamKey::Ipv4Hint as u16 => "ipv4hint",
        x if x == DnsSvcParamKey::Ech as u16 => "ech",
        x if x == DnsSvcParamKey::Ipv6Hint as u16 => "ipv6hint",
        x if x == DnsSvcParamKey::DohPath as u16 => "dohpath",
        x if x == DnsSvcParamKey::Ohttp as u16 => "ohttp",
        _ => "key",
    }
}

mod chrono_like {
    #[derive(Debug, Clone, Copy)]
    pub struct DateTime {
        pub year: i32,
        pub month: u32,
        pub day: u32,
        pub hour: u32,
        pub minute: u32,
        pub second: u32,
    }

    impl From<std::time::SystemTime> for DateTime {
        fn from(value: std::time::SystemTime) -> Self {
            let secs = value
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let days = secs.div_euclid(86_400);
            let sod = secs.rem_euclid(86_400);
            let (year, month, day) = civil_from_days(days);
            Self {
                year,
                month,
                day,
                hour: (sod / 3600) as u32,
                minute: ((sod % 3600) / 60) as u32,
                second: (sod % 60) as u32,
            }
        }
    }

    fn civil_from_days(days: i64) -> (i32, u32, u32) {
        let z = days + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = mp + if mp < 10 { 3 } else { -9 };
        ((y + i64::from(m <= 2)) as i32, m as u32, d as u32)
    }
}
