// SPDX-License-Identifier: LGPL-2.1-or-later
//
// DNS resource-record wire parsing and serialization.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::key::{DnsResourceKey, dns_name_is_root, normalize_name};
use super::model::{DnsSvcParam, DnsTxtItem, DnsType, ParseError, Rdata};
use super::record::DnsResourceRecord;

impl DnsResourceRecord {
    pub fn to_wire(&mut self, canonical: bool) -> Result<&[u8], ParseError> {
        if self
            .wire_format
            .as_ref()
            .is_some_and(|_| self.wire_format_canonical == canonical)
        {
            return Ok(self.wire_format.as_deref().unwrap_or(&[]));
        }

        let mut out = Vec::new();
        encode_name(&self.key.name, canonical, &mut out)?;
        out.extend_from_slice(&self.key.rr_type.to_be_bytes());
        out.extend_from_slice(&self.key.dns_class.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        let rdlen_pos = out.len();
        out.extend_from_slice(&0u16.to_be_bytes());
        let rdata_offset = out.len();
        self.encode_rdata(canonical, &mut out)?;
        let rdlen = u16::try_from(out.len() - rdata_offset).map_err(|_| ParseError::Overflow)?;
        out[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
        self.wire_format_canonical = canonical;
        self.wire_format_rdata_offset = rdata_offset;
        self.wire_format = Some(out);
        Ok(self.wire_format.as_deref().unwrap_or(&[]))
    }

    pub fn from_wire(data: &[u8], offset: usize) -> Result<(Self, usize), ParseError> {
        let mut cursor = offset;
        let name = decode_name(data, &mut cursor)?;
        let rr_type = read_u16(data, &mut cursor)?;
        let dns_class = read_u16(data, &mut cursor)?;
        let ttl = read_u32(data, &mut cursor)?;
        let rdlen = read_u16(data, &mut cursor)? as usize;
        let rdata_start = cursor;
        let rdata_end = cursor.checked_add(rdlen).ok_or(ParseError::Overflow)?;
        if rdata_end > data.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let rdata = decode_rdata(rr_type, &data[rdata_start..rdata_end])?;
        cursor = rdata_end;

        let mut rr = Self::new(DnsResourceKey::new(dns_class, rr_type, name)?, rdata);
        rr.ttl = ttl;
        rr.wire_format = Some(data[offset..cursor].to_vec());
        rr.wire_format_rdata_offset = rdata_start - offset;
        Ok((rr, cursor))
    }

    pub fn new_from_raw(data: &[u8]) -> Result<Self, ParseError> {
        let (rr, end) = Self::from_wire(data, 0)?;
        if end != data.len() {
            return Err(ParseError::InvalidRdata("trailing bytes after RR"));
        }
        Ok(rr)
    }
    fn encode_rdata(&self, canonical: bool, out: &mut Vec<u8>) -> Result<(), ParseError> {
        match &self.rdata {
            Rdata::Generic(data) | Rdata::Opt(data) => out.extend_from_slice(data),
            Rdata::Srv {
                priority,
                weight,
                port,
                name,
            } => {
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                encode_name(name, canonical, out)?;
            }
            Rdata::Ptr { name }
            | Rdata::Ns { name }
            | Rdata::Cname { name }
            | Rdata::Dname { name } => encode_name(name, canonical, out)?,
            Rdata::Hinfo { cpu, os } => {
                encode_character_string(cpu.as_bytes(), out)?;
                encode_character_string(os.as_bytes(), out)?;
            }
            Rdata::Txt { items } | Rdata::Spf { items } => {
                for item in items {
                    encode_character_string(&item.data, out)?;
                }
            }
            Rdata::A { address } => out.extend_from_slice(&address.octets()),
            Rdata::Aaaa { address } => out.extend_from_slice(&address.octets()),
            Rdata::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                encode_name(mname, canonical, out)?;
                encode_name(rname, canonical, out)?;
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&refresh.to_be_bytes());
                out.extend_from_slice(&retry.to_be_bytes());
                out.extend_from_slice(&expire.to_be_bytes());
                out.extend_from_slice(&minimum.to_be_bytes());
            }
            Rdata::Mx { priority, exchange } => {
                out.extend_from_slice(&priority.to_be_bytes());
                encode_name(exchange, canonical, out)?;
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
                out.extend_from_slice(&[*version, *size, *horiz_pre, *vert_pre]);
                out.extend_from_slice(&latitude.to_be_bytes());
                out.extend_from_slice(&longitude.to_be_bytes());
                out.extend_from_slice(&altitude.to_be_bytes());
            }
            Rdata::Sshfp {
                fingerprint,
                algorithm,
                fptype,
            } => {
                out.extend_from_slice(&[*algorithm, *fptype]);
                out.extend_from_slice(fingerprint);
            }
            Rdata::Dnskey {
                key,
                flags,
                protocol,
                algorithm,
            } => {
                out.extend_from_slice(&flags.to_be_bytes());
                out.extend_from_slice(&[*protocol, *algorithm]);
                out.extend_from_slice(key);
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
                out.extend_from_slice(&type_covered.to_be_bytes());
                out.extend_from_slice(&[*algorithm, *labels]);
                out.extend_from_slice(&original_ttl.to_be_bytes());
                out.extend_from_slice(&expiration.to_be_bytes());
                out.extend_from_slice(&inception.to_be_bytes());
                out.extend_from_slice(&key_tag.to_be_bytes());
                encode_name(signer, canonical, out)?;
                out.extend_from_slice(signature);
            }
            Rdata::Nsec {
                next_domain_name,
                types,
            } => {
                encode_name(next_domain_name, canonical, out)?;
                encode_type_bitmap(types, out)?;
            }
            Rdata::Ds {
                digest,
                key_tag,
                algorithm,
                digest_type,
            } => {
                out.extend_from_slice(&key_tag.to_be_bytes());
                out.extend_from_slice(&[*algorithm, *digest_type]);
                out.extend_from_slice(digest);
            }
            Rdata::Nsec3 {
                types,
                salt,
                next_hashed_name,
                algorithm,
                flags,
                iterations,
            } => {
                out.extend_from_slice(&[*algorithm, *flags]);
                out.extend_from_slice(&iterations.to_be_bytes());
                encode_counted_bytes(salt, out)?;
                encode_counted_bytes(next_hashed_name, out)?;
                encode_type_bitmap(types, out)?;
            }
            Rdata::Tlsa {
                data,
                cert_usage,
                selector,
                matching_type,
            } => {
                out.extend_from_slice(&[*cert_usage, *selector, *matching_type]);
                out.extend_from_slice(data);
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
                out.extend_from_slice(&priority.to_be_bytes());
                encode_name(target_name, canonical, out)?;
                for param in params {
                    out.extend_from_slice(&param.key.to_be_bytes());
                    out.extend_from_slice(&(param.value.len() as u16).to_be_bytes());
                    out.extend_from_slice(&param.value);
                }
            }
            Rdata::Caa { tag, value, flags } => {
                out.push(*flags);
                encode_character_string(tag.as_bytes(), out)?;
                out.extend_from_slice(value);
            }
            Rdata::Naptr {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => {
                out.extend_from_slice(&order.to_be_bytes());
                out.extend_from_slice(&preference.to_be_bytes());
                encode_character_string(flags.as_bytes(), out)?;
                encode_character_string(services.as_bytes(), out)?;
                encode_character_string(regexp.as_bytes(), out)?;
                encode_name(replacement, canonical, out)?;
            }
        }
        Ok(())
    }
}

fn decode_rdata(rr_type: u16, data: &[u8]) -> Result<Rdata, ParseError> {
    let mut cursor = 0usize;
    let rdata = match rr_type {
        x if x == DnsType::A as u16 => Rdata::A {
            address: Ipv4Addr::from(
                <[u8; 4]>::try_from(data)
                    .map_err(|_| ParseError::InvalidRdata("A requires 4 bytes"))?,
            ),
        },
        x if x == DnsType::Aaaa as u16 => Rdata::Aaaa {
            address: Ipv6Addr::from(
                <[u8; 16]>::try_from(data)
                    .map_err(|_| ParseError::InvalidRdata("AAAA requires 16 bytes"))?,
            ),
        },
        x if matches!(x, y if y == DnsType::Ptr as u16 || y == DnsType::Ns as u16 || y == DnsType::Cname as u16 || y == DnsType::Dname as u16) =>
        {
            let name = decode_name(data, &mut cursor)?;
            expect_end(cursor, data.len())?;
            match rr_type {
                x if x == DnsType::Ptr as u16 => Rdata::Ptr { name },
                x if x == DnsType::Ns as u16 => Rdata::Ns { name },
                x if x == DnsType::Cname as u16 => Rdata::Cname { name },
                _ => Rdata::Dname { name },
            }
        }
        x if x == DnsType::Srv as u16 => {
            let priority = read_u16(data, &mut cursor)?;
            let weight = read_u16(data, &mut cursor)?;
            let port = read_u16(data, &mut cursor)?;
            let name = decode_name(data, &mut cursor)?;
            expect_end(cursor, data.len())?;
            Rdata::Srv {
                priority,
                weight,
                port,
                name,
            }
        }
        x if x == DnsType::Txt as u16 || x == DnsType::Spf as u16 => {
            let mut items = Vec::new();
            while cursor < data.len() {
                items.push(DnsTxtItem {
                    data: decode_character_string(data, &mut cursor)?,
                });
            }
            if rr_type == DnsType::Txt as u16 {
                Rdata::Txt { items }
            } else {
                Rdata::Spf { items }
            }
        }
        x if x == DnsType::Hinfo as u16 => {
            let cpu = String::from_utf8(decode_character_string(data, &mut cursor)?)
                .map_err(|_| ParseError::InvalidRdata("invalid HINFO cpu"))?;
            let os = String::from_utf8(decode_character_string(data, &mut cursor)?)
                .map_err(|_| ParseError::InvalidRdata("invalid HINFO os"))?;
            expect_end(cursor, data.len())?;
            Rdata::Hinfo { cpu, os }
        }
        x if x == DnsType::Soa as u16 => {
            let mname = decode_name(data, &mut cursor)?;
            let rname = decode_name(data, &mut cursor)?;
            let serial = read_u32(data, &mut cursor)?;
            let refresh = read_u32(data, &mut cursor)?;
            let retry = read_u32(data, &mut cursor)?;
            let expire = read_u32(data, &mut cursor)?;
            let minimum = read_u32(data, &mut cursor)?;
            Rdata::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            }
        }
        x if x == DnsType::Mx as u16 => {
            let priority = read_u16(data, &mut cursor)?;
            let exchange = decode_name(data, &mut cursor)?;
            Rdata::Mx { priority, exchange }
        }
        x if x == DnsType::Loc as u16 => {
            if data.len() != 16 {
                return Err(ParseError::InvalidRdata("LOC requires 16 bytes"));
            }
            let version = data[0];
            let size = data[1];
            let horiz_pre = data[2];
            let vert_pre = data[3];
            let latitude = u32::from_be_bytes(
                data[4..8]
                    .try_into()
                    .map_err(|_| ParseError::UnexpectedEof)?,
            );
            let longitude = u32::from_be_bytes(
                data[8..12]
                    .try_into()
                    .map_err(|_| ParseError::UnexpectedEof)?,
            );
            let altitude = u32::from_be_bytes(
                data[12..16]
                    .try_into()
                    .map_err(|_| ParseError::UnexpectedEof)?,
            );
            Rdata::Loc {
                version,
                size,
                horiz_pre,
                vert_pre,
                latitude,
                longitude,
                altitude,
            }
        }
        x if x == DnsType::Sshfp as u16 => {
            if data.len() < 2 {
                return Err(ParseError::InvalidRdata("SSHFP too short"));
            }
            Rdata::Sshfp {
                algorithm: data[0],
                fptype: data[1],
                fingerprint: data[2..].to_vec(),
            }
        }
        x if x == DnsType::Dnskey as u16 => {
            if data.len() < 4 {
                return Err(ParseError::InvalidRdata("DNSKEY too short"));
            }
            Rdata::Dnskey {
                flags: u16::from_be_bytes([data[0], data[1]]),
                protocol: data[2],
                algorithm: data[3],
                key: data[4..].to_vec(),
            }
        }
        x if x == DnsType::Rrsig as u16 => {
            let type_covered = read_u16(data, &mut cursor)?;
            let algorithm = read_u8(data, &mut cursor)?;
            let labels = read_u8(data, &mut cursor)?;
            let original_ttl = read_u32(data, &mut cursor)?;
            let expiration = read_u32(data, &mut cursor)?;
            let inception = read_u32(data, &mut cursor)?;
            let key_tag = read_u16(data, &mut cursor)?;
            let signer = decode_name(data, &mut cursor)?;
            let signature = data[cursor..].to_vec();
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
            }
        }
        x if x == DnsType::Nsec as u16 => {
            let next_domain_name = decode_name(data, &mut cursor)?;
            let types = decode_type_bitmap(&data[cursor..])?;
            Rdata::Nsec {
                next_domain_name,
                types,
            }
        }
        x if x == DnsType::Ds as u16 => {
            let key_tag = read_u16(data, &mut cursor)?;
            let algorithm = read_u8(data, &mut cursor)?;
            let digest_type = read_u8(data, &mut cursor)?;
            Rdata::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest: data[cursor..].to_vec(),
            }
        }
        x if x == DnsType::Nsec3 as u16 => {
            let algorithm = read_u8(data, &mut cursor)?;
            let flags = read_u8(data, &mut cursor)?;
            let iterations = read_u16(data, &mut cursor)?;
            let salt = decode_counted_bytes(data, &mut cursor)?;
            let next_hashed_name = decode_counted_bytes(data, &mut cursor)?;
            let types = decode_type_bitmap(&data[cursor..])?;
            Rdata::Nsec3 {
                types,
                salt,
                next_hashed_name,
                algorithm,
                flags,
                iterations,
            }
        }
        x if x == DnsType::Tlsa as u16 => {
            if data.len() < 3 {
                return Err(ParseError::InvalidRdata("TLSA too short"));
            }
            Rdata::Tlsa {
                cert_usage: data[0],
                selector: data[1],
                matching_type: data[2],
                data: data[3..].to_vec(),
            }
        }
        x if x == DnsType::Svcb as u16 || x == DnsType::Https as u16 => {
            let priority = read_u16(data, &mut cursor)?;
            let target_name = decode_name(data, &mut cursor)?;
            let mut params = Vec::new();
            while cursor < data.len() {
                let key = read_u16(data, &mut cursor)?;
                let len = read_u16(data, &mut cursor)? as usize;
                let end = cursor + len;
                if end > data.len() {
                    return Err(ParseError::UnexpectedEof);
                }
                params.push(DnsSvcParam {
                    key,
                    value: data[cursor..end].to_vec(),
                });
                cursor = end;
            }
            if rr_type == DnsType::Svcb as u16 {
                Rdata::Svcb {
                    priority,
                    target_name,
                    params,
                }
            } else {
                Rdata::Https {
                    priority,
                    target_name,
                    params,
                }
            }
        }
        x if x == DnsType::Caa as u16 => {
            let flags = read_u8(data, &mut cursor)?;
            let tag = String::from_utf8(decode_character_string(data, &mut cursor)?)
                .map_err(|_| ParseError::InvalidRdata("invalid CAA tag"))?;
            Rdata::Caa {
                tag,
                value: data[cursor..].to_vec(),
                flags,
            }
        }
        x if x == DnsType::Naptr as u16 => {
            let order = read_u16(data, &mut cursor)?;
            let preference = read_u16(data, &mut cursor)?;
            let flags = String::from_utf8(decode_character_string(data, &mut cursor)?)
                .map_err(|_| ParseError::InvalidRdata("invalid NAPTR flags"))?;
            let services = String::from_utf8(decode_character_string(data, &mut cursor)?)
                .map_err(|_| ParseError::InvalidRdata("invalid NAPTR services"))?;
            let regexp = String::from_utf8(decode_character_string(data, &mut cursor)?)
                .map_err(|_| ParseError::InvalidRdata("invalid NAPTR regexp"))?;
            let replacement = decode_name(data, &mut cursor)?;
            Rdata::Naptr {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            }
        }
        x if x == DnsType::Opt as u16 => Rdata::Opt(data.to_vec()),
        _ => Rdata::Generic(data.to_vec()),
    };
    Ok(rdata)
}

fn encode_name(name: &str, canonical: bool, out: &mut Vec<u8>) -> Result<(), ParseError> {
    if dns_name_is_root(name) {
        out.push(0);
        return Ok(());
    }
    for label in normalize_name(name)?.split('.') {
        let label = if canonical {
            label.to_ascii_lowercase()
        } else {
            label.to_owned()
        };
        let bytes = label.as_bytes();
        if bytes.len() > 63 {
            return Err(ParseError::InvalidLabel);
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    Ok(())
}

fn decode_name(data: &[u8], cursor: &mut usize) -> Result<String, ParseError> {
    let mut labels = Vec::new();
    loop {
        let len = read_u8(data, cursor)?;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return Err(ParseError::CompressionUnsupported);
        }
        let end = *cursor + len as usize;
        if end > data.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let label =
            std::str::from_utf8(&data[*cursor..end]).map_err(|_| ParseError::InvalidLabel)?;
        if label.is_empty() || label.len() > 63 {
            return Err(ParseError::InvalidLabel);
        }
        labels.push(label.to_owned());
        *cursor = end;
    }
    if labels.is_empty() {
        Ok(".".into())
    } else {
        Ok(labels.join("."))
    }
}

fn encode_character_string(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), ParseError> {
    let len = u8::try_from(bytes.len()).map_err(|_| ParseError::Overflow)?;
    out.push(len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_character_string(data: &[u8], cursor: &mut usize) -> Result<Vec<u8>, ParseError> {
    let len = read_u8(data, cursor)? as usize;
    let end = *cursor + len;
    if end > data.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let bytes = data[*cursor..end].to_vec();
    *cursor = end;
    Ok(bytes)
}

fn encode_counted_bytes(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), ParseError> {
    encode_character_string(bytes, out)
}

fn decode_counted_bytes(data: &[u8], cursor: &mut usize) -> Result<Vec<u8>, ParseError> {
    decode_character_string(data, cursor)
}

fn encode_type_bitmap(types: &BTreeSet<u16>, out: &mut Vec<u8>) -> Result<(), ParseError> {
    let mut by_window = std::collections::BTreeMap::<u8, [u8; 32]>::new();
    for rr_type in types {
        let window = (rr_type / 256) as u8;
        let offset = (rr_type % 256) as usize;
        let octet = offset / 8;
        let bit = 7 - (offset % 8);
        by_window.entry(window).or_insert([0; 32])[octet] |= 1 << bit;
    }
    for (window, bytes) in by_window {
        let len = bytes
            .iter()
            .rposition(|b| *b != 0)
            .map(|p| p + 1)
            .unwrap_or(0);
        if len == 0 {
            continue;
        }
        out.push(window);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    Ok(())
}

fn decode_type_bitmap(data: &[u8]) -> Result<BTreeSet<u16>, ParseError> {
    let mut cursor = 0usize;
    let mut out = BTreeSet::new();
    while cursor < data.len() {
        let window = read_u8(data, &mut cursor)?;
        let len = read_u8(data, &mut cursor)? as usize;
        if len == 0 || len > 32 || cursor + len > data.len() {
            return Err(ParseError::InvalidRdata("invalid type bitmap"));
        }
        for (octet_index, octet) in data[cursor..cursor + len].iter().enumerate() {
            for bit in 0..8 {
                if octet & (1 << (7 - bit)) != 0 {
                    out.insert(u16::from(window) * 256 + (octet_index * 8 + bit) as u16);
                }
            }
        }
        cursor += len;
    }
    Ok(out)
}

fn read_u8(data: &[u8], cursor: &mut usize) -> Result<u8, ParseError> {
    if *cursor >= data.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let v = data[*cursor];
    *cursor += 1;
    Ok(v)
}

fn read_u16(data: &[u8], cursor: &mut usize) -> Result<u16, ParseError> {
    let end = *cursor + 2;
    if end > data.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let v = u16::from_be_bytes(
        data[*cursor..end]
            .try_into()
            .map_err(|_| ParseError::UnexpectedEof)?,
    );
    *cursor = end;
    Ok(v)
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32, ParseError> {
    let end = *cursor + 4;
    if end > data.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let v = u32::from_be_bytes(
        data[*cursor..end]
            .try_into()
            .map_err(|_| ParseError::UnexpectedEof)?,
    );
    *cursor = end;
    Ok(v)
}

fn expect_end(cursor: usize, end: usize) -> Result<(), ParseError> {
    if cursor == end {
        Ok(())
    } else {
        Err(ParseError::InvalidRdata("trailing bytes"))
    }
}
