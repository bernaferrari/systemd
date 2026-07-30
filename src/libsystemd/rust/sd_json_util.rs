// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-json/json-util.c

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;

#[derive(Clone, Debug, PartialEq)]
pub enum JsonVariant {
    Null,
    Boolean(bool),
    Integer(i64),
    Unsigned(u64),
    Real(f64),
    String(String),
    Array(Vec<JsonVariant>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Iovec {
    pub data: Vec<u8>,
}

pub fn json_dispatch_unhex_iovec(variant: &JsonVariant, out: &mut Iovec) -> Result<()> {
    match variant {
        JsonVariant::Null => {
            out.data.clear();
            Ok(())
        }
        JsonVariant::String(s) => {
            out.data = decode_hex(s)?;
            Ok(())
        }
        _ => Err(NEG_EINVAL),
    }
}

pub fn json_dispatch_unbase64_iovec(variant: &JsonVariant, out: &mut Iovec) -> Result<()> {
    match variant {
        JsonVariant::Null => {
            out.data.clear();
            Ok(())
        }
        JsonVariant::String(s) => {
            out.data = decode_base64(s)?;
            Ok(())
        }
        _ => Err(NEG_EINVAL),
    }
}

pub fn json_dispatch_byte_array_iovec(variant: &JsonVariant, out: &mut Iovec) -> Result<()> {
    match variant {
        JsonVariant::Null => {
            out.data.clear();
            Ok(())
        }
        JsonVariant::Array(items) => {
            let mut data = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    JsonVariant::Unsigned(v) if *v <= u8::MAX as u64 => data.push(*v as u8),
                    _ => return Err(NEG_EINVAL),
                }
            }
            out.data = data;
            Ok(())
        }
        _ => Err(NEG_EINVAL),
    }
}

pub fn json_dispatch_const_user_group_name(
    variant: &JsonVariant,
    relax: bool,
) -> Result<Option<String>> {
    match variant {
        JsonVariant::Null => Ok(None),
        JsonVariant::String(s) if is_valid_user_group_name(s, relax) => Ok(Some(s.clone())),
        _ => Err(NEG_EINVAL),
    }
}

pub fn json_dispatch_const_unit_name(
    variant: &JsonVariant,
    strict: bool,
    relax: bool,
) -> Result<Option<String>> {
    match variant {
        JsonVariant::Null => Ok(None),
        JsonVariant::String(s) if is_valid_unit_name(s, strict, relax) => Ok(Some(s.clone())),
        _ => Err(NEG_EINVAL),
    }
}

pub fn json_dispatch_in_addr(variant: &JsonVariant) -> Result<Ipv4Addr> {
    match variant {
        JsonVariant::Null => Ok(Ipv4Addr::UNSPECIFIED),
        JsonVariant::String(s) => s.parse().map_err(|_| NEG_EINVAL),
        JsonVariant::Array(_) => {
            let mut iov = Iovec::default();
            json_dispatch_byte_array_iovec(variant, &mut iov)?;
            let bytes: [u8; 4] = iov.data.try_into().map_err(|_| NEG_EINVAL)?;
            Ok(Ipv4Addr::from(bytes))
        }
        _ => Err(NEG_EINVAL),
    }
}

pub fn json_dispatch_in6_addr(variant: &JsonVariant) -> Result<Ipv6Addr> {
    match variant {
        JsonVariant::Null => Ok(Ipv6Addr::UNSPECIFIED),
        JsonVariant::String(s) => s.parse().map_err(|_| NEG_EINVAL),
        JsonVariant::Array(_) => {
            let mut iov = Iovec::default();
            json_dispatch_byte_array_iovec(variant, &mut iov)?;
            let bytes: [u8; 16] = iov.data.try_into().map_err(|_| NEG_EINVAL)?;
            Ok(Ipv6Addr::from(bytes))
        }
        _ => Err(NEG_EINVAL),
    }
}

pub fn json_dispatch_const_path(variant: &JsonVariant) -> Result<Option<PathBuf>> {
    match variant {
        JsonVariant::Null => Ok(None),
        JsonVariant::String(s) if Path::new(s).is_absolute() => Ok(Some(PathBuf::from(s))),
        _ => Err(NEG_EINVAL),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(NEG_EINVAL);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        out.push((hex_value(pair[0])? << 4) | hex_value(pair[1])?);
    }
    Ok(out)
}

fn decode_base64(s: &str) -> Result<Vec<u8>> {
    let mut sextets = Vec::new();
    for b in s.bytes().filter(|b| !b.is_ascii_whitespace()) {
        match b {
            b'=' => break,
            _ => sextets.push(base64_value(b)?),
        }
    }

    let mut out = Vec::new();
    for chunk in sextets.chunks(4) {
        if chunk.len() < 2 {
            return Err(NEG_EINVAL);
        }
        let a = chunk[0] as u32;
        let b = chunk[1] as u32;
        out.push(((a << 2) | (b >> 4)) as u8);
        if chunk.len() > 2 {
            let c = chunk[2] as u32;
            out.push((((b & 0x0f) << 4) | (c >> 2)) as u8);
            if chunk.len() > 3 {
                let d = chunk[3] as u32;
                out.push((((c & 0x03) << 6) | d) as u8);
            }
        }
    }
    Ok(out)
}

fn hex_value(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(NEG_EINVAL),
    }
}

fn base64_value(b: u8) -> Result<u8> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(NEG_EINVAL),
    }
}

fn is_valid_user_group_name(name: &str, relax: bool) -> bool {
    !name.is_empty()
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') || (relax && c == '@')
        })
}

fn is_valid_unit_name(name: &str, strict: bool, relax: bool) -> bool {
    if name.is_empty() || !name.contains('.') {
        return false;
    }
    let valid_chars =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | ':');
    if !name.chars().all(valid_chars) {
        return false;
    }
    if strict {
        !name.contains('@')
    } else if relax {
        true
    } else {
        !name.starts_with('.')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hex_into_iovec() {
        let mut out = Iovec::default();
        json_dispatch_unhex_iovec(&JsonVariant::String("4142".into()), &mut out).unwrap();
        assert_eq!(out.data, b"AB");
    }

    #[test]
    fn decodes_base64_into_iovec() {
        let mut out = Iovec::default();
        json_dispatch_unbase64_iovec(&JsonVariant::String("QUI=".into()), &mut out).unwrap();
        assert_eq!(out.data, b"AB");
    }

    #[test]
    fn converts_byte_array_to_iovec() {
        let mut out = Iovec::default();
        json_dispatch_byte_array_iovec(
            &JsonVariant::Array(vec![JsonVariant::Unsigned(1), JsonVariant::Unsigned(255)]),
            &mut out,
        )
        .unwrap();
        assert_eq!(out.data, vec![1, 255]);
    }

    #[test]
    fn validates_user_group_names() {
        assert_eq!(
            json_dispatch_const_user_group_name(&JsonVariant::String("systemd".into()), false)
                .unwrap(),
            Some("systemd".into())
        );
    }

    #[test]
    fn validates_unit_names() {
        assert_eq!(
            json_dispatch_const_unit_name(&JsonVariant::String("sshd.service".into()), true, false)
                .unwrap(),
            Some("sshd.service".into())
        );
    }

    #[test]
    fn parses_ipv4_from_string() {
        assert_eq!(
            json_dispatch_in_addr(&JsonVariant::String("127.0.0.1".into())).unwrap(),
            Ipv4Addr::LOCALHOST
        );
    }

    #[test]
    fn parses_ipv6_from_bytes() {
        let bytes = (0u64..16).map(JsonVariant::Unsigned).collect::<Vec<_>>();
        assert_eq!(
            json_dispatch_in6_addr(&JsonVariant::Array(bytes))
                .unwrap()
                .octets()[15],
            15
        );
    }

    #[test]
    fn parses_absolute_path() {
        assert_eq!(
            json_dispatch_const_path(&JsonVariant::String("/etc/machine-id".into())).unwrap(),
            Some(PathBuf::from("/etc/machine-id"))
        );
    }

    #[test]
    fn rejects_invalid_path() {
        assert_eq!(
            json_dispatch_const_path(&JsonVariant::String("relative".into())),
            Err(NEG_EINVAL)
        );
    }

    #[test]
    fn null_variants_reset_outputs() {
        let mut out = Iovec {
            data: vec![1, 2, 3],
        };
        json_dispatch_unhex_iovec(&JsonVariant::Null, &mut out).unwrap();
        assert!(out.data.is_empty());
    }
}
