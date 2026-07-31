// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-bus/bus-match.c, src/libsystemd/sd-bus/bus-match.h

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BusMatchNodeType(i32);

#[allow(non_upper_case_globals)]
impl BusMatchNodeType {
    pub const Root: Self = Self(0);
    pub const Value: Self = Self(1);
    pub const Leaf: Self = Self(2);
    pub const Sender: Self = Self(3);
    pub const MessageType: Self = Self(4);
    pub const Destination: Self = Self(5);
    pub const Interface: Self = Self(6);
    pub const Member: Self = Self(7);
    pub const Path: Self = Self(8);
    pub const PathNamespace: Self = Self(9);
    pub const Arg: Self = Self(10);
    pub const ArgLast: Self = Self(73);
    pub const ArgPath: Self = Self(74);
    pub const ArgPathLast: Self = Self(137);
    pub const ArgNamespace: Self = Self(138);
    pub const ArgNamespaceLast: Self = Self(201);
    pub const ArgHas: Self = Self(202);
    pub const ArgHasLast: Self = Self(265);

    const fn raw(self) -> i32 {
        self.0
    }

    fn from_raw(value: i32) -> Result<Self> {
        if (Self::Root.raw()..=Self::ArgHasLast.raw()).contains(&value) {
            Ok(Self(value))
        } else {
            Err(NEG_EINVAL)
        }
    }

    pub fn is_compare(self) -> bool {
        matches!(
            self.raw(),
            x if x >= Self::Sender.raw() && x <= Self::ArgHasLast.raw()
        )
    }

    pub fn can_hash(self) -> bool {
        matches!(
            self.raw(),
            x if (x >= Self::MessageType.raw() && x <= Self::Path.raw())
                || (x >= Self::Arg.raw() && x <= Self::ArgLast.raw())
                || (x >= Self::ArgHas.raw() && x <= Self::ArgHasLast.raw())
        )
    }
}

pub fn bus_match_node_type_from_string(key: &str) -> Result<BusMatchNodeType> {
    match key {
        "type" => return Ok(BusMatchNodeType::MessageType),
        "sender" => return Ok(BusMatchNodeType::Sender),
        "destination" => return Ok(BusMatchNodeType::Destination),
        "interface" => return Ok(BusMatchNodeType::Interface),
        "member" => return Ok(BusMatchNodeType::Member),
        "path" => return Ok(BusMatchNodeType::Path),
        "path_namespace" => return Ok(BusMatchNodeType::PathNamespace),
        _ => {}
    }

    parse_arg_family(key)
}

pub fn bus_match_node_type_to_string(node_type: BusMatchNodeType) -> Result<String> {
    match node_type.raw() {
        0 => Ok("root".into()),
        1 => Ok("value".into()),
        2 => Ok("leaf".into()),
        3 => Ok("sender".into()),
        4 => Ok("type".into()),
        5 => Ok("destination".into()),
        6 => Ok("interface".into()),
        7 => Ok("member".into()),
        8 => Ok("path".into()),
        9 => Ok("path_namespace".into()),
        value => format_arg_family(value),
    }
}

fn parse_arg_family(key: &str) -> Result<BusMatchNodeType> {
    for (base, suffix) in [
        (BusMatchNodeType::Arg.raw(), ""),
        (BusMatchNodeType::ArgPath.raw(), "path"),
        (BusMatchNodeType::ArgNamespace.raw(), "namespace"),
        (BusMatchNodeType::ArgHas.raw(), "has"),
    ] {
        if let Some(index) = key
            .strip_prefix("arg")
            .and_then(|rest| rest.strip_suffix(suffix))
            && let Ok(value) = parse_arg_index(index)
        {
            return BusMatchNodeType::from_raw(base + value);
        }
    }

    Err(NEG_EINVAL)
}

fn parse_arg_index(index: &str) -> Result<i32> {
    match index.as_bytes() {
        [digit] if digit.is_ascii_digit() => Ok((*digit - b'0') as i32),
        [first, second] if first.is_ascii_digit() && second.is_ascii_digit() && *first != b'0' => {
            let value = (((*first - b'0') as i32) * 10) + ((*second - b'0') as i32);
            if value <= 63 {
                Ok(value)
            } else {
                Err(NEG_EINVAL)
            }
        }
        _ => Err(NEG_EINVAL),
    }
}

fn format_arg_family(value: i32) -> Result<String> {
    if (BusMatchNodeType::Arg.raw()..=BusMatchNodeType::ArgLast.raw()).contains(&value) {
        return Ok(format!("arg{}", value - BusMatchNodeType::Arg.raw()));
    }
    if (BusMatchNodeType::ArgPath.raw()..=BusMatchNodeType::ArgPathLast.raw()).contains(&value) {
        return Ok(format!(
            "arg{}path",
            value - BusMatchNodeType::ArgPath.raw()
        ));
    }
    if (BusMatchNodeType::ArgNamespace.raw()..=BusMatchNodeType::ArgNamespaceLast.raw())
        .contains(&value)
    {
        return Ok(format!(
            "arg{}namespace",
            value - BusMatchNodeType::ArgNamespace.raw()
        ));
    }
    if (BusMatchNodeType::ArgHas.raw()..=BusMatchNodeType::ArgHasLast.raw()).contains(&value) {
        return Ok(format!("arg{}has", value - BusMatchNodeType::ArgHas.raw()));
    }

    Err(NEG_EINVAL)
}

fn int_to_node_type(value: i32) -> Result<BusMatchNodeType> {
    BusMatchNodeType::from_raw(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixed_node_types() {
        assert_eq!(
            bus_match_node_type_from_string("type"),
            Ok(BusMatchNodeType::MessageType)
        );
    }

    #[test]
    fn parses_and_formats_arg_variants() {
        for (key, raw) in [
            ("arg0", 10),
            ("arg9", 19),
            ("arg10", 20),
            ("arg63", 73),
            ("arg0path", 74),
            ("arg9path", 83),
            ("arg63path", 137),
            ("arg0namespace", 138),
            ("arg9namespace", 147),
            ("arg63namespace", 201),
            ("arg0has", 202),
            ("arg9has", 211),
            ("arg63has", 265),
        ] {
            let node_type = int_to_node_type(raw).unwrap();
            assert_eq!(bus_match_node_type_from_string(key), Ok(node_type));
            assert_eq!(bus_match_node_type_to_string(node_type), Ok(key.into()));
        }
    }

    #[test]
    fn rejects_invalid_arg_variants() {
        for key in [
            "arg",
            "arg00",
            "arg01",
            "arg64",
            "arg000",
            "arg0pathx",
            "arg00path",
            "arg01path",
            "arg64path",
            "arg0namespacex",
            "arg00namespace",
            "arg01namespace",
            "arg64namespace",
            "arg0hasx",
            "arg00has",
            "arg01has",
            "arg64has",
            "argX",
        ] {
            assert_eq!(
                bus_match_node_type_from_string(key),
                Err(NEG_EINVAL),
                "key: {key}"
            );
        }

        assert_eq!(int_to_node_type(-1), Err(NEG_EINVAL));
        assert_eq!(int_to_node_type(266), Err(NEG_EINVAL));
    }

    #[test]
    fn rejects_internal_node_labels_as_match_keys() {
        for key in ["root", "value", "leaf"] {
            assert_eq!(bus_match_node_type_from_string(key), Err(NEG_EINVAL));
        }
    }

    #[test]
    fn formats_fixed_node_types() {
        assert_eq!(
            bus_match_node_type_to_string(BusMatchNodeType::Sender),
            Ok("sender".into())
        );
    }

    #[test]
    fn formats_arg_variants() {
        assert_eq!(
            bus_match_node_type_to_string(BusMatchNodeType::Arg),
            Ok("arg0".into())
        );
        assert_eq!(
            bus_match_node_type_to_string(int_to_node_type(74).unwrap()),
            Ok("arg0path".into())
        );
        assert_eq!(
            bus_match_node_type_to_string(int_to_node_type(201).unwrap()),
            Ok("arg63namespace".into())
        );
    }

    #[test]
    fn identifies_compare_nodes() {
        assert!(BusMatchNodeType::Sender.is_compare());
        assert!(!BusMatchNodeType::Leaf.is_compare());
    }

    #[test]
    fn identifies_hashable_nodes() {
        assert!(BusMatchNodeType::MessageType.can_hash());
        assert!(int_to_node_type(202).unwrap().can_hash());
        assert!(!BusMatchNodeType::PathNamespace.can_hash());
    }

    #[test]
    fn rejects_unknown_node_type() {
        assert_eq!(bus_match_node_type_from_string("bogus"), Err(NEG_EINVAL));
    }
}
