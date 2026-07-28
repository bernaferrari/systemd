// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-net_id.c
//
// Predictable network interface naming helpers.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetTopology {
    pub prefix: String,
    pub onboard_index: Option<u32>,
    pub slot: Option<String>,
    pub path_id: Option<String>,
    pub mac_address: Option<[u8; 6]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetIdError {
    EmptyPrefix,
    MissingTopology,
}
pub type Result<T> = std::result::Result<T, NetIdError>;

pub fn stable_interface_name(topology: &NetTopology) -> Result<String> {
    if topology.prefix.trim().is_empty() {
        return Err(NetIdError::EmptyPrefix);
    }
    if let Some(index) = topology.onboard_index {
        return Ok(format!("{}o{}", topology.prefix, index));
    }
    if let Some(slot) = &topology.slot {
        return Ok(format!("{}s{}", topology.prefix, slot));
    }
    if let Some(path) = &topology.path_id {
        return Ok(format!("{}p{}", topology.prefix, sanitize_component(path)));
    }
    if let Some(mac) = topology.mac_address {
        return Ok(format!("{}x{}", topology.prefix, format_mac(mac)));
    }
    Err(NetIdError::MissingTopology)
}

fn sanitize_component(component: &str) -> String {
    component
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.into_iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prefers_onboard_index() {
        let topology = NetTopology {
            prefix: "en".into(),
            onboard_index: Some(3),
            slot: Some("1".into()),
            path_id: None,
            mac_address: None,
        };
        assert_eq!(stable_interface_name(&topology).unwrap(), "eno3");
    }
    #[test]
    fn falls_back_to_slot() {
        let topology = NetTopology {
            prefix: "en".into(),
            onboard_index: None,
            slot: Some("5".into()),
            path_id: None,
            mac_address: None,
        };
        assert_eq!(stable_interface_name(&topology).unwrap(), "ens5");
    }
    #[test]
    fn falls_back_to_path() {
        let topology = NetTopology {
            prefix: "en".into(),
            onboard_index: None,
            slot: None,
            path_id: Some("0000:00:1f.6".into()),
            mac_address: None,
        };
        assert_eq!(stable_interface_name(&topology).unwrap(), "enp0000001f6");
    }
    #[test]
    fn falls_back_to_mac() {
        let topology = NetTopology {
            prefix: "wl".into(),
            onboard_index: None,
            slot: None,
            path_id: None,
            mac_address: Some([0, 17, 34, 51, 68, 85]),
        };
        assert_eq!(stable_interface_name(&topology).unwrap(), "wlx001122334455");
    }
    #[test]
    fn rejects_missing_topology() {
        let topology = NetTopology {
            prefix: "en".into(),
            onboard_index: None,
            slot: None,
            path_id: None,
            mac_address: None,
        };
        assert_eq!(
            stable_interface_name(&topology),
            Err(NetIdError::MissingTopology)
        );
    }
}
