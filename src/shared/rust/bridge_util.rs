// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bridge-util.c, src/shared/bridge-util.h
//
// Network bridge state string table lookups.

// ── Enums ─────────────────────────────────────────────────────────────────

/// Bridge port states (matches `BR_STATE_*` from linux/if_bridge.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeState {
    Disabled = 0,
    Listening = 1,
    Learning = 2,
    Forwarding = 3,
    Blocking = 4,
}

impl BridgeState {
    /// Sentinel for invalid / unknown states.
    pub const INVALID: i32 = -22; // -EINVAL

    /// Number of states that have a string representation in the table.
    pub const TABLE_LEN: usize = 4;
}

impl std::fmt::Display for BridgeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match bridge_state_to_string(*self) {
            Some(s) => write!(f, "{s}"),
            None => write!(f, "unknown({})", *self as i32),
        }
    }
}

impl std::str::FromStr for BridgeState {
    type Err = i32;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bridge_state_from_string(s).ok_or(Self::INVALID)
    }
}

// ── String table ──────────────────────────────────────────────────────────

static BRIDGE_STATE_TABLE: &[(BridgeState, &str)] = &[
    (BridgeState::Disabled, "disabled"),
    (BridgeState::Listening, "listening"),
    (BridgeState::Learning, "learning"),
    (BridgeState::Forwarding, "forwarding"),
];

// ── Public API ────────────────────────────────────────────────────────────

/// Convert a [`BridgeState`] to its string representation.
///
/// Returns `None` for states without a defined string (e.g. `Blocking`).
pub fn bridge_state_to_string(state: BridgeState) -> Option<&'static str> {
    BRIDGE_STATE_TABLE
        .iter()
        .find(|&&(s, _)| s == state)
        .map(|&(_, name)| name)
}

/// Parse a bridge state from a string.
///
/// Case-sensitive. Returns `None` for unrecognised inputs.
pub fn bridge_state_from_string(s: &str) -> Option<BridgeState> {
    BRIDGE_STATE_TABLE
        .iter()
        .find(|&&(_, name)| name == s)
        .map(|&(state, _)| state)
}

/// Number of valid entries in the bridge state table.
pub fn bridge_state_table_len() -> usize {
    BRIDGE_STATE_TABLE.len()
}

/// Iterate over all (state, name) pairs in the table.
pub fn bridge_state_table_iter() -> impl Iterator<Item = (BridgeState, &'static str)> {
    BRIDGE_STATE_TABLE.iter().copied()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_string_disabled() {
        assert_eq!(
            bridge_state_to_string(BridgeState::Disabled),
            Some("disabled")
        );
    }

    #[test]
    fn to_string_listening() {
        assert_eq!(
            bridge_state_to_string(BridgeState::Listening),
            Some("listening")
        );
    }

    #[test]
    fn to_string_learning() {
        assert_eq!(
            bridge_state_to_string(BridgeState::Learning),
            Some("learning")
        );
    }

    #[test]
    fn to_string_forwarding() {
        assert_eq!(
            bridge_state_to_string(BridgeState::Forwarding),
            Some("forwarding")
        );
    }

    #[test]
    fn to_string_blocking_is_none() {
        assert_eq!(bridge_state_to_string(BridgeState::Blocking), None);
    }

    #[test]
    fn from_string_disabled() {
        assert_eq!(
            bridge_state_from_string("disabled"),
            Some(BridgeState::Disabled)
        );
    }

    #[test]
    fn from_string_listening() {
        assert_eq!(
            bridge_state_from_string("listening"),
            Some(BridgeState::Listening)
        );
    }

    #[test]
    fn from_string_learning() {
        assert_eq!(
            bridge_state_from_string("learning"),
            Some(BridgeState::Learning)
        );
    }

    #[test]
    fn from_string_forwarding() {
        assert_eq!(
            bridge_state_from_string("forwarding"),
            Some(BridgeState::Forwarding)
        );
    }

    #[test]
    fn from_string_unknown_returns_none() {
        assert_eq!(bridge_state_from_string("blocking"), None);
        assert_eq!(bridge_state_from_string("unknown"), None);
        assert_eq!(bridge_state_from_string(""), None);
    }

    #[test]
    fn from_string_is_case_sensitive() {
        assert_eq!(bridge_state_from_string("Disabled"), None);
        assert_eq!(bridge_state_from_string("DISABLED"), None);
    }

    #[test]
    fn from_str_trait_valid() {
        use std::str::FromStr;
        assert_eq!(
            BridgeState::from_str("forwarding"),
            Ok(BridgeState::Forwarding)
        );
    }

    #[test]
    fn from_str_trait_invalid() {
        use std::str::FromStr;
        assert_eq!(BridgeState::from_str("nope"), Err(BridgeState::INVALID));
    }

    #[test]
    fn display_trait_valid_state() {
        assert_eq!(format!("{}", BridgeState::Learning), "learning");
    }

    #[test]
    fn display_trait_unknown_state() {
        assert_eq!(format!("{}", BridgeState::Blocking), "unknown(4)");
    }

    #[test]
    fn table_len_matches_constant() {
        assert_eq!(bridge_state_table_len(), BridgeState::TABLE_LEN);
        assert_eq!(bridge_state_table_len(), 4);
    }

    #[test]
    fn table_iter_roundtrip() {
        for (state, name) in bridge_state_table_iter() {
            assert_eq!(bridge_state_to_string(state), Some(name));
            assert_eq!(bridge_state_from_string(name), Some(state));
        }
    }

    #[test]
    fn enum_discriminant_values() {
        assert_eq!(BridgeState::Disabled as i32, 0);
        assert_eq!(BridgeState::Listening as i32, 1);
        assert_eq!(BridgeState::Learning as i32, 2);
        assert_eq!(BridgeState::Forwarding as i32, 3);
        assert_eq!(BridgeState::Blocking as i32, 4);
    }

    #[test]
    fn table_is_sorted_by_discriminant() {
        let entries: Vec<_> = bridge_state_table_iter().collect();
        for window in entries.windows(2) {
            assert!((window[0].0 as i32) < (window[1].0 as i32));
        }
    }
}
