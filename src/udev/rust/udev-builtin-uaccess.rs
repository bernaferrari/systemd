// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-uaccess.c
//
// Access-tag resolution.

use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAccessProfile {
    pub seat: String,
    pub tags: BTreeSet<String>,
}

pub fn compute_uaccess_tags(
    seat: &str,
    active_session: bool,
    requires_acl: bool,
) -> DeviceAccessProfile {
    let mut tags = BTreeSet::new();
    if active_session && requires_acl {
        tags.insert("uaccess".into());
    }
    if seat != "seat0" {
        tags.insert(format!("seat:{}", seat));
    }
    DeviceAccessProfile {
        seat: seat.into(),
        tags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grants_uaccess_when_session_is_active() {
        let profile = compute_uaccess_tags("seat0", true, true);
        assert!(profile.tags.contains("uaccess"));
    }
    #[test]
    fn adds_nondefault_seat_tag() {
        let profile = compute_uaccess_tags("seat1", false, false);
        assert!(profile.tags.contains("seat:seat1"));
    }
}
