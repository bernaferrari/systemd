// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-target.c
//
// Target units are synchronization points (empty D-Bus vtable in C).
// No Target-specific D-Bus properties — everything comes from Unit base.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetState {
    pub id: String,
}

impl TargetState {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_state_new() {
        let t = TargetState::new("multi-user.target");
        assert_eq!(t.id, "multi-user.target");
    }
}
