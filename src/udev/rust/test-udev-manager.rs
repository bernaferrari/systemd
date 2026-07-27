// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/test-udev-manager.c
//
// Small manager lifecycle tests and helpers.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerState {
    pub children_max: u32,
    pub trace: bool,
    pub log_level: i32,
}

pub fn make_test_manager() -> ManagerState {
    ManagerState { children_max: 8, trace: false, log_level: 6 }
}

pub fn reload_manager(state: &ManagerState) -> ManagerState {
    state.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn manager_defaults_are_stable() { let state = make_test_manager(); assert_eq!(state.children_max, 8); assert_eq!(state.log_level, 6); }
    #[test] fn reload_preserves_state() { let state = make_test_manager(); assert_eq!(reload_manager(&state), state); }
}
