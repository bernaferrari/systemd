// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn-stub-pid1.c

use crate::common::{Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/nspawn/nspawn-stub-pid1.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &["reset_environ", "stub_pid1"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubState {
    Running,
    Reboot,
    Poweroff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvironmentWindow {
    pub start: usize,
    pub end: usize,
}

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn_stub_pid1",
        source_path: SOURCE_PATH,
        source_lines: 199,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}

pub fn reset_environ(new_environment: &str) -> Result<EnvironmentWindow, Errno> {
    Ok(EnvironmentWindow {
        start: 0,
        end: new_environment.len(),
    })
}

pub fn stub_pid1_next_state(state: StubState, signo: i32) -> Result<StubState, Errno> {
    if state != StubState::Running {
        return Ok(state);
    }

    match signo {
        2 | 39 | 40 | 49 | 50 => Ok(StubState::Reboot),
        37 | 38 | 47 | 48 => Ok(StubState::Poweroff),
        17 => Ok(StubState::Running),
        _ => Err(Errno::new(-22)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_environ_tracks_new_window() {
        let window = reset_environ("container=systemd-nspawn\0").unwrap();
        assert_eq!(window.end, 25);
    }

    #[test]
    fn reboot_signals_switch_state() {
        assert_eq!(
            stub_pid1_next_state(StubState::Running, 2).unwrap(),
            StubState::Reboot
        );
    }
}
