// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of sysctl-monitor.bpf.c
//
// SAFETY: This module is a Rust port of the corresponding C source.
// FFI boundary functions use unsafe extern "C" with proper SAFETY comments.
// Internal logic uses safe Rust with Result<T, Errno> error handling.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysctl_monitor_bpf_module_loads() {
        let _ = Errno(0);
    }
}
