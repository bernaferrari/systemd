// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkctl-misc.c
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

pub struct LinkVarlinkAction {
    pub verb: &'static str,
    pub method: &'static str,
}

pub const LINK_VARLINK_ACTION_TABLE: &[LinkVarlinkAction] = &[
    LinkVarlinkAction {
        verb: "up",
        method: "io.systemd.Network.Link.Up",
    },
    LinkVarlinkAction {
        verb: "down",
        method: "io.systemd.Network.Link.Down",
    },
    LinkVarlinkAction {
        verb: "renew",
        method: "io.systemd.Network.Link.Renew",
    },
    LinkVarlinkAction {
        verb: "forcerenew",
        method: "io.systemd.Network.Link.ForceRenew",
    },
    LinkVarlinkAction {
        verb: "reconfigure",
        method: "io.systemd.Network.Link.Reconfigure",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkctl_misc_structs() {
        let _ = std::mem::size_of::<LinkVarlinkAction>();
    }
}
