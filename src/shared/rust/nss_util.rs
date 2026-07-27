// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/nss-util.c, src/shared/nss-util.h

use std::fmt;

// ── NSS status enum ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum NssStatus {
    Tryagain = -2,
    Unavail = -1,
    Notfound = 0,
    Success = 1,
    Return = 2,
}

impl NssStatus {
    pub fn from_i32(v: i32) -> Self {
        match v {
            -2 => Self::Tryagain,
            -1 => Self::Unavail,
            0 => Self::Notfound,
            1 => Self::Success,
            2 => Self::Return,
            _ => Self::Unavail,
        }
    }

    pub fn to_errno(self) -> i32 {
        match self {
            Self::Success | Self::Return => 0,
            Self::Notfound => libc::ESRCH,
            Self::Tryagain => libc::EAGAIN,
            Self::Unavail => libc::EADDRNOTAVAIL,
        }
    }

    pub fn from_errno(errno: i32) -> Self {
        match errno {
            0 => Self::Success,
            libc::ESRCH => Self::Notfound,
            libc::EAGAIN => Self::Tryagain,
            libc::EADDRNOTAVAIL => Self::Unavail,
            _ => Self::Unavail,
        }
    }
}

impl fmt::Display for NssStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "SUCCESS"),
            Self::Notfound => write!(f, "NOTFOUND"),
            Self::Tryagain => write!(f, "TRYAGAIN"),
            Self::Unavail => write!(f, "UNAVAIL"),
            Self::Return => write!(f, "RETURN"),
        }
    }
}

// ── Compatibility constants ────────────────────────────────────────────────

pub const NSS_STATUS_TRYAGAIN: i32 = NssStatus::Tryagain as i32;
pub const NSS_STATUS_UNAVAIL: i32 = NssStatus::Unavail as i32;
pub const NSS_STATUS_NOTFOUND: i32 = NssStatus::Notfound as i32;
pub const NSS_STATUS_SUCCESS: i32 = NssStatus::Success as i32;
pub const NSS_STATUS_RETURN: i32 = NssStatus::Return as i32;

pub const DEPRECATED_RES_USE_INET6: u32 = 0x00002000;

// ── Conversion functions (legacy API) ──────────────────────────────────────

pub fn nss_status_to_errno(status: i32) -> i32 {
    NssStatus::from_i32(status).to_errno()
}

pub fn errno_to_nss_status(errno: i32) -> i32 {
    NssStatus::from_errno(errno) as i32
}

// ── Logging setup ──────────────────────────────────────────────────────────

pub fn log_setup_nss() {
    // Rust port: logging is handled via log/tracing crate, no openlog needed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nss_status_constants() {
        assert_eq!(NSS_STATUS_TRYAGAIN, -2);
        assert_eq!(NSS_STATUS_UNAVAIL, -1);
        assert_eq!(NSS_STATUS_NOTFOUND, 0);
        assert_eq!(NSS_STATUS_SUCCESS, 1);
        assert_eq!(NSS_STATUS_RETURN, 2);
    }

    #[test]
    fn test_enum_values() {
        assert_eq!(NssStatus::Tryagain as i32, -2);
        assert_eq!(NssStatus::Unavail as i32, -1);
        assert_eq!(NssStatus::Notfound as i32, 0);
        assert_eq!(NssStatus::Success as i32, 1);
        assert_eq!(NssStatus::Return as i32, 2);
    }

    #[test]
    fn test_from_i32() {
        assert_eq!(NssStatus::from_i32(-2), NssStatus::Tryagain);
        assert_eq!(NssStatus::from_i32(-1), NssStatus::Unavail);
        assert_eq!(NssStatus::from_i32(0), NssStatus::Notfound);
        assert_eq!(NssStatus::from_i32(1), NssStatus::Success);
        assert_eq!(NssStatus::from_i32(2), NssStatus::Return);
    }

    #[test]
    fn test_from_i32_unknown() {
        assert_eq!(NssStatus::from_i32(99), NssStatus::Unavail);
        assert_eq!(NssStatus::from_i32(-99), NssStatus::Unavail);
    }

    #[test]
    fn test_to_errno() {
        assert_eq!(NssStatus::Success.to_errno(), 0);
        assert_eq!(NssStatus::Return.to_errno(), 0);
        assert_eq!(NssStatus::Notfound.to_errno(), libc::ESRCH);
        assert_eq!(NssStatus::Tryagain.to_errno(), libc::EAGAIN);
        assert_eq!(NssStatus::Unavail.to_errno(), libc::EADDRNOTAVAIL);
    }

    #[test]
    fn test_from_errno() {
        assert_eq!(NssStatus::from_errno(0), NssStatus::Success);
        assert_eq!(NssStatus::from_errno(libc::ESRCH), NssStatus::Notfound);
        assert_eq!(NssStatus::from_errno(libc::EAGAIN), NssStatus::Tryagain);
        assert_eq!(
            NssStatus::from_errno(libc::EADDRNOTAVAIL),
            NssStatus::Unavail
        );
    }

    #[test]
    fn test_from_errno_unknown() {
        assert_eq!(NssStatus::from_errno(libc::ENOENT), NssStatus::Unavail);
    }

    #[test]
    fn test_legacy_nss_status_to_errno() {
        assert_eq!(nss_status_to_errno(NSS_STATUS_SUCCESS), 0);
        assert_eq!(nss_status_to_errno(NSS_STATUS_NOTFOUND), libc::ESRCH);
        assert_eq!(nss_status_to_errno(NSS_STATUS_TRYAGAIN), libc::EAGAIN);
        assert_eq!(nss_status_to_errno(NSS_STATUS_UNAVAIL), libc::EADDRNOTAVAIL);
    }

    #[test]
    fn test_legacy_errno_to_nss_status() {
        assert_eq!(errno_to_nss_status(0), NSS_STATUS_SUCCESS);
        assert_eq!(errno_to_nss_status(libc::ESRCH), NSS_STATUS_NOTFOUND);
        assert_eq!(errno_to_nss_status(libc::EAGAIN), NSS_STATUS_TRYAGAIN);
    }

    #[test]
    fn test_roundtrip() {
        for status in [
            NssStatus::Success,
            NssStatus::Notfound,
            NssStatus::Tryagain,
            NssStatus::Unavail,
        ] {
            let errno = status.to_errno();
            let back = NssStatus::from_errno(errno);
            assert_eq!(status, back, "roundtrip failed for {status}");
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", NssStatus::Success), "SUCCESS");
        assert_eq!(format!("{}", NssStatus::Notfound), "NOTFOUND");
        assert_eq!(format!("{}", NssStatus::Tryagain), "TRYAGAIN");
        assert_eq!(format!("{}", NssStatus::Unavail), "UNAVAIL");
        assert_eq!(format!("{}", NssStatus::Return), "RETURN");
    }

    #[test]
    fn test_deprecated_res_use_inet6() {
        assert_eq!(DEPRECATED_RES_USE_INET6, 0x00002000);
    }
}
