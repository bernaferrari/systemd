// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-error.c
//
// Udev-specific error normalization.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdevError {
    InvalidArgument,
    NotFound,
    Busy,
    Other(i32),
}

pub fn classify_errno(errno: i32) -> UdevError {
    match errno {
        -22 => UdevError::InvalidArgument,
        -2 => UdevError::NotFound,
        -16 => UdevError::Busy,
        other => UdevError::Other(other),
    }
}

pub fn errno_message(error: UdevError) -> &'static str {
    match error {
        UdevError::InvalidArgument => "invalid argument",
        UdevError::NotFound => "not found",
        UdevError::Busy => "resource busy",
        UdevError::Other(_) => "udev error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_common_errno_values() {
        assert_eq!(classify_errno(-22), UdevError::InvalidArgument);
        assert_eq!(classify_errno(-2), UdevError::NotFound);
    }
    #[test]
    fn formats_messages() {
        assert_eq!(errno_message(UdevError::Busy), "resource busy");
    }
}
