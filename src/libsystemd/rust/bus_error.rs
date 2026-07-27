// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: conservative Rust shadow of src/libsystemd/sd-bus/bus-error.c

use libc::c_char;

/// Standard D-Bus error name constants.
pub const SD_BUS_ERROR_FAILED: &[u8] = b"org.freedesktop.DBus.Error.Failed";
pub const SD_BUS_ERROR_NO_MEMORY: &[u8] = b"org.freedesktop.DBus.Error.NoMemory";
pub const SD_BUS_ERROR_SERVICE_UNKNOWN: &[u8] = b"org.freedesktop.DBus.Error.ServiceUnknown";
pub const SD_BUS_ERROR_NAME_HAS_NO_OWNER: &[u8] = b"org.freedesktop.DBus.Error.NameHasNoOwner";
pub const SD_BUS_ERROR_NO_REPLY: &[u8] = b"org.freedesktop.DBus.Error.NoReply";
pub const SD_BUS_ERROR_IO_ERROR: &[u8] = b"org.freedesktop.DBus.Error.IOError";
pub const SD_BUS_ERROR_ACCESS_DENIED: &[u8] = b"org.freedesktop.DBus.Error.AccessDenied";
pub const SD_BUS_ERROR_AUTH_FAILED: &[u8] = b"org.freedesktop.DBus.Error.AuthFailed";
pub const SD_BUS_ERROR_TIMEOUT: &[u8] = b"org.freedesktop.DBus.Error.Timeout";
pub const SD_BUS_ERROR_NO_SERVER: &[u8] = b"org.freedesktop.DBus.Error.NoServer";
pub const SD_BUS_ERROR_NO_NETWORK: &[u8] = b"org.freedesktop.DBus.Error.NoNetwork";
pub const SD_BUS_ERROR_DISCONNECTED: &[u8] = b"org.freedesktop.DBus.Error.Disconnected";
pub const SD_BUS_ERROR_INVALID_ARGS: &[u8] = b"org.freedesktop.DBus.Error.InvalidArgs";
pub const SD_BUS_ERROR_FILE_NOT_FOUND: &[u8] = b"org.freedesktop.DBus.Error.FileNotFound";
pub const SD_BUS_ERROR_FILE_EXISTS: &[u8] = b"org.freedesktop.DBus.Error.FileExists";
pub const SD_BUS_ERROR_UNKNOWN_METHOD: &[u8] = b"org.freedesktop.DBus.Error.UnknownMethod";
pub const SD_BUS_ERROR_UNKNOWN_OBJECT: &[u8] = b"org.freedesktop.DBus.Error.UnknownObject";
pub const SD_BUS_ERROR_UNKNOWN_INTERFACE: &[u8] = b"org.freedesktop.DBus.Error.UnknownInterface";
pub const SD_BUS_ERROR_UNKNOWN_PROPERTY: &[u8] = b"org.freedesktop.DBus.Error.UnknownProperty";
pub const SD_BUS_ERROR_PROPERTY_READ_ONLY: &[u8] = b"org.freedesktop.DBus.Error.PropertyReadOnly";
pub const SD_BUS_ERROR_NOT_SUPPORTED: &[u8] = b"org.freedesktop.DBus.Error.NotSupported";

/// Opaque D-Bus error structure, matching the C layout.
///
/// SAFETY: This type is only used through FFI from C code that manages
/// the lifetime and initialization of the struct.
#[repr(C)]
pub struct SdBusError {
    pub name: *const c_char,
    pub message: *const c_char,
    pub _need_free: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_name_constants() {
        // Verify the error names are NUL-terminated
        assert_eq!(SD_BUS_ERROR_FAILED.last(), &0);
        assert_eq!(SD_BUS_ERROR_NO_MEMORY.last(), &0);
        assert_eq!(SD_BUS_ERROR_ACCESS_DENIED.last(), &0);
    }
}
