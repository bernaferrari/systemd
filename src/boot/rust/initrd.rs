// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/initrd.c
//
// EFI initrd loading via LINUX_INITRD_MEDIA_GUID DevicePath.
//
// Provides registration and unregistration of an initrd loader that
// uses the EFI_LOAD_FILE2_PROTOCOL. The Linux kernel (5.8+) uses this
// to discover initrds via a well-known device path GUID rather than
// requiring boot loader-specific mechanisms.

// ── Constants ─────────────────────────────────────────────────────────────

/// EFI status codes (matching UEFI spec values)
pub const EFI_SUCCESS: usize = 0;
pub const EFI_INVALID_PARAMETER: usize = 2;
pub const EFI_UNSUPPORTED: usize = 3;
pub const EFI_NOT_FOUND: usize = 14;
pub const EFI_BUFFER_TOO_SMALL: usize = 5;
pub const EFI_ALREADY_STARTED: usize = 0x8000000E;
pub const EFI_OUT_OF_RESOURCES: usize = 9;

/// The LINUX_INITRD_MEDIA_GUID as raw bytes (matches the C GUID_DEF)
pub const LINUX_INITRD_MEDIA_GUID: [u8; 16] = [
    0x27, 0xe4, 0x68, 0x55, 0xfc, 0x68, 0x3d, 0x4f, 0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68,
];

// ── Types ─────────────────────────────────────────────────────────────────

/// Represents a data buffer (iovec equivalent)
#[derive(Debug, Clone, Default)]
pub struct IoVec {
    pub base: Vec<u8>,
}

impl IoVec {
    pub fn new(data: Vec<u8>) -> Self {
        Self { base: data }
    }

    pub fn is_set(&self) -> bool {
        !self.base.is_empty()
    }

    pub fn len(&self) -> usize {
        self.base.len()
    }

    pub fn is_empty(&self) -> bool {
        self.base.is_empty()
    }
}

/// Represents an EFI handle (opaque identifier)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EfiHandle(pub u64);

impl EfiHandle {
    pub const NULL: EfiHandle = EfiHandle(0);

    pub fn is_null(&self) -> bool {
        self.0 == 0
    }
}

/// Represents an EFI device path (simplified)
#[derive(Debug, Clone, Default)]
pub struct DevicePath {
    pub data: Vec<u8>,
}

/// Error type for initrd operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitrdError {
    InvalidParameter,
    Unsupported,
    NotFound,
    BufferTooSmall,
    AlreadyStarted,
    OutOfResources,
    LoadError(usize),
}

impl std::fmt::Display for InitrdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitrdError::InvalidParameter => write!(f, "invalid parameter"),
            InitrdError::Unsupported => write!(f, "boot policy not supported"),
            InitrdError::NotFound => write!(f, "initrd not found"),
            InitrdError::BufferTooSmall => write!(f, "buffer too small"),
            InitrdError::AlreadyStarted => write!(f, "initrd already registered"),
            InitrdError::OutOfResources => write!(f, "out of resources"),
            InitrdError::LoadError(code) => write!(f, "load error: {}", code),
        }
    }
}

impl std::error::Error for InitrdError {}

// ── Initrd Loader State ───────────────────────────────────────────────────

/// Tracks registered initrd state. In the C code, this is a static
/// `struct initrd_loader` that wraps EFI_LOAD_FILE_PROTOCOL.
#[derive(Debug, Clone, Default)]
pub struct InitrdLoader {
    /// The initrd data
    data: IoVec,
}

// ── EFI Protocol Registry (simulated) ─────────────────────────────────────

/// Simulates the EFI protocol registration system for testing.
/// In real EFI, protocols are registered via Boot Services.
#[derive(Debug, Clone, Default)]
pub struct EfiProtocolRegistry {
    /// Whether a LINUX_INITRD_MEDIA_GUID device path is already registered
    initrd_registered: bool,
    /// The currently registered initrd data
    registered_data: Option<IoVec>,
    /// Track the registered handle
    registered_handle: EfiHandle,
    /// Next handle counter
    next_handle: u64,
}

impl EfiProtocolRegistry {
    pub fn new() -> Self {
        Self {
            next_handle: 1,
            ..Self::default()
        }
    }

    fn allocate_handle(&mut self) -> EfiHandle {
        let handle = EfiHandle(self.next_handle);
        self.next_handle += 1;
        handle
    }
}

// ── Load file operation ───────────────────────────────────────────────────

/// Attempt to load initrd data into the provided buffer.
///
/// Matches the C `initrd_load_file` function:
/// - Validates parameters
/// - Rejects boot_policy = true
/// - Returns the initrd data if available
/// - Returns BufferTooSmall if buffer is too small
pub fn initrd_load_file(
    loader: &InitrdLoader,
    _file_path: &DevicePath,
    boot_policy: bool,
    buffer: &mut [u8],
) -> Result<usize, InitrdError> {
    if boot_policy {
        return Err(InitrdError::Unsupported);
    }

    if !loader.data.is_set() {
        return Err(InitrdError::NotFound);
    }

    let data_len = loader.data.len();
    if buffer.len() < data_len {
        return Err(InitrdError::BufferTooSmall);
    }

    buffer[..data_len].copy_from_slice(&loader.data.base);
    Ok(data_len)
}

// ── Register initrd ───────────────────────────────────────────────────────

/// Register an initrd with the EFI protocol system.
///
/// Matches the C `initrd_register` function:
/// - If no initrd is specified, returns Ok without registration
/// - If initrd is already registered, returns AlreadyStarted
/// - Otherwise, creates a new handle and registers the protocol
pub fn initrd_register(
    initrd: &IoVec,
    registry: &mut EfiProtocolRegistry,
) -> Result<EfiHandle, InitrdError> {
    // If no initrd is specified, we don't install any protocol
    if !initrd.is_set() {
        return Ok(EfiHandle::NULL);
    }

    // Check if a LINUX_INITRD_MEDIA_GUID DevicePath is already registered
    if registry.initrd_registered {
        return Err(InitrdError::AlreadyStarted);
    }

    // Allocate new handle and register
    let handle = registry.allocate_handle();
    registry.initrd_registered = true;
    registry.registered_data = Some(initrd.clone());
    registry.registered_handle = handle;

    Ok(handle)
}

// ── Unregister initrd ─────────────────────────────────────────────────────

/// Unregister an initrd handle from the protocol system.
///
/// Matches the C `initrd_unregister` function:
/// - NULL handle is a no-op success
/// - Uninstalls all protocols on the handle, destroying it
pub fn initrd_unregister(
    handle: EfiHandle,
    registry: &mut EfiProtocolRegistry,
) -> Result<(), InitrdError> {
    if handle.is_null() {
        return Ok(());
    }

    // Verify this handle matches the registered one
    if !registry.initrd_registered || registry.registered_handle != handle {
        return Err(InitrdError::NotFound);
    }

    // Uninstall all protocols, destroying the handle
    registry.initrd_registered = false;
    registry.registered_data = None;
    registry.registered_handle = EfiHandle::NULL;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iovec_new_and_is_set() {
        let iov = IoVec::new(vec![1, 2, 3]);
        assert!(iov.is_set());
        assert_eq!(iov.len(), 3);
        assert!(!iov.is_empty());
    }

    #[test]
    fn test_iovec_default_not_set() {
        let iov = IoVec::default();
        assert!(!iov.is_set());
        assert_eq!(iov.len(), 0);
    }

    #[test]
    fn test_initrd_load_file_basic() {
        let loader = InitrdLoader {
            data: IoVec::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };
        let mut buffer = vec![0u8; 16];
        let result = initrd_load_file(&loader, &DevicePath::default(), false, &mut buffer);
        assert_eq!(result.unwrap(), 4);
        assert_eq!(&buffer[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_initrd_load_file_boot_policy_rejected() {
        let loader = InitrdLoader {
            data: IoVec::new(vec![1, 2, 3]),
        };
        let mut buffer = vec![0u8; 16];
        let result = initrd_load_file(&loader, &DevicePath::default(), true, &mut buffer);
        assert_eq!(result.unwrap_err(), InitrdError::Unsupported);
    }

    #[test]
    fn test_initrd_load_file_no_data() {
        let loader = InitrdLoader::default();
        let mut buffer = vec![0u8; 16];
        let result = initrd_load_file(&loader, &DevicePath::default(), false, &mut buffer);
        assert_eq!(result.unwrap_err(), InitrdError::NotFound);
    }

    #[test]
    fn test_initrd_load_file_buffer_too_small() {
        let loader = InitrdLoader {
            data: IoVec::new(vec![1, 2, 3, 4, 5]),
        };
        let mut buffer = vec![0u8; 3];
        let result = initrd_load_file(&loader, &DevicePath::default(), false, &mut buffer);
        assert_eq!(result.unwrap_err(), InitrdError::BufferTooSmall);
    }

    #[test]
    fn test_initrd_register_no_initrd() {
        let mut registry = EfiProtocolRegistry::new();
        let empty = IoVec::default();
        let handle = initrd_register(&empty, &mut registry).unwrap();
        assert_eq!(handle, EfiHandle::NULL);
        assert!(!registry.initrd_registered);
    }

    #[test]
    fn test_initrd_register_success() {
        let mut registry = EfiProtocolRegistry::new();
        let initrd = IoVec::new(vec![1, 2, 3]);
        let handle = initrd_register(&initrd, &mut registry).unwrap();
        assert!(!handle.is_null());
        assert!(registry.initrd_registered);
    }

    #[test]
    fn test_initrd_register_already_started() {
        let mut registry = EfiProtocolRegistry::new();
        let initrd = IoVec::new(vec![1, 2, 3]);
        initrd_register(&initrd, &mut registry).unwrap();
        let result = initrd_register(&initrd, &mut registry);
        assert_eq!(result.unwrap_err(), InitrdError::AlreadyStarted);
    }

    #[test]
    fn test_initrd_unregister_null_handle() {
        let mut registry = EfiProtocolRegistry::new();
        let result = initrd_unregister(EfiHandle::NULL, &mut registry);
        assert!(result.is_ok());
    }

    #[test]
    fn test_initrd_unregister_success() {
        let mut registry = EfiProtocolRegistry::new();
        let initrd = IoVec::new(vec![1, 2, 3]);
        let handle = initrd_register(&initrd, &mut registry).unwrap();
        assert!(initrd_unregister(handle, &mut registry).is_ok());
        assert!(!registry.initrd_registered);
    }

    #[test]
    fn test_initrd_unregister_wrong_handle() {
        let mut registry = EfiProtocolRegistry::new();
        let initrd = IoVec::new(vec![1, 2, 3]);
        initrd_register(&initrd, &mut registry).unwrap();
        let result = initrd_unregister(EfiHandle(999), &mut registry);
        assert_eq!(result.unwrap_err(), InitrdError::NotFound);
    }

    #[test]
    fn test_initrd_register_unregister_cycle() {
        let mut registry = EfiProtocolRegistry::new();
        let initrd = IoVec::new(vec![0xAA, 0xBB]);
        let handle = initrd_register(&initrd, &mut registry).unwrap();
        initrd_unregister(handle, &mut registry).unwrap();
        // Can register again after unregistration
        let handle2 = initrd_register(&initrd, &mut registry).unwrap();
        assert_ne!(handle, handle2);
    }

    #[test]
    fn test_efi_handle_null() {
        assert!(EfiHandle::NULL.is_null());
        assert!(!EfiHandle(1).is_null());
    }
}
