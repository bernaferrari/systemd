// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bpf-link.c, src/shared/bpf-link.h
//
// BPF link management — creation, cleanup, serialization, and ring-buffer
// lifecycle helpers for BPF program attachment links.
//
// Provides safe Rust value models for the error and serialization behavior
// around libbpf link objects and ring buffers. Actual libbpf object ownership
// remains C-owned until this module has typed, lifetime-safe calls through the
// loader; an integer file descriptor alone is not a `struct bpf_link *`.

use std::io::{self, Write};

use crate::bpf_dlopen::{BpfError, bpf_get_error_translated};
use crate::ffi::Errno;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors specific to BPF link operations.
#[derive(Debug)]
pub enum BpfLinkError {
    /// libbpf is not available or not loaded.
    Unsupported(BpfError),
    /// The link pointer is NULL / absent.
    NoLink,
    /// The link carries a translated error code (not a valid link).
    InvalidLink(i32),
    /// A serialization or I/O error occurred.
    Io(io::Error),
    /// Invalid argument (e.g. empty key).
    InvalidArgument(String),
}

impl std::fmt::Display for BpfLinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(e) => write!(f, "BPF not supported: {}", e),
            Self::NoLink => write!(f, "BPF link is NULL"),
            Self::InvalidLink(code) => {
                write!(f, "BPF link carries error code {}", code)
            }
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
        }
    }
}

impl std::error::Error for BpfLinkError {}

impl From<io::Error> for BpfLinkError {
    fn from(e: io::Error) -> Self {
        BpfLinkError::Io(e)
    }
}

impl From<BpfError> for BpfLinkError {
    fn from(e: BpfError) -> Self {
        BpfLinkError::Unsupported(e)
    }
}

// ── BpfLink ─────────────────────────────────────────────────────────────────

/// A safe value model of a BPF link result.
///
/// This records the observable result of a libbpf operation for pure error
/// handling and serialization. It deliberately does *not* own a libbpf
/// `struct bpf_link`: `bpf_link__destroy()` requires that opaque pointer, and
/// closing a copied descriptor would not faithfully replace it. A future
/// production wrapper must retain the opaque handle and invoke the typed
/// destructor from the validated dynamic-loader table.
///
/// A `BpfLink` can be in one of three states:
/// - **Valid**: `fd >= 0`, the link is active.
/// - **Error pointer**: `fd < 0` but `is_error()` is true, indicating libbpf
///   returned an error rather than a valid link.
/// - **Null**: `fd == BPF_LINK_NULL_FD`, representing a NULL link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfLink {
    /// Kernel file descriptor for the link, or a sentinel value.
    fd: i32,
    /// Whether this link was produced by libbpf and carries an error.
    is_error_ptr: bool,
}

/// Sentinel fd value representing a NULL (absent) link.
const BPF_LINK_NULL_FD: i32 = -1;

impl BpfLink {
    /// Create a valid `BpfLink` from a kernel file descriptor.
    ///
    /// # Panics
    ///
    /// Panics if `fd < 0`.
    pub fn from_fd(fd: i32) -> Self {
        assert!(fd >= 0, "BpfLink fd must be non-negative");
        Self {
            fd,
            is_error_ptr: false,
        }
    }

    /// Create a null (absent) link placeholder.
    pub fn null() -> Self {
        Self {
            fd: BPF_LINK_NULL_FD,
            is_error_ptr: false,
        }
    }

    /// Create a link that represents an error pointer from libbpf.
    ///
    /// libbpf sometimes returns error codes encoded as pointers. This
    /// constructor captures that state for later inspection.
    pub fn from_error_code(code: i32) -> Self {
        Self {
            fd: code,
            is_error_ptr: true,
        }
    }

    /// Returns the underlying file descriptor.
    ///
    /// Only meaningful when `is_valid()` is true.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Whether this link is valid (has a usable kernel fd).
    pub fn is_valid(&self) -> bool {
        self.fd >= 0 && !self.is_error_ptr
    }

    /// Whether this link is null (absent).
    pub fn is_null(&self) -> bool {
        self.fd == BPF_LINK_NULL_FD && !self.is_error_ptr
    }

    /// Whether this link represents an error pointer from libbpf.
    pub fn is_error(&self) -> bool {
        self.is_error_ptr
    }

    /// Consume this pure value model, returning `None`.
    ///
    /// This mirrors the ownership shape of the C cleanup helper without
    /// claiming to destroy an opaque libbpf allocation (which this type does
    /// not possess).
    pub fn free(self) -> Option<Self> {
        None
    }
}

impl Default for BpfLink {
    fn default() -> Self {
        Self::null()
    }
}

// ── RingBuffer ──────────────────────────────────────────────────────────────

/// A safe value model of a libbpf ring-buffer result.
///
/// Like [`BpfLink`], this does not own the opaque libbpf allocation. It only
/// carries a descriptor-like value for pure state handling until a typed
/// ownership wrapper can call `ring_buffer__free` exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingBuffer {
    /// Kernel file descriptor for the ring buffer's epoll fd, or sentinel.
    fd: i32,
    /// Whether this ring buffer is valid (non-null).
    is_valid: bool,
}

/// Sentinel fd value representing a NULL ring buffer.
const RING_BUFFER_NULL_FD: i32 = -1;

impl RingBuffer {
    /// Create a valid `RingBuffer` from a kernel file descriptor.
    ///
    /// # Panics
    ///
    /// Panics if `fd < 0`.
    pub fn from_fd(fd: i32) -> Self {
        assert!(fd >= 0, "RingBuffer fd must be non-negative");
        Self { fd, is_valid: true }
    }

    /// Create a null (absent) ring buffer placeholder.
    pub fn null() -> Self {
        Self {
            fd: RING_BUFFER_NULL_FD,
            is_valid: false,
        }
    }

    /// Returns the underlying file descriptor.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Whether this ring buffer is valid.
    pub fn is_valid(&self) -> bool {
        self.is_valid && self.fd >= 0
    }

    /// Whether this ring buffer is null.
    pub fn is_null(&self) -> bool {
        !self.is_valid
    }

    /// Consume this pure value model, returning `None`.
    ///
    /// Equivalent to the C `_cleanup_(bpf_ring_buffer_freep)` pattern.
    pub fn free(self) -> Option<Self> {
        None
    }
}

impl Default for RingBuffer {
    fn default() -> Self {
        Self::null()
    }
}

// ── Free functions ──────────────────────────────────────────────────────────

/// Free a BPF link (cleanup helper for Option<BpfLink>).
///
/// Sets the option to `None`. This does not call `bpf_link__destroy`, because
/// [`BpfLink`] does not contain the required opaque libbpf pointer.
pub fn bpf_link_free(link: &mut Option<BpfLink>) {
    *link = None;
}

/// Free a ring buffer (cleanup helper for Option<RingBuffer>).
///
/// Sets the option to `None`. This does not call `ring_buffer__free`, because
/// [`RingBuffer`] does not contain the required opaque libbpf pointer.
pub fn bpf_ring_buffer_free(buffer: &mut Option<RingBuffer>) {
    *buffer = None;
}

/// Unref (decrement reference) a BPF link.
///
/// In C this calls `bpf_link__destroy` on non-NULL opaque pointers. Here it
/// only drops the pure value model; see [`bpf_link_free`].
pub fn bpf_link_unref(link: &mut Option<BpfLink>) {
    *link = None;
}

// ── Capability probing ──────────────────────────────────────────────────────

/// Check whether the kernel supports BPF program linking.
///
/// This mirrors the C `bpf_can_link_program()` function. The C version
/// attempts to attach a BPF program to an invalid cgroup fd (-1); if the
/// kernel returns `-EBADF`, BPF linking is supported.
///
/// In our safe Rust version, we check via the translated error path:
/// a return value of `-EBADF` (which is -9) indicates kernel support.
///
/// # Arguments
///
/// * `link` - A `BpfLink` that may carry an error code from a previous
///   attach attempt. The error code is inspected via
///   `bpf_get_error_translated()`.
///
/// # Returns
///
/// `true` if the translated error is `-EBADF`, indicating BPF link support.
pub fn bpf_can_link_program(link: &BpfLink) -> bool {
    if link.is_error() {
        bpf_get_error_translated(link.fd()) == Errno::EBADF.to_neg_errno()
    } else {
        false
    }
}

/// Check whether a BPF link carries a translatable error code.
///
/// Returns the translated error code, or 0 if the link is valid or null.
pub fn bpf_link_error_translated(link: &BpfLink) -> i32 {
    if link.is_error() {
        bpf_get_error_translated(link.fd())
    } else {
        0
    }
}

// ── Serialization ──────────────────────────────────────────────────────────

/// Serialize a BPF link's file descriptor to a writer.
///
/// This mirrors the C `bpf_serialize_link()` function, which writes the
/// link's fd to a FILE* via `serialize_fd()`.
///
/// # Arguments
///
/// * `writer` - Any `Write` implementation (file, buffer, etc.)
/// * `key` - The key name to prefix the serialized fd with
/// * `link` - The BPF link to serialize (must be valid)
///
/// # Errors
///
/// * `BpfLinkError::InvalidArgument` if `key` is empty
/// * `BpfLinkError::NoLink` if `link` is `None` (null)
/// * `BpfLinkError::InvalidLink` if the link carries an error code
/// * `BpfLinkError::Io` if writing fails
pub fn bpf_serialize_link<W: Write>(
    writer: &mut W,
    key: &str,
    link: Option<&BpfLink>,
) -> Result<(), BpfLinkError> {
    if key.is_empty() {
        return Err(BpfLinkError::InvalidArgument(
            "key must not be empty".into(),
        ));
    }

    let link = match link {
        Some(l) => l,
        None => return Err(BpfLinkError::NoLink),
    };

    if !link.is_valid() {
        if link.is_null() {
            return Err(BpfLinkError::NoLink);
        }
        if link.is_error() {
            // C's bpf_serialize_link() deliberately normalizes every libbpf
            // error pointer to -EINVAL rather than leaking the kernel/libbpf
            // diagnostic through its serialization contract.
            return Err(BpfLinkError::InvalidLink(Errno::EINVAL.to_neg_errno()));
        }
        return Err(BpfLinkError::NoLink);
    }

    writeln!(writer, "{}={}", key, link.fd())?;
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_link_from_fd() {
        let link = BpfLink::from_fd(42);
        assert_eq!(link.fd(), 42);
        assert!(link.is_valid());
        assert!(!link.is_null());
        assert!(!link.is_error());
    }

    #[test]
    fn test_bpf_link_null() {
        let link = BpfLink::null();
        assert_eq!(link.fd(), BPF_LINK_NULL_FD);
        assert!(!link.is_valid());
        assert!(link.is_null());
        assert!(!link.is_error());
    }

    #[test]
    fn test_bpf_link_default() {
        let link = BpfLink::default();
        assert!(link.is_null());
    }

    #[test]
    fn test_bpf_link_from_error_code() {
        let link = BpfLink::from_error_code(-9); // -EBADF
        assert_eq!(link.fd(), -9);
        assert!(link.is_error());
        assert!(!link.is_valid());
        assert!(!link.is_null());
    }

    #[test]
    fn test_bpf_link_equality() {
        let a = BpfLink::from_fd(10);
        let b = BpfLink::from_fd(10);
        let c = BpfLink::from_fd(20);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_bpf_link_free_option() {
        let mut link = Some(BpfLink::from_fd(5));
        assert!(link.is_some());
        bpf_link_free(&mut link);
        assert!(link.is_none());
    }

    #[test]
    fn test_bpf_link_free_already_none() {
        let mut link: Option<BpfLink> = None;
        bpf_link_free(&mut link);
        assert!(link.is_none());
    }

    #[test]
    fn test_bpf_link_unref() {
        let mut link = Some(BpfLink::from_fd(7));
        bpf_link_unref(&mut link);
        assert!(link.is_none());
    }

    #[test]
    fn test_bpf_link_consume_free() {
        let link = BpfLink::from_fd(3);
        let result = link.free();
        assert!(result.is_none());
    }

    #[test]
    fn test_bpf_link_debug_format() {
        let link = BpfLink::from_fd(42);
        let debug_str = format!("{:?}", link);
        assert!(debug_str.contains("BpfLink"));
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn test_bpf_can_link_program_with_ebadf() {
        // -EBADF = -9, which is Errno::EBADF.to_neg_errno()
        let link = BpfLink::from_error_code(Errno::EBADF.to_neg_errno());
        assert!(bpf_can_link_program(&link));
    }

    #[test]
    fn test_bpf_can_link_program_with_other_error() {
        // -EINVAL = -22
        let link = BpfLink::from_error_code(-22);
        assert!(!bpf_can_link_program(&link));
    }

    #[test]
    fn test_bpf_can_link_program_valid_link() {
        let link = BpfLink::from_fd(10);
        assert!(!bpf_can_link_program(&link));
    }

    #[test]
    fn test_bpf_can_link_program_null_link() {
        let link = BpfLink::null();
        assert!(!bpf_can_link_program(&link));
    }

    #[test]
    fn test_bpf_link_error_translated_error_ptr() {
        let link = BpfLink::from_error_code(-524);
        // -524 is the kernel BPF internal error → translated to -EOPNOTSUPP
        let translated = bpf_link_error_translated(&link);
        assert_ne!(translated, -524);
        assert_eq!(translated, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_bpf_link_error_translated_valid_link() {
        let link = BpfLink::from_fd(10);
        assert_eq!(bpf_link_error_translated(&link), 0);
    }

    #[test]
    fn test_bpf_link_error_translated_null_link() {
        let link = BpfLink::null();
        assert_eq!(bpf_link_error_translated(&link), 0);
    }

    #[test]
    fn test_bpf_link_error_translated_passthrough() {
        let link = BpfLink::from_error_code(-22);
        assert_eq!(bpf_link_error_translated(&link), -22);
    }

    #[test]
    fn test_bpf_serialize_link_valid() {
        let link = BpfLink::from_fd(42);
        let mut output = Vec::new();
        bpf_serialize_link(&mut output, "bpf_link", Some(&link)).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("bpf_link=42"));
    }

    #[test]
    fn test_bpf_serialize_link_none() {
        let mut output = Vec::new();
        let result = bpf_serialize_link::<Vec<u8>>(&mut output, "key", None);
        assert!(matches!(result.unwrap_err(), BpfLinkError::NoLink));
    }

    #[test]
    fn test_bpf_serialize_link_error_ptr() {
        let link = BpfLink::from_error_code(-22);
        let mut output = Vec::new();
        let result = bpf_serialize_link(&mut output, "key", Some(&link));
        match result.unwrap_err() {
            BpfLinkError::InvalidLink(code) => assert_eq!(code, Errno::EINVAL.to_neg_errno()),
            other => panic!("Expected InvalidLink, got {:?}", other),
        }
    }

    #[test]
    fn test_bpf_serialize_link_empty_key() {
        let link = BpfLink::from_fd(1);
        let mut output = Vec::new();
        let result = bpf_serialize_link(&mut output, "", Some(&link));
        assert!(matches!(
            result.unwrap_err(),
            BpfLinkError::InvalidArgument(_)
        ));
    }

    #[test]
    fn test_bpf_serialize_link_null_link() {
        let link = BpfLink::null();
        let mut output = Vec::new();
        let result = bpf_serialize_link(&mut output, "key", Some(&link));
        assert!(matches!(result.unwrap_err(), BpfLinkError::NoLink));
    }

    #[test]
    fn test_bpf_link_error_display() {
        let e = BpfLinkError::NoLink;
        assert!(e.to_string().contains("NULL"));

        let e = BpfLinkError::InvalidLink(-22);
        assert!(e.to_string().contains("-22"));

        let e = BpfLinkError::InvalidArgument("bad key".into());
        assert!(e.to_string().contains("bad key"));
    }

    #[test]
    fn test_ring_buffer_from_fd() {
        let rb = RingBuffer::from_fd(100);
        assert_eq!(rb.fd(), 100);
        assert!(rb.is_valid());
        assert!(!rb.is_null());
    }

    #[test]
    fn test_ring_buffer_null() {
        let rb = RingBuffer::null();
        assert_eq!(rb.fd(), RING_BUFFER_NULL_FD);
        assert!(!rb.is_valid());
        assert!(rb.is_null());
    }

    #[test]
    fn test_ring_buffer_default() {
        let rb = RingBuffer::default();
        assert!(rb.is_null());
    }

    #[test]
    fn test_ring_buffer_free_option() {
        let mut rb = Some(RingBuffer::from_fd(5));
        assert!(rb.is_some());
        bpf_ring_buffer_free(&mut rb);
        assert!(rb.is_none());
    }

    #[test]
    fn test_ring_buffer_free_already_none() {
        let mut rb: Option<RingBuffer> = None;
        bpf_ring_buffer_free(&mut rb);
        assert!(rb.is_none());
    }

    #[test]
    fn test_ring_buffer_consume_free() {
        let rb = RingBuffer::from_fd(3);
        let result = rb.free();
        assert!(result.is_none());
    }

    #[test]
    fn test_ring_buffer_equality() {
        let a = RingBuffer::from_fd(10);
        let b = RingBuffer::from_fd(10);
        let c = RingBuffer::from_fd(20);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_ring_buffer_debug_format() {
        let rb = RingBuffer::from_fd(42);
        let debug_str = format!("{:?}", rb);
        assert!(debug_str.contains("RingBuffer"));
        assert!(debug_str.contains("42"));
    }
}
