// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/memory-util.h, src/shared/creds-util.c
//
// Ownership boundary for credential and key material.

use std::fmt;

/// An owned byte buffer whose complete allocation is erased on drop.
///
/// `SecretBytes` deliberately does not implement `Clone`: copying a secret
/// must be an explicit operation at the call site with an independently owned
/// erasure lifetime. It also redacts `Debug` output and does not expose an
/// `into_vec()` escape hatch that could silently discard the zeroizing owner.
pub struct SecretBytes(Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretBytesFinalizeError {
    InvalidLength,
    OutOfMemory,
}

impl SecretBytes {
    /// Create an empty secret buffer.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Take ownership of an existing byte vector without copying it.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Allocate a fixed, zero-filled region before any secret bytes are read.
    ///
    /// Callers receive only a fixed-size slice, not a growable `Vec`, so a
    /// partially initialized secret can never trigger an un-erased
    /// reallocation.
    pub(crate) fn try_zeroed(size: usize) -> Result<Self, std::collections::TryReserveError> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size)?;
        bytes.resize(size, 0);
        Ok(Self(bytes))
    }

    /// Borrow the initialized secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Borrow the secret as UTF-8 without changing its ownership or lifetime.
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.as_bytes())
    }

    /// Return the number of initialized secret bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return whether the initialized secret contains `byte`.
    pub fn contains(&self, byte: u8) -> bool {
        self.0.contains(&byte)
    }

    /// Borrow the fixed initialized region while filling a new secret.
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Finalize a prefix after a fixed-buffer initialization.
    ///
    /// The tail must still contain only its original zeros. Refusing to
    /// truncate a modified tail ensures no secret bytes are moved outside the
    /// initialized length that `Drop` erases.
    pub(crate) fn finalize_prefix(self, length: usize) -> Result<Self, SecretBytesFinalizeError> {
        let Some(tail) = self.0.get(length..) else {
            return Err(SecretBytesFinalizeError::InvalidLength);
        };
        if tail.iter().any(|byte| *byte != 0) {
            return Err(SecretBytesFinalizeError::InvalidLength);
        }
        if length == self.0.len() {
            return Ok(self);
        }

        /*
         * Do not retain the fixed 1 MiB read buffer for every small
         * credential, and do not use Vec::shrink_to_fit(): an allocator
         * reallocation could release the old secret without erasing it.
         * Instead, copy the initialized prefix into a second zeroizing owner;
         * returning from this function then drops and erases the full original
         * allocation.
         */
        let mut compact =
            Self::try_zeroed(length).map_err(|_| SecretBytesFinalizeError::OutOfMemory)?;
        compact.0.copy_from_slice(&self.0[..length]);
        Ok(compact)
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Default for SecretBytes {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_vec(bytes)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("len", &self.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        let capacity = self.0.capacity();
        if capacity == 0 {
            return;
        }

        // Vec exposes a writable allocation of exactly `capacity` u8 slots.
        // SAFETY: explicit_bzero is non-elidable, retains no pointer, and
        // initializes/clears only storage owned exclusively by this Vec.
        unsafe_ffi!({
            libc::explicit_bzero(self.0.as_mut_ptr().cast::<libc::c_void>(), capacity);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_contents() {
        let secret = SecretBytes::from_vec(b"do-not-log".to_vec());
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("do-not-log"));
    }

    #[test]
    fn borrowed_views_do_not_copy() {
        let secret = SecretBytes::from_vec(b"credential".to_vec());
        assert_eq!(secret.as_bytes(), b"credential");
        assert_eq!(secret.as_str(), Ok("credential"));
        assert_eq!(secret.len(), 10);
        assert!(!secret.is_empty());
        assert!(secret.contains(b'd'));
    }
}
