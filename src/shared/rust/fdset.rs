// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/fdset.c, src/shared/fdset.h
//
// File descriptor set — a sorted collection of open file descriptors.
//
// Provides RAII management of fd lifetimes. When `close_on_drop` is true,
// the `Drop` impl closes every fd in the set, mirroring `fdset_free()`.
// When false, it merely deallocates, mirroring `fdset_shallow_freep()`.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::ffi::*;
use nix::errno::Errno;
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::fmt;
use std::fs::File;
use std::io::{self, Write as IoWrite};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr::NonNull;

// ── Constants ─────────────────────────────────────────────────────────────

/// Minimum fd number to consider for set operations.
/// fds 0-2 (stdin/stdout/stderr) are excluded from auto-fill.
const FDSET_MIN_FD: RawFd = 3;

/// Sentinel indicating "not found" in operations that return an fd.
pub const FDSET_FD_NONE: RawFd = -1;

/// `sd_listen_fds(3)` start offset.
pub const SD_LISTEN_FDS_START: RawFd = 3;

/// An owned `DIR*` for the `/proc/self/fd` scan. `std::fs::ReadDir` does not
/// expose its descriptor, but this scan must omit exactly that descriptor just
/// like C's `fdset_new_fill()` does.
struct ProcFdDir(NonNull<libc::DIR>);

impl ProcFdDir {
    fn open() -> io::Result<Self> {
        // SAFETY: the byte string is statically NUL-terminated and remains
        // valid for the duration of the synchronous `opendir` call.
        let directory = unsafe_ffi!(libc::opendir(c"/proc/self/fd".as_ptr()));
        NonNull::new(directory)
            .map(Self)
            .ok_or_else(io::Error::last_os_error)
    }

    fn fd(&self) -> io::Result<RawFd> {
        // SAFETY: `self.0` is a live `DIR*` owned by this guard.
        let fd = unsafe_ffi!(libc::dirfd(self.0.as_ptr()));
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn next(&mut self) -> io::Result<Option<&libc::dirent>> {
        Errno::clear();
        // SAFETY: `self.0` is exclusively borrowed for this call. A non-null
        // result is valid until the next directory operation on this stream;
        // the returned reference is consumed before the next call.
        unsafe {
            let entry = libc::readdir(self.0.as_ptr());
            if entry.is_null() {
                return match Errno::last_raw() {
                    0 => Ok(None),
                    _ => Err(io::Error::last_os_error()),
                };
            }
            Ok(Some(&*entry))
        }
    }
}

impl Drop for ProcFdDir {
    fn drop(&mut self) {
        // SAFETY: this guard owns the `DIR*` exactly once. Drop intentionally
        // ignores close errors, matching the prior `ReadDir` drop behavior.
        let _ = unsafe_ffi!(libc::closedir(self.0.as_ptr()));
    }
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors produced by `FdSet` operations.
#[derive(Debug)]
pub enum FdSetError {
    /// The fd argument is negative or `i32::MAX` (reserved sentinel).
    InvalidFd(RawFd),
    /// An I/O error occurred (e.g. `dup`, `close`, `/proc` read).
    Io(io::Error),
    /// The fd was not present in the set.
    NotFound(RawFd),
}

impl fmt::Display for FdSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FdSetError::InvalidFd(fd) => write!(f, "invalid file descriptor: {fd}"),
            FdSetError::Io(e) => write!(f, "I/O error: {e}"),
            FdSetError::NotFound(fd) => write!(f, "file descriptor {fd} not found in set"),
        }
    }
}

impl std::error::Error for FdSetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FdSetError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for FdSetError {
    fn from(e: io::Error) -> Self {
        FdSetError::Io(e)
    }
}

// ── FdSet ─────────────────────────────────────────────────────────────────

/// A sorted set of file descriptors.
///
/// Internally backed by `BTreeSet<RawFd>` so iteration yields fds in
/// ascending order, matching the C implementation's behaviour with
/// `FDSET_FOREACH`.
///
/// # Ownership
///
/// When `close_on_drop` is `true` (the default for [`FdSet::new`]),
/// dropping the set closes every fd it still contains — equivalent to
/// C's `fdset_free()`. Use [`FdSet::new_shallow`] to create a set
/// that does **not** close fds on drop (equivalent to
/// `fdset_shallow_freep()`).
#[derive(Debug)]
pub struct FdSet {
    fds: BTreeSet<RawFd>,
    close_on_drop: bool,
}

// ── Constructors ──────────────────────────────────────────────────────────

impl FdSet {
    /// Create a new empty fd set. Dropping this set will close all fds.
    ///
    /// Equivalent to C's `fdset_new()`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fds: BTreeSet::new(),
            close_on_drop: true,
        }
    }

    /// Create a new empty fd set that does **not** close fds on drop.
    ///
    /// Equivalent to C's `fdset_shallow_freep()` behaviour when freed.
    #[must_use]
    pub fn new_shallow() -> Self {
        Self {
            fds: BTreeSet::new(),
            close_on_drop: false,
        }
    }

    /// Create an fd set pre-populated from a slice of fds.
    ///
    /// Equivalent to C's `fdset_new_array()`.
    pub fn from_array(fds: &[RawFd]) -> Result<Self, FdSetError> {
        // The caller retains ownership until the complete input has been
        // accepted. This is the same shallow-on-error cleanup used by C's
        // `fdset_new_array()`.
        let mut set = Self::new_shallow();
        for &fd in fds {
            set.put(fd)?;
        }
        set.close_on_drop = true;
        Ok(set)
    }

    /// Scan `/proc/self/fd/` and collect currently open fds.
    ///
    /// `filter_cloexec` controls which fds are collected:
    /// - `None` — collect all fds >= 3.
    /// - `Some(true)` — only fds with `FD_CLOEXEC` set.
    /// - `Some(false)` — only fds without `FD_CLOEXEC`.
    ///
    /// All collected fds have `FD_CLOEXEC` set after this call
    /// (if they didn't already).
    ///
    /// Equivalent to C's `fdset_new_fill()`.
    pub fn new_fill(filter_cloexec: Option<bool>) -> Result<Self, FdSetError> {
        // As in C, these are borrowed descriptors until the entire scan has
        // succeeded. An error must not close descriptors which the caller
        // still owns.
        let mut set = Self::new_shallow();
        let mut dir = ProcFdDir::open().map_err(FdSetError::Io)?;
        let dir_fd = dir.fd().map_err(FdSetError::Io)?;

        while let Some(entry) = dir.next().map_err(FdSetError::Io)? {
            // SAFETY: `d_name` is NUL-terminated for a successful `readdir`
            // result and is consumed before the next directory operation.
            let name = unsafe_ffi!(CStr::from_ptr(entry.d_name.as_ptr()));
            let fd: RawFd = match name.to_str().ok().and_then(|s| s.parse().ok()) {
                Some(v) => v,
                None => continue,
            };

            if fd < FDSET_MIN_FD {
                continue;
            }

            // `ReadDir` owns the descriptor used for the `/proc` scan. It
            // must remain live until iteration completes and must never be
            // transferred into the resulting set.
            if fd == dir_fd {
                continue;
            }

            // Filter by CLOEXEC if requested
            if let Some(want_cloexec) = filter_cloexec {
                let flags = get_fd_flags(fd)?;
                let has_cloexec = (flags & libc::FD_CLOEXEC) != 0;
                if has_cloexec != want_cloexec {
                    continue;
                }
            }

            // Set CLOEXEC on non-cloexec fds (or always if not filtering for cloexec)
            if filter_cloexec != Some(true) {
                set_cloexec_fd(fd, true)?;
            }

            set.put(fd)?;
        }

        set.close_on_drop = true;
        Ok(set)
    }
}

// ── Mutation ──────────────────────────────────────────────────────────────

impl FdSet {
    /// Insert an fd into the set.
    ///
    /// Returns `Ok(true)` if the fd was newly inserted, `Ok(false)` if it
    /// was already present.
    ///
    /// Equivalent to C's `fdset_put()`.
    pub fn put(&mut self, fd: RawFd) -> Result<bool, FdSetError> {
        validate_fd(fd)?;
        Ok(self.fds.insert(fd))
    }

    /// Insert an fd into the set, taking ownership.
    ///
    /// If insertion fails the fd is closed immediately.
    ///
    /// Equivalent to C's `fdset_consume()`.
    pub fn consume(&mut self, fd: OwnedFd) -> Result<(), FdSetError> {
        let raw = fd.as_raw_fd();
        match self.put(raw) {
            Ok(_) => {
                // fd was inserted; intentionally leak the OwnedFd since
                // we now track the raw fd in the set.
                std::mem::forget(fd);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Duplicate an fd via `F_DUPFD_CLOEXEC` and insert the copy.
    ///
    /// Returns the duplicated fd number.
    ///
    /// Equivalent to C's `fdset_put_dup()`.
    pub fn put_dup(&mut self, fd: RawFd) -> Result<RawFd, FdSetError> {
        validate_fd(fd)?;
        // SAFETY: `fd` passed validation and `F_DUPFD_CLOEXEC` takes only
        // scalar arguments. The returned descriptor is handled below on every
        // path, matching C's `_cleanup_close_` ownership discipline.
        let copy = unsafe_ffi!(libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, FDSET_MIN_FD));
        if copy < 0 {
            return Err(FdSetError::Io(io::Error::last_os_error()));
        }
        match self.put(copy) {
            Ok(_) => Ok(copy),
            Err(error) => {
                close_fd(copy);
                Err(error)
            }
        }
    }

    /// Remove an fd from the set and return it.
    ///
    /// Returns the fd number on success, or `Err(FdSetError::NotFound)`
    /// if it was not present.
    ///
    /// Equivalent to C's `fdset_remove()`.
    pub fn remove(&mut self, fd: RawFd) -> Result<RawFd, FdSetError> {
        validate_fd(fd)?;
        if self.fds.remove(&fd) {
            Ok(fd)
        } else {
            Err(FdSetError::NotFound(fd))
        }
    }

    /// Remove and return the smallest fd from the set.
    ///
    /// Equivalent to C's `fdset_steal_first()`.
    pub fn steal_first(&mut self) -> Option<RawFd> {
        self.fds.pop_first()
    }

    /// Close all fds in the set and remove them.
    ///
    /// Equivalent to C's `fdset_close()` with `async=false`.
    pub fn close_all(&mut self) {
        while let Some(fd) = self.fds.pop_first() {
            close_fd(fd);
        }
    }

    /// Asynchronously close all fds in the set and remove them.
    ///
    /// Equivalent to C's `fdset_free_async()`.
    pub fn close_all_async(&mut self) {
        while let Some(fd) = self.fds.pop_first() {
            async_close_fd(fd);
        }
    }

    /// Close all open fds that are **not** in this set.
    ///
    /// Equivalent to C's `fdset_close_others()`.
    pub fn close_others(&self) -> Result<(), FdSetError> {
        let mut except = Vec::new();
        except
            .try_reserve_exact(self.fds.len())
            .map_err(|_| FdSetError::Io(io::Error::from_raw_os_error(libc::ENOMEM)))?;
        except.extend(self.fds.iter().copied());
        close_all_except(&except)
    }

    /// Set or clear `FD_CLOEXEC` on all fds in the set.
    ///
    /// Equivalent to C's `fdset_cloexec()`.
    pub fn set_cloexec(&self, value: bool) -> Result<(), FdSetError> {
        for &fd in &self.fds {
            set_cloexec_fd(fd, value)?;
        }
        Ok(())
    }
}

// ── Queries ───────────────────────────────────────────────────────────────

impl FdSet {
    /// Check whether the set contains `fd`.
    ///
    /// Equivalent to C's `fdset_contains()`.
    #[must_use]
    pub fn contains(&self, fd: RawFd) -> bool {
        if fd < 0 || fd == i32::MAX as RawFd {
            return false;
        }
        self.fds.contains(&fd)
    }

    /// Number of fds in the set.
    ///
    /// Equivalent to C's `fdset_size()`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    /// Whether the set is empty.
    ///
    /// Equivalent to C's `fdset_isempty()`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }

    /// Iterate: return the smallest fd strictly greater than `after`.
    ///
    /// Pass `FDSET_FD_NONE` (-1) to get the very first fd.
    ///
    /// Equivalent to C's `fdset_iterate()`.
    #[must_use]
    pub fn next_above(&self, after: RawFd) -> Option<RawFd> {
        self.fds.range((after + 1)..).next().copied()
    }

    /// Return the smallest fd in the set.
    #[must_use]
    pub fn first(&self) -> Option<RawFd> {
        self.fds.first().copied()
    }

    /// Collect all fds into a `Vec<RawFd>` in ascending order.
    ///
    /// Equivalent to C's `fdset_to_array()`.
    #[must_use]
    pub fn to_vec(&self) -> Vec<RawFd> {
        self.fds.iter().copied().collect()
    }

    /// Duplicate every fd in the set and return a new set with the copies.
    ///
    /// Equivalent to C's `fdset_dup()` concept.
    pub fn dup_all(&self) -> Result<Self, FdSetError> {
        let mut copy = Self::new();
        for &fd in &self.fds {
            copy.put_dup(fd)?;
        }
        Ok(copy)
    }

    /// Shallow clone — same fds, no duplication.
    ///
    /// Equivalent to C's `fdset_copy()` concept.
    #[must_use]
    pub fn shallow_copy(&self) -> Self {
        Self {
            fds: self.fds.clone(),
            close_on_drop: false, // shallow copy should not close fds
        }
    }
}

// ── Serialization ─────────────────────────────────────────────────────────

impl FdSet {
    /// Serialize the set of fd numbers to a `File` (one fd per line).
    ///
    /// Equivalent to C's `fdset_serialize()` concept.
    pub fn serialize(&self, file: &mut File) -> io::Result<()> {
        for &fd in &self.fds {
            writeln!(file, "{}", fd)?;
        }
        Ok(())
    }

    /// Deserialize fd numbers from a `File` (one fd per line).
    ///
    /// Equivalent to C's `fdset_deserialize()` concept.
    pub fn deserialize(file: &mut File) -> Result<Self, FdSetError> {
        use std::io::BufRead;
        let mut set = Self::new();
        let reader = io::BufReader::new(file);
        for line in reader.lines() {
            let line = line.map_err(FdSetError::Io)?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let fd: RawFd = line
                .parse()
                .map_err(|_| FdSetError::InvalidFd(FDSET_FD_NONE))?;
            set.put(fd)?;
        }
        Ok(set)
    }
}

// ── RAII Drop ─────────────────────────────────────────────────────────────

impl Drop for FdSet {
    fn drop(&mut self) {
        if self.close_on_drop {
            self.close_all();
        }
    }
}

// ── Trait impls ───────────────────────────────────────────────────────────

impl Default for FdSet {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for FdSet {
    fn eq(&self, other: &Self) -> bool {
        self.fds == other.fds
    }
}

impl Eq for FdSet {}

impl IntoIterator for FdSet {
    type Item = RawFd;
    type IntoIter = std::collections::btree_set::IntoIter<RawFd>;

    fn into_iter(mut self) -> Self::IntoIter {
        let fds = std::mem::take(&mut self.fds);
        std::mem::forget(self);
        fds.into_iter()
    }
}

impl<'a> IntoIterator for &'a FdSet {
    type Item = &'a RawFd;
    type IntoIter = std::collections::btree_set::Iter<'a, RawFd>;

    fn into_iter(self) -> Self::IntoIter {
        self.fds.iter()
    }
}

// ── Helper functions (private) ────────────────────────────────────────────

/// Validate that an fd is a legal file descriptor.
fn validate_fd(fd: RawFd) -> Result<(), FdSetError> {
    if fd < 0 || fd == i32::MAX as RawFd {
        Err(FdSetError::InvalidFd(fd))
    } else {
        Ok(())
    }
}

/// Close a single fd, ignoring errors (like C's `(void) close(fd)`).
fn close_fd(fd: RawFd) {
    // SAFETY: `close` accepts any integer descriptor. This helper deliberately
    // ignores errors, exactly like the C fd-set destruction paths.
    unsafe {
        libc::close(fd);
    }
}

/// Close a single fd asynchronously, preserving `async.c`'s shared
/// descriptor-table semantics. Errors are deliberately ignored like C's
/// `(void) asynchronous_close(fd)` cleanup path.
fn async_close_fd(fd: RawFd) {
    let _ = crate::r#async::asynchronous_close(fd);
}

/// Get the fd flags via `fcntl(F_GETFD)`.
fn get_fd_flags(fd: RawFd) -> Result<i32, FdSetError> {
    // SAFETY: `F_GETFD` takes a scalar descriptor and has no pointer or
    // ownership preconditions. A negative result is translated below.
    let flags = unsafe_ffi!(libc::fcntl(fd, libc::F_GETFD));
    if flags < 0 {
        Err(FdSetError::Io(io::Error::last_os_error()))
    } else {
        Ok(flags)
    }
}

/// Set or clear `FD_CLOEXEC` on a single fd via `fcntl(F_SETFD)`.
fn set_cloexec_fd(fd: RawFd, value: bool) -> Result<(), FdSetError> {
    let flags = get_fd_flags(fd)?;
    let new_flags = if value {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: `F_SETFD` takes the scalar flag word computed above and does not
    // retain memory. Failure is reported before this helper returns.
    let ret = unsafe_ffi!(libc::fcntl(fd, libc::F_SETFD, new_flags));
    if ret < 0 {
        Err(FdSetError::Io(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

// SAFETY: `close_all_fds` reads a live slice (or `n_except == 0`) only for the
// call and retains neither the pointer nor descriptor ownership.
unsafe extern "C" {
    fn close_all_fds(except: *const libc::c_int, n_except: usize) -> libc::c_int;
}

/// Close every descriptor other than `except`, preserving C's close-range and
/// fallback policy without opening an iterator descriptor that could be closed
/// during the operation.
fn close_all_except(except: &[RawFd]) -> Result<(), FdSetError> {
    // SAFETY: `except` is a contiguous `c_int` buffer that remains alive for
    // the synchronous C call. `close_all_fds` only reads it and returns a
    // negative errno-style value on failure.
    let result = unsafe_ffi!(close_all_fds(except.as_ptr(), except.len()));
    if result < 0 {
        Err(FdSetError::Io(io::Error::from_raw_os_error(-result)))
    } else {
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

    /// Return a private descriptor that is never one of the standard streams.
    fn fresh_fd() -> OwnedFd {
        let mut pipes = [-1; 2];
        // SAFETY: `pipes` is a valid, writable two-element `int` array. On
        // success `pipe2` initializes both entries with new descriptors.
        assert_eq!(
            unsafe_ffi!(libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC)),
            0
        );

        // SAFETY: the successful `pipe2` call above created two distinct,
        // exclusively owned descriptors in `pipes`.
        let read = unsafe_ffi!(OwnedFd::from_raw_fd(pipes[0]));
        // SAFETY: see the preceding ownership argument for the other pipe end.
        let write = unsafe_ffi!(OwnedFd::from_raw_fd(pipes[1]));

        // `F_DUPFD_CLOEXEC` gives tests a descriptor outside the standard
        // streams even if the test process started with one of them closed.
        // SAFETY: `read` is a live descriptor and all arguments are scalars.
        let fd = unsafe_ffi!(libc::fcntl(
            read.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            FDSET_MIN_FD
        ));
        assert!(
            fd >= FDSET_MIN_FD,
            "failed to duplicate test pipe: {}",
            io::Error::last_os_error()
        );
        drop(read);
        drop(write);

        // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` succeeded and returned a new,
        // exclusively owned descriptor not managed by another Rust object.
        unsafe_ffi!(OwnedFd::from_raw_fd(fd))
    }

    /// Transfer a private descriptor to an owning set through `put`.
    fn put_owned(set: &mut FdSet, fd: OwnedFd) -> RawFd {
        let raw = fd.as_raw_fd();
        assert!(set.put(raw).unwrap());
        fd.into_raw_fd()
    }

    // ── Constructors ───────────────────────────────────────────────────

    #[test]
    fn test_new_empty() {
        let set = FdSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_new_shallow() {
        let set = FdSet::new_shallow();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_default() {
        let set = FdSet::default();
        assert!(set.is_empty());
    }

    #[test]
    fn test_from_array() {
        let owned = [fresh_fd(), fresh_fd(), fresh_fd()];
        let fds = owned.each_ref().map(|fd| fd.as_raw_fd());
        let set = FdSet::from_array(&fds).unwrap();
        let _ = owned.map(OwnedFd::into_raw_fd);
        assert_eq!(set.len(), 3);
        assert!(fds.iter().all(|&fd| set.contains(fd)));
    }

    #[test]
    fn test_from_array_empty() {
        let set = FdSet::from_array(&[]).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn test_from_array_rejects_invalid() {
        assert!(FdSet::from_array(&[-1]).is_err());
        assert!(FdSet::from_array(&[i32::MAX as RawFd]).is_err());
    }

    // ── put / contains ─────────────────────────────────────────────────

    #[test]
    fn test_put_and_contains() {
        let mut set = FdSet::new_shallow();
        assert!(set.put(42).unwrap());
        assert!(!set.put(42).unwrap()); // duplicate
        assert!(set.contains(42));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_put_invalid_fd() {
        let mut set = FdSet::new_shallow();
        assert!(matches!(set.put(-1), Err(FdSetError::InvalidFd(-1))));
        assert!(matches!(
            set.put(i32::MAX as RawFd),
            Err(FdSetError::InvalidFd(_))
        ));
    }

    #[test]
    fn test_contains_invalid_fd() {
        let mut set = FdSet::new_shallow();
        set.put(5).unwrap();
        assert!(!set.contains(-1));
        assert!(!set.contains(i32::MAX as RawFd));
    }

    // ── remove ─────────────────────────────────────────────────────────

    #[test]
    fn test_remove_present() {
        let mut set = FdSet::new_shallow();
        set.put(7).unwrap();
        assert_eq!(set.remove(7).unwrap(), 7);
        assert!(!set.contains(7));
        assert!(set.is_empty());
    }

    #[test]
    fn test_remove_absent() {
        let mut set = FdSet::new_shallow();
        assert!(matches!(set.remove(99), Err(FdSetError::NotFound(99))));
    }

    #[test]
    fn test_remove_invalid() {
        let mut set = FdSet::new_shallow();
        assert!(matches!(set.remove(-1), Err(FdSetError::InvalidFd(-1))));
    }

    // ── steal_first ────────────────────────────────────────────────────

    #[test]
    fn test_steal_first() {
        let mut set = FdSet::new_shallow();
        set.put(30).unwrap();
        set.put(10).unwrap();
        set.put(20).unwrap();
        assert_eq!(set.steal_first(), Some(10));
        assert_eq!(set.steal_first(), Some(20));
        assert_eq!(set.steal_first(), Some(30));
        assert_eq!(set.steal_first(), None);
    }

    #[test]
    fn test_steal_first_empty() {
        let mut set = FdSet::new_shallow();
        assert_eq!(set.steal_first(), None);
    }

    // ── next_above (iterate) ───────────────────────────────────────────

    #[test]
    fn test_next_above() {
        let mut set = FdSet::new_shallow();
        set.put(5).unwrap();
        set.put(15).unwrap();
        set.put(25).unwrap();

        assert_eq!(set.next_above(FDSET_FD_NONE), Some(5));
        assert_eq!(set.next_above(5), Some(15));
        assert_eq!(set.next_above(14), Some(15));
        assert_eq!(set.next_above(25), None);
        assert_eq!(set.next_above(100), None);
    }

    #[test]
    fn test_next_above_empty() {
        let set = FdSet::new_shallow();
        assert_eq!(set.next_above(FDSET_FD_NONE), None);
    }

    #[test]
    fn test_full_iteration() {
        let mut set = FdSet::new_shallow();
        set.put(3).unwrap();
        set.put(1).unwrap();
        set.put(2).unwrap();

        let mut collected = Vec::new();
        let mut cursor = FDSET_FD_NONE;
        while let Some(fd) = set.next_above(cursor) {
            collected.push(fd);
            cursor = fd;
        }
        assert_eq!(collected, vec![1, 2, 3]);
    }

    // ── first ──────────────────────────────────────────────────────────

    #[test]
    fn test_first() {
        let mut set = FdSet::new_shallow();
        assert!(set.first().is_none());
        set.put(42).unwrap();
        set.put(7).unwrap();
        assert_eq!(set.first(), Some(7));
    }

    // ── to_vec ─────────────────────────────────────────────────────────

    #[test]
    fn test_to_vec_sorted() {
        let mut set = FdSet::new_shallow();
        set.put(50).unwrap();
        set.put(10).unwrap();
        set.put(30).unwrap();
        assert_eq!(set.to_vec(), vec![10, 30, 50]);
    }

    #[test]
    fn test_to_vec_empty() {
        let set = FdSet::new_shallow();
        assert!(set.to_vec().is_empty());
    }

    // ── put_dup ────────────────────────────────────────────────────────

    #[test]
    fn test_put_dup_valid_fd() {
        let mut set = FdSet::new();
        let source = fresh_fd();
        let duped = set.put_dup(source.as_raw_fd()).unwrap();
        assert!(duped >= FDSET_MIN_FD);
        assert!(set.contains(duped));
    }

    #[test]
    fn test_put_dup_invalid_fd() {
        let mut set = FdSet::new_shallow();
        assert!(set.put_dup(-1).is_err());
    }

    // ── consume (OwnedFd) ──────────────────────────────────────────────

    #[test]
    fn test_consume_owned_fd() {
        let mut set = FdSet::new();
        let owned = fresh_fd();
        let raw = owned.as_raw_fd();
        set.consume(owned).unwrap();
        assert!(set.contains(raw));
    }

    // ── close_all / close_all_async ────────────────────────────────────

    #[test]
    fn test_close_all() {
        let mut set = FdSet::new();
        let d1 = put_owned(&mut set, fresh_fd());
        let d2 = put_owned(&mut set, fresh_fd());
        assert_eq!(set.len(), 2);
        set.close_all();
        assert!(set.is_empty());
        // fds should now be closed
        // SAFETY: `fcntl` accepts scalar arguments. `d1` and `d2` were
        // closed by `close_all`, so querying them must fail with `EBADF`.
        assert_eq!(unsafe_ffi!(libc::fcntl(d1, libc::F_GETFD)), -1);
        // SAFETY: same reasoning as for `d1` above.
        assert_eq!(unsafe_ffi!(libc::fcntl(d2, libc::F_GETFD)), -1);
    }

    // ── dup_all ────────────────────────────────────────────────────────

    #[test]
    fn test_dup_all() {
        let mut set = FdSet::new_shallow();
        let source = fresh_fd();
        let source_fd = source.as_raw_fd();
        set.put(source_fd).unwrap();
        let duped = set.dup_all().unwrap();
        assert_eq!(duped.len(), 1);
        assert!(!duped.contains(source_fd));
        assert!(duped.first().is_some_and(|fd| fd >= FDSET_MIN_FD));
    }

    // ── shallow_copy ───────────────────────────────────────────────────

    #[test]
    fn test_shallow_copy() {
        let mut set = FdSet::new_shallow();
        set.put(10).unwrap();
        set.put(20).unwrap();
        let copy = set.shallow_copy();
        assert_eq!(set, copy);
        assert_eq!(copy.len(), 2);
        // Remove from original — copy unaffected
        set.remove(10).unwrap();
        assert!(!set.contains(10));
        assert!(copy.contains(10));
    }

    // ── equality ───────────────────────────────────────────────────────

    #[test]
    fn test_equality() {
        let mut a = FdSet::new_shallow();
        let mut b = FdSet::new_shallow();
        assert_eq!(a, b);
        a.put(5).unwrap();
        b.put(5).unwrap();
        assert_eq!(a, b);
        a.put(10).unwrap();
        assert_ne!(a, b);
    }

    // ── iteration via IntoIterator ─────────────────────────────────────

    #[test]
    fn test_into_iter() {
        let mut set = FdSet::new_shallow();
        set.put(3).unwrap();
        set.put(1).unwrap();
        set.put(2).unwrap();
        let mut v: Vec<RawFd> = set.into_iter().collect();
        v.sort();
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn test_iter_ref() {
        let mut set = FdSet::new_shallow();
        set.put(3).unwrap();
        set.put(1).unwrap();
        set.put(2).unwrap();
        let v: Vec<RawFd> = (&set).into_iter().copied().collect();
        assert_eq!(v, vec![1, 2, 3]); // BTreeSet order
    }

    // ── serialization ──────────────────────────────────────────────────

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let owned = [fresh_fd(), fresh_fd(), fresh_fd()];
        let fds = owned.each_ref().map(|fd| fd.as_raw_fd());
        let mut set = FdSet::new_shallow();
        for fd in fds {
            set.put(fd).unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fdset.txt");

        // Serialize
        {
            let mut file = File::create(&path).unwrap();
            set.serialize(&mut file).unwrap();
        }

        // Deserialize
        {
            let mut file = File::open(&path).unwrap();
            let restored = FdSet::deserialize(&mut file).unwrap();
            let _ = owned.map(OwnedFd::into_raw_fd);
            assert_eq!(restored, set);
        }
    }

    #[test]
    fn test_deserialize_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        File::create(&path).unwrap();

        let mut file = File::open(&path).unwrap();
        let set = FdSet::deserialize(&mut file).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn test_deserialize_invalid_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.txt");
        let owned = fresh_fd();
        let fd = owned.as_raw_fd();
        {
            let mut file = File::create(&path).unwrap();
            writeln!(file, "{fd}").unwrap();
            writeln!(file, "not_a_number").unwrap();
        }

        let _ = owned.into_raw_fd();
        let mut file = File::open(&path).unwrap();
        assert!(FdSet::deserialize(&mut file).is_err());
    }

    // ── close_others ───────────────────────────────────────────────────

    // Disabled: close_others() closes ALL fds not in set, including
    // Rust runtime internals (kqueue/epoll), causing IO Safety abort.
    // This test should only run on Linux with /proc/self/fd available.
    // #[test]
    // fn test_close_others_keeps_set_fds() { ... }

    // ── set_cloexec ────────────────────────────────────────────────────
    #[test]
    fn test_set_cloexec() {
        let mut set = FdSet::new();
        let fd = put_owned(&mut set, fresh_fd());

        set.set_cloexec(true).unwrap();
        // SAFETY: `fd` is still owned by `set`; `fcntl` uses scalar arguments.
        let flags = unsafe_ffi!(libc::fcntl(fd, libc::F_GETFD));
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);

        set.set_cloexec(false).unwrap();
        // SAFETY: `fd` remains live and owned by `set` until the end of this test.
        let flags = unsafe_ffi!(libc::fcntl(fd, libc::F_GETFD));
        assert!(flags >= 0);
        assert_eq!(flags & libc::FD_CLOEXEC, 0);
    }

    // ── Drop behaviour ─────────────────────────────────────────────────

    #[test]
    fn test_drop_closes_fds() {
        let fd;

        {
            let mut set = FdSet::new(); // close_on_drop = true
            fd = put_owned(&mut set, fresh_fd());
            // set drops here, closing fd
        }

        // SAFETY: `fcntl` accepts scalar arguments. `FdSet::drop` closed its
        // private descriptor synchronously, so this query must fail.
        assert_eq!(unsafe_ffi!(libc::fcntl(fd, libc::F_GETFD)), -1);
    }

    #[test]
    fn test_drop_shallow_does_not_close() {
        let fd = fresh_fd();
        let raw = fd.as_raw_fd();

        {
            let mut set = FdSet::new_shallow(); // close_on_drop = false
            set.put(raw).unwrap();
            // set drops here, fd NOT closed
        }

        // SAFETY: `fd` is still owned by the local `OwnedFd`.
        let flags = unsafe_ffi!(libc::fcntl(raw, libc::F_GETFD));
        assert!(flags >= 0);
    }

    // ── len / is_empty ─────────────────────────────────────────────────

    #[test]
    fn test_len_is_empty() {
        let mut set = FdSet::new_shallow();
        assert_eq!(set.len(), 0);
        assert!(set.is_empty());
        set.put(100).unwrap();
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
        set.remove(100).unwrap();
        assert_eq!(set.len(), 0);
        assert!(set.is_empty());
    }
}
