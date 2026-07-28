// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/journal-file-util.c, src/shared/journal-file-util.h
//
// Journal file utilities — offline state machine, hole punching, rotation,
// reliable open recovery, and entry iteration helpers.
//
// Translates the core logic from journal-file-util.c into idiomatic safe Rust.
// Syscall wrappers (pread, fallocate, fsync) are kept behind thin safe
// abstractions; all state machine and data structure logic is pure Rust.

// ── Constants ─────────────────────────────────────────────────────────────

/// Buffer size for reading hash table payload in chunks.
use crate::ffi::*;
pub const PAYLOAD_BUFFER_SIZE: usize = 16 * 1024;

/// Minimum hole size (in bytes) for fallocate punch-hole to be worthwhile.
pub const MINIMUM_HOLE_SIZE: u64 = 512 * 1024;

/// Linux errno values not always present in libc bindings.
mod linux_errno {
    pub const ENODATA: i32 = 61;
    pub const ESHUTDOWN: i32 = 108;
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors produced by journal file utility operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalFileError {
    /// Operation not permitted (file opened read-only).
    Eperm,
    /// Invalid argument (null pointer, bad fd, etc.).
    Einval,
    /// Corrupted journal file (bad message format).
    Ebadmsg,
    /// Referenced object offset out of bounds.
    Eaddrnotavail,
    /// Truncated journal file.
    Enodata,
    /// Journal file is from a different machine.
    Ehostdown,
    /// Incompatible journal feature flag.
    Eprotonosupport,
    /// Unclean shutdown detected.
    Ebusy,
    /// Journal already archived.
    Eshutdown,
    /// I/O error (including SIGBUS on mmap).
    Eio,
    /// File has been deleted.
    Eidrm,
    /// Operation not supported (e.g. hole punching on tmpfs).
    Eopnotsupp,
    /// Unrecognized errno value.
    Other(i32),
}

impl JournalFileError {
    /// Convert to systemd's negative-errno return convention.
    pub fn to_neg_errno(self) -> i32 {
        match self {
            Self::Eperm => -libc::EPERM,
            Self::Einval => -libc::EINVAL,
            Self::Ebadmsg => -libc::EBADMSG,
            Self::Eaddrnotavail => -libc::EADDRNOTAVAIL,
            Self::Enodata => -linux_errno::ENODATA,
            Self::Ehostdown => -libc::EHOSTDOWN,
            Self::Eprotonosupport => -libc::EPROTONOSUPPORT,
            Self::Ebusy => -libc::EBUSY,
            Self::Eshutdown => -linux_errno::ESHUTDOWN,
            Self::Eio => -libc::EIO,
            Self::Eidrm => -libc::EIDRM,
            Self::Eopnotsupp => -libc::EOPNOTSUPP,
            Self::Other(e) => -e,
        }
    }

    fn from_errno(raw: i32) -> Self {
        match raw {
            libc::EPERM => Self::Eperm,
            libc::EINVAL => Self::Einval,
            libc::EBADMSG => Self::Ebadmsg,
            libc::EADDRNOTAVAIL => Self::Eaddrnotavail,
            linux_errno::ENODATA => Self::Enodata,
            libc::EHOSTDOWN => Self::Ehostdown,
            libc::EPROTONOSUPPORT => Self::Eprotonosupport,
            libc::EBUSY => Self::Ebusy,
            linux_errno::ESHUTDOWN => Self::Eshutdown,
            libc::EIO => Self::Eio,
            libc::EIDRM => Self::Eidrm,
            libc::EOPNOTSUPP | libc::ENOSYS => Self::Eopnotsupp,
            other => Self::Other(other),
        }
    }

    fn last_errno() -> Self {
        let e = crate::ffi::get_errno();
        Self::from_errno(e)
    }
}

impl std::fmt::Display for JournalFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eperm => write!(f, "Operation not permitted"),
            Self::Einval => write!(f, "Invalid argument"),
            Self::Ebadmsg => write!(f, "Corrupted journal file"),
            Self::Eaddrnotavail => write!(f, "Object offset out of bounds"),
            Self::Enodata => write!(f, "Truncated journal file"),
            Self::Ehostdown => write!(f, "Foreign machine journal"),
            Self::Eprotonosupport => write!(f, "Incompatible feature"),
            Self::Ebusy => write!(f, "Unclean shutdown"),
            Self::Eshutdown => write!(f, "Already archived"),
            Self::Eio => write!(f, "I/O error"),
            Self::Eidrm => write!(f, "File deleted"),
            Self::Eopnotsupp => write!(f, "Operation not supported"),
            Self::Other(e) => write!(f, "errno({})", e),
        }
    }
}

impl std::error::Error for JournalFileError {}

type Result<T> = std::result::Result<T, JournalFileError>;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Offline state machine states for journal file transitions.
///
/// Mirrors the C `OfflineState` enum in `journal-file.h`.
/// The state machine drives the async offline thread that fsyncs
/// and optionally punches holes before marking a journal offline/archived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OfflineState {
    /// Thread has been joined; no offline operation pending.
    Joined = 0,
    /// Currently syncing (fsync) the journal file.
    Syncing = 1,
    /// Post-sync: writing offline/archived state to the header.
    Offlining = 2,
    /// Cancellation requested; offline thread should abort.
    Cancel = 3,
    /// Restart requested while syncing → loop back to Syncing.
    AgainFromSyncing = 4,
    /// Restart requested while offlining → loop back to Syncing.
    AgainFromOfflining = 5,
    /// Offline operation completed successfully.
    Done = 6,
}

/// Journal file header state field.
///
/// Mirrors the C `STATE_OFFLINE / STATE_ONLINE / STATE_ARCHIVED` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum JournalState {
    Offline = 0,
    Online = 1,
    Archived = 2,
}

// ── Bitflags ──────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Journal file feature and compression flags.
    ///
    /// Mirrors `JournalFileFlags` and the `HEADER_INCOMPATIBLE_*` /
    /// `HEADER_COMPATIBLE_*` constants from the on-disk format.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct JournalFileFlags: u32 {
        const TRUSTED                              = 1 << 0;
        const COMPRESS                             = 1 << 1;
        const SEAL                                 = 1 << 2;
        const HEADER_INCOMPATIBLE_COMPRESSED_XZ    = 1 << 3;
        const HEADER_INCOMPATIBLE_COMPRESSED_LZ4   = 1 << 4;
        const HEADER_INCOMPATIBLE_COMPRESSED_ZSTD  = 1 << 5;
        const HEADER_INCOMPATIBLE_KEYED_HASH       = 1 << 6;
        const HEADER_COMPATIBLE_SEALED             = 1 << 7;
        const HEADER_INCOMPATIBLE_SEALED           = 1 << 8;
        const HEADER_INCOMPATIBLE_COMPRESSED_ZSTD_FAST = 1 << 9;
        const HEADER_INCOMPATIBLE_COMPRESSED_XZ_FAST  = 1 << 10;
        const HEADER_INCOMPATIBLE_COMPRESSED_LZ4HC   = 1 << 11;
        const HEADER_INCOMPATIBLE_COMPACT           = 1 << 12;
    }
}

// ── Offline state machine ─────────────────────────────────────────────────

/// Result of [`OfflineState::try_restart`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineTransition {
    /// Already in a restart-pending state; no transition needed.
    AlreadyRestarting,
    /// Transition to this state to trigger a restart.
    TransitionTo(OfflineState),
    /// No restart needed (terminal state: Done or Joined).
    NoRestart,
}

impl OfflineState {
    /// Returns `true` if the journal is mid-offline (any state except Done/Joined).
    ///
    /// Mirrors `journal_file_is_offlining()`.
    pub fn is_offlining(self) -> bool {
        !matches!(self, OfflineState::Done | OfflineState::Joined)
    }

    /// Check whether the offline thread is in a restartable state.
    ///
    /// Mirrors the CAS loop in `journal_file_set_offline_try_restart()`.
    pub fn try_restart(self) -> OfflineTransition {
        match self {
            Self::AgainFromSyncing | Self::AgainFromOfflining => {
                OfflineTransition::AlreadyRestarting
            }
            Self::Cancel => OfflineTransition::TransitionTo(Self::AgainFromSyncing),
            Self::Syncing => OfflineTransition::TransitionTo(Self::AgainFromSyncing),
            Self::Offlining => OfflineTransition::TransitionTo(Self::AgainFromOfflining),
            Self::Done | Self::Joined => OfflineTransition::NoRestart,
        }
    }

    /// Perform one step of the offline internal state machine.
    ///
    /// This is the pure-logic core of `journal_file_set_offline_internal()`.
    /// Returns the action the caller should take next.
    pub fn step(self) -> OfflineAction {
        match self {
            Self::Cancel => OfflineAction::TransitionTo(Self::Done),
            Self::AgainFromSyncing | Self::AgainFromOfflining => {
                OfflineAction::TransitionTo(Self::Syncing)
            }
            Self::Syncing => OfflineAction::SyncAndTransition(Self::Offlining),
            Self::Offlining => OfflineAction::TransitionTo(Self::Done),
            Self::Done | Self::Joined => OfflineAction::Finished,
        }
    }

    /// Determine the target [`JournalState`] after offline completes.
    pub fn target_journal_state(archive: bool) -> JournalState {
        if archive {
            JournalState::Archived
        } else {
            JournalState::Offline
        }
    }
}

/// Actions emitted by the offline state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineAction {
    /// Transition directly to a new state (no side-effects).
    TransitionTo(OfflineState),
    /// Perform fsync (and optional hole punching / COW rewrite), then
    /// transition to the given state.
    SyncAndTransition(OfflineState),
    /// State machine has reached a terminal state.
    Finished,
}

// ── Hole punching ─────────────────────────────────────────────────────────

/// A file region eligible for hole punching via `fallocate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoleRegion {
    pub offset: u64,
    pub size: u64,
}

impl HoleRegion {
    /// Create a new hole region.
    pub const fn new(offset: u64, size: u64) -> Self {
        Self { offset, size }
    }

    /// Returns `true` if the region is large enough to be worth punching.
    pub fn meets_minimum_size(&self) -> bool {
        self.size >= MINIMUM_HOLE_SIZE
    }

    /// Compute the tail hole region of a journal file.
    ///
    /// Given the total file size and the byte offset of the last valid
    /// object's end, returns the region from `tail_end` to `file_size`
    /// if it meets [`MINIMUM_HOLE_SIZE`].
    ///
    /// Mirrors `journal_file_end_punch_hole()`.
    pub fn tail_hole(file_size: u64, tail_end: u64) -> Option<Self> {
        if tail_end > file_size {
            return None;
        }
        let region = Self::new(tail_end, file_size - tail_end);
        if region.meets_minimum_size() {
            Some(region)
        } else {
            None
        }
    }
}

/// Punch a hole in a file, removing backing storage for the given region.
///
/// Wraps `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)`.
/// Returns [`JournalFileError::Eopnotsupp`] when the filesystem does not
/// support hole punching (caller should skip silently).
pub fn punch_hole(fd: i32, offset: u64, size: u64) -> Result<()> {
    if fd < 0 || size == 0 {
        return Err(JournalFileError::Einval);
    }
    // SAFETY: fd is validated >= 0; offset/size are u64 values from journal metadata.
    let ret = unsafe {
        crate::ffi::fallocate(
            fd,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            offset as i64,
            size as i64,
        )
    };
    if ret < 0 {
        let err = JournalFileError::last_errno();
        if matches!(err, JournalFileError::Eopnotsupp) {
            return Err(JournalFileError::Eopnotsupp);
        }
        return Err(err);
    }
    Ok(())
}

/// Synchronize a file's in-core state with storage device.
///
/// Wraps `fsync(2)`.
pub fn sync_fd(fd: i32) -> Result<()> {
    if fd < 0 {
        return Err(JournalFileError::Einval);
    }
    // SAFETY: fd validated >= 0.
    let ret = unsafe { libc::fsync(fd) };
    if ret < 0 {
        return Err(JournalFileError::last_errno());
    }
    Ok(())
}

/// Read bytes from a file at a specific offset without advancing the file offset.
///
/// Wraps `pread(2)`. Returns the number of bytes actually read.
pub fn pread_bytes(fd: i32, buf: &mut [u8], offset: u64) -> Result<usize> {
    if fd < 0 || buf.is_empty() {
        return Err(JournalFileError::Einval);
    }
    // SAFETY: fd validated, buf is a valid mutable slice.
    let ret = unsafe {
        libc::pread(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            offset as i64,
        )
    };
    if ret < 0 {
        return Err(JournalFileError::last_errno());
    }
    Ok(ret as usize)
}

// ── Hash table iteration ──────────────────────────────────────────────────

/// A single hash table bucket (on-disk layout).
///
/// Mirrors the C `HashItem` struct from `journal-def.h`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct HashItem {
    pub head_hash_offset: u64,
    pub tail_hash_offset: u64,
}

impl HashItem {
    /// Size of one [`HashItem`] in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Create a zeroed (empty) hash item.
    pub const fn zero() -> Self {
        Self {
            head_hash_offset: 0,
            tail_hash_offset: 0,
        }
    }

    /// Returns `true` if this bucket has no entries.
    pub fn is_empty(&self) -> bool {
        self.head_hash_offset == 0
    }

    /// Interpret a byte slice as a slice of [`HashItem`]s.
    ///
    /// Partial trailing items (fewer than `SIZE` bytes) are silently ignored,
    /// mirroring the C code's `n -= n % sizeof(HashItem)` rounding.
    pub fn slice_from_bytes(buf: &[u8]) -> &[Self] {
        let count = buf.len() / Self::SIZE;
        if count == 0 {
            return &[];
        }
        let (_, aligned, _) = unsafe { buf.align_to::<Self>() };
        let take = aligned.len().min(count);
        &aligned[..take]
    }
}

/// Iterate over non-empty hash table buckets.
pub fn iter_nonempty_buckets(items: &[HashItem]) -> impl Iterator<Item = &HashItem> {
    items.iter().filter(|h| !h.is_empty())
}

// ── Entry array helpers ───────────────────────────────────────────────────

/// Compute the number of entry items stored in an entry-array object.
///
/// An entry-array object consists of an 8-byte object header plus an 8-byte
/// `next_entry_array_offset`, followed by the item payload.  Each item is
/// 8 bytes in regular mode or 4 bytes in compact mode.
///
/// Mirrors `journal_file_entry_array_n_items()`.
pub fn entry_array_n_items(object_size: u64, compact: bool) -> u64 {
    const FIXED_OVERHEAD: u64 = 16; // ObjectHeader(8) + next_entry_array_offset(8)
    let item_size: u64 = if compact { 4 } else { 8 };
    object_size.saturating_sub(FIXED_OVERHEAD) / item_size
}

/// Size in bytes of a single entry-array item.
pub fn entry_array_item_size(compact: bool) -> usize {
    if compact { 4 } else { 8 }
}

/// Compute the unused tail region of the final entry array in a chain.
///
/// Given the on-disk layout of the last entry-array object, the number of
/// entries actually used, and the total items in the array, returns a
/// [`HoleRegion`] covering the unused trailing items — but only if it is
/// large enough to justify hole punching.
///
/// Mirrors `journal_file_entry_array_punch_hole()`.
pub fn entry_array_unused_hole(
    array_offset: u64,
    object_size: u64,
    n_entries: u64,
    n_total_items: u64,
    compact: bool,
) -> Option<HoleRegion> {
    if n_entries > n_total_items {
        return None;
    }
    let n_unused = n_total_items - n_entries;
    if n_unused == 0 {
        return None;
    }
    let item_size = entry_array_item_size(compact) as u64;
    let items_in_this_array = (object_size.saturating_sub(16)) / item_size;
    let used = items_in_this_array - n_unused;
    let hole_offset = array_offset + 16 + used * item_size;
    let hole_size = array_offset + object_size - hole_offset;
    let region = HoleRegion::new(hole_offset, hole_size);
    if region.meets_minimum_size() {
        Some(region)
    } else {
        None
    }
}

// ── Reliable-open error classification ────────────────────────────────────

/// Check whether a negative-errno return from `journal_file_open` indicates
/// a corruption/shutdown issue that justifies rotating the file away and
/// retrying the open.
///
/// Mirrors the `IN_SET(r, -EBADMSG, -EADDRNOTAVAIL, ...)` check in
/// `journal_file_open_reliably()`.
pub fn is_recoverable_open_error(neg_errno: i32) -> bool {
    const RECOVERABLE: &[i32] = &[
        -libc::EBADMSG,
        -libc::EADDRNOTAVAIL,
        -linux_errno::ENODATA,
        -libc::EHOSTDOWN,
        -libc::EPROTONOSUPPORT,
        -libc::EBUSY,
        -linux_errno::ESHUTDOWN,
        -libc::EIO,
        -libc::EIDRM,
    ];
    RECOVERABLE.contains(&neg_errno)
}

/// Determine whether the open flags allow recovery rotation.
///
/// The journal is only rotated on corruption if:
/// 1. The file was opened for write access (not O_RDONLY).
/// 2. The O_CREAT flag was set (caller intends to create).
/// 3. The filename ends with `.journal`.
///
/// Mirrors the guard checks in `journal_file_open_reliably()`.
pub fn can_rotate_on_corruption(fname: &str, open_flags: i32) -> bool {
    if (open_flags & libc::O_ACCMODE) == libc::O_RDONLY {
        return false;
    }
    if open_flags & libc::O_CREAT == 0 {
        return false;
    }
    fname.ends_with(".journal")
}

// ── Journal state helpers ─────────────────────────────────────────────────

impl JournalState {
    /// Parse a journal state from the raw on-disk header byte.
    pub fn from_raw(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Offline),
            1 => Some(Self::Online),
            2 => Some(Self::Archived),
            _ => None,
        }
    }

    /// Serialize to the raw on-disk header byte.
    pub const fn to_raw(self) -> u8 {
        self as u8
    }

    /// Returns `true` if the journal is in the online (writable) state.
    pub const fn is_online(self) -> bool {
        matches!(self, Self::Online)
    }

    /// Returns `true` if the journal is offline or archived (not writable).
    pub const fn is_offline(self) -> bool {
        matches!(self, Self::Offline | Self::Archived)
    }
}

// ── Set-offline decision logic ────────────────────────────────────────────

/// Decision point for `journal_file_set_offline()`: what should the caller do?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOfflineAction {
    /// The journal is already in the target state; just join any lingering thread.
    JoinExisting,
    /// An in-flight offline was restarted; if `wait` is true, join the thread.
    RestartedJoin,
    /// An in-flight offline was restarted and `wait` is false; return immediately.
    RestartedReturn,
    /// Start a new offline operation.
    StartNew,
}

/// Compute the initial action for `journal_file_set_offline()`.
///
/// This is the decision logic before any thread or fsync is initiated.
pub fn set_offline_decision(
    current_journal_state: JournalState,
    target_journal_state: JournalState,
    currently_offlining: bool,
    offline_state: OfflineState,
    wait: bool,
) -> SetOfflineAction {
    // Already in the desired state — just join the thread.
    if !currently_offlining && current_journal_state == target_journal_state {
        return SetOfflineAction::JoinExisting;
    }

    // Try restarting an in-flight offline thread.
    match offline_state.try_restart() {
        OfflineTransition::AlreadyRestarting => {
            if wait {
                SetOfflineAction::RestartedJoin
            } else {
                SetOfflineAction::RestartedReturn
            }
        }
        OfflineTransition::TransitionTo(_) => {
            if wait {
                SetOfflineAction::RestartedJoin
            } else {
                SetOfflineAction::RestartedReturn
            }
        }
        OfflineTransition::NoRestart => SetOfflineAction::StartNew,
    }
}

// ── Rotate decision logic ─────────────────────────────────────────────────

/// Validates the inputs for `journal_file_rotate()`.
///
/// Returns `Err(Einval)` if either the file pointer or the inner pointer is null.
pub fn validate_rotate_inputs(has_file: bool, has_inner: bool) -> Result<()> {
    if !has_file || !has_inner {
        Err(JournalFileError::Einval)
    } else {
        Ok(())
    }
}

/// Validates the inputs for `journal_file_open_reliably()`.
pub fn validate_open_reliably_inputs(fname_valid: bool, ret_valid: bool) -> Result<()> {
    if !fname_valid || !ret_valid {
        Err(JournalFileError::Einval)
    } else {
        Ok(())
    }
}

/// Validates inputs for `journal_file_set_offline()`.
pub fn validate_set_offline_inputs(writable: bool, fd_valid: bool, has_header: bool) -> Result<()> {
    if !writable {
        return Err(JournalFileError::Eperm);
    }
    if !fd_valid || !has_header {
        return Err(JournalFileError::Einval);
    }
    Ok(())
}

/// Minimal journal-file lifecycle state needed to mirror the C wrapper layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalLifecycleState {
    pub journal_state: JournalState,
    pub offline_state: OfflineState,
    pub archive: bool,
    pub writable: bool,
    pub fd_valid: bool,
    pub has_header: bool,
    pub sealed: bool,
    pub post_change_timer_enabled: bool,
}

/// What `journal_file_write_final_tag()` should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalTagAction {
    Skip,
    Append,
}

/// Safe Rust equivalent of `journal_file_is_offlining()`.
pub fn journal_file_is_offlining(state: JournalLifecycleState) -> bool {
    state.offline_state.is_offlining()
}

/// Safe Rust equivalent of the decision inside `journal_file_write_final_tag()`.
pub fn write_final_tag_action(state: JournalLifecycleState) -> FinalTagAction {
    if state.sealed && state.writable {
        FinalTagAction::Append
    } else {
        FinalTagAction::Skip
    }
}

/// Execution plan for `journal_file_set_offline()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetOfflinePlan {
    pub action: SetOfflineAction,
    pub target_journal_state: JournalState,
    pub restart_to: Option<OfflineState>,
    pub start_offline_state: Option<OfflineState>,
    pub join_offline_thread: bool,
    pub run_sync: bool,
    pub spawn_thread: bool,
}

/// Build the wrapper-level plan for `journal_file_set_offline()`.
pub fn plan_set_offline(state: JournalLifecycleState, wait: bool) -> Result<SetOfflinePlan> {
    validate_set_offline_inputs(state.writable, state.fd_valid, state.has_header)?;

    let target_journal_state = OfflineState::target_journal_state(state.archive);
    let action = set_offline_decision(
        state.journal_state,
        target_journal_state,
        journal_file_is_offlining(state),
        state.offline_state,
        wait,
    );

    let restart_to = match action {
        SetOfflineAction::RestartedJoin | SetOfflineAction::RestartedReturn => {
            match state.offline_state.try_restart() {
                OfflineTransition::TransitionTo(next) => Some(next),
                OfflineTransition::AlreadyRestarting => Some(state.offline_state),
                OfflineTransition::NoRestart => None,
            }
        }
        _ => None,
    };

    Ok(SetOfflinePlan {
        action,
        target_journal_state,
        restart_to,
        start_offline_state: matches!(action, SetOfflineAction::StartNew)
            .then_some(OfflineState::Syncing),
        join_offline_thread: matches!(
            action,
            SetOfflineAction::JoinExisting | SetOfflineAction::RestartedJoin
        ),
        run_sync: matches!(action, SetOfflineAction::StartNew) && wait,
        spawn_thread: matches!(action, SetOfflineAction::StartNew) && !wait,
    })
}

/// Execution plan for `journal_file_offline_close()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineClosePlan {
    pub final_tag_action: FinalTagAction,
    pub flush_post_change: bool,
    pub disable_post_change_timer: bool,
    pub set_offline: SetOfflinePlan,
    pub close_file: bool,
}

/// Safe Rust equivalent of `journal_file_offline_close()`.
pub fn plan_offline_close(state: JournalLifecycleState) -> Result<OfflineClosePlan> {
    Ok(OfflineClosePlan {
        final_tag_action: write_final_tag_action(state),
        flush_post_change: state.post_change_timer_enabled,
        disable_post_change_timer: state.post_change_timer_enabled,
        set_offline: plan_set_offline(state, true)?,
        close_file: true,
    })
}

/// Execution plan for `journal_file_initiate_close()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiateClosePlan {
    Deferred { set_offline: SetOfflinePlan },
    Immediate { offline_close: OfflineClosePlan },
}

/// Safe Rust equivalent of `journal_file_initiate_close()`.
pub fn plan_initiate_close(
    state: JournalLifecycleState,
    deferred_closes_available: bool,
) -> Result<InitiateClosePlan> {
    if deferred_closes_available {
        return Ok(InitiateClosePlan::Deferred {
            set_offline: plan_set_offline(state, false)?,
        });
    }

    Ok(InitiateClosePlan::Immediate {
        offline_close: plan_offline_close(state)?,
    })
}

/// Execution plan for `journal_file_rotate()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotatePlan {
    pub final_tag_action: FinalTagAction,
    pub archive_current_file: bool,
    pub clear_deferred_closes: bool,
    pub open_new_file_from_template: bool,
    pub close_previous_after_open: InitiateClosePlan,
}

/// Safe Rust equivalent of the control flow in `journal_file_rotate()`.
pub fn plan_rotate(
    state: JournalLifecycleState,
    has_file: bool,
    has_inner: bool,
    deferred_closes_available: bool,
) -> Result<RotatePlan> {
    validate_rotate_inputs(has_file, has_inner)?;

    Ok(RotatePlan {
        final_tag_action: write_final_tag_action(state),
        archive_current_file: true,
        clear_deferred_closes: true,
        open_new_file_from_template: true,
        close_previous_after_open: plan_initiate_close(state, deferred_closes_available)?,
    })
}

/// Recovery plan for `journal_file_open_reliably()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenReliablyPlan {
    ReturnOriginalResult(i32),
    RotateCorrupted {
        original_result: i32,
        open_template_read_only: bool,
        dispose_corrupted_file: bool,
        reopen_with_template: bool,
    },
}

/// Safe Rust equivalent of the retry branch in `journal_file_open_reliably()`.
pub fn plan_open_reliably(
    fname: &str,
    open_flags: i32,
    original_result: i32,
    fname_valid: bool,
    ret_valid: bool,
) -> Result<OpenReliablyPlan> {
    validate_open_reliably_inputs(fname_valid, ret_valid)?;

    if !is_recoverable_open_error(original_result) || !can_rotate_on_corruption(fname, open_flags) {
        return Ok(OpenReliablyPlan::ReturnOriginalResult(original_result));
    }

    Ok(OpenReliablyPlan::RotateCorrupted {
        original_result,
        open_template_read_only: true,
        dispose_corrupted_file: true,
        reopen_with_template: true,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ─────────────────────────────────────────────────────────

    #[test]
    fn test_constants_match_c() {
        assert_eq!(PAYLOAD_BUFFER_SIZE, 16 * 1024);
        assert_eq!(MINIMUM_HOLE_SIZE, 512 * 1024);
        assert_eq!(HashItem::SIZE, 16);
    }

    // ── OfflineState ──────────────────────────────────────────────────────

    #[test]
    fn test_offline_state_is_offlining() {
        assert!(OfflineState::Syncing.is_offlining());
        assert!(OfflineState::Offlining.is_offlining());
        assert!(OfflineState::Cancel.is_offlining());
        assert!(OfflineState::AgainFromSyncing.is_offlining());
        assert!(OfflineState::AgainFromOfflining.is_offlining());
        assert!(!OfflineState::Done.is_offlining());
        assert!(!OfflineState::Joined.is_offlining());
    }

    #[test]
    fn test_offline_state_try_restart() {
        // Already in restart states
        assert_eq!(
            OfflineState::AgainFromSyncing.try_restart(),
            OfflineTransition::AlreadyRestarting
        );
        assert_eq!(
            OfflineState::AgainFromOfflining.try_restart(),
            OfflineTransition::AlreadyRestarting
        );
        // Cancel → AgainFromSyncing
        assert_eq!(
            OfflineState::Cancel.try_restart(),
            OfflineTransition::TransitionTo(OfflineState::AgainFromSyncing)
        );
        // Syncing → AgainFromSyncing
        assert_eq!(
            OfflineState::Syncing.try_restart(),
            OfflineTransition::TransitionTo(OfflineState::AgainFromSyncing)
        );
        // Offlining → AgainFromOfflining
        assert_eq!(
            OfflineState::Offlining.try_restart(),
            OfflineTransition::TransitionTo(OfflineState::AgainFromOfflining)
        );
        // Terminal states → NoRestart
        assert_eq!(
            OfflineState::Done.try_restart(),
            OfflineTransition::NoRestart
        );
        assert_eq!(
            OfflineState::Joined.try_restart(),
            OfflineTransition::NoRestart
        );
    }

    #[test]
    fn test_offline_state_step() {
        // Cancel → Done
        assert_eq!(
            OfflineState::Cancel.step(),
            OfflineAction::TransitionTo(OfflineState::Done)
        );
        // AgainFromSyncing → Syncing
        assert_eq!(
            OfflineState::AgainFromSyncing.step(),
            OfflineAction::TransitionTo(OfflineState::Syncing)
        );
        // AgainFromOfflining → Syncing
        assert_eq!(
            OfflineState::AgainFromOfflining.step(),
            OfflineAction::TransitionTo(OfflineState::Syncing)
        );
        // Syncing → sync then Offlining
        assert_eq!(
            OfflineState::Syncing.step(),
            OfflineAction::SyncAndTransition(OfflineState::Offlining)
        );
        // Offlining → Done
        assert_eq!(
            OfflineState::Offlining.step(),
            OfflineAction::TransitionTo(OfflineState::Done)
        );
        // Terminal states → Finished
        assert_eq!(OfflineState::Done.step(), OfflineAction::Finished);
        assert_eq!(OfflineState::Joined.step(), OfflineAction::Finished);
    }

    #[test]
    fn test_offline_state_target_journal_state() {
        assert_eq!(
            OfflineState::target_journal_state(false),
            JournalState::Offline
        );
        assert_eq!(
            OfflineState::target_journal_state(true),
            JournalState::Archived
        );
    }

    // ── JournalState ──────────────────────────────────────────────────────

    #[test]
    fn test_journal_state_roundtrip() {
        for state in [
            JournalState::Offline,
            JournalState::Online,
            JournalState::Archived,
        ] {
            assert_eq!(JournalState::from_raw(state.to_raw()), Some(state));
        }
        assert_eq!(JournalState::from_raw(99), None);
    }

    #[test]
    fn test_journal_state_predicates() {
        assert!(JournalState::Online.is_online());
        assert!(!JournalState::Offline.is_online());
        assert!(!JournalState::Archived.is_online());

        assert!(JournalState::Offline.is_offline());
        assert!(JournalState::Archived.is_offline());
        assert!(!JournalState::Online.is_offline());
    }

    // ── HoleRegion ────────────────────────────────────────────────────────

    #[test]
    fn test_hole_region_meets_minimum_size() {
        let small = HoleRegion::new(0, MINIMUM_HOLE_SIZE - 1);
        assert!(!small.meets_minimum_size());

        let exact = HoleRegion::new(0, MINIMUM_HOLE_SIZE);
        assert!(exact.meets_minimum_size());

        let large = HoleRegion::new(1024, 2 * MINIMUM_HOLE_SIZE);
        assert!(large.meets_minimum_size());
    }

    #[test]
    fn test_hole_region_tail_hole() {
        // Exact minimum size
        assert_eq!(
            HoleRegion::tail_hole(MINIMUM_HOLE_SIZE, 0),
            Some(HoleRegion::new(0, MINIMUM_HOLE_SIZE))
        );

        // Just below minimum
        assert_eq!(HoleRegion::tail_hole(MINIMUM_HOLE_SIZE - 1, 0), None);

        // tail_end == file_size → zero-size hole
        assert_eq!(HoleRegion::tail_hole(1024, 1024), None);

        // tail_end > file_size → invalid
        assert_eq!(HoleRegion::tail_hole(100, 200), None);

        // Typical case
        let file_size = 4 * 1024 * 1024;
        let tail_end = 3 * 1024 * 1024;
        let hole = HoleRegion::tail_hole(file_size, tail_end).unwrap();
        assert_eq!(hole.offset, tail_end);
        assert_eq!(hole.size, 1024 * 1024);
    }

    // ── HashItem ──────────────────────────────────────────────────────────

    #[test]
    fn test_hash_item_default_is_empty() {
        let item = HashItem::zero();
        assert!(item.is_empty());
    }

    #[test]
    fn test_hash_item_nonempty() {
        let item = HashItem {
            head_hash_offset: 1024,
            tail_hash_offset: 2048,
        };
        assert!(!item.is_empty());
    }

    #[test]
    fn test_hash_item_slice_from_bytes() {
        // 3 items worth of bytes
        let buf = [0u8; 48]; // 3 × 16
        let items = HashItem::slice_from_bytes(&buf);
        assert_eq!(items.len(), 3);
        assert!(items.iter().all(|h| h.is_empty()));

        // Partial trailing item is ignored
        let buf = [0u8; 50]; // 3 items + 2 extra bytes
        let items = HashItem::slice_from_bytes(&buf);
        assert_eq!(items.len(), 3);

        // Empty buffer
        let items = HashItem::slice_from_bytes(&[]);
        assert!(items.is_empty());

        // Less than one item
        let items = HashItem::slice_from_bytes(&[0u8; 15]);
        assert!(items.is_empty());
    }

    #[test]
    fn test_iter_nonempty_buckets() {
        let items = [
            HashItem::zero(),
            HashItem {
                head_hash_offset: 1,
                tail_hash_offset: 2,
            },
            HashItem::zero(),
            HashItem {
                head_hash_offset: 3,
                tail_hash_offset: 4,
            },
        ];
        let nonempty: Vec<_> = iter_nonempty_buckets(&items).collect();
        assert_eq!(nonempty.len(), 2);
        assert_eq!(nonempty[0].head_hash_offset, 1);
        assert_eq!(nonempty[1].head_hash_offset, 3);
    }

    // ── Entry array ───────────────────────────────────────────────────────

    #[test]
    fn test_entry_array_n_items_regular() {
        // object_size = 16 (header) + 3 × 8 = 40
        assert_eq!(entry_array_n_items(40, false), 3);
        // Just header
        assert_eq!(entry_array_n_items(16, false), 0);
        // Header + partial
        assert_eq!(entry_array_n_items(20, false), 0);
        // Zero size
        assert_eq!(entry_array_n_items(0, false), 0);
        // Undersize
        assert_eq!(entry_array_n_items(8, false), 0);
    }

    #[test]
    fn test_entry_array_n_items_compact() {
        // object_size = 16 (header) + 4 × 4 = 32
        assert_eq!(entry_array_n_items(32, true), 4);
        // 16 + 1 × 4 = 20
        assert_eq!(entry_array_n_items(20, true), 1);
        // Just header
        assert_eq!(entry_array_n_items(16, true), 0);
    }

    #[test]
    fn test_entry_array_item_size() {
        assert_eq!(entry_array_item_size(false), 8);
        assert_eq!(entry_array_item_size(true), 4);
    }

    #[test]
    fn test_entry_array_unused_hole() {
        // 100 items in array, 80 used, 20 unused, regular mode
        let object_size = 16 + 100 * 8; // 816
        let hole = entry_array_unused_hole(1000, object_size, 80, 100, false);
        // unused = 20 items × 8 bytes = 160 bytes < MINIMUM_HOLE_SIZE
        assert!(hole.is_none());

        // Compact mode, more items — unused portion must exceed MINIMUM_HOLE_SIZE.
        let object_size = 16 + 200_000 * 4;
        let hole = entry_array_unused_hole(0, object_size, 10, 200_000, true).unwrap();
        assert_eq!(hole.offset, 16 + 10 * 4);
        assert_eq!(hole.size, (200_000 - 10) * 4);

        // n_entries > n_total_items → error
        assert!(entry_array_unused_hole(0, 100, 200, 100, false).is_none());

        // n_entries == n_total_items → no unused
        assert!(entry_array_unused_hole(0, 100, 50, 50, false).is_none());
    }

    // ── Error classification ──────────────────────────────────────────────

    #[test]
    fn test_is_recoverable_open_error() {
        // All recoverable errors
        assert!(is_recoverable_open_error(-libc::EBADMSG));
        assert!(is_recoverable_open_error(-libc::EADDRNOTAVAIL));
        assert!(is_recoverable_open_error(-linux_errno::ENODATA));
        assert!(is_recoverable_open_error(-libc::EHOSTDOWN));
        assert!(is_recoverable_open_error(-libc::EPROTONOSUPPORT));
        assert!(is_recoverable_open_error(-libc::EBUSY));
        assert!(is_recoverable_open_error(-linux_errno::ESHUTDOWN));
        assert!(is_recoverable_open_error(-libc::EIO));
        assert!(is_recoverable_open_error(-libc::EIDRM));

        // Non-recoverable errors
        assert!(!is_recoverable_open_error(-libc::EINVAL));
        assert!(!is_recoverable_open_error(-libc::ENOENT));
        assert!(!is_recoverable_open_error(-libc::ENOMEM));
        assert!(!is_recoverable_open_error(0)); // success
        assert!(!is_recoverable_open_error(42)); // positive "error"
    }

    #[test]
    fn test_can_rotate_on_corruption() {
        // Read-only → no
        assert!(!can_rotate_on_corruption("test.journal", libc::O_RDONLY));

        // No O_CREAT → no
        assert!(!can_rotate_on_corruption("test.journal", libc::O_RDWR));

        // Wrong extension → no
        assert!(!can_rotate_on_corruption(
            "test.log",
            libc::O_RDWR | libc::O_CREAT
        ));

        // All conditions met → yes
        assert!(can_rotate_on_corruption(
            "user-1000.journal",
            libc::O_RDWR | libc::O_CREAT
        ));
    }

    // ── JournalFileFlags ──────────────────────────────────────────────────

    #[test]
    fn test_journal_file_flags() {
        let empty = JournalFileFlags::empty();
        assert!(empty.is_empty());

        let trusted = JournalFileFlags::TRUSTED;
        assert_eq!(trusted.bits(), 1);

        let combined = JournalFileFlags::TRUSTED | JournalFileFlags::COMPRESS;
        assert_eq!(combined.bits(), 3);
        assert!(combined.contains(JournalFileFlags::TRUSTED));
        assert!(combined.contains(JournalFileFlags::COMPRESS));
        assert!(!combined.contains(JournalFileFlags::SEAL));
    }

    // ── JournalFileError ──────────────────────────────────────────────────

    #[test]
    fn test_journal_file_error_to_neg_errno() {
        assert_eq!(JournalFileError::Eperm.to_neg_errno(), -libc::EPERM);
        assert_eq!(JournalFileError::Einval.to_neg_errno(), -libc::EINVAL);
        assert_eq!(JournalFileError::Ebadmsg.to_neg_errno(), -libc::EBADMSG);
        assert_eq!(JournalFileError::Eio.to_neg_errno(), -libc::EIO);
        assert_eq!(JournalFileError::Eidrm.to_neg_errno(), -libc::EIDRM);
    }

    #[test]
    fn test_journal_file_error_display() {
        assert!(!JournalFileError::Eperm.to_string().is_empty());
        assert!(!JournalFileError::Einval.to_string().is_empty());
        assert!(!JournalFileError::Other(999).to_string().is_empty());
    }

    #[test]
    fn test_journal_file_error_from_errno() {
        assert_eq!(
            JournalFileError::from_errno(libc::EINVAL),
            JournalFileError::Einval
        );
        assert_eq!(
            JournalFileError::from_errno(libc::EIO),
            JournalFileError::Eio
        );
        assert_eq!(
            JournalFileError::from_errno(libc::EOPNOTSUPP),
            JournalFileError::Eopnotsupp
        );
        assert_eq!(
            JournalFileError::from_errno(999),
            JournalFileError::Other(999)
        );
    }

    // ── Set-offline decision ──────────────────────────────────────────────

    #[test]
    fn test_set_offline_decision_already_offline() {
        // Already offline, not offlining → JoinExisting
        assert_eq!(
            set_offline_decision(
                JournalState::Offline,
                JournalState::Offline,
                false,
                OfflineState::Joined,
                false
            ),
            SetOfflineAction::JoinExisting
        );
    }

    #[test]
    fn test_set_offline_decision_restart_wait() {
        // In-flight, wait=true → RestartedJoin
        assert_eq!(
            set_offline_decision(
                JournalState::Online,
                JournalState::Offline,
                true,
                OfflineState::Syncing,
                true
            ),
            SetOfflineAction::RestartedJoin
        );
    }

    #[test]
    fn test_set_offline_decision_restart_no_wait() {
        // In-flight, wait=false → RestartedReturn
        assert_eq!(
            set_offline_decision(
                JournalState::Online,
                JournalState::Offline,
                true,
                OfflineState::Cancel,
                false
            ),
            SetOfflineAction::RestartedReturn
        );
    }

    #[test]
    fn test_set_offline_decision_start_new() {
        // No in-flight thread, not in target state → StartNew
        assert_eq!(
            set_offline_decision(
                JournalState::Online,
                JournalState::Offline,
                false,
                OfflineState::Joined,
                true
            ),
            SetOfflineAction::StartNew
        );
    }

    // ── Validation helpers ────────────────────────────────────────────────

    #[test]
    fn test_validate_rotate_inputs() {
        assert!(validate_rotate_inputs(true, true).is_ok());
        assert_eq!(
            validate_rotate_inputs(false, true).unwrap_err(),
            JournalFileError::Einval
        );
        assert_eq!(
            validate_rotate_inputs(true, false).unwrap_err(),
            JournalFileError::Einval
        );
    }

    #[test]
    fn test_validate_open_reliably_inputs() {
        assert!(validate_open_reliably_inputs(true, true).is_ok());
        assert_eq!(
            validate_open_reliably_inputs(false, true).unwrap_err(),
            JournalFileError::Einval
        );
        assert_eq!(
            validate_open_reliably_inputs(true, false).unwrap_err(),
            JournalFileError::Einval
        );
    }

    #[test]
    fn test_validate_set_offline_inputs() {
        // Writable, valid fd, has header → OK
        assert!(validate_set_offline_inputs(true, true, true).is_ok());
        // Not writable → Eperm
        assert_eq!(
            validate_set_offline_inputs(false, true, true).unwrap_err(),
            JournalFileError::Eperm
        );
        // Invalid fd → Einval
        assert_eq!(
            validate_set_offline_inputs(true, false, true).unwrap_err(),
            JournalFileError::Einval
        );
        // No header → Einval
        assert_eq!(
            validate_set_offline_inputs(true, true, false).unwrap_err(),
            JournalFileError::Einval
        );
    }

    fn sample_state() -> JournalLifecycleState {
        JournalLifecycleState {
            journal_state: JournalState::Online,
            offline_state: OfflineState::Joined,
            archive: false,
            writable: true,
            fd_valid: true,
            has_header: true,
            sealed: false,
            post_change_timer_enabled: false,
        }
    }

    #[test]
    fn test_journal_file_is_offlining_matches_offline_state() {
        let mut state = sample_state();
        assert!(!journal_file_is_offlining(state));

        state.offline_state = OfflineState::Syncing;
        assert!(journal_file_is_offlining(state));
    }

    #[test]
    fn test_write_final_tag_action_requires_sealed_and_writable() {
        let mut state = sample_state();
        assert_eq!(write_final_tag_action(state), FinalTagAction::Skip);

        state.sealed = true;
        assert_eq!(write_final_tag_action(state), FinalTagAction::Append);

        state.writable = false;
        assert_eq!(write_final_tag_action(state), FinalTagAction::Skip);
    }

    #[test]
    fn test_plan_set_offline_start_new_sync() {
        let plan = plan_set_offline(sample_state(), true).unwrap();
        assert_eq!(plan.action, SetOfflineAction::StartNew);
        assert_eq!(plan.target_journal_state, JournalState::Offline);
        assert_eq!(plan.start_offline_state, Some(OfflineState::Syncing));
        assert_eq!(plan.restart_to, None);
        assert!(plan.run_sync);
        assert!(!plan.spawn_thread);
        assert!(!plan.join_offline_thread);
    }

    #[test]
    fn test_plan_set_offline_restart_async() {
        let mut state = sample_state();
        state.offline_state = OfflineState::Syncing;

        let plan = plan_set_offline(state, false).unwrap();
        assert_eq!(plan.action, SetOfflineAction::RestartedReturn);
        assert_eq!(plan.restart_to, Some(OfflineState::AgainFromSyncing));
        assert!(!plan.run_sync);
        assert!(!plan.spawn_thread);
        assert!(!plan.join_offline_thread);
    }

    #[test]
    fn test_plan_set_offline_join_existing_archived_target() {
        let mut state = sample_state();
        state.archive = true;
        state.journal_state = JournalState::Archived;

        let plan = plan_set_offline(state, true).unwrap();
        assert_eq!(plan.action, SetOfflineAction::JoinExisting);
        assert_eq!(plan.target_journal_state, JournalState::Archived);
        assert!(plan.join_offline_thread);
        assert!(!plan.run_sync);
        assert!(!plan.spawn_thread);
    }

    #[test]
    fn test_plan_offline_close_flushes_timer_and_closes() {
        let mut state = sample_state();
        state.sealed = true;
        state.post_change_timer_enabled = true;

        let plan = plan_offline_close(state).unwrap();
        assert_eq!(plan.final_tag_action, FinalTagAction::Append);
        assert!(plan.flush_post_change);
        assert!(plan.disable_post_change_timer);
        assert_eq!(plan.set_offline.action, SetOfflineAction::StartNew);
        assert!(plan.close_file);
    }

    #[test]
    fn test_plan_initiate_close_prefers_deferred_close_set() {
        let plan = plan_initiate_close(sample_state(), true).unwrap();
        assert_eq!(
            plan,
            InitiateClosePlan::Deferred {
                set_offline: SetOfflinePlan {
                    action: SetOfflineAction::StartNew,
                    target_journal_state: JournalState::Offline,
                    restart_to: None,
                    start_offline_state: Some(OfflineState::Syncing),
                    join_offline_thread: false,
                    run_sync: false,
                    spawn_thread: true,
                }
            }
        );
    }

    #[test]
    fn test_plan_initiate_close_falls_back_to_immediate_offline_close() {
        let plan = plan_initiate_close(sample_state(), false).unwrap();
        match plan {
            InitiateClosePlan::Immediate { offline_close } => {
                assert_eq!(offline_close.final_tag_action, FinalTagAction::Skip);
                assert_eq!(offline_close.set_offline.action, SetOfflineAction::StartNew);
                assert!(offline_close.close_file);
            }
            InitiateClosePlan::Deferred { .. } => panic!("expected immediate close"),
        }
    }

    #[test]
    fn test_plan_rotate_clears_deferred_closes_and_opens_from_template() {
        let plan = plan_rotate(sample_state(), true, true, true).unwrap();
        assert_eq!(plan.final_tag_action, FinalTagAction::Skip);
        assert!(plan.archive_current_file);
        assert!(plan.clear_deferred_closes);
        assert!(plan.open_new_file_from_template);
        match plan.close_previous_after_open {
            InitiateClosePlan::Deferred { set_offline } => {
                assert_eq!(set_offline.action, SetOfflineAction::StartNew);
                assert!(set_offline.spawn_thread);
            }
            InitiateClosePlan::Immediate { .. } => panic!("expected deferred close"),
        }
    }

    #[test]
    fn test_plan_open_reliably_returns_original_for_nonrecoverable_errors() {
        let plan = plan_open_reliably("system.journal", libc::O_RDONLY, -libc::EINVAL, true, true)
            .unwrap();
        assert_eq!(plan, OpenReliablyPlan::ReturnOriginalResult(-libc::EINVAL));
    }

    #[test]
    fn test_plan_open_reliably_returns_original_when_rotation_is_disallowed() {
        let plan = plan_open_reliably("system.journal", libc::O_RDONLY, -libc::EBADMSG, true, true)
            .unwrap();
        assert_eq!(plan, OpenReliablyPlan::ReturnOriginalResult(-libc::EBADMSG));
    }

    #[test]
    fn test_plan_open_reliably_rotates_corruption_once() {
        let plan = plan_open_reliably(
            "system.journal",
            libc::O_RDWR | libc::O_CREAT,
            -libc::EBADMSG,
            true,
            true,
        )
        .unwrap();
        assert_eq!(
            plan,
            OpenReliablyPlan::RotateCorrupted {
                original_result: -libc::EBADMSG,
                open_template_read_only: true,
                dispose_corrupted_file: true,
                reopen_with_template: true,
            }
        );
    }
}
