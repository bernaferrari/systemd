// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.unit-def; authority=src/basic/unit-def.c,src/basic/unit-def.h
//
// Unit definition string tables and pure helper functions.

// ── Enums ─────────────────────────────────────────────────────────────────

/// Unit type enum matching systemd's UnitType.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitType {
    Service,
    Mount,
    Swap,
    Socket,
    Target,
    Device,
    Automount,
    Timer,
    Path,
    Slice,
    Scope,
}

impl UnitType {
    const COUNT: usize = 11;

    #[cfg(test)]
    fn from_index(i: usize) -> Option<Self> {
        match i {
            0 => Some(UnitType::Service),
            1 => Some(UnitType::Mount),
            2 => Some(UnitType::Swap),
            3 => Some(UnitType::Socket),
            4 => Some(UnitType::Target),
            5 => Some(UnitType::Device),
            6 => Some(UnitType::Automount),
            7 => Some(UnitType::Timer),
            8 => Some(UnitType::Path),
            9 => Some(UnitType::Slice),
            10 => Some(UnitType::Scope),
            _ => None,
        }
    }

    fn index(self) -> usize {
        match self {
            UnitType::Service => 0,
            UnitType::Mount => 1,
            UnitType::Swap => 2,
            UnitType::Socket => 3,
            UnitType::Target => 4,
            UnitType::Device => 5,
            UnitType::Automount => 6,
            UnitType::Timer => 7,
            UnitType::Path => 8,
            UnitType::Slice => 9,
            UnitType::Scope => 10,
        }
    }
}

/// Unit load state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitLoadState {
    Stub,
    Loaded,
    NotFound,
    BadSetting,
    Error,
    Merged,
    Masked,
}

/// Unit active state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActiveState {
    Active,
    Reloading,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    Maintenance,
    Refreshing,
}

/// Freezer state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezerState {
    Running,
    Freezing,
    Frozen,
    FreezingByParent,
    FrozenByParent,
    Thawing,
}

/// Unit marker enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitMarker {
    NeedsReload,
    NeedsRestart,
    NeedsStop,
    NeedsStart,
}

/// Automount state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomountState {
    Dead,
    Waiting,
    Running,
    Failed,
}

/// Device state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Dead,
    Tentative,
    Plugged,
}

/// Mount state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountState {
    Dead,
    Mounting,
    MountingDone,
    Mounted,
    Remounting,
    Unmounting,
    RemountingSigterm,
    RemountingSigkill,
    UnmountingSigterm,
    UnmountingSigkill,
    Failed,
    Cleaning,
}

/// Path state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Dead,
    Waiting,
    Running,
    Failed,
}

/// Scope state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeState {
    Dead,
    StartChown,
    Running,
    Abandoned,
    StopSigterm,
    StopSigkill,
    Failed,
}

/// Service state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Dead,
    Condition,
    StartPre,
    Start,
    StartPost,
    Running,
    Exited,
    RefreshExtensions,
    RefreshCredentials,
    Reload,
    ReloadSignal,
    ReloadNotify,
    ReloadPost,
    Mounting,
    Stop,
    StopWatchdog,
    StopSigterm,
    StopSigkill,
    StopPost,
    FinalWatchdog,
    FinalSigterm,
    FinalSigkill,
    Failed,
    DeadBeforeAutoRestart,
    FailedBeforeAutoRestart,
    DeadResourcesPinned,
    AutoRestart,
    AutoRestartQueued,
    Cleaning,
}

/// Slice state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceState {
    Dead,
    Active,
}

/// Socket state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Dead,
    StartPre,
    StartOpen,
    StartChown,
    StartPost,
    Listening,
    Deferred,
    Running,
    StopPre,
    StopPreSigterm,
    StopPreSigkill,
    StopPost,
    FinalSigterm,
    FinalSigkill,
    Failed,
    Cleaning,
}

/// Swap state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapState {
    Dead,
    Activating,
    ActivatingDone,
    Active,
    Deactivating,
    DeactivatingSigterm,
    DeactivatingSigkill,
    Failed,
    Cleaning,
}

/// Target state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    Dead,
    Active,
}

/// Timer state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerState {
    Dead,
    Waiting,
    Running,
    Elapsed,
    Failed,
}

/// Notify access enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyAccess {
    None,
    All,
    Main,
    Exec,
}

/// Job mode enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JobMode {
    #[default]
    Fail,
    Lenient,
    Replace,
    ReplaceIrreversibly,
    Isolate,
    Flush,
    IgnoreDependencies,
    IgnoreRequirements,
    Triggering,
    RestartDependencies,
}

/// Error returned when a job mode name is not part of C's `job_mode` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseJobModeError;

impl std::fmt::Display for ParseJobModeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid job mode")
    }
}

impl std::error::Error for ParseJobModeError {}

impl JobMode {
    /// Every mode in the C `job_mode` table, in its defined order.
    pub const ALL: [Self; 10] = [
        Self::Fail,
        Self::Lenient,
        Self::Replace,
        Self::ReplaceIrreversibly,
        Self::Isolate,
        Self::Flush,
        Self::IgnoreDependencies,
        Self::IgnoreRequirements,
        Self::Triggering,
        Self::RestartDependencies,
    ];

    /// Return the canonical, case-sensitive C table name.
    pub fn as_str(self) -> &'static str {
        <Self as StringTable>::to_str(self)
            .expect("every JobMode variant is present in the job_mode table")
    }
}

impl std::fmt::Display for JobMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for JobMode {
    type Err = ParseJobModeError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        job_mode_from_string(input).ok_or(ParseJobModeError)
    }
}

/// Parse a job mode with the exact, case-sensitive C `job_mode_from_string()` table.
pub fn job_mode_from_string(input: &str) -> Option<JobMode> {
    <JobMode as StringTable>::from_str(input)
}

/// Return the exact C `job_mode_to_string()` name for a valid mode.
pub fn job_mode_to_string(mode: JobMode) -> &'static str {
    mode.as_str()
}

/// Exec directory type enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecDirectoryType {
    Runtime,
    State,
    Cache,
    Logs,
    Configuration,
}

// ── String table trait ────────────────────────────────────────────────────

/// Trait for enums backed by a string table (to_string / from_string).
pub trait StringTable: Sized + Copy + PartialEq + Eq {
    /// Convert enum variant to its string representation.
    fn to_str(self) -> Option<&'static str>;

    /// Parse a string to the enum variant. Case-sensitive.
    fn from_str(s: &str) -> Option<Self>;
}

// ── Single-source enum string tables ─────────────────────────────────────
//
// Each invocation is the complete value/name authority: the ergonomically
// typed Rust lookup and the NUL-backed borrowed C ABI are generated from the
// same variant/name list. In particular, no hand-maintained integer table can
// drift from a Rust enum's declaration order again.

use crate::ffi_string_table::{self, Entry as FfiEntry};

const EINVAL: i32 = -libc::EINVAL;

macro_rules! ffi_string_table {
    ($table:ident, $enum:ident, $to_fn:ident, $from_fn:ident; $( $variant:ident => $name:literal ),+ $(,)?) => {
        static $table: &[FfiEntry] = &[
            $(($enum::$variant as i32, concat!($name, "\0").as_bytes()),)+
        ];

        impl StringTable for $enum {
            fn to_str(self) -> Option<&'static str> {
                ffi_string_table::to_str($table, self as i32)
            }

            fn from_str(input: &str) -> Option<Self> {
                match ffi_string_table::from_str($table, input) {
                    $(Some(value) if value == $enum::$variant as i32 => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn $to_fn(value: i32) -> *const std::ffi::c_char {
            ffi_string_table::to_ptr($table, value)
        }

        /// # Safety
        ///
        /// `input` must be null or point to a live NUL-terminated C string;
        /// ownership remains with the caller.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $from_fn(input: *const std::ffi::c_char) -> i32 {
            // SAFETY: this entry point forwards its documented C-string contract.
            unsafe_ffi!( { ffi_string_table::from_ptr($table, input, EINVAL) })
        }
    };
}

ffi_string_table!(UNIT_TYPE_TABLE, UnitType, rs_unit_type_to_string, rs_unit_type_from_string;
    Service => "service", Mount => "mount", Swap => "swap", Socket => "socket",
    Target => "target", Device => "device", Automount => "automount", Timer => "timer",
    Path => "path", Slice => "slice", Scope => "scope",
);
ffi_string_table!(UNIT_LOAD_STATE_TABLE, UnitLoadState, rs_unit_load_state_to_string, rs_unit_load_state_from_string;
    Stub => "stub", Loaded => "loaded", NotFound => "not-found", BadSetting => "bad-setting",
    Error => "error", Merged => "merged", Masked => "masked",
);
ffi_string_table!(UNIT_ACTIVE_STATE_TABLE, UnitActiveState, rs_unit_active_state_to_string, rs_unit_active_state_from_string;
    Active => "active", Reloading => "reloading", Inactive => "inactive", Failed => "failed",
    Activating => "activating", Deactivating => "deactivating", Maintenance => "maintenance", Refreshing => "refreshing",
);
ffi_string_table!(FREEZER_STATE_TABLE, FreezerState, rs_freezer_state_to_string, rs_freezer_state_from_string;
    Running => "running", Freezing => "freezing", Frozen => "frozen",
    FreezingByParent => "freezing-by-parent", FrozenByParent => "frozen-by-parent", Thawing => "thawing",
);
ffi_string_table!(UNIT_MARKER_TABLE, UnitMarker, rs_unit_marker_to_string, rs_unit_marker_from_string;
    NeedsReload => "needs-reload", NeedsRestart => "needs-restart", NeedsStop => "needs-stop", NeedsStart => "needs-start",
);
ffi_string_table!(AUTOMOUNT_STATE_TABLE, AutomountState, rs_automount_state_to_string, rs_automount_state_from_string;
    Dead => "dead", Waiting => "waiting", Running => "running", Failed => "failed",
);
ffi_string_table!(DEVICE_STATE_TABLE, DeviceState, rs_device_state_to_string, rs_device_state_from_string;
    Dead => "dead", Tentative => "tentative", Plugged => "plugged",
);
ffi_string_table!(MOUNT_STATE_TABLE, MountState, rs_mount_state_to_string, rs_mount_state_from_string;
    Dead => "dead", Mounting => "mounting", MountingDone => "mounting-done", Mounted => "mounted",
    Remounting => "remounting", Unmounting => "unmounting", RemountingSigterm => "remounting-sigterm",
    RemountingSigkill => "remounting-sigkill", UnmountingSigterm => "unmounting-sigterm",
    UnmountingSigkill => "unmounting-sigkill", Failed => "failed", Cleaning => "cleaning",
);
ffi_string_table!(PATH_STATE_TABLE, PathState, rs_path_state_to_string, rs_path_state_from_string;
    Dead => "dead", Waiting => "waiting", Running => "running", Failed => "failed",
);
ffi_string_table!(SCOPE_STATE_TABLE, ScopeState, rs_scope_state_to_string, rs_scope_state_from_string;
    Dead => "dead", StartChown => "start-chown", Running => "running", Abandoned => "abandoned",
    StopSigterm => "stop-sigterm", StopSigkill => "stop-sigkill", Failed => "failed",
);
ffi_string_table!(SERVICE_STATE_TABLE, ServiceState, rs_service_state_to_string, rs_service_state_from_string;
    Dead => "dead", Condition => "condition", StartPre => "start-pre", Start => "start",
    StartPost => "start-post", Running => "running", Exited => "exited", RefreshExtensions => "refresh-extensions",
    RefreshCredentials => "refresh-credentials", Reload => "reload", ReloadSignal => "reload-signal",
    ReloadNotify => "reload-notify", ReloadPost => "reload-post", Mounting => "mounting", Stop => "stop",
    StopWatchdog => "stop-watchdog", StopSigterm => "stop-sigterm", StopSigkill => "stop-sigkill",
    StopPost => "stop-post", FinalWatchdog => "final-watchdog", FinalSigterm => "final-sigterm",
    FinalSigkill => "final-sigkill", Failed => "failed", DeadBeforeAutoRestart => "dead-before-auto-restart",
    FailedBeforeAutoRestart => "failed-before-auto-restart", DeadResourcesPinned => "dead-resources-pinned",
    AutoRestart => "auto-restart", AutoRestartQueued => "auto-restart-queued", Cleaning => "cleaning",
);
ffi_string_table!(SLICE_STATE_TABLE, SliceState, rs_slice_state_to_string, rs_slice_state_from_string;
    Dead => "dead", Active => "active",
);
ffi_string_table!(SOCKET_STATE_TABLE, SocketState, rs_socket_state_to_string, rs_socket_state_from_string;
    Dead => "dead", StartPre => "start-pre", StartOpen => "start-open", StartChown => "start-chown",
    StartPost => "start-post", Listening => "listening", Deferred => "deferred", Running => "running",
    StopPre => "stop-pre", StopPreSigterm => "stop-pre-sigterm", StopPreSigkill => "stop-pre-sigkill",
    StopPost => "stop-post", FinalSigterm => "final-sigterm", FinalSigkill => "final-sigkill",
    Failed => "failed", Cleaning => "cleaning",
);
ffi_string_table!(SWAP_STATE_TABLE, SwapState, rs_swap_state_to_string, rs_swap_state_from_string;
    Dead => "dead", Activating => "activating", ActivatingDone => "activating-done", Active => "active",
    Deactivating => "deactivating", DeactivatingSigterm => "deactivating-sigterm",
    DeactivatingSigkill => "deactivating-sigkill", Failed => "failed", Cleaning => "cleaning",
);
ffi_string_table!(TARGET_STATE_TABLE, TargetState, rs_target_state_to_string, rs_target_state_from_string;
    Dead => "dead", Active => "active",
);
ffi_string_table!(TIMER_STATE_TABLE, TimerState, rs_timer_state_to_string, rs_timer_state_from_string;
    Dead => "dead", Waiting => "waiting", Running => "running", Elapsed => "elapsed", Failed => "failed",
);

/// Unit dependency enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitDependency {
    Requires,
    Requisite,
    Wants,
    BindsTo,
    PartOf,
    Upholds,
    RequiredBy,
    RequisiteOf,
    WantedBy,
    BoundBy,
    ConsistsOf,
    UpheldBy,
    Conflicts,
    ConflictedBy,
    Before,
    After,
    OnSuccess,
    OnSuccessOf,
    OnFailure,
    OnFailureOf,
    Triggers,
    TriggeredBy,
    PropagatesReloadTo,
    ReloadPropagatedFrom,
    PropagatesStopTo,
    StopPropagatedFrom,
    JoinsNamespaceOf,
    References,
    ReferencedBy,
    InSlice,
    SliceOf,
}

ffi_string_table!(UNIT_DEPENDENCY_TABLE, UnitDependency, rs_unit_dependency_to_string, rs_unit_dependency_from_string;
    Requires => "Requires", Requisite => "Requisite", Wants => "Wants", BindsTo => "BindsTo",
    PartOf => "PartOf", Upholds => "Upholds", RequiredBy => "RequiredBy", RequisiteOf => "RequisiteOf",
    WantedBy => "WantedBy", BoundBy => "BoundBy", ConsistsOf => "ConsistsOf", UpheldBy => "UpheldBy",
    Conflicts => "Conflicts", ConflictedBy => "ConflictedBy", Before => "Before", After => "After",
    OnSuccess => "OnSuccess", OnSuccessOf => "OnSuccessOf", OnFailure => "OnFailure", OnFailureOf => "OnFailureOf",
    Triggers => "Triggers", TriggeredBy => "TriggeredBy", PropagatesReloadTo => "PropagatesReloadTo",
    ReloadPropagatedFrom => "ReloadPropagatedFrom", PropagatesStopTo => "PropagatesStopTo",
    StopPropagatedFrom => "StopPropagatedFrom", JoinsNamespaceOf => "JoinsNamespaceOf", References => "References",
    ReferencedBy => "ReferencedBy", InSlice => "InSlice", SliceOf => "SliceOf",
);
ffi_string_table!(NOTIFY_ACCESS_TABLE, NotifyAccess, rs_notify_access_to_string, rs_notify_access_from_string;
    None => "none", All => "all", Main => "main", Exec => "exec",
);
ffi_string_table!(JOB_MODE_TABLE, JobMode, rs_job_mode_to_string, rs_job_mode_from_string;
    Fail => "fail", Lenient => "lenient", Replace => "replace", ReplaceIrreversibly => "replace-irreversibly",
    Isolate => "isolate", Flush => "flush", IgnoreDependencies => "ignore-dependencies",
    IgnoreRequirements => "ignore-requirements", Triggering => "triggering", RestartDependencies => "restart-dependencies",
);
ffi_string_table!(EXEC_DIRECTORY_TYPE_TABLE, ExecDirectoryType, rs_exec_directory_type_to_string, rs_exec_directory_type_from_string;
    Runtime => "RuntimeDirectory", State => "StateDirectory", Cache => "CacheDirectory",
    Logs => "LogsDirectory", Configuration => "ConfigurationDirectory",
);

// ── Freezer state helpers ─────────────────────────────────────────────────

/// Maps in-progress freezer states to their corresponding finished state.
/// Mirrors C's freezer_state_finish().
pub fn freezer_state_finish(state: FreezerState) -> FreezerState {
    match state {
        FreezerState::Freezing => FreezerState::Frozen,
        FreezerState::FreezingByParent => FreezerState::FrozenByParent,
        FreezerState::Thawing => FreezerState::Running,
        FreezerState::Running => FreezerState::Running,
        FreezerState::Frozen => FreezerState::Frozen,
        FreezerState::FrozenByParent => FreezerState::FrozenByParent,
    }
}

/// Returns the "objective" freezer state: the target state when
/// freeze/thaw operations complete. FrozenByParent normalizes to Frozen.
/// Mirrors C's freezer_state_objective().
pub fn freezer_state_objective(state: FreezerState) -> FreezerState {
    let objective = freezer_state_finish(state);
    if objective == FreezerState::FrozenByParent {
        FreezerState::Frozen
    } else {
        objective
    }
}

#[inline]
fn freezer_state_from_raw(value: i32) -> Option<FreezerState> {
    match value {
        0 => Some(FreezerState::Running),
        1 => Some(FreezerState::Freezing),
        2 => Some(FreezerState::Frozen),
        3 => Some(FreezerState::FreezingByParent),
        4 => Some(FreezerState::FrozenByParent),
        5 => Some(FreezerState::Thawing),
        _ => None,
    }
}

#[inline]
fn freezer_state_to_raw(state: FreezerState) -> i32 {
    match state {
        FreezerState::Running => 0,
        FreezerState::Freezing => 1,
        FreezerState::Frozen => 2,
        FreezerState::FreezingByParent => 3,
        FreezerState::FrozenByParent => 4,
        FreezerState::Thawing => 5,
    }
}

/// C ABI facade for `freezer_state_finish`.
///
/// C asserts on an out-of-range enum; the Rust boundary instead rejects it
/// deterministically so malformed FFI input cannot trigger an out-of-bounds
/// access or panic.
#[unsafe(no_mangle)]
pub extern "C" fn rs_freezer_state_finish(value: i32) -> i32 {
    freezer_state_from_raw(value)
        .map(freezer_state_finish)
        .map(freezer_state_to_raw)
        .unwrap_or(EINVAL)
}

/// C ABI facade for `freezer_state_objective`; see `rs_freezer_state_finish`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_freezer_state_objective(value: i32) -> i32 {
    freezer_state_from_raw(value)
        .map(freezer_state_objective)
        .map(freezer_state_to_raw)
        .unwrap_or(EINVAL)
}

// ── D-Bus interface helpers ───────────────────────────────────────────────

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;

use crate::bus_label::{rs_bus_label_escape, rs_bus_label_unescape_n};
use crate::ffi::{free, malloc, strlen};

const UNIT_DBUS_INTERFACE_TABLE: &[&str] = &[
    "org.freedesktop.systemd1.Service",
    "org.freedesktop.systemd1.Mount",
    "org.freedesktop.systemd1.Swap",
    "org.freedesktop.systemd1.Socket",
    "org.freedesktop.systemd1.Target",
    "org.freedesktop.systemd1.Device",
    "org.freedesktop.systemd1.Automount",
    "org.freedesktop.systemd1.Timer",
    "org.freedesktop.systemd1.Path",
    "org.freedesktop.systemd1.Slice",
    "org.freedesktop.systemd1.Scope",
];

/// Returns the D-Bus interface name for a given unit type.
pub fn unit_dbus_interface_from_type(t: UnitType) -> Option<&'static str> {
    UNIT_DBUS_INTERFACE_TABLE.get(t.index()).copied()
}

const UNIT_DBUS_PATH_PREFIX: &str = "/org/freedesktop/systemd1/unit/";
const UNIT_DBUS_PATH_PREFIX_BYTES: &[u8] = b"/org/freedesktop/systemd1/unit/";

// Keep this byte table separate from the ergonomic `&str` table above: C
// callers receive pointers which must remain valid for the entire process and
// which must be NUL-terminated. The ordering is the `UnitType` ABI ordering
// from unit-def.h, rather than the designated-initializer ordering in C.
const UNIT_DBUS_INTERFACE_CSTRS: [&[u8]; UnitType::COUNT] = [
    b"org.freedesktop.systemd1.Service\0",
    b"org.freedesktop.systemd1.Mount\0",
    b"org.freedesktop.systemd1.Swap\0",
    b"org.freedesktop.systemd1.Socket\0",
    b"org.freedesktop.systemd1.Target\0",
    b"org.freedesktop.systemd1.Device\0",
    b"org.freedesktop.systemd1.Automount\0",
    b"org.freedesktop.systemd1.Timer\0",
    b"org.freedesktop.systemd1.Path\0",
    b"org.freedesktop.systemd1.Slice\0",
    b"org.freedesktop.systemd1.Scope\0",
];

/// C ABI mirror of `unit_dbus_path_from_name()`.
///
/// # Safety
///
/// `name` must be null or point to a live NUL-terminated byte string. A
/// non-null result is a fresh process-C-allocator allocation owned by the C
/// caller and must be released with `free(3)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_dbus_path_from_name(name: *const c_char) -> *mut c_char {
    if name.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the entry-point contract supplies a live NUL-terminated name.
    let escaped = unsafe_ffi!(rs_bus_label_escape(name));
    if escaped.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `rs_bus_label_escape` returned this live, NUL-terminated C
    // allocation, whose ownership remains local until the cleanup below.
    let escaped_len = unsafe_ffi!(strlen(escaped));
    let Some(allocation_size) = UNIT_DBUS_PATH_PREFIX_BYTES
        .len()
        .checked_add(escaped_len)
        .and_then(|size| size.checked_add(1))
    else {
        // SAFETY: `escaped` is the unique live C allocation returned above.
        unsafe_ffi!(free(escaped.cast()));
        return ptr::null_mut();
    };

    let output = malloc(allocation_size).cast::<c_char>();
    if output.is_null() {
        // SAFETY: `escaped` is the unique live C allocation returned above.
        unsafe_ffi!(free(escaped.cast()));
        return ptr::null_mut();
    }

    // SAFETY: `output` owns `allocation_size` bytes, which is exactly the
    // prefix, escaped contents, and terminator. `escaped` is a distinct live
    // C allocation with `escaped_len` readable payload bytes.
    unsafe_ffi!({
        ptr::copy_nonoverlapping(
            UNIT_DBUS_PATH_PREFIX_BYTES.as_ptr(),
            output.cast::<u8>(),
            UNIT_DBUS_PATH_PREFIX_BYTES.len(),
        );
        ptr::copy_nonoverlapping(
            escaped.cast::<u8>(),
            output.cast::<u8>().add(UNIT_DBUS_PATH_PREFIX_BYTES.len()),
            escaped_len,
        );
        *output.cast::<u8>().add(allocation_size - 1) = 0;
        free(escaped.cast());
    });

    output
}

/// C ABI mirror of `unit_name_from_dbus_path()`.
///
/// # Safety
///
/// `path` must be null or point to a live NUL-terminated byte string. `name`
/// must be null or point to writable storage for one `char *`. On success the
/// function publishes a process-C-allocator allocation in `*name`, owned by
/// the C caller and released with `free(3)`; failures leave `*name` untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_from_dbus_path(
    path: *const c_char,
    name: *mut *mut c_char,
) -> i32 {
    if path.is_null() || name.is_null() {
        return EINVAL;
    }

    // SAFETY: the entry-point contract supplies a live NUL-terminated path.
    let path_bytes = unsafe_ffi!(CStr::from_ptr(path)).to_bytes();
    if !path_bytes.starts_with(UNIT_DBUS_PATH_PREFIX_BYTES) {
        return EINVAL;
    }

    // SAFETY: the exact prefix check above proves this offset remains within
    // the live C string. The Rust bus-label port returns a C-owned allocation
    // with the same `bus_label_unescape()` byte semantics as the C authority.
    // SAFETY: the exact-prefix proof above makes this derived pointer valid,
    // and `path` stays live and NUL-terminated for the delegated call.
    let decoded = unsafe_ffi!(rs_bus_label_unescape_n(
        path.add(UNIT_DBUS_PATH_PREFIX_BYTES.len()),
        usize::MAX
    ));
    if decoded.is_null() {
        return -libc::ENOMEM;
    }

    // SAFETY: `name` is writable by the entry-point contract. Publish only
    // after all fallible work succeeds, matching C's output-pointer behavior.
    unsafe_ffi!(*name = decoded);
    0
}

/// C ABI mirror of `unit_dbus_interface_from_type()`.
///
/// Invalid `UnitType` values return null. Valid results are borrowed static
/// NUL-terminated strings and must not be freed by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn rs_unit_dbus_interface_from_type(t: i32) -> *const c_char {
    let Ok(index) = usize::try_from(t) else {
        return ptr::null();
    };

    UNIT_DBUS_INTERFACE_CSTRS
        .get(index)
        .map_or(ptr::null(), |value| value.as_ptr().cast::<c_char>())
}

/// C ABI mirror of `unit_dbus_interface_from_name()`.
///
/// # Safety
///
/// `name` must be null or point to a live NUL-terminated byte string. A
/// non-null result is a borrowed static NUL-terminated string and must not be
/// freed by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_dbus_interface_from_name(name: *const c_char) -> *const c_char {
    if name.is_null() {
        return ptr::null();
    }

    // SAFETY: the entry-point contract supplies the C string required by the
    // Rust unit-name port. Its result uses the UnitType integer ABI from
    // unit-def.h; invalid names produce a negative errno and map to null.
    let unit_type = unsafe_ffi!(crate::unit_name::rs_unit_name_to_type(name));
    rs_unit_dbus_interface_from_type(unit_type)
}

pub fn unit_dbus_path_from_name(name: &str) -> String {
    let escaped = bus_label_escape(name);
    let mut path = String::with_capacity(UNIT_DBUS_PATH_PREFIX.len() + escaped.len());
    path.push_str(UNIT_DBUS_PATH_PREFIX);
    path.push_str(&escaped);
    path
}

/// Decode a unit D-Bus path using the byte semantics of
/// `unit_name_from_dbus_path()`.
///
/// Unlike a `String`-only helper, this retains decoded NUL and non-UTF-8
/// bytes and keeps malformed escapes literal, matching the C implementation.
/// `path` must begin with the byte-exact systemd unit-path prefix.
pub fn unit_name_bytes_from_dbus_path(path: &[u8]) -> Result<Vec<u8>, i32> {
    let rest = path
        .strip_prefix(UNIT_DBUS_PATH_PREFIX_BYTES)
        .ok_or(-libc::EINVAL)?;
    crate::bus_label::bus_label_unescape_bytes(rest).ok_or(-libc::ENOMEM)
}

/// Decode a UTF-8 unit D-Bus path into a Rust string.
///
/// This is a strict UTF-8 convenience wrapper around
/// [`unit_name_bytes_from_dbus_path`], not the C ABI mirror. For byte-exact C
/// behavior (including decoded NUL or non-UTF-8 bytes), use the byte helper or
/// [`rs_unit_name_from_dbus_path`].
pub fn unit_name_from_dbus_path_utf8(path: &str) -> Result<String, i32> {
    String::from_utf8(unit_name_bytes_from_dbus_path(path.as_bytes())?).map_err(|_| -libc::EINVAL)
}

// ── Bus label escape/unescape ─────────────────────────────────────────────

/// Escape a unit name for use in a D-Bus object path.
///
/// This follows `bus_label_escape()`: only ASCII letters are copied
/// unconditionally, while ASCII digits are copied only after the first byte.
fn bus_label_escape(s: &str) -> String {
    if s.is_empty() {
        return "_".into();
    }

    let mut out = String::with_capacity(s.len());
    for (index, byte) in s.bytes().enumerate() {
        if byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit()) {
            out.push(byte as char);
        } else {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.push('_');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unit_type_to_string() {
        assert_eq!(UnitType::Service.to_str(), Some("service"));
        assert_eq!(UnitType::Target.to_str(), Some("target"));
        assert_eq!(UnitType::Scope.to_str(), Some("scope"));
    }

    #[test]
    fn test_unit_type_from_string() {
        assert_eq!(UnitType::from_str("service"), Some(UnitType::Service));
        assert_eq!(UnitType::from_str("mount"), Some(UnitType::Mount));
        assert_eq!(UnitType::from_str("scope"), Some(UnitType::Scope));
        assert_eq!(UnitType::from_str("INVALID"), None);
        assert_eq!(UnitType::from_str(""), None);
    }

    #[test]
    fn test_unit_type_case_sensitive() {
        assert_eq!(UnitType::from_str("Service"), None);
        assert_eq!(UnitType::from_str("SERVICE"), None);
        assert_eq!(UnitType::from_str("TARGET"), None);
    }

    #[test]
    fn test_unit_type_roundtrip() {
        for i in 0..UnitType::COUNT {
            let t = UnitType::from_index(i).unwrap();
            let s = t.to_str().unwrap();
            assert_eq!(UnitType::from_str(s), Some(t));
        }
    }

    #[test]
    fn test_unit_load_state_roundtrip() {
        let all = [
            UnitLoadState::Stub,
            UnitLoadState::Loaded,
            UnitLoadState::NotFound,
            UnitLoadState::BadSetting,
            UnitLoadState::Error,
            UnitLoadState::Merged,
            UnitLoadState::Masked,
        ];
        for state in all {
            let s = state.to_str().unwrap();
            assert_eq!(UnitLoadState::from_str(s), Some(state));
        }
    }

    #[test]
    fn test_unit_active_state_roundtrip() {
        let all = [
            UnitActiveState::Active,
            UnitActiveState::Reloading,
            UnitActiveState::Inactive,
            UnitActiveState::Failed,
            UnitActiveState::Activating,
            UnitActiveState::Deactivating,
            UnitActiveState::Maintenance,
            UnitActiveState::Refreshing,
        ];
        for state in all {
            let s = state.to_str().unwrap();
            assert_eq!(UnitActiveState::from_str(s), Some(state));
        }
    }

    #[test]
    fn test_unit_dbus_path_from_name_uses_bus_label_rules() {
        assert_eq!(
            unit_dbus_path_from_name("foo_bar.service"),
            "/org/freedesktop/systemd1/unit/foo_5fbar_2eservice"
        );
        assert_eq!(
            unit_dbus_path_from_name("7foo.service"),
            "/org/freedesktop/systemd1/unit/_37foo_2eservice"
        );
        assert_eq!(
            unit_dbus_path_from_name(""),
            "/org/freedesktop/systemd1/unit/_"
        );
    }

    #[test]
    fn test_unit_name_bytes_from_dbus_path_preserves_c_unescape_rules() {
        assert_eq!(
            unit_name_bytes_from_dbus_path(b"/org/freedesktop/systemd1/unit/foo_"),
            Ok(b"foo_".to_vec())
        );
        assert_eq!(
            unit_name_bytes_from_dbus_path(b"/org/freedesktop/systemd1/unit/foo_xz"),
            Ok(b"foo_xz".to_vec())
        );
        assert_eq!(
            unit_name_bytes_from_dbus_path(b"/org/freedesktop/systemd1/unit/foo_ba"),
            Ok(vec![b'f', b'o', b'o', 0xba])
        );
        assert_eq!(
            unit_name_bytes_from_dbus_path(b"/org/freedesktop/systemd1/unit/_"),
            Ok(Vec::new())
        );
    }

    #[test]
    fn test_freezer_state_finish() {
        assert_eq!(
            freezer_state_finish(FreezerState::Running),
            FreezerState::Running
        );
        assert_eq!(
            freezer_state_finish(FreezerState::Freezing),
            FreezerState::Frozen
        );
        assert_eq!(
            freezer_state_finish(FreezerState::Frozen),
            FreezerState::Frozen
        );
        assert_eq!(
            freezer_state_finish(FreezerState::FreezingByParent),
            FreezerState::FrozenByParent
        );
        assert_eq!(
            freezer_state_finish(FreezerState::FrozenByParent),
            FreezerState::FrozenByParent
        );
        assert_eq!(
            freezer_state_finish(FreezerState::Thawing),
            FreezerState::Running
        );
    }

    #[test]
    fn test_freezer_state_objective() {
        assert_eq!(
            freezer_state_objective(FreezerState::Running),
            FreezerState::Running
        );
        assert_eq!(
            freezer_state_objective(FreezerState::Freezing),
            FreezerState::Frozen
        );
        assert_eq!(
            freezer_state_objective(FreezerState::FreezingByParent),
            FreezerState::Frozen
        );
        assert_eq!(
            freezer_state_objective(FreezerState::FrozenByParent),
            FreezerState::Frozen
        );
        assert_eq!(
            freezer_state_objective(FreezerState::Thawing),
            FreezerState::Running
        );
    }

    #[test]
    fn test_service_state_roundtrip() {
        let all = [
            ServiceState::Dead,
            ServiceState::Condition,
            ServiceState::Running,
            ServiceState::Failed,
            ServiceState::Mounting,
            ServiceState::AutoRestartQueued,
        ];
        for state in all {
            let s = state.to_str().unwrap();
            assert_eq!(ServiceState::from_str(s), Some(state));
        }
    }

    #[test]
    fn test_unit_dependency_roundtrip() {
        /* These adjacent inverse dependencies have historically been easy to
         * transpose. Keep their C ABI discriminants explicit. */
        assert_eq!(UnitDependency::ConsistsOf as i32, 10);
        assert_eq!(UnitDependency::UpheldBy as i32, 11);

        let all = [
            UnitDependency::Requires,
            UnitDependency::Wants,
            UnitDependency::ConsistsOf,
            UnitDependency::UpheldBy,
            UnitDependency::After,
            UnitDependency::SliceOf,
        ];
        for dep in all {
            let s = dep.to_str().unwrap();
            assert_eq!(UnitDependency::from_str(s), Some(dep));
        }
    }

    #[test]
    fn test_dbus_interface_from_type() {
        assert_eq!(
            unit_dbus_interface_from_type(UnitType::Service),
            Some("org.freedesktop.systemd1.Service")
        );
        assert_eq!(
            unit_dbus_interface_from_type(UnitType::Scope),
            Some("org.freedesktop.systemd1.Scope")
        );
    }

    #[test]
    fn test_dbus_path_roundtrip() {
        let name = "test.service";
        let path = unit_dbus_path_from_name(name);
        assert!(path.starts_with("/org/freedesktop/systemd1/unit/"));
        let roundtrip = unit_name_from_dbus_path_utf8(&path).unwrap();
        assert_eq!(roundtrip, name);
    }

    #[test]
    fn test_dbus_path_invalid_prefix() {
        assert!(unit_name_from_dbus_path_utf8("/wrong/path").is_err());
        assert!(unit_name_from_dbus_path_utf8("").is_err());
    }

    #[test]
    fn test_job_mode_roundtrip() {
        let names = [
            "fail",
            "lenient",
            "replace",
            "replace-irreversibly",
            "isolate",
            "flush",
            "ignore-dependencies",
            "ignore-requirements",
            "triggering",
            "restart-dependencies",
        ];
        assert_eq!(JobMode::ALL.len(), names.len());

        for (mode, name) in JobMode::ALL.into_iter().zip(names) {
            assert_eq!(mode.as_str(), name);
            assert_eq!(job_mode_to_string(mode), name);
            assert_eq!(job_mode_from_string(name), Some(mode));
            assert_eq!(name.parse::<JobMode>(), Ok(mode));
        }
    }

    #[test]
    fn test_job_mode_rejects_non_c_names() {
        for name in [
            "",
            "irreversible",
            "irreversibly",
            "quiet",
            "enqueue",
            "trigger",
        ] {
            assert_eq!(job_mode_from_string(name), None);
            assert_eq!(name.parse::<JobMode>(), Err(ParseJobModeError));
        }
    }

    #[test]
    fn test_exec_directory_type_roundtrip() {
        let all = [
            ExecDirectoryType::Runtime,
            ExecDirectoryType::State,
            ExecDirectoryType::Cache,
            ExecDirectoryType::Logs,
            ExecDirectoryType::Configuration,
        ];
        for t in all {
            let s = t.to_str().unwrap();
            assert_eq!(ExecDirectoryType::from_str(s), Some(t));
        }
    }
}
