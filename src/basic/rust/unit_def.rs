// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/unit-def.c (string table subset + pure helpers)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobMode {
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
            unsafe { ffi_string_table::from_ptr($table, input, EINVAL) }
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
    UpheldBy,
    ConsistsOf,
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
    WantedBy => "WantedBy", BoundBy => "BoundBy", UpheldBy => "UpheldBy", ConsistsOf => "ConsistsOf",
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

pub fn unit_dbus_path_from_name(name: &str) -> String {
    let escaped = bus_label_escape(name);
    let mut path = String::with_capacity(UNIT_DBUS_PATH_PREFIX.len() + escaped.len());
    path.push_str(UNIT_DBUS_PATH_PREFIX);
    path.push_str(&escaped);
    path
}

pub fn unit_name_from_dbus_path(path: &str) -> Result<String, i32> {
    let rest = path.strip_prefix(UNIT_DBUS_PATH_PREFIX).ok_or(-(22i32))?; // -EINVAL
    let name = bus_label_unescape(rest)?;
    Ok(name)
}

// ── Bus label escape/unescape ─────────────────────────────────────────────

/// Escape a unit name for use in a D-Bus object path.
/// Replaces characters not valid in D-Bus paths with _xx hex encoding.
fn bus_label_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'_' => out.push_str("_5f"),
            b @ 0x00..=0x2f | b @ 0x3a..=0x40 | b @ 0x5b..=0x5e | b @ 0x60 | b @ 0x7b..=0xff => {
                out.push('_');
                out.push_str(&format!("{:02x}", b));
            }
            _ => out.push(b as char),
        }
    }
    out
}

/// Unescape a D-Bus path element back to a unit name.
fn bus_label_unescape(s: &str) -> Result<String, i32> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'_' {
            if i + 2 >= bytes.len() {
                return Err(-(22)); // -EINVAL
            }
            let hex = &s[i + 1..i + 3];
            let byte = u8::from_str_radix(hex, 16).map_err(|_| -(22i32))?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| -(22))
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
    fn test_unit_dbus_path_from_name_escapes_underscore() {
        assert_eq!(
            unit_dbus_path_from_name("foo_bar.service"),
            "/org/freedesktop/systemd1/unit/foo_5fbar_2eservice"
        );
    }

    #[test]
    fn test_unit_name_from_dbus_path_rejects_short_escape() {
        assert_eq!(
            unit_name_from_dbus_path("/org/freedesktop/systemd1/unit/foo_"),
            Err(-22)
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
        let all = [
            UnitDependency::Requires,
            UnitDependency::Wants,
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
        let roundtrip = unit_name_from_dbus_path(&path).unwrap();
        assert_eq!(roundtrip, name);
    }

    #[test]
    fn test_dbus_path_invalid_prefix() {
        assert!(unit_name_from_dbus_path("/wrong/path").is_err());
        assert!(unit_name_from_dbus_path("").is_err());
    }

    #[test]
    fn test_job_mode_roundtrip() {
        let all = [
            JobMode::Fail,
            JobMode::Replace,
            JobMode::Isolate,
            JobMode::RestartDependencies,
        ];
        for mode in all {
            let s = mode.to_str().unwrap();
            assert_eq!(JobMode::from_str(s), Some(mode));
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
