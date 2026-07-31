// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/service.c

use crate::ffi::Errno;
use crate::service_tables::{ServiceExecCommand, ServiceResult};

pub const SOURCE_PATH: &str = "src/core/service.c";
pub const USEC_INFINITY: u64 = u64::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActiveState {
    Inactive,
    Activating,
    Active,
    Refreshing,
    Reloading,
    Deactivating,
    Failed,
    Maintenance,
}

impl From<UnitActiveState> for crate::unit::ActiveState {
    fn from(s: UnitActiveState) -> Self {
        match s {
            UnitActiveState::Inactive => crate::unit::ActiveState::Inactive,
            UnitActiveState::Activating => crate::unit::ActiveState::Activating,
            UnitActiveState::Active => crate::unit::ActiveState::Active,
            UnitActiveState::Refreshing => crate::unit::ActiveState::Refreshing,
            UnitActiveState::Reloading => crate::unit::ActiveState::Reloading,
            UnitActiveState::Deactivating => crate::unit::ActiveState::Deactivating,
            UnitActiveState::Failed => crate::unit::ActiveState::Failed,
            UnitActiveState::Maintenance => crate::unit::ActiveState::Maintenance,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    Invalid,
    Simple,
    Forking,
    Oneshot,
    Dbus,
    Notify,
    NotifyReload,
    Idle,
    Exec,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecKeyringMode {
    Private,
    Inherit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyAccess {
    Invalid,
    None,
    Main,
    Exec,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyState {
    Invalid,
    Ready,
    Reloading,
    ReloadReady,
    Stopping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OomPolicy {
    Invalid,
    Continue,
    Stop,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecPreserveMode {
    No,
    Yes,
    Restart,
    OnSuccess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerDefaults {
    pub timeout_start_usec: u64,
    pub timeout_stop_usec: u64,
    pub timeout_abort_usec: u64,
    pub timeout_abort_set: bool,
    pub restart_usec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manager {
    pub defaults: ManagerDefaults,
    pub is_system: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecContext {
    pub keyring_mode: ExecKeyringMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecStatus {
    pub started_pids: Vec<i32>,
    pub last_start_time: Option<u64>,
    /// Typed completion of the actual main process for restart
    /// force/prevent evaluation. Control-command status must never overwrite
    /// this field.
    pub last_exit: Option<ServiceExitStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceExitStatus {
    ExitCode(i32),
    Signal(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidRef {
    pub pid: i32,
    pub start_time: Option<u64>,
    pub is_self: bool,
    pub is_child: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub service_type: ServiceType,
    pub timeout_start_usec: u64,
    pub timeout_stop_usec: u64,
    pub timeout_abort_usec: u64,
    pub timeout_abort_set: bool,
    pub restart_usec: u64,
    pub restart_max_delay_usec: u64,
    pub runtime_max_usec: u64,
    pub socket_fd: i32,
    pub stdin_fd: i32,
    pub stdout_fd: i32,
    pub stderr_fd: i32,
    pub root_directory_fd: i32,
    pub guess_main_pid: bool,
    pub main_pid: Option<PidRef>,
    pub main_pid_known: bool,
    pub main_pid_alien: bool,
    pub control_pid: Option<PidRef>,
    pub control_command_id: Option<ServiceExecCommand>,
    /// First terminal failure for the current activation, matching
    /// `Service.result` in service.c. Cleanup failures must not overwrite the
    /// original cause.
    pub result: ServiceResult,
    /// Reload is nonterminal. Its result is reported independently and never
    /// overwrites the activation's terminal result.
    pub reload_result: ServiceResult,
    pub exec_context: ExecContext,
    /// The configured notification sender policy. This is intentionally kept
    /// distinct from a runtime `NOTIFYACCESS=` override, as in service.c.
    /// A future authenticated notify dispatcher must consult
    /// [`service_get_notify_access`] rather than either field alone.
    pub notify_access: NotifyAccess,
    pub notify_access_override: NotifyAccess,
    pub notify_state: NotifyState,
    pub watchdog_original_usec: u64,
    pub oom_policy: OomPolicy,
    pub reload_begin_usec: u64,
    pub reload_signal: i32,
    pub fd_store_preserve_mode: ExecPreserveMode,
    pub state: ServiceState,
    pub n_restarts: u32,
    pub restart_steps: u32,
    pub timer_event_deadline: Option<u64>,
    pub watchdog_event_deadline: Option<u64>,
    pub watchdog_timestamp: Option<u64>,
    pub watchdog_usec: u64,
    pub watchdog_override_enable: bool,
    pub watchdog_override_usec: u64,
    pub main_exec_status: ExecStatus,
}

impl Default for ManagerDefaults {
    fn default() -> Self {
        Self {
            timeout_start_usec: 90_000_000,
            timeout_stop_usec: 90_000_000,
            timeout_abort_usec: 90_000_000,
            timeout_abort_set: false,
            restart_usec: 100_000,
        }
    }
}

impl Default for Manager {
    fn default() -> Self {
        Self {
            defaults: ManagerDefaults::default(),
            is_system: true,
        }
    }
}

impl Default for Service {
    fn default() -> Self {
        Self {
            service_type: ServiceType::Invalid,
            timeout_start_usec: 0,
            timeout_stop_usec: 0,
            timeout_abort_usec: 0,
            timeout_abort_set: false,
            restart_usec: 0,
            restart_max_delay_usec: USEC_INFINITY,
            runtime_max_usec: USEC_INFINITY,
            socket_fd: 0,
            stdin_fd: 0,
            stdout_fd: 0,
            stderr_fd: 0,
            root_directory_fd: 0,
            guess_main_pid: false,
            main_pid: None,
            main_pid_known: false,
            main_pid_alien: false,
            control_pid: None,
            control_command_id: None,
            result: ServiceResult::Success,
            reload_result: ServiceResult::Success,
            exec_context: ExecContext {
                keyring_mode: ExecKeyringMode::Inherit,
            },
            notify_access: NotifyAccess::None,
            notify_access_override: NotifyAccess::Invalid,
            notify_state: NotifyState::Invalid,
            watchdog_original_usec: USEC_INFINITY,
            oom_policy: OomPolicy::Invalid,
            reload_begin_usec: USEC_INFINITY,
            reload_signal: libc::SIGHUP,
            fd_store_preserve_mode: ExecPreserveMode::Restart,
            state: ServiceState::Dead,
            n_restarts: 0,
            restart_steps: 0,
            timer_event_deadline: None,
            watchdog_event_deadline: None,
            watchdog_timestamp: None,
            // service_init() in C leaves the zeroed configured watchdog
            // disabled. `watchdog_original_usec` is the separate runtime
            // override baseline and intentionally uses USEC_INFINITY.
            watchdog_usec: 0,
            watchdog_override_enable: false,
            watchdog_override_usec: USEC_INFINITY,
            main_exec_status: ExecStatus::default(),
        }
    }
}

pub fn service_state_translation(
    state: ServiceState,
    service_type: ServiceType,
) -> UnitActiveState {
    match service_type {
        ServiceType::Idle => service_state_translation_idle(state),
        _ => service_state_translation_normal(state),
    }
}

fn service_state_translation_normal(state: ServiceState) -> UnitActiveState {
    match state {
        ServiceState::Dead
        | ServiceState::DeadBeforeAutoRestart
        | ServiceState::DeadResourcesPinned => UnitActiveState::Inactive,
        ServiceState::Condition
        | ServiceState::StartPre
        | ServiceState::Start
        | ServiceState::StartPost
        | ServiceState::AutoRestart
        | ServiceState::AutoRestartQueued => UnitActiveState::Activating,
        ServiceState::Running | ServiceState::Exited => UnitActiveState::Active,
        ServiceState::RefreshExtensions
        | ServiceState::RefreshCredentials
        | ServiceState::Mounting => UnitActiveState::Refreshing,
        ServiceState::Reload
        | ServiceState::ReloadSignal
        | ServiceState::ReloadNotify
        | ServiceState::ReloadPost => UnitActiveState::Reloading,
        ServiceState::Stop
        | ServiceState::StopWatchdog
        | ServiceState::StopSigterm
        | ServiceState::StopSigkill
        | ServiceState::StopPost
        | ServiceState::FinalWatchdog
        | ServiceState::FinalSigterm
        | ServiceState::FinalSigkill => UnitActiveState::Deactivating,
        ServiceState::Failed | ServiceState::FailedBeforeAutoRestart => UnitActiveState::Failed,
        ServiceState::Cleaning => UnitActiveState::Maintenance,
    }
}

fn service_state_translation_idle(state: ServiceState) -> UnitActiveState {
    match state {
        ServiceState::Condition
        | ServiceState::StartPre
        | ServiceState::Start
        | ServiceState::StartPost => UnitActiveState::Active,
        other => service_state_translation_normal(other),
    }
}

pub fn service_state_with_main_process(state: ServiceState) -> bool {
    matches!(
        state,
        ServiceState::Start
            | ServiceState::StartPost
            | ServiceState::Running
            | ServiceState::RefreshExtensions
            | ServiceState::RefreshCredentials
            | ServiceState::Reload
            | ServiceState::ReloadSignal
            | ServiceState::ReloadNotify
            | ServiceState::ReloadPost
            | ServiceState::Mounting
            | ServiceState::Stop
            | ServiceState::StopWatchdog
            | ServiceState::StopSigterm
            | ServiceState::StopSigkill
            | ServiceState::StopPost
            | ServiceState::FinalWatchdog
            | ServiceState::FinalSigterm
            | ServiceState::FinalSigkill
    )
}

pub fn service_state_with_control_process(state: ServiceState) -> bool {
    matches!(
        state,
        ServiceState::Condition
            | ServiceState::StartPre
            | ServiceState::Start
            | ServiceState::StartPost
            | ServiceState::RefreshExtensions
            | ServiceState::RefreshCredentials
            | ServiceState::Reload
            | ServiceState::ReloadPost
            | ServiceState::Mounting
            | ServiceState::Stop
            | ServiceState::StopWatchdog
            | ServiceState::StopSigterm
            | ServiceState::StopSigkill
            | ServiceState::StopPost
            | ServiceState::FinalWatchdog
            | ServiceState::FinalSigterm
            | ServiceState::FinalSigkill
            | ServiceState::Cleaning
    )
}

pub fn service_state_with_watchdog(state: ServiceState) -> bool {
    matches!(
        state,
        ServiceState::StartPost
            | ServiceState::Running
            | ServiceState::RefreshExtensions
            | ServiceState::RefreshCredentials
            | ServiceState::Reload
            | ServiceState::ReloadSignal
            | ServiceState::ReloadNotify
            | ServiceState::ReloadPost
            | ServiceState::Mounting
    )
}

pub fn service_init(service: &mut Service, manager: &Manager) {
    service.timeout_start_usec = manager.defaults.timeout_start_usec;
    service.timeout_stop_usec = manager.defaults.timeout_stop_usec;
    service.timeout_abort_usec = manager.defaults.timeout_abort_usec;
    service.timeout_abort_set = manager.defaults.timeout_abort_set;
    service.restart_usec = manager.defaults.restart_usec;
    service.restart_max_delay_usec = USEC_INFINITY;
    service.runtime_max_usec = USEC_INFINITY;
    service.service_type = ServiceType::Invalid;
    service.socket_fd = Errno::EBADF.to_neg_errno();
    service.stdin_fd = Errno::EBADF.to_neg_errno();
    service.stdout_fd = Errno::EBADF.to_neg_errno();
    service.stderr_fd = Errno::EBADF.to_neg_errno();
    service.root_directory_fd = Errno::EBADF.to_neg_errno();
    service.guess_main_pid = true;
    service.main_pid = None;
    service.control_pid = None;
    service.control_command_id = None;
    service.result = ServiceResult::Success;
    service.reload_result = ServiceResult::Success;
    service.exec_context.keyring_mode = if manager.is_system {
        ExecKeyringMode::Private
    } else {
        ExecKeyringMode::Inherit
    };
    service.notify_access = NotifyAccess::None;
    service.notify_access_override = NotifyAccess::Invalid;
    service.notify_state = NotifyState::Invalid;
    service.watchdog_usec = 0;
    service.watchdog_original_usec = USEC_INFINITY;
    service.oom_policy = OomPolicy::Invalid;
    service.reload_begin_usec = USEC_INFINITY;
    service.reload_signal = libc::SIGHUP;
    service.fd_store_preserve_mode = ExecPreserveMode::Restart;
}

/// Return the sender policy currently in effect for a service.
///
/// `NOTIFYACCESS=` is a privileged runtime override in C and must supersede
/// the parsed `NotifyAccess=` setting. Keeping that distinction in the model
/// prevents a future receiver from accidentally making a temporary override
/// permanent across service activation or reexecution.
pub fn service_get_notify_access(service: &Service) -> NotifyAccess {
    match service.notify_access_override {
        NotifyAccess::Invalid => service.notify_access,
        override_access => override_access,
    }
}

/// Apply the load-time `NotifyAccess=` policy and C's automatic enablement.
///
/// `Type=notify`, a nonzero `WatchdogSec=`, and a positive
/// `FileDescriptorStoreMax=` each require the notify socket. C changes an
/// otherwise disabled policy to `main` for precisely those cases. This is a
/// pure model operation: it does not expose `NOTIFY_SOCKET` or make any
/// service startable until an authenticated manager dispatcher owns the full
/// protocol.
pub fn service_configure_notify_access(
    service: &mut Service,
    configured: Option<NotifyAccess>,
    watchdog_sec: Option<u64>,
    fd_store_max: Option<u64>,
) {
    service.notify_access = configured.unwrap_or(NotifyAccess::None);
    if service.notify_access == NotifyAccess::None
        && (matches!(
            service.service_type,
            ServiceType::Notify | ServiceType::NotifyReload
        ) || watchdog_sec.is_some_and(|value| value > 0)
            || fd_store_max.is_some_and(|value| value > 0))
    {
        service.notify_access = NotifyAccess::Main;
    }
}

/// Check the PID portion of C's `service_notify_message_authorized()` policy.
///
/// The eventual transport must first authenticate this PID using kernel
/// credentials and a stable pid reference. This helper deliberately accepts
/// no notification content, uid, or file descriptors: authorization precedes
/// every state, watchdog, and FD-store action. PID comparisons are the same
/// fallback semantics as C's `pidref_equal()` when pidfd identity cannot be
/// obtained.
pub fn service_notify_sender_authorized(service: &Service, sender_pid: i32) -> bool {
    if sender_pid <= 0 {
        return false;
    }

    let is_main = service
        .main_pid
        .as_ref()
        .is_some_and(|pidref| pidref.pid == sender_pid);
    let is_control = service
        .control_pid
        .as_ref()
        .is_some_and(|pidref| pidref.pid == sender_pid);

    match service_get_notify_access(service) {
        NotifyAccess::All => true,
        NotifyAccess::Main => is_main,
        NotifyAccess::Exec => is_main || is_control,
        NotifyAccess::Invalid | NotifyAccess::None => false,
    }
}

/// Preserve the first failure which caused this activation to unwind.
///
/// Cleanup phases may encounter additional failures, but service.c reports the
/// original cause unless the current result is still success.
pub fn service_record_result(service: &mut Service, result: ServiceResult) {
    if service.result == ServiceResult::Success {
        service.result = result;
    }
}

pub fn service_reset_result(service: &mut Service) {
    service.result = ServiceResult::Success;
    service.main_exec_status.last_exit = None;
}

/// Record the first error in one nonterminal reload transaction.
///
/// Reload failures are reported independently from activation and must never
/// overwrite `result` or drive the service into `Failed`.
pub fn service_record_reload_result(service: &mut Service, result: ServiceResult) {
    if service.reload_result == ServiceResult::Success {
        service.reload_result = result;
    }
}

pub fn service_reset_reload_result(service: &mut Service) {
    service.reload_result = ServiceResult::Success;
}

pub fn service_set_main_pid_known(service: &mut Service, known: bool) {
    service.main_pid_known = known;
}

pub fn service_set_main_pidref(
    service: &mut Service,
    pidref: PidRef,
    start_timestamp: Option<u64>,
) -> Result<(), Errno> {
    if pidref.pid <= 0 {
        return Err(Errno::ESRCH);
    }
    if pidref.pid <= 1 || pidref.is_self {
        return Err(Errno::EINVAL);
    }

    if service.main_pid_known && service.main_pid.as_ref() == Some(&pidref) {
        return Ok(());
    }

    let effective_start = start_timestamp.or(pidref.start_time);
    if service.main_pid.as_ref() != Some(&pidref) {
        service.main_exec_status.started_pids.push(pidref.pid);
        service.main_exec_status.last_start_time = effective_start;
    }

    service.main_pid_alien = !pidref.is_child.unwrap_or(false);
    service.main_pid = Some(pidref);
    service.main_pid_known = true;
    Ok(())
}

pub fn service_restart_usec_next(service: &Service) -> u64 {
    let n_restarts_next =
        service.n_restarts + u32::from(service.state != ServiceState::AutoRestartQueued);

    if n_restarts_next <= 1
        || service.restart_steps == 0
        || service.restart_usec == 0
        || service.restart_max_delay_usec == USEC_INFINITY
        || service.restart_usec >= service.restart_max_delay_usec
    {
        return service.restart_usec;
    }

    if n_restarts_next > service.restart_steps {
        return service.restart_max_delay_usec;
    }

    let ratio = service.restart_max_delay_usec as f64 / service.restart_usec as f64;
    let exponent = (n_restarts_next - 1) as f64 / service.restart_steps as f64;
    (service.restart_usec as f64 * ratio.powf(exponent)) as u64
}

pub fn service_extend_timeout(service: &mut Service, now_monotonic: u64, extend_timeout_usec: u64) {
    if extend_timeout_usec == USEC_INFINITY {
        return;
    }

    let extended = now_monotonic.saturating_add(extend_timeout_usec);
    if service
        .timer_event_deadline
        .is_none_or(|current| current < extended)
    {
        service.timer_event_deadline = Some(extended);
    }
    if service
        .watchdog_event_deadline
        .is_none_or(|current| current < extended)
    {
        service.watchdog_event_deadline = Some(extended);
    }
}

pub fn service_override_watchdog_timeout(
    service: &mut Service,
    watchdog_override_usec: u64,
    now_monotonic: u64,
) {
    service.watchdog_override_enable = true;
    service.watchdog_override_usec = watchdog_override_usec;
    service.watchdog_timestamp = Some(now_monotonic);
    if watchdog_override_usec != USEC_INFINITY {
        service.watchdog_event_deadline =
            Some(now_monotonic.saturating_add(watchdog_override_usec));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_path_points_to_c_file() {
        assert_eq!(SOURCE_PATH, "src/core/service.c");
    }

    #[test]
    fn normal_state_translation_matches_visible_table() {
        assert_eq!(
            service_state_translation(ServiceState::Running, ServiceType::Simple),
            UnitActiveState::Active
        );
        assert_eq!(
            service_state_translation(ServiceState::Reload, ServiceType::Simple),
            UnitActiveState::Reloading
        );
        assert_eq!(
            service_state_translation(ServiceState::Cleaning, ServiceType::Simple),
            UnitActiveState::Maintenance
        );
    }

    #[test]
    fn idle_state_translation_promotes_startup_states_to_active() {
        assert_eq!(
            service_state_translation(ServiceState::StartPre, ServiceType::Idle),
            UnitActiveState::Active
        );
        assert_eq!(
            service_state_translation(ServiceState::Condition, ServiceType::Idle),
            UnitActiveState::Active
        );
    }

    #[test]
    fn state_helper_sets_match_c_macros() {
        assert!(service_state_with_main_process(ServiceState::ReloadNotify));
        assert!(service_state_with_control_process(ServiceState::Cleaning));
        assert!(service_state_with_watchdog(ServiceState::Mounting));
        assert!(!service_state_with_watchdog(ServiceState::Stop));
    }

    #[test]
    fn init_uses_manager_defaults_for_system_manager() {
        let manager = Manager::default();
        let mut service = Service::default();
        service_init(&mut service, &manager);

        assert_eq!(
            service.timeout_start_usec,
            manager.defaults.timeout_start_usec
        );
        assert_eq!(service.socket_fd, Errno::EBADF.to_neg_errno());
        assert_eq!(service.exec_context.keyring_mode, ExecKeyringMode::Private);
        assert_eq!(service.watchdog_usec, 0);
        assert!(service.guess_main_pid);
    }

    #[test]
    fn init_uses_inherited_keyring_for_user_manager() {
        let manager = Manager {
            is_system: false,
            ..Manager::default()
        };
        let mut service = Service::default();
        service_init(&mut service, &manager);

        assert_eq!(service.exec_context.keyring_mode, ExecKeyringMode::Inherit);
    }

    #[test]
    fn set_main_pidref_rejects_invalid_inputs() {
        let mut service = Service::default();
        assert_eq!(
            service_set_main_pidref(
                &mut service,
                PidRef {
                    pid: 0,
                    start_time: None,
                    is_self: false,
                    is_child: Some(true),
                },
                None,
            )
            .unwrap_err(),
            Errno::ESRCH
        );
        assert_eq!(
            service_set_main_pidref(
                &mut service,
                PidRef {
                    pid: 1,
                    start_time: None,
                    is_self: false,
                    is_child: Some(true),
                },
                None,
            )
            .unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn set_main_pidref_updates_tracking_and_alien_status() {
        let mut service = Service::default();
        service_set_main_pidref(
            &mut service,
            PidRef {
                pid: 4242,
                start_time: Some(77),
                is_self: false,
                is_child: Some(false),
            },
            None,
        )
        .unwrap();

        assert!(service.main_pid_known);
        assert!(service.main_pid_alien);
        assert_eq!(service.main_exec_status.started_pids, vec![4242]);
        assert_eq!(service.main_exec_status.last_start_time, Some(77));
    }

    #[test]
    fn restart_delay_growth_matches_formula_shape() {
        let service = Service {
            restart_usec: 10,
            restart_max_delay_usec: 160,
            restart_steps: 4,
            n_restarts: 1,
            state: ServiceState::DeadBeforeAutoRestart,
            ..Service::default()
        };

        let next = service_restart_usec_next(&service);
        assert!(next > 10);
        assert!(next < 160);
    }

    #[test]
    fn restart_delay_caps_at_maximum() {
        let service = Service {
            restart_usec: 10,
            restart_max_delay_usec: 160,
            restart_steps: 2,
            n_restarts: 4,
            state: ServiceState::DeadBeforeAutoRestart,
            ..Service::default()
        };

        assert_eq!(service_restart_usec_next(&service), 160);
    }

    #[test]
    fn service_result_retains_the_first_failure_until_reset() {
        let mut service = Service::default();
        service_record_result(&mut service, ServiceResult::FailureExitCode);
        service_record_result(&mut service, ServiceResult::FailureTimeout);
        assert_eq!(service.result, ServiceResult::FailureExitCode);

        service_reset_result(&mut service);
        assert_eq!(service.result, ServiceResult::Success);
    }

    #[test]
    fn reload_result_is_independent_and_first_failure_wins() {
        let mut service = Service::default();
        service_record_result(&mut service, ServiceResult::FailureProtocol);
        service_record_reload_result(&mut service, ServiceResult::FailureExitCode);
        service_record_reload_result(&mut service, ServiceResult::FailureTimeout);
        assert_eq!(service.result, ServiceResult::FailureProtocol);
        assert_eq!(service.reload_result, ServiceResult::FailureExitCode);

        service_reset_reload_result(&mut service);
        assert_eq!(service.reload_result, ServiceResult::Success);
        assert_eq!(service.result, ServiceResult::FailureProtocol);
    }

    #[test]
    fn extending_timeout_updates_both_deadlines_monotonically() {
        let mut service = Service {
            timer_event_deadline: Some(5),
            watchdog_event_deadline: Some(8),
            ..Service::default()
        };
        service_extend_timeout(&mut service, 10, 20);
        assert_eq!(service.timer_event_deadline, Some(30));
        assert_eq!(service.watchdog_event_deadline, Some(30));
    }

    #[test]
    fn watchdog_override_records_new_deadline() {
        let mut service = Service::default();
        service_override_watchdog_timeout(&mut service, 15, 100);
        assert!(service.watchdog_override_enable);
        assert_eq!(service.watchdog_override_usec, 15);
        assert_eq!(service.watchdog_event_deadline, Some(115));
    }

    #[test]
    fn notify_access_auto_enables_only_the_c_supported_configurations() {
        let mut service = Service {
            service_type: ServiceType::Notify,
            ..Service::default()
        };
        service_configure_notify_access(&mut service, None, None, None);
        assert_eq!(service.notify_access, NotifyAccess::Main);

        let mut watchdog = Service::default();
        service_configure_notify_access(&mut watchdog, None, Some(1), None);
        assert_eq!(watchdog.notify_access, NotifyAccess::Main);

        let mut fd_store = Service::default();
        service_configure_notify_access(&mut fd_store, None, None, Some(1));
        assert_eq!(fd_store.notify_access, NotifyAccess::Main);

        let mut ordinary = Service::default();
        service_configure_notify_access(&mut ordinary, None, Some(0), Some(0));
        assert_eq!(ordinary.notify_access, NotifyAccess::None);

        let mut explicit = Service {
            service_type: ServiceType::Notify,
            ..Service::default()
        };
        service_configure_notify_access(&mut explicit, Some(NotifyAccess::All), None, None);
        assert_eq!(explicit.notify_access, NotifyAccess::All);
    }

    #[test]
    fn notify_sender_authorization_uses_effective_policy_and_pid_roles() {
        let mut service = Service {
            notify_access: NotifyAccess::Main,
            main_pid: Some(PidRef {
                pid: 101,
                start_time: None,
                is_self: false,
                is_child: Some(true),
            }),
            control_pid: Some(PidRef {
                pid: 202,
                start_time: None,
                is_self: false,
                is_child: Some(true),
            }),
            ..Service::default()
        };

        assert!(service_notify_sender_authorized(&service, 101));
        assert!(!service_notify_sender_authorized(&service, 202));
        assert!(!service_notify_sender_authorized(&service, 303));
        assert!(!service_notify_sender_authorized(&service, 0));

        service.notify_access = NotifyAccess::Exec;
        assert!(service_notify_sender_authorized(&service, 101));
        assert!(service_notify_sender_authorized(&service, 202));

        service.notify_access_override = NotifyAccess::None;
        assert_eq!(service_get_notify_access(&service), NotifyAccess::None);
        assert!(!service_notify_sender_authorized(&service, 101));

        service.notify_access_override = NotifyAccess::All;
        assert!(service_notify_sender_authorized(&service, 303));
    }
}
