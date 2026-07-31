// SPDX-License-Identifier: LGPL-2.1-or-later
#![cfg(target_os = "linux")]

//! Manager-owned dispatch for authenticated service notification datagrams.

use std::time::{Duration, Instant};

use super::RuntimeManager;
use crate::pid1_notify_source::{
    NotifyFdStoreRequest, NotifyLifecycle, NotifyMainPid, NotifyWatchdog, ParsedNotifyDatagram,
};
use crate::service::{
    NotifyState, ServiceState, ServiceType, service_notify_sender_authorized,
    service_state_with_watchdog,
};

/// Result of routing one kernel-authenticated notification through the
/// manager-owned service model. This is deliberately observational: callers
/// can distinguish an unknown or unauthorized sender from accepted state
/// fields which remain unsupported (FDSTORE, MAINPID, watchdog trigger).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthenticatedNotifyDispatch {
    IgnoredUnknownSender {
        pid: u32,
    },
    IgnoredUnauthorized {
        unit: String,
        pid: u32,
    },
    Applied {
        unit: String,
        lifecycle: NotifyLifecycle,
        entered_start_post: bool,
        entered_reload_post: bool,
        entered_stop_by_notify: bool,
        watchdog_reset: bool,
        main_pid_ignored: bool,
        fd_store_ignored: bool,
        status_observed: bool,
    },
}

impl RuntimeManager {
    /// Route a typed datagram only after `NotifySourceOwner` authenticated its
    /// sender through `SCM_CREDENTIALS`.
    ///
    /// This intentionally does not make the notify transport production
    /// ready: `MAINPID=`, FDSTORE, `WATCHDOG=trigger`, status publication,
    /// and reload propagation each still need their own owned contracts. The
    /// transitions below are the pieces which already have a single
    /// RuntimeManager owner and can be applied without guessing identity or
    /// fabricating descriptors.
    #[cfg(target_os = "linux")]
    pub(crate) fn dispatch_authenticated_notify(
        &mut self,
        notification: ParsedNotifyDatagram,
    ) -> AuthenticatedNotifyDispatch {
        let sender_pid = notification.peer.pid;
        let Some(unit) = self.pid_to_unit_map.get(&sender_pid).cloned() else {
            return AuthenticatedNotifyDispatch::IgnoredUnknownSender { pid: sender_pid };
        };
        let authorized = i32::try_from(sender_pid).ok().is_some_and(|pid| {
            self.services
                .get(&unit)
                .is_some_and(|service| service_notify_sender_authorized(service, pid))
        });
        if !authorized {
            return AuthenticatedNotifyDispatch::IgnoredUnauthorized {
                unit,
                pid: sender_pid,
            };
        }

        let Some((service_type, prior_state, prior_notify_state, reload_begin_usec)) =
            self.services.get(&unit).map(|service| {
                (
                    service.service_type,
                    service.state,
                    service.notify_state,
                    service.reload_begin_usec,
                )
            })
        else {
            // `pid_to_unit_map` is only a compatibility routing index. Do
            // not let stale bookkeeping become a PID 1 panic or authorization
            // bypass if its corresponding Service was removed first.
            return AuthenticatedNotifyDispatch::IgnoredUnauthorized {
                unit,
                pid: sender_pid,
            };
        };

        let mut entered_start_post = false;
        let mut entered_reload_post = false;
        let mut entered_stop_by_notify = false;

        if notification.lifecycle == NotifyLifecycle::Stopping {
            if let Some(service) = self.services.get_mut(&unit) {
                service.notify_state = NotifyState::Stopping;
            }
            if matches!(
                prior_state,
                ServiceState::Running
                    | ServiceState::RefreshExtensions
                    | ServiceState::RefreshCredentials
                    | ServiceState::ReloadSignal
                    | ServiceState::ReloadNotify
            ) {
                self.enter_stop_by_notify(&unit);
                entered_stop_by_notify = true;
            }
        } else if prior_notify_state != NotifyState::Stopping {
            match notification.lifecycle {
                NotifyLifecycle::Ready => {
                    if let Some(service) = self.services.get_mut(&unit) {
                        service.notify_state = if prior_notify_state == NotifyState::Reloading {
                            NotifyState::ReloadReady
                        } else {
                            NotifyState::Ready
                        };
                    }

                    // A READY=1 sent while handling a notify service's main
                    // command owns the normal StartPost sequence, exactly as
                    // service_notify_message_process_state() does.
                    if matches!(
                        service_type,
                        ServiceType::Notify | ServiceType::NotifyReload
                    ) && prior_state == ServiceState::Start
                    {
                        self.enter_start_post(&unit);
                        entered_start_post = true;
                    } else if prior_state == ServiceState::ReloadNotify
                        || (notification.reloading
                            && prior_state == ServiceState::ReloadSignal
                            && notification
                                .monotonic_usec
                                .is_some_and(|timestamp| timestamp >= reload_begin_usec))
                    {
                        self.enter_reload_post(&unit);
                        entered_reload_post = true;
                    }
                }
                NotifyLifecycle::Reloading => {
                    if let Some(service) = self.services.get_mut(&unit) {
                        service.notify_state = NotifyState::Reloading;
                    }
                    // The ReloadSignal -> ReloadNotify edge is local to this
                    // unit and guarded by C's monotonic freshness condition.
                    // A RELOADING=1 received while Running would additionally
                    // propagate a reload transaction; defer that branch until
                    // dependency propagation has one production owner.
                    if prior_state == ServiceState::ReloadSignal
                        && notification
                            .monotonic_usec
                            .is_some_and(|timestamp| timestamp >= reload_begin_usec)
                    {
                        self.set_service_state(&unit, ServiceState::ReloadNotify);
                    }
                }
                NotifyLifecycle::None | NotifyLifecycle::Stopping => {}
            }
        }

        let watchdog_reset = notification.watchdog == NotifyWatchdog::Ping
            && self.reset_service_watchdog_from_notify(&unit);
        AuthenticatedNotifyDispatch::Applied {
            unit,
            lifecycle: notification.lifecycle,
            entered_start_post,
            entered_reload_post,
            entered_stop_by_notify,
            watchdog_reset,
            main_pid_ignored: !matches!(notification.main_pid, NotifyMainPid::Absent),
            fd_store_ignored: !matches!(notification.fd_store, NotifyFdStoreRequest::None),
            status_observed: notification.status.is_some(),
        }
    }

    #[cfg(target_os = "linux")]
    fn reset_service_watchdog_from_notify(&mut self, name: &str) -> bool {
        let Some((state, watchdog_usec)) = self
            .services
            .get(name)
            .map(|service| (service.state, service.watchdog_usec))
        else {
            return false;
        };
        if !service_state_with_watchdog(state) || watchdog_usec == 0 {
            return false;
        }
        self.service_watchdog_deadlines.insert(
            name.to_owned(),
            Instant::now() + Duration::from_micros(watchdog_usec),
        );
        true
    }

    /// C's `service_enter_stop_by_notify()` arms the stop timeout and changes
    /// state, but does *not* send a signal—the service reported that it has
    /// already begun stopping. Reusing `enter_signal()` here would violate
    /// that contract by issuing an unnecessary SIGTERM.
    #[cfg(target_os = "linux")]
    fn enter_stop_by_notify(&mut self, name: &str) {
        let Some(info) = self.unit_files.get(name).cloned() else {
            return;
        };
        // `service_set_state(SERVICE_STOP_SIGTERM)` stops watchdog supervision
        // before arming the normal stop timeout. A notify-originated stop must
        // not leave a stale watchdog deadline racing the shutdown path.
        self.service_watchdog_deadlines.remove(name);
        self.arm_signal_deadline(name, ServiceState::StopSigterm, &info);
        self.set_service_state(name, ServiceState::StopSigterm);
    }
}
