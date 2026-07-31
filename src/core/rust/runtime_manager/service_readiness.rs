// SPDX-License-Identifier: LGPL-2.1-or-later

//! Service readiness policy kept separate from execution-phase transitions.

use super::unit_file::UnitFileInfo;
use crate::service::{NotifyAccess, ServiceType};

/// Return the fail-closed reason for service types whose manager transport is
/// not yet available. Linux `Type=idle` is backed by the real manager-owned
/// pipe gate, while `Type=notify` below exposes only the explicitly modeled
/// direct-main subset; other readiness protocols still require their
/// authoritative C-compatible transport before they may claim success.
pub(super) fn readiness_rejection(
    service_type: ServiceType,
    info: &UnitFileInfo,
    authenticated_notify_socket_configured: bool,
) -> Option<&'static str> {
    match service_type {
        ServiceType::Idle => {
            #[cfg(target_os = "linux")]
            {
                None
            }
            #[cfg(not(target_os = "linux"))]
            {
                Some("Type=idle requires the Linux manager idle gate")
            }
        }
        // This is deliberately a small production subset, not a claim that
        // every sd_notify field has reached C parity. A bound source, exact
        // direct-child pidfd identity, and `NotifyAccess=main` are sufficient
        // for a normal Type=notify READY=/STOPPING= lifecycle. Cgroup-child
        // routing, NotifyAccess=exec/all, watchdog configuration, FDSTORE,
        // and Type=notify-reload remain fail closed until their contracts are
        // complete. Watchdog pings use the same authenticated direct-main
        // route and manager-owned deadline already used by the service FSM.
        ServiceType::Notify if !authenticated_notify_socket_configured => {
            Some("Type=notify requires a bound authenticated sd_notify socket")
        }
        ServiceType::Notify
            if !matches!(
                info.service.notify_access,
                None | Some(NotifyAccess::None | NotifyAccess::Main)
            ) =>
        {
            Some("Type=notify currently supports only NotifyAccess=main")
        }
        ServiceType::Notify
            if info
                .service
                .file_descriptor_store_max
                .is_some_and(|value| value > 0) =>
        {
            Some("Type=notify FDSTORE is not implemented")
        }
        ServiceType::NotifyReload => Some(
            "Type=notify-reload requires complete reload transaction routing, which is not implemented",
        ),
        ServiceType::Dbus
            if info
                .service
                .bus_name
                .as_deref()
                .is_none_or(|name| name.trim().is_empty()) =>
        {
            Some("Type=dbus requires a non-empty BusName=")
        }
        ServiceType::Dbus => Some(
            "Type=dbus requires authenticated BusName ownership tracking, which is not implemented",
        ),
        _ => None,
    }
}
