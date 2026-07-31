// SPDX-License-Identifier: LGPL-2.1-or-later

//! Service readiness policy kept separate from execution-phase transitions.

use super::unit_file::UnitFileInfo;
use crate::service::ServiceType;

/// Return the fail-closed reason for service types whose manager transport is
/// not yet available. Linux `Type=idle` is backed by the real manager-owned
/// pipe gate; the other readiness protocols still require their authoritative
/// C-compatible transport before they may claim success.
pub(super) fn readiness_rejection(
    service_type: ServiceType,
    info: &UnitFileInfo,
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
        ServiceType::Notify | ServiceType::NotifyReload => Some(
            "Type=notify requires an authenticated sd_notify transport, which is not implemented",
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
