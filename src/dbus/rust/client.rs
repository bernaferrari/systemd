// SPDX-License-Identifier: LGPL-2.1-or-later

use crate::constants::{SD_INTERFACE, SD_PATH, SD_SERVICE};
use crate::proxy::{UnitStatus, UnitStatusWire};

use zbus::zvariant::OwnedObjectPath;

/// `org.freedesktop.systemd1`'s system manager is only available on Linux.
///
/// Keep non-Linux entry points type-compatible without fabricating an empty
/// reply that callers could mistake for a successful manager operation.
#[cfg(not(target_os = "linux"))]
fn system_manager_unsupported<T>() -> zbus::Result<T> {
    Err(zbus::Error::Unsupported)
}

#[cfg(target_os = "linux")]
pub async fn list_units_system() -> zbus::Result<Vec<UnitStatus>> {
    let conn = zbus::Connection::system().await?;
    let reply: Vec<UnitStatusWire> = conn
        .call_method(
            Some(SD_SERVICE),
            SD_PATH,
            Some(SD_INTERFACE),
            "ListUnits",
            &(),
        )
        .await?
        .body()
        .deserialize()?;

    Ok(reply.into_iter().map(UnitStatus::from).collect())
}

#[cfg(not(target_os = "linux"))]
pub async fn list_units_system() -> zbus::Result<Vec<UnitStatus>> {
    system_manager_unsupported()
}

#[cfg(target_os = "linux")]
pub async fn start_unit_system(name: &str, mode: &str) -> zbus::Result<String> {
    let conn = zbus::Connection::system().await?;
    let reply: OwnedObjectPath = conn
        .call_method(
            Some(SD_SERVICE),
            SD_PATH,
            Some(SD_INTERFACE),
            "StartUnit",
            &(name, mode),
        )
        .await?
        .body()
        .deserialize()?;
    Ok(reply.to_string())
}

#[cfg(not(target_os = "linux"))]
pub async fn start_unit_system(_name: &str, _mode: &str) -> zbus::Result<String> {
    system_manager_unsupported()
}

#[cfg(target_os = "linux")]
pub async fn stop_unit_system(name: &str, mode: &str) -> zbus::Result<String> {
    let conn = zbus::Connection::system().await?;
    let reply: OwnedObjectPath = conn
        .call_method(
            Some(SD_SERVICE),
            SD_PATH,
            Some(SD_INTERFACE),
            "StopUnit",
            &(name, mode),
        )
        .await?
        .body()
        .deserialize()?;
    Ok(reply.to_string())
}

#[cfg(not(target_os = "linux"))]
pub async fn stop_unit_system(_name: &str, _mode: &str) -> zbus::Result<String> {
    system_manager_unsupported()
}

#[cfg(target_os = "linux")]
pub async fn restart_unit_system(name: &str, mode: &str) -> zbus::Result<String> {
    let conn = zbus::Connection::system().await?;
    let reply: OwnedObjectPath = conn
        .call_method(
            Some(SD_SERVICE),
            SD_PATH,
            Some(SD_INTERFACE),
            "RestartUnit",
            &(name, mode),
        )
        .await?
        .body()
        .deserialize()?;
    Ok(reply.to_string())
}

#[cfg(not(target_os = "linux"))]
pub async fn restart_unit_system(_name: &str, _mode: &str) -> zbus::Result<String> {
    system_manager_unsupported()
}

#[cfg(target_os = "linux")]
pub async fn try_restart_unit_system(name: &str, mode: &str) -> zbus::Result<String> {
    let conn = zbus::Connection::system().await?;
    let reply: OwnedObjectPath = conn
        .call_method(
            Some(SD_SERVICE),
            SD_PATH,
            Some(SD_INTERFACE),
            "TryRestartUnit",
            &(name, mode),
        )
        .await?
        .body()
        .deserialize()?;
    Ok(reply.to_string())
}

#[cfg(not(target_os = "linux"))]
pub async fn try_restart_unit_system(_name: &str, _mode: &str) -> zbus::Result<String> {
    system_manager_unsupported()
}

#[cfg(target_os = "linux")]
pub async fn reload_or_restart_unit_system(name: &str, mode: &str) -> zbus::Result<String> {
    let conn = zbus::Connection::system().await?;
    let reply: OwnedObjectPath = conn
        .call_method(
            Some(SD_SERVICE),
            SD_PATH,
            Some(SD_INTERFACE),
            "ReloadOrRestartUnit",
            &(name, mode),
        )
        .await?
        .body()
        .deserialize()?;
    Ok(reply.to_string())
}

#[cfg(not(target_os = "linux"))]
pub async fn reload_or_restart_unit_system(_name: &str, _mode: &str) -> zbus::Result<String> {
    system_manager_unsupported()
}

#[cfg(target_os = "linux")]
pub async fn reload_or_try_restart_unit_system(name: &str, mode: &str) -> zbus::Result<String> {
    let conn = zbus::Connection::system().await?;
    let reply: OwnedObjectPath = conn
        .call_method(
            Some(SD_SERVICE),
            SD_PATH,
            Some(SD_INTERFACE),
            "ReloadOrTryRestartUnit",
            &(name, mode),
        )
        .await?
        .body()
        .deserialize()?;
    Ok(reply.to_string())
}

#[cfg(not(target_os = "linux"))]
pub async fn reload_or_try_restart_unit_system(_name: &str, _mode: &str) -> zbus::Result<String> {
    system_manager_unsupported()
}

#[cfg(target_os = "linux")]
pub async fn get_job_system(id: u32) -> zbus::Result<String> {
    let conn = zbus::Connection::system().await?;
    let reply: OwnedObjectPath = conn
        .call_method(
            Some(SD_SERVICE),
            SD_PATH,
            Some(SD_INTERFACE),
            "GetJob",
            &(id,),
        )
        .await?
        .body()
        .deserialize()?;
    Ok(reply.to_string())
}

#[cfg(not(target_os = "linux"))]
pub async fn get_job_system(_id: u32) -> zbus::Result<String> {
    system_manager_unsupported()
}

#[cfg(target_os = "linux")]
pub async fn cancel_job_system(id: u32) -> zbus::Result<()> {
    let conn = zbus::Connection::system().await?;
    conn.call_method(
        Some(SD_SERVICE),
        SD_PATH,
        Some(SD_INTERFACE),
        "CancelJob",
        &(id,),
    )
    .await?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn cancel_job_system(_id: u32) -> zbus::Result<()> {
    system_manager_unsupported()
}

#[cfg(target_os = "linux")]
pub async fn enable_unit_files_system(
    units: &[&str],
) -> zbus::Result<Vec<(String, String, String)>> {
    let conn = zbus::Connection::system().await?;
    let (_carries_install_info, changes): (bool, Vec<(String, String, String)>) = conn
        .call_method(
            Some(SD_SERVICE),
            SD_PATH,
            Some(SD_INTERFACE),
            "EnableUnitFiles",
            &(units, false, false),
        )
        .await?
        .body()
        .deserialize()?;

    // Preserve the established Rust API: callers only consume the change list.
    Ok(changes)
}

#[cfg(not(target_os = "linux"))]
pub async fn enable_unit_files_system(
    _units: &[&str],
) -> zbus::Result<Vec<(String, String, String)>> {
    system_manager_unsupported()
}

#[cfg(target_os = "linux")]
pub async fn disable_unit_files_system(
    units: &[&str],
) -> zbus::Result<Vec<(String, String, String)>> {
    let conn = zbus::Connection::system().await?;
    let reply: Vec<(String, String, String)> = conn
        .call_method(
            Some(SD_SERVICE),
            SD_PATH,
            Some(SD_INTERFACE),
            "DisableUnitFiles",
            &(units, false),
        )
        .await?
        .body()
        .deserialize()?;
    Ok(reply)
}

#[cfg(not(target_os = "linux"))]
pub async fn disable_unit_files_system(
    _units: &[&str],
) -> zbus::Result<Vec<(String, String, String)>> {
    system_manager_unsupported()
}

#[cfg(target_os = "linux")]
pub async fn reload_system() -> zbus::Result<()> {
    let conn = zbus::Connection::system().await?;
    conn.call_method(Some(SD_SERVICE), SD_PATH, Some(SD_INTERFACE), "Reload", &())
        .await?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn reload_system() -> zbus::Result<()> {
    system_manager_unsupported()
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn assert_immediately_unsupported<T>(future: impl Future<Output = zbus::Result<T>>) {
        let mut future = pin!(future);
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let Poll::Ready(result) = future.as_mut().poll(&mut context) else {
            panic!("non-Linux system-manager stub unexpectedly suspended");
        };
        assert!(matches!(result, Err(zbus::Error::Unsupported)));
    }

    #[test]
    fn every_system_manager_entry_point_fails_closed() {
        assert_immediately_unsupported(list_units_system());
        assert_immediately_unsupported(start_unit_system("example.service", "replace"));
        assert_immediately_unsupported(stop_unit_system("example.service", "replace"));
        assert_immediately_unsupported(restart_unit_system("example.service", "replace"));
        assert_immediately_unsupported(try_restart_unit_system("example.service", "replace"));
        assert_immediately_unsupported(reload_or_restart_unit_system("example.service", "replace"));
        assert_immediately_unsupported(reload_or_try_restart_unit_system(
            "example.service",
            "replace",
        ));
        assert_immediately_unsupported(get_job_system(1));
        assert_immediately_unsupported(cancel_job_system(1));
        assert_immediately_unsupported(enable_unit_files_system(&["example.service"]));
        assert_immediately_unsupported(disable_unit_files_system(&["example.service"]));
        assert_immediately_unsupported(reload_system());
    }
}
