// SPDX-License-Identifier: LGPL-2.1-or-later

//! Parent-side environment preparation for Linux service launches.
//!
//! Runtime-owned assignments are applied after unit environment transforms;
//! child-only PID values are added later by `ChildScratch` after fork.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

use super::super::{SpawnSecurity, parse_environment_file};

pub(super) fn prepare_environment(
    security: &SpawnSecurity,
    skip_exec_context: bool,
) -> Result<(Vec<CString>, bool), String> {
    let mut environment: BTreeMap<Vec<u8>, Vec<u8>> = std::env::vars_os()
        .map(|(key, value)| {
            (
                key.as_os_str().as_bytes().to_vec(),
                value.as_os_str().as_bytes().to_vec(),
            )
        })
        .collect();

    if !skip_exec_context {
        for path in &security.environment_file {
            let mut file_environment = BTreeMap::new();
            parse_environment_file(path, &mut file_environment)?;
            environment.extend(
                file_environment
                    .into_iter()
                    .map(|(key, value)| (key.into_bytes(), value.into_bytes())),
            );
        }

        for assignment in &security.environment {
            let Some((key, value)) = assignment.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if !key.is_empty() {
                environment.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec());
            }
        }

        for key in &security.pass_environment {
            if let Some(value) = std::env::var_os(key) {
                environment.insert(
                    key.as_bytes().to_vec(),
                    value.as_os_str().as_bytes().to_vec(),
                );
            }
        }

        for key in &security.unset_environment {
            let target = key.split('=').next().unwrap_or(key).trim();
            if !target.is_empty() {
                environment.remove(target.as_bytes());
            }
        }
    }

    // PID 1 owns these values. Inherited or unit-supplied copies must never
    // shadow the launch-specific assignments appended by PreparedEnvironment.
    for runtime_name in [
        "MAINPID",
        "LISTEN_PID",
        "LISTEN_FDS",
        "LISTEN_FDNAMES",
        "LISTEN_PIDFDID",
        "NOTIFY_SOCKET",
        "WATCHDOG_PID",
        "WATCHDOG_USEC",
    ] {
        environment.remove(runtime_name.as_bytes());
    }

    // Manager-owned transport and watchdog values are appended after all
    // EnvironmentFile=/Environment=/PassEnvironment=/UnsetEnvironment= work.
    if let Some(notify_socket) = &security.notify_socket {
        if !notify_socket.starts_with('/') || notify_socket.as_bytes().contains(&0) {
            return Err("manager supplied an invalid NOTIFY_SOCKET path".to_string());
        }
        environment.insert(b"NOTIFY_SOCKET".to_vec(), notify_socket.as_bytes().to_vec());
    }

    let has_watchdog = !skip_exec_context
        && security
            .watchdog_usec
            .is_some_and(|watchdog_usec| watchdog_usec > 0);
    if let Some(watchdog_usec) = security.watchdog_usec.filter(|value| *value > 0)
        && !skip_exec_context
    {
        environment.insert(
            b"WATCHDOG_USEC".to_vec(),
            watchdog_usec.to_string().into_bytes(),
        );
    }

    let environment = environment
        .into_iter()
        .map(|(key, value)| {
            if key.is_empty() || key.contains(&b'=') || key.contains(&0) {
                return Err(format!(
                    "invalid environment variable name {:?}",
                    String::from_utf8_lossy(&key)
                ));
            }
            let mut assignment = Vec::with_capacity(key.len() + 1 + value.len());
            assignment.extend_from_slice(&key);
            assignment.push(b'=');
            assignment.extend_from_slice(&value);
            CString::new(assignment).map_err(|error| {
                format!(
                    "invalid environment value for {:?}: {error}",
                    String::from_utf8_lossy(&key)
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((environment, has_watchdog))
}
