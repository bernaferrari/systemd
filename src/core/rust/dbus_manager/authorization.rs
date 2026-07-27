// SPDX-License-Identifier: LGPL-2.1-or-later

use super::{
    manager_dispatch, map_method_call_to_request, map_reply_to_method_result, ManagerMethodCall,
    ManagerMethodResultPayload, ManagerRecord, ManagerRequest, Result,
};
use crate::dbus_util::{
    bus_verify_manage_units_authorization, bus_verify_polkit_action_authorization,
    POLKIT_ACTION_RELOAD_DAEMON, POLKIT_ACTION_SET_ENVIRONMENT,
};
use crate::ffi::Errno;
use crate::runtime_manager::RuntimeManager;
use systemd_shared_rs::bus_polkit::{AsyncPolkitQueryAction, AsyncPolkitReturn};

pub struct ManagerMethodContext {
    pub runtime: RuntimeManager,
    pub manager: ManagerRecord,
    pub sender_uid: u32,
    pub sender_privileged: bool,
    pub polkit_actions: Vec<AsyncPolkitQueryAction>,
    pub allow_interactive_auth: bool,
}

// Production transports must provide the peer identity explicitly. A `Default`
// implementation would make it too easy to authorize a request without binding
// it to the credentials supplied by sd-bus.
#[cfg(test)]
impl Default for ManagerMethodContext {
    fn default() -> Self {
        Self {
            runtime: RuntimeManager::new(),
            manager: ManagerRecord::default(),
            sender_uid: u32::MAX,
            sender_privileged: false,
            polkit_actions: Vec::new(),
            allow_interactive_auth: false,
        }
    }
}

fn manager_request_unit_and_verb(request: &ManagerRequest) -> Option<(&str, &'static str)> {
    match request {
        ManagerRequest::StartUnit { name, .. } => Some((name, "start")),
        ManagerRequest::StopUnit { name, .. } => Some((name, "stop")),
        ManagerRequest::ReloadUnit { name, .. } => Some((name, "reload")),
        ManagerRequest::RestartUnit { name, .. } => Some((name, "restart")),
        ManagerRequest::TryRestartUnit { name, .. } => Some((name, "try-restart")),
        ManagerRequest::ReloadOrRestartUnit { name, .. } => Some((name, "reload-or-restart")),
        ManagerRequest::ReloadOrTryRestartUnit { name, .. } => {
            Some((name, "reload-or-try-restart"))
        }
        _ => None,
    }
}

fn manager_request_polkit_action(request: &ManagerRequest) -> Option<&'static str> {
    match request {
        ManagerRequest::Reload | ManagerRequest::Reexecute => Some(POLKIT_ACTION_RELOAD_DAEMON),
        ManagerRequest::SetEnvironment { .. }
        | ManagerRequest::UnsetEnvironment { .. }
        | ManagerRequest::UnsetAndSetEnvironment { .. } => Some(POLKIT_ACTION_SET_ENVIRONMENT),
        _ => None,
    }
}

fn manager_request_requires_privileged_sender(request: &ManagerRequest) -> bool {
    matches!(
        request,
        ManagerRequest::Exit
            | ManagerRequest::Reboot
            | ManagerRequest::SoftReboot { .. }
            | ManagerRequest::Poweroff
            | ManagerRequest::Halt
            | ManagerRequest::Kexec
            | ManagerRequest::SwitchRoot { .. }
            | ManagerRequest::SetExitCode { .. }
    )
}

pub fn authorize_manager_method_request(
    context: &ManagerMethodContext,
    request: &ManagerRequest,
) -> Result<()> {
    if let Some((unit, verb)) = manager_request_unit_and_verb(request) {
        let polkit_message = format!("{verb} {unit}");
        let decision = bus_verify_manage_units_authorization(
            Some(unit),
            Some(verb),
            Some(&polkit_message),
            context.sender_uid,
            context.sender_privileged,
            &context.polkit_actions,
            context.allow_interactive_auth,
        )
        .map_err(|_| Errno::EACCES)?;

        match decision {
            AsyncPolkitReturn::Authorized => {}
            AsyncPolkitReturn::QueryDispatched | AsyncPolkitReturn::Denied => {
                return Err(Errno::EACCES);
            }
        }
    }

    if let Some(action) = manager_request_polkit_action(request) {
        let decision = bus_verify_polkit_action_authorization(
            action,
            context.sender_uid,
            context.sender_privileged,
            &context.polkit_actions,
            context.allow_interactive_auth,
        )
        .map_err(|_| Errno::EACCES)?;

        match decision {
            AsyncPolkitReturn::Authorized => {}
            AsyncPolkitReturn::QueryDispatched | AsyncPolkitReturn::Denied => {
                return Err(Errno::EACCES);
            }
        }
    }

    if manager_request_requires_privileged_sender(request) && !context.sender_privileged {
        return Err(Errno::EACCES);
    }

    Ok(())
}

/// Authorize and dispatch a typed manager call without raw-pointer message casts.
pub fn handle_authorized_manager_method_call(
    context: &mut ManagerMethodContext,
    call: &ManagerMethodCall,
) -> Result<ManagerMethodResultPayload> {
    let request = map_method_call_to_request(call)?;
    authorize_manager_method_request(context, &request)?;
    let reply = manager_dispatch(&mut context.runtime, &mut context.manager, request)?;
    Ok(map_reply_to_method_result(reply))
}
