// SPDX-License-Identifier: LGPL-2.1-or-later

use super::{
    ManagerJobTuple, ManagerRecord, ManagerReply, ManagerRequest, ManagerUnitTuple, Result,
    manager_dispatch,
};
use crate::ffi::Errno;
use crate::runtime_manager::RuntimeManager;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagerMethodPayload {
    None,
    UnitName(String),
    InvocationId(String),
    ControlGroup(String),
    Pid(u32),
    PidFd(i32),
    UnitNames(Vec<String>),
    UnitFilters {
        states: Vec<String>,
        patterns: Vec<String>,
    },
    Patterns(Vec<String>),
    StringValue(String),
    StringPair {
        left: String,
        right: String,
    },
    StringList(Vec<String>),
    StringLists {
        first: Vec<String>,
        second: Vec<String>,
    },
    U8(u8),
    JobId(u32),
    UnitAndMode {
        name: String,
        mode: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerMethodCall {
    pub member: String,
    pub payload: ManagerMethodPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagerMethodResultPayload {
    Empty,
    UnitPath(String),
    Units(Vec<ManagerUnitTuple>),
    JobPath(String),
    Jobs(Vec<ManagerJobTuple>),
}

pub fn map_method_call_to_request(call: &ManagerMethodCall) -> Result<ManagerRequest> {
    match call.member.as_str() {
        "GetUnit" => match &call.payload {
            ManagerMethodPayload::UnitName(name) => {
                Ok(ManagerRequest::GetUnit { name: name.clone() })
            }
            _ => Err(Errno::EINVAL),
        },
        "GetUnitByPID" => match call.payload {
            ManagerMethodPayload::Pid(pid) => Ok(ManagerRequest::GetUnitByPid { pid }),
            _ => Err(Errno::EINVAL),
        },
        "GetUnitByInvocationID" => match &call.payload {
            ManagerMethodPayload::InvocationId(invocation_id) => {
                Ok(ManagerRequest::GetUnitByInvocationId {
                    invocation_id: invocation_id.clone(),
                })
            }
            _ => Err(Errno::EINVAL),
        },
        "GetUnitByControlGroup" => match &call.payload {
            ManagerMethodPayload::ControlGroup(cgroup) => {
                Ok(ManagerRequest::GetUnitByControlGroup {
                    cgroup: cgroup.clone(),
                })
            }
            _ => Err(Errno::EINVAL),
        },
        "GetUnitByPIDFD" => match call.payload {
            ManagerMethodPayload::PidFd(pidfd) => Ok(ManagerRequest::GetUnitByPidFd { pidfd }),
            _ => Err(Errno::EINVAL),
        },
        "LoadUnit" => match &call.payload {
            ManagerMethodPayload::UnitName(name) => {
                Ok(ManagerRequest::LoadUnit { name: name.clone() })
            }
            _ => Err(Errno::EINVAL),
        },
        "ListUnits" => match call.payload {
            ManagerMethodPayload::None => Ok(ManagerRequest::ListUnits),
            _ => Err(Errno::EINVAL),
        },
        "ListUnitsByNames" => match &call.payload {
            ManagerMethodPayload::UnitNames(names) => Ok(ManagerRequest::ListUnitsByNames {
                names: names.clone(),
            }),
            _ => Err(Errno::EINVAL),
        },
        "ListUnitsFiltered" => match &call.payload {
            ManagerMethodPayload::UnitFilters { states, patterns } => {
                Ok(ManagerRequest::ListUnitsFiltered {
                    states: states.clone(),
                    patterns: patterns.clone(),
                })
            }
            _ => Err(Errno::EINVAL),
        },
        "ListUnitsByPatterns" => match &call.payload {
            ManagerMethodPayload::Patterns(patterns) => Ok(ManagerRequest::ListUnitsByPatterns {
                patterns: patterns.clone(),
            }),
            _ => Err(Errno::EINVAL),
        },
        "GetJob" => match call.payload {
            ManagerMethodPayload::JobId(id) => Ok(ManagerRequest::GetJob { id }),
            _ => Err(Errno::EINVAL),
        },
        "ListJobs" => match call.payload {
            ManagerMethodPayload::None => Ok(ManagerRequest::ListJobs),
            _ => Err(Errno::EINVAL),
        },
        "StartUnit" => match &call.payload {
            ManagerMethodPayload::UnitAndMode { name, mode } => Ok(ManagerRequest::StartUnit {
                name: name.clone(),
                mode: mode.clone(),
            }),
            _ => Err(Errno::EINVAL),
        },
        "StopUnit" => match &call.payload {
            ManagerMethodPayload::UnitAndMode { name, mode } => Ok(ManagerRequest::StopUnit {
                name: name.clone(),
                mode: mode.clone(),
            }),
            _ => Err(Errno::EINVAL),
        },
        "ReloadUnit" => match &call.payload {
            ManagerMethodPayload::UnitAndMode { name, mode } => Ok(ManagerRequest::ReloadUnit {
                name: name.clone(),
                mode: mode.clone(),
            }),
            _ => Err(Errno::EINVAL),
        },
        "RestartUnit" => match &call.payload {
            ManagerMethodPayload::UnitAndMode { name, mode } => Ok(ManagerRequest::RestartUnit {
                name: name.clone(),
                mode: mode.clone(),
            }),
            _ => Err(Errno::EINVAL),
        },
        "TryRestartUnit" => match &call.payload {
            ManagerMethodPayload::UnitAndMode { name, mode } => {
                Ok(ManagerRequest::TryRestartUnit {
                    name: name.clone(),
                    mode: mode.clone(),
                })
            }
            _ => Err(Errno::EINVAL),
        },
        "ReloadOrRestartUnit" => match &call.payload {
            ManagerMethodPayload::UnitAndMode { name, mode } => {
                Ok(ManagerRequest::ReloadOrRestartUnit {
                    name: name.clone(),
                    mode: mode.clone(),
                })
            }
            _ => Err(Errno::EINVAL),
        },
        "ReloadOrTryRestartUnit" => match &call.payload {
            ManagerMethodPayload::UnitAndMode { name, mode } => {
                Ok(ManagerRequest::ReloadOrTryRestartUnit {
                    name: name.clone(),
                    mode: mode.clone(),
                })
            }
            _ => Err(Errno::EINVAL),
        },
        "Reload" => match call.payload {
            ManagerMethodPayload::None => Ok(ManagerRequest::Reload),
            _ => Err(Errno::EINVAL),
        },
        "Reexecute" => match call.payload {
            ManagerMethodPayload::None => Ok(ManagerRequest::Reexecute),
            _ => Err(Errno::EINVAL),
        },
        "Exit" => match call.payload {
            ManagerMethodPayload::None => Ok(ManagerRequest::Exit),
            _ => Err(Errno::EINVAL),
        },
        "Reboot" => match call.payload {
            ManagerMethodPayload::None => Ok(ManagerRequest::Reboot),
            _ => Err(Errno::EINVAL),
        },
        "SoftReboot" => match &call.payload {
            ManagerMethodPayload::StringValue(root) => Ok(ManagerRequest::SoftReboot {
                root: (!root.is_empty()).then(|| root.clone()),
            }),
            _ => Err(Errno::EINVAL),
        },
        "PowerOff" => match call.payload {
            ManagerMethodPayload::None => Ok(ManagerRequest::Poweroff),
            _ => Err(Errno::EINVAL),
        },
        "Halt" => match call.payload {
            ManagerMethodPayload::None => Ok(ManagerRequest::Halt),
            _ => Err(Errno::EINVAL),
        },
        "KExec" => match call.payload {
            ManagerMethodPayload::None => Ok(ManagerRequest::Kexec),
            _ => Err(Errno::EINVAL),
        },
        "SwitchRoot" => match &call.payload {
            ManagerMethodPayload::StringPair { left, right } => Ok(ManagerRequest::SwitchRoot {
                root: left.clone(),
                init: right.clone(),
            }),
            _ => Err(Errno::EINVAL),
        },
        "SetEnvironment" => match &call.payload {
            ManagerMethodPayload::StringList(plus) => {
                Ok(ManagerRequest::SetEnvironment { plus: plus.clone() })
            }
            _ => Err(Errno::EINVAL),
        },
        "UnsetEnvironment" => match &call.payload {
            ManagerMethodPayload::StringList(minus) => Ok(ManagerRequest::UnsetEnvironment {
                minus: minus.clone(),
            }),
            _ => Err(Errno::EINVAL),
        },
        "UnsetAndSetEnvironment" => match &call.payload {
            ManagerMethodPayload::StringLists { first, second } => {
                Ok(ManagerRequest::UnsetAndSetEnvironment {
                    minus: first.clone(),
                    plus: second.clone(),
                })
            }
            _ => Err(Errno::EINVAL),
        },
        "SetExitCode" => match call.payload {
            ManagerMethodPayload::U8(code) => Ok(ManagerRequest::SetExitCode { code }),
            _ => Err(Errno::EINVAL),
        },
        "Subscribe" => match call.payload {
            ManagerMethodPayload::None => Ok(ManagerRequest::Subscribe),
            _ => Err(Errno::EINVAL),
        },
        "Unsubscribe" => match call.payload {
            ManagerMethodPayload::None => Ok(ManagerRequest::Unsubscribe),
            _ => Err(Errno::EINVAL),
        },
        _ => Err(Errno::EOPNOTSUPP),
    }
}

pub fn map_reply_to_method_result(reply: ManagerReply) -> ManagerMethodResultPayload {
    match reply {
        ManagerReply::Done => ManagerMethodResultPayload::Empty,
        ManagerReply::UnitPath(path) => ManagerMethodResultPayload::UnitPath(path),
        ManagerReply::Units(units) => ManagerMethodResultPayload::Units(units),
        ManagerReply::JobPath(path) => ManagerMethodResultPayload::JobPath(path),
        ManagerReply::Jobs(jobs) => ManagerMethodResultPayload::Jobs(jobs),
    }
}

/// Dispatch a transport-neutral call from an already trusted caller.
///
/// Bus transports carrying an untrusted sender must use
/// [`super::handle_authorized_manager_method_call`] instead.
pub fn handle_manager_method_call(
    runtime: &mut RuntimeManager,
    manager: &mut ManagerRecord,
    call: &ManagerMethodCall,
) -> Result<ManagerMethodResultPayload> {
    let request = map_method_call_to_request(call)?;
    let reply = manager_dispatch(runtime, manager, request)?;
    Ok(map_reply_to_method_result(reply))
}
