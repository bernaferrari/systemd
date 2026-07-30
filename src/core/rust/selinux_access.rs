// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/selinux-access.c

use std::collections::HashSet;

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/selinux-access.c";

pub const LOG_ERR: i32 = 3;
pub const LOG_WARNING: i32 = 4;
pub const LOG_NOTICE: i32 = 5;
pub const LOG_INFO: i32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelinuxCallbackType {
    Error,
    Warning,
    Info,
    Avc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessError {
    pub errno: Errno,
    pub message: String,
}

impl AccessError {
    fn new(errno: Errno, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Unit {
    pub access_selinux_context: Option<String>,
    pub fragment_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusCreds {
    pub audit_login_uid: Option<u32>,
    pub euid: Option<u32>,
    pub egid: Option<u32>,
    pub cmdline: Vec<String>,
    pub selinux_context: String,
    pub augmented_selinux_context: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarlinkPeer {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub fd: i32,
    pub selinux_context: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditInfo {
    pub creds: Option<BusCreds>,
    pub link: Option<VarlinkPeer>,
    pub path: Option<String>,
    pub cmdline: Option<String>,
    pub function: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSet {
    pub acon: String,
    pub tclass: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelinuxState {
    pub use_selinux: bool,
    pub enforcing: bool,
    pub initialized: bool,
    pub avc_open_result: Result<(), Errno>,
    pub current_context: Option<String>,
}

impl Default for SelinuxState {
    fn default() -> Self {
        Self {
            use_selinux: true,
            enforcing: true,
            initialized: false,
            avc_open_result: Ok(()),
            current_context: Some("system_u:system_r:init_t:s0".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelinuxPolicy {
    allowed: HashSet<(String, String, String, String)>,
}

impl SelinuxPolicy {
    pub fn allow(&mut self, scon: &str, tcon: &str, tclass: &str, permission: &str) {
        self.allowed.insert((
            scon.to_string(),
            tcon.to_string(),
            tclass.to_string(),
            permission.to_string(),
        ));
    }

    fn check(&self, scon: &str, tcon: &str, tclass: &str, permission: &str) -> bool {
        self.allowed.contains(&(
            scon.to_string(),
            tcon.to_string(),
            tclass.to_string(),
            permission.to_string(),
        ))
    }
}

pub fn callback_type_to_priority(kind: SelinuxCallbackType) -> i32 {
    match kind {
        SelinuxCallbackType::Error => LOG_ERR,
        SelinuxCallbackType::Warning => LOG_WARNING,
        SelinuxCallbackType::Info => LOG_INFO,
        SelinuxCallbackType::Avc => LOG_NOTICE,
    }
}

pub fn audit_message(audit: &AuditInfo) -> String {
    let login_uid = audit
        .creds
        .as_ref()
        .and_then(|creds| creds.audit_login_uid)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".into());
    let uid = audit
        .creds
        .as_ref()
        .and_then(|creds| creds.euid)
        .or_else(|| audit.link.as_ref().and_then(|link| link.uid))
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".into());
    let gid = audit
        .creds
        .as_ref()
        .and_then(|creds| creds.egid)
        .or_else(|| audit.link.as_ref().and_then(|link| link.gid))
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".into());

    let mut message = format!("auid={login_uid} uid={uid} gid={gid}");
    if let Some(path) = audit.path.as_deref() {
        message.push_str(&format!(" path=\"{path}\""));
    }
    if let Some(cmdline) = audit.cmdline.as_deref() {
        message.push_str(&format!(" cmdline=\"{cmdline}\""));
    }
    if !audit.function.is_empty() {
        message.push_str(&format!(" function=\"{}\"", audit.function));
    }
    message
}

pub fn access_init(state: &mut SelinuxState) -> Result<bool, AccessError> {
    if !state.use_selinux {
        return Ok(false);
    }

    if state.initialized {
        return Ok(true);
    }

    match state.avc_open_result {
        Ok(()) => {
            state.initialized = true;
            Ok(true)
        }
        Err(_errno) if !state.enforcing => Ok(false),
        Err(errno) => Err(AccessError::new(errno, "Failed to open the SELinux AVC")),
    }
}

pub fn get_our_contexts(
    unit: Option<&Unit>,
    state: &SelinuxState,
) -> Result<ContextSet, AccessError> {
    if let Some(context) = unit.and_then(|unit| unit.access_selinux_context.as_ref()) {
        return Ok(ContextSet {
            acon: context.clone(),
            tclass: "service",
        });
    }

    let context = state.current_context.clone().ok_or_else(|| {
        AccessError::new(
            Errno::EOPNOTSUPP,
            "SELinux returned no context of the current process",
        )
    })?;

    Ok(ContextSet {
        acon: context,
        tclass: "system",
    })
}

pub fn check_access(
    policy: &SelinuxPolicy,
    state: &SelinuxState,
    scon: &str,
    tcon: &str,
    tclass: &str,
    permission: &str,
    audit_info: &AuditInfo,
) -> Result<(), AccessError> {
    if policy.check(scon, tcon, tclass, permission) {
        return Ok(());
    }

    let state_name = if state.enforcing {
        "enforcing"
    } else {
        "permissive"
    };
    let detail = audit_message(audit_info);

    if state.enforcing {
        return Err(AccessError::new(
            Errno::EPERM,
            format!(
                "SELinux policy denies access scon={scon} tcon={tcon} tclass={tclass} perm={permission} state={state_name} {detail}"
            ),
        ));
    }

    Ok(())
}

pub fn mac_selinux_access_check_bus_internal(
    state: &mut SelinuxState,
    policy: &SelinuxPolicy,
    creds: &BusCreds,
    unit: Option<&Unit>,
    permission: &str,
    function: &str,
) -> Result<bool, AccessError> {
    if permission.is_empty() || function.is_empty() {
        return Err(AccessError::new(
            Errno::EINVAL,
            "permission/function must not be empty",
        ));
    }

    let init = access_init(state)?;
    if !init {
        return Ok(false);
    }

    if creds.augmented_selinux_context {
        return Err(AccessError::new(
            Errno::EPERM,
            "SELinux context from credentials must not be augmented",
        ));
    }

    let contexts = get_our_contexts(unit, state)?;
    let audit = AuditInfo {
        creds: Some(creds.clone()),
        link: None,
        path: unit.and_then(|unit| unit.fragment_path.clone()),
        cmdline: (!creds.cmdline.is_empty()).then(|| creds.cmdline.join(" ")),
        function: function.to_string(),
    };

    check_access(
        policy,
        state,
        &creds.selinux_context,
        &contexts.acon,
        contexts.tclass,
        permission,
        &audit,
    )?;

    Ok(true)
}

pub fn mac_selinux_access_check_varlink_internal(
    state: &mut SelinuxState,
    policy: &SelinuxPolicy,
    link: &VarlinkPeer,
    unit: Option<&Unit>,
    permission: &str,
    function: &str,
) -> Result<bool, AccessError> {
    if permission.is_empty() || function.is_empty() {
        return Err(AccessError::new(
            Errno::EINVAL,
            "permission/function must not be empty",
        ));
    }

    let init = access_init(state)?;
    if !init {
        return Ok(false);
    }

    if link.fd < 0 {
        return Err(AccessError::new(
            Errno::EBADF,
            "Failed to get varlink peer fd",
        ));
    }

    let scon = link
        .selinux_context
        .clone()
        .ok_or_else(|| AccessError::new(Errno::EOPNOTSUPP, "Peer does not have SELinux context"))?;

    let contexts = get_our_contexts(unit, state)?;
    let audit = AuditInfo {
        creds: None,
        link: Some(link.clone()),
        path: unit.and_then(|unit| unit.fragment_path.clone()),
        cmdline: None,
        function: function.to_string(),
    };

    check_access(
        policy,
        state,
        &scon,
        &contexts.acon,
        contexts.tclass,
        permission,
        &audit,
    )?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_creds() -> BusCreds {
        BusCreds {
            audit_login_uid: Some(1000),
            euid: Some(1000),
            egid: Some(100),
            cmdline: vec!["systemctl".into(), "restart".into(), "sshd.service".into()],
            selinux_context: "unconfined_u:unconfined_r:unconfined_t:s0".into(),
            augmented_selinux_context: false,
        }
    }

    #[test]
    fn source_path_points_to_c_file() {
        assert_eq!(SOURCE_PATH, "src/core/selinux-access.c");
    }

    #[test]
    fn callback_priority_matches_c_mapping() {
        assert_eq!(
            callback_type_to_priority(SelinuxCallbackType::Error),
            LOG_ERR
        );
        assert_eq!(
            callback_type_to_priority(SelinuxCallbackType::Warning),
            LOG_WARNING
        );
        assert_eq!(
            callback_type_to_priority(SelinuxCallbackType::Info),
            LOG_INFO
        );
        assert_eq!(
            callback_type_to_priority(SelinuxCallbackType::Avc),
            LOG_NOTICE
        );
    }

    #[test]
    fn audit_message_formats_bus_credentials() {
        let audit = AuditInfo {
            creds: Some(sample_creds()),
            link: None,
            path: Some("/usr/lib/systemd/system/sshd.service".into()),
            cmdline: Some("systemctl restart sshd.service".into()),
            function: "StartUnit".into(),
        };

        let rendered = audit_message(&audit);
        assert!(rendered.contains("auid=1000"));
        assert!(rendered.contains("cmdline=\"systemctl restart sshd.service\""));
        assert!(rendered.contains("function=\"StartUnit\""));
    }

    #[test]
    fn access_init_returns_false_when_selinux_disabled() {
        let mut state = SelinuxState {
            use_selinux: false,
            ..SelinuxState::default()
        };
        assert!(!access_init(&mut state).unwrap());
        assert!(!state.initialized);
    }

    #[test]
    fn access_init_returns_false_when_permissive_and_avc_fails() {
        let mut state = SelinuxState {
            enforcing: false,
            avc_open_result: Err(Errno::EIO),
            ..SelinuxState::default()
        };
        assert!(!access_init(&mut state).unwrap());
    }

    #[test]
    fn get_our_contexts_prefers_unit_context() {
        let state = SelinuxState::default();
        let unit = Unit {
            access_selinux_context: Some("system_u:object_r:httpd_unit_file_t:s0".into()),
            fragment_path: None,
        };

        let contexts = get_our_contexts(Some(&unit), &state).unwrap();
        assert_eq!(contexts.tclass, "service");
        assert_eq!(contexts.acon, "system_u:object_r:httpd_unit_file_t:s0");
    }

    #[test]
    fn bus_check_rejects_augmented_contexts() {
        let mut state = SelinuxState::default();
        let mut creds = sample_creds();
        creds.augmented_selinux_context = true;
        let err = mac_selinux_access_check_bus_internal(
            &mut state,
            &SelinuxPolicy::default(),
            &creds,
            None,
            "start",
            "StartUnit",
        )
        .unwrap_err();

        assert_eq!(err.errno, Errno::EPERM);
    }

    #[test]
    fn bus_check_allows_authorized_access() {
        let mut state = SelinuxState::default();
        let creds = sample_creds();
        let mut policy = SelinuxPolicy::default();
        policy.allow(
            &creds.selinux_context,
            state.current_context.as_deref().unwrap(),
            "system",
            "start",
        );

        assert!(
            mac_selinux_access_check_bus_internal(
                &mut state,
                &policy,
                &creds,
                None,
                "start",
                "StartUnit",
            )
            .unwrap()
        );
    }

    #[test]
    fn bus_check_denies_unauthorized_access_when_enforcing() {
        let mut state = SelinuxState::default();
        let creds = sample_creds();
        let err = mac_selinux_access_check_bus_internal(
            &mut state,
            &SelinuxPolicy::default(),
            &creds,
            None,
            "stop",
            "StopUnit",
        )
        .unwrap_err();

        assert_eq!(err.errno, Errno::EPERM);
        assert!(err.message.contains("SELinux policy denies access"));
    }

    #[test]
    fn varlink_check_rejects_missing_peer_context() {
        let mut state = SelinuxState::default();
        let link = VarlinkPeer {
            uid: Some(0),
            gid: Some(0),
            fd: 3,
            selinux_context: None,
        };

        let err = mac_selinux_access_check_varlink_internal(
            &mut state,
            &SelinuxPolicy::default(),
            &link,
            None,
            "reload",
            "ReloadUnit",
        )
        .unwrap_err();

        assert_eq!(err.errno, Errno::EOPNOTSUPP);
    }

    #[test]
    fn varlink_check_allows_authorized_peer() {
        let mut state = SelinuxState::default();
        let link = VarlinkPeer {
            uid: Some(0),
            gid: Some(0),
            fd: 7,
            selinux_context: Some("system_u:system_r:init_t:s0".into()),
        };
        let unit = Unit {
            access_selinux_context: Some("system_u:object_r:unit_t:s0".into()),
            fragment_path: Some("/etc/systemd/system/demo.service".into()),
        };
        let mut policy = SelinuxPolicy::default();
        policy.allow(
            "system_u:system_r:init_t:s0",
            "system_u:object_r:unit_t:s0",
            "service",
            "reload",
        );

        assert!(
            mac_selinux_access_check_varlink_internal(
                &mut state,
                &policy,
                &link,
                Some(&unit),
                "reload",
                "ReloadUnit",
            )
            .unwrap()
        );
    }
}
