// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/bpf-socket-bind.c
//
use std::fmt;

pub const SOCKET_BIND_MAX_RULES: usize = 256;
pub const SOCKET_BIND_RULE_AF_MATCH_NOTHING: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketBindError {
    TooManyRules { kind: &'static str, count: usize },
    MissingRuntime,
}

impl fmt::Display for SocketBindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRules { kind, count } => write!(
                f,
                "{kind} rule count {count} exceeds {SOCKET_BIND_MAX_RULES}"
            ),
            Self::MissingRuntime => write!(f, "missing cgroup runtime"),
        }
    }
}

impl std::error::Error for SocketBindError {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SocketBindRule {
    pub address_family: u32,
    pub protocol: u32,
    pub nr_ports: u32,
    pub port_min: u32,
}

impl SocketBindRule {
    pub fn match_nothing() -> Self {
        Self {
            address_family: SOCKET_BIND_RULE_AF_MATCH_NOTHING,
            protocol: 0,
            nr_ports: 0,
            port_min: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CGroupSocketBindItem {
    pub address_family: i32,
    pub ip_protocol: i32,
    pub nr_ports: u32,
    pub port_min: u32,
}

impl CGroupSocketBindItem {
    pub fn to_rule(self) -> SocketBindRule {
        SocketBindRule {
            address_family: self.address_family as u32,
            protocol: self.ip_protocol as u32,
            nr_ports: self.nr_ports,
            port_min: self.port_min,
        }
    }
}

pub fn update_rules_map(
    rules: &[CGroupSocketBindItem],
) -> Result<Vec<(u32, SocketBindRule)>, SocketBindError> {
    if rules.is_empty() {
        return Ok(vec![(0, SocketBindRule::match_nothing())]);
    }

    Ok(rules
        .iter()
        .enumerate()
        .map(|(idx, item)| (idx as u32, item.to_rule()))
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketBindPrepared {
    pub allow_entries: Vec<(u32, SocketBindRule)>,
    pub deny_entries: Vec<(u32, SocketBindRule)>,
}

pub fn prepare_socket_bind_bpf(
    allow_rules: &[CGroupSocketBindItem],
    deny_rules: &[CGroupSocketBindItem],
) -> Result<SocketBindPrepared, SocketBindError> {
    if allow_rules.len() > SOCKET_BIND_MAX_RULES {
        return Err(SocketBindError::TooManyRules {
            kind: "allow",
            count: allow_rules.len(),
        });
    }
    if deny_rules.len() > SOCKET_BIND_MAX_RULES {
        return Err(SocketBindError::TooManyRules {
            kind: "deny",
            count: deny_rules.len(),
        });
    }

    Ok(SocketBindPrepared {
        allow_entries: update_rules_map(allow_rules)?,
        deny_entries: update_rules_map(deny_rules)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupRuntime {
    pub initial_socket_bind_link_fds: Vec<i32>,
    pub ipv4_socket_bind_link: Option<i32>,
    pub ipv6_socket_bind_link: Option<i32>,
}

pub fn bpf_socket_bind_add_initial_link_fd(
    runtime: &mut CGroupRuntime,
    fd: i32,
) -> Result<(), SocketBindError> {
    runtime.initial_socket_bind_link_fds.push(fd);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketBindInstallPlan {
    pub cgroup_path: String,
    pub attach_ipv4: bool,
    pub attach_ipv6: bool,
    pub prepared: SocketBindPrepared,
}

pub fn socket_bind_install_impl(
    cgroup_path: &str,
    allow_rules: &[CGroupSocketBindItem],
    deny_rules: &[CGroupSocketBindItem],
) -> Result<Option<SocketBindInstallPlan>, SocketBindError> {
    if allow_rules.is_empty() && deny_rules.is_empty() {
        return Ok(None);
    }

    Ok(Some(SocketBindInstallPlan {
        cgroup_path: cgroup_path.to_owned(),
        attach_ipv4: true,
        attach_ipv6: true,
        prepared: prepare_socket_bind_bpf(allow_rules, deny_rules)?,
    }))
}

pub fn bpf_socket_bind_supported(framework_available: bool) -> bool {
    framework_available
}

pub fn bpf_socket_bind_serialize(
    runtime: &CGroupRuntime,
) -> Result<Vec<(&'static str, i32)>, SocketBindError> {
    let mut serialized = Vec::new();
    if let Some(fd) = runtime.ipv4_socket_bind_link {
        serialized.push(("ipv4-socket-bind-bpf-link", fd));
    }
    if let Some(fd) = runtime.ipv6_socket_bind_link {
        serialized.push(("ipv6-socket-bind-bpf-link", fd));
    }
    Ok(serialized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(port_min: u32) -> CGroupSocketBindItem {
        CGroupSocketBindItem {
            address_family: 2,
            ip_protocol: 6,
            nr_ports: 1,
            port_min,
        }
    }

    #[test]
    fn empty_map_gets_match_nothing_sentinel() {
        let entries = update_rules_map(&[]).unwrap();
        assert_eq!(entries, vec![(0, SocketBindRule::match_nothing())]);
    }

    #[test]
    fn non_empty_map_preserves_input_order() {
        let entries = update_rules_map(&[item(80), item(443)]).unwrap();
        assert_eq!(entries[0].0, 0);
        assert_eq!(entries[1].1.port_min, 443);
    }

    #[test]
    fn preparation_rejects_excessive_allow_rules() {
        let rules = vec![item(1); SOCKET_BIND_MAX_RULES + 1];
        assert_eq!(
            prepare_socket_bind_bpf(&rules, &[]),
            Err(SocketBindError::TooManyRules {
                kind: "allow",
                count: SOCKET_BIND_MAX_RULES + 1
            })
        );
    }

    #[test]
    fn preparation_rejects_excessive_deny_rules() {
        let rules = vec![item(1); SOCKET_BIND_MAX_RULES + 1];
        assert_eq!(
            prepare_socket_bind_bpf(&[], &rules),
            Err(SocketBindError::TooManyRules {
                kind: "deny",
                count: SOCKET_BIND_MAX_RULES + 1
            })
        );
    }

    #[test]
    fn preparation_keeps_allow_and_deny_entries() {
        let prepared = prepare_socket_bind_bpf(&[item(80)], &[item(1024)]).unwrap();
        assert_eq!(prepared.allow_entries[0].1.port_min, 80);
        assert_eq!(prepared.deny_entries[0].1.port_min, 1024);
    }

    #[test]
    fn install_plan_is_skipped_without_rules() {
        assert_eq!(
            socket_bind_install_impl("/sys/fs/cgroup/x", &[], &[]).unwrap(),
            None
        );
    }

    #[test]
    fn install_plan_attaches_both_programs() {
        let plan = socket_bind_install_impl("/sys/fs/cgroup/x", &[item(80)], &[])
            .unwrap()
            .unwrap();
        assert!(plan.attach_ipv4);
        assert!(plan.attach_ipv6);
    }

    #[test]
    fn initial_link_fd_is_recorded() {
        let mut runtime = CGroupRuntime {
            initial_socket_bind_link_fds: Vec::new(),
            ipv4_socket_bind_link: None,
            ipv6_socket_bind_link: None,
        };
        bpf_socket_bind_add_initial_link_fd(&mut runtime, 17).unwrap();
        assert_eq!(runtime.initial_socket_bind_link_fds, vec![17]);
    }

    #[test]
    fn serialization_uses_expected_keys() {
        let runtime = CGroupRuntime {
            initial_socket_bind_link_fds: Vec::new(),
            ipv4_socket_bind_link: Some(3),
            ipv6_socket_bind_link: Some(4),
        };
        assert_eq!(
            bpf_socket_bind_serialize(&runtime).unwrap(),
            vec![
                ("ipv4-socket-bind-bpf-link", 3),
                ("ipv6-socket-bind-bpf-link", 4)
            ]
        );
    }

    #[test]
    fn support_query_reflects_framework_flag() {
        assert!(bpf_socket_bind_supported(true));
        assert!(!bpf_socket_bind_supported(false));
    }
}
