// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/bpf-firewall.c
//
use std::fmt;

pub const BPF_CGROUP_INET_INGRESS: u32 = 0;
pub const BPF_CGROUP_INET_EGRESS: u32 = 1;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;
pub const ACCESS_ALLOWED: u32 = 1;
pub const ACCESS_DENIED: u32 = 2;
pub const MAP_KEY_PACKETS: u32 = 0;
pub const MAP_KEY_BYTES: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallError {
    BadFileDescriptor(i32),
    AddressFamilyNotSupported(i32),
    ProtocolNotSupported(u16),
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFileDescriptor(fd) => write!(f, "invalid map fd {fd}"),
            Self::AddressFamilyNotSupported(family) => {
                write!(f, "unsupported address family {family}")
            }
            Self::ProtocolNotSupported(protocol) => {
                write!(f, "unsupported protocol {protocol:#06x}")
            }
        }
    }
}

impl std::error::Error for FirewallError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InAddrPrefix {
    pub family: i32,
    pub prefixlen: u8,
    pub address: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessUpdate {
    pub family: i32,
    pub key: Vec<u8>,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BpfInstruction {
    MatchProtocol {
        protocol_be: u16,
        skip_if_mismatch: usize,
    },
    LoadPacketAddress {
        offset: i16,
        size: usize,
    },
    LookupMap {
        map_fd: i32,
        prefix_len_bits: u32,
    },
    OrVerdict {
        verdict: u32,
    },
    InitializeVerdict,
    SetReturnAllowed,
    DenyIfExact {
        denied_verdict: u32,
    },
    AccountPackets {
        map_fd: i32,
    },
    AccountBytes {
        map_fd: i32,
    },
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfProgram {
    pub name: String,
    pub instructions: Vec<BpfInstruction>,
}

impl BpfProgram {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            instructions: Vec::new(),
        }
    }

    pub fn push(&mut self, insn: BpfInstruction) {
        self.instructions.push(insn);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountingMap {
    pub packets: u64,
    pub bytes: u64,
}

pub fn add_lookup_instructions(
    program: &mut BpfProgram,
    map_fd: i32,
    protocol: u16,
    is_ingress: bool,
    verdict: u32,
) -> Result<(), FirewallError> {
    if map_fd < 0 {
        return Err(FirewallError::BadFileDescriptor(map_fd));
    }

    let (addr_size, addr_offset) = match protocol {
        ETH_P_IP => (4usize, if is_ingress { 12 } else { 16 }),
        ETH_P_IPV6 => (16usize, if is_ingress { 8 } else { 24 }),
        other => return Err(FirewallError::ProtocolNotSupported(other)),
    };

    program.push(BpfInstruction::MatchProtocol {
        protocol_be: protocol.to_be(),
        skip_if_mismatch: 3,
    });
    program.push(BpfInstruction::LoadPacketAddress {
        offset: addr_offset,
        size: addr_size,
    });
    program.push(BpfInstruction::LookupMap {
        map_fd,
        prefix_len_bits: (addr_size * 8) as u32,
    });
    program.push(BpfInstruction::OrVerdict { verdict });
    Ok(())
}

pub fn add_instructions_for_ip_any(
    program: &mut BpfProgram,
    verdict: u32,
) -> Result<(), FirewallError> {
    program.push(BpfInstruction::OrVerdict { verdict });
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallMaps {
    pub ipv4_allow_map_fd: i32,
    pub ipv6_allow_map_fd: i32,
    pub ipv4_deny_map_fd: i32,
    pub ipv6_deny_map_fd: i32,
    pub accounting_map_fd: i32,
}

pub fn bpf_firewall_compile_bpf(
    prog_name: &str,
    is_ingress: bool,
    ip_allow_any: bool,
    ip_deny_any: bool,
    maps: FirewallMaps,
) -> Result<Option<BpfProgram>, FirewallError> {
    let access_enabled = maps.ipv4_allow_map_fd >= 0
        || maps.ipv6_allow_map_fd >= 0
        || maps.ipv4_deny_map_fd >= 0
        || maps.ipv6_deny_map_fd >= 0
        || ip_allow_any
        || ip_deny_any;

    if maps.accounting_map_fd < 0 && !access_enabled {
        return Ok(None);
    }

    let mut program = BpfProgram::new(prog_name);
    program.push(BpfInstruction::InitializeVerdict);

    if access_enabled {
        if maps.ipv4_deny_map_fd >= 0 {
            add_lookup_instructions(
                &mut program,
                maps.ipv4_deny_map_fd,
                ETH_P_IP,
                is_ingress,
                ACCESS_DENIED,
            )?;
        }
        if maps.ipv6_deny_map_fd >= 0 {
            add_lookup_instructions(
                &mut program,
                maps.ipv6_deny_map_fd,
                ETH_P_IPV6,
                is_ingress,
                ACCESS_DENIED,
            )?;
        }
        if maps.ipv4_allow_map_fd >= 0 {
            add_lookup_instructions(
                &mut program,
                maps.ipv4_allow_map_fd,
                ETH_P_IP,
                is_ingress,
                ACCESS_ALLOWED,
            )?;
        }
        if maps.ipv6_allow_map_fd >= 0 {
            add_lookup_instructions(
                &mut program,
                maps.ipv6_allow_map_fd,
                ETH_P_IPV6,
                is_ingress,
                ACCESS_ALLOWED,
            )?;
        }
        if ip_allow_any {
            add_instructions_for_ip_any(&mut program, ACCESS_ALLOWED)?;
        }
        if ip_deny_any {
            add_instructions_for_ip_any(&mut program, ACCESS_DENIED)?;
        }
    }

    program.push(BpfInstruction::SetReturnAllowed);
    program.push(BpfInstruction::DenyIfExact {
        denied_verdict: ACCESS_DENIED,
    });

    if maps.accounting_map_fd >= 0 {
        program.push(BpfInstruction::AccountPackets {
            map_fd: maps.accounting_map_fd,
        });
        program.push(BpfInstruction::AccountBytes {
            map_fd: maps.accounting_map_fd,
        });
    }

    program.push(BpfInstruction::Exit);
    Ok(Some(program))
}

pub fn bpf_firewall_count_access_items(
    prefixes: &[InAddrPrefix],
) -> Result<(usize, usize), FirewallError> {
    let mut ipv4 = 0;
    let mut ipv6 = 0;

    for prefix in prefixes {
        match prefix.family {
            AF_INET => ipv4 += 1,
            AF_INET6 => ipv6 += 1,
            other => return Err(FirewallError::AddressFamilyNotSupported(other)),
        }
    }

    Ok((ipv4, ipv6))
}

pub fn bpf_firewall_build_access_updates(
    prefixes: &[InAddrPrefix],
    verdict: u32,
) -> Result<Vec<AccessUpdate>, FirewallError> {
    let mut updates = Vec::with_capacity(prefixes.len());

    for prefix in prefixes {
        match prefix.family {
            AF_INET => {
                let mut key = Vec::with_capacity(8);
                key.extend_from_slice(&(prefix.prefixlen as u32).to_ne_bytes());
                key.extend_from_slice(&prefix.address[..4]);
                updates.push(AccessUpdate {
                    family: AF_INET,
                    key,
                    value: verdict as u64,
                });
            }
            AF_INET6 => {
                let mut key = Vec::with_capacity(20);
                key.extend_from_slice(&(prefix.prefixlen as u32).to_ne_bytes());
                key.extend_from_slice(&prefix.address);
                updates.push(AccessUpdate {
                    family: AF_INET6,
                    key,
                    value: verdict as u64,
                });
            }
            other => return Err(FirewallError::AddressFamilyNotSupported(other)),
        }
    }

    Ok(updates)
}

pub fn bpf_firewall_read_accounting(
    map_fd: i32,
    accounting: AccountingMap,
) -> Result<(u64, u64), FirewallError> {
    if map_fd < 0 {
        return Err(FirewallError::BadFileDescriptor(map_fd));
    }
    Ok((accounting.bytes, accounting.packets))
}

pub fn bpf_firewall_reset_accounting(
    map_fd: i32,
    accounting: &mut AccountingMap,
) -> Result<(), FirewallError> {
    if map_fd < 0 {
        return Err(FirewallError::BadFileDescriptor(map_fd));
    }
    accounting.packets = 0;
    accounting.bytes = 0;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfFirewallState {
    pub ip_accounting_ingress_map_fd: i32,
    pub ip_accounting_egress_map_fd: i32,
    pub ipv4_allow_map_fd: i32,
    pub ipv6_allow_map_fd: i32,
    pub ipv4_deny_map_fd: i32,
    pub ipv6_deny_map_fd: i32,
}

impl BpfFirewallState {
    pub fn close_all(&mut self) {
        self.ip_accounting_ingress_map_fd = -1;
        self.ip_accounting_egress_map_fd = -1;
        self.ipv4_allow_map_fd = -1;
        self.ipv6_allow_map_fd = -1;
        self.ipv4_deny_map_fd = -1;
        self.ipv6_deny_map_fd = -1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_prefix() -> InAddrPrefix {
        InAddrPrefix {
            family: AF_INET,
            prefixlen: 24,
            address: [192, 168, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    fn ipv6_prefix() -> InAddrPrefix {
        InAddrPrefix {
            family: AF_INET6,
            prefixlen: 64,
            address: [0x20; 16],
        }
    }

    #[test]
    fn lookup_instructions_encode_ipv4_ingress_offset() {
        let mut program = BpfProgram::new("fw");
        add_lookup_instructions(&mut program, 3, ETH_P_IP, true, ACCESS_DENIED).unwrap();
        assert_eq!(
            program.instructions[1],
            BpfInstruction::LoadPacketAddress {
                offset: 12,
                size: 4
            }
        );
    }

    #[test]
    fn lookup_instructions_encode_ipv6_egress_offset() {
        let mut program = BpfProgram::new("fw");
        add_lookup_instructions(&mut program, 4, ETH_P_IPV6, false, ACCESS_ALLOWED).unwrap();
        assert_eq!(
            program.instructions[1],
            BpfInstruction::LoadPacketAddress {
                offset: 24,
                size: 16
            }
        );
    }

    #[test]
    fn lookup_rejects_invalid_protocol() {
        let mut program = BpfProgram::new("fw");
        assert_eq!(
            add_lookup_instructions(&mut program, 1, 0x9999, true, ACCESS_ALLOWED),
            Err(FirewallError::ProtocolNotSupported(0x9999))
        );
    }

    #[test]
    fn compile_returns_none_when_no_work_exists() {
        assert_eq!(
            bpf_firewall_compile_bpf(
                "fw",
                true,
                false,
                false,
                FirewallMaps {
                    ipv4_allow_map_fd: -1,
                    ipv6_allow_map_fd: -1,
                    ipv4_deny_map_fd: -1,
                    ipv6_deny_map_fd: -1,
                    accounting_map_fd: -1
                }
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn compile_includes_accounting_when_requested() {
        let program = bpf_firewall_compile_bpf(
            "fw",
            true,
            false,
            false,
            FirewallMaps {
                ipv4_allow_map_fd: -1,
                ipv6_allow_map_fd: -1,
                ipv4_deny_map_fd: -1,
                ipv6_deny_map_fd: -1,
                accounting_map_fd: 9,
            },
        )
        .unwrap()
        .unwrap();
        assert!(
            program
                .instructions
                .contains(&BpfInstruction::AccountPackets { map_fd: 9 })
        );
        assert!(
            program
                .instructions
                .contains(&BpfInstruction::AccountBytes { map_fd: 9 })
        );
    }

    #[test]
    fn count_access_items_splits_ipv4_and_ipv6() {
        assert_eq!(
            bpf_firewall_count_access_items(&[ipv4_prefix(), ipv6_prefix(), ipv4_prefix()])
                .unwrap(),
            (2, 1)
        );
    }

    #[test]
    fn build_access_updates_preserves_ipv4_prefix_shape() {
        let updates = bpf_firewall_build_access_updates(&[ipv4_prefix()], ACCESS_ALLOWED).unwrap();
        assert_eq!(updates[0].key.len(), 8);
        assert_eq!(updates[0].value, ACCESS_ALLOWED as u64);
    }

    #[test]
    fn build_access_updates_rejects_unknown_family() {
        let invalid = InAddrPrefix {
            family: 999,
            prefixlen: 0,
            address: [0; 16],
        };
        assert_eq!(
            bpf_firewall_build_access_updates(&[invalid], ACCESS_ALLOWED),
            Err(FirewallError::AddressFamilyNotSupported(999))
        );
    }

    #[test]
    fn accounting_read_and_reset_work() {
        let mut accounting = AccountingMap {
            packets: 7,
            bytes: 21,
        };
        assert_eq!(
            bpf_firewall_read_accounting(5, accounting).unwrap(),
            (21, 7)
        );
        bpf_firewall_reset_accounting(5, &mut accounting).unwrap();
        assert_eq!(
            accounting,
            AccountingMap {
                packets: 0,
                bytes: 0
            }
        );
    }

    #[test]
    fn close_all_invalidates_state() {
        let mut state = BpfFirewallState {
            ip_accounting_ingress_map_fd: 1,
            ip_accounting_egress_map_fd: 2,
            ipv4_allow_map_fd: 3,
            ipv6_allow_map_fd: 4,
            ipv4_deny_map_fd: 5,
            ipv6_deny_map_fd: 6,
        };
        state.close_all();
        assert_eq!(state.ipv4_allow_map_fd, -1);
        assert_eq!(state.ipv6_deny_map_fd, -1);
    }
}
