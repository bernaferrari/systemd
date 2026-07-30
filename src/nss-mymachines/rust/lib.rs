// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/nss-mymachines/nss-mymachines.c
const ALIGN_TO: usize = std::mem::size_of::<usize>();
const GAIH_ADDRTUPLE_SIZE: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssStatus {
    Success,
    NotFound,
    TryAgain,
    Unavail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Inet,
    Inet6,
    Unspec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAddress {
    pub family: AddressFamily,
    pub ifindex: i32,
    pub bytes: Vec<u8>,
}

fn align(value: usize) -> usize {
    value.div_ceil(ALIGN_TO) * ALIGN_TO
}

pub fn count_addresses(addresses: &[MachineAddress], family: AddressFamily) -> usize {
    addresses
        .iter()
        .filter(|address| family == AddressFamily::Unspec || address.family == family)
        .count()
}

pub fn avoid_deadlock(
    euid: u32,
    activation_unit: Option<&str>,
    activation_scope: Option<&str>,
) -> bool {
    euid == 0
        && activation_unit == Some("systemd-machined.service")
        && activation_scope == Some("system")
}

pub fn scopeid_for_result(ifindices: &[i32]) -> u32 {
    if ifindices.len() == 1 && ifindices[0] > 0 {
        ifindices[0] as u32
    } else {
        0
    }
}

pub fn response_buffer_size(name: &str, address_count: usize) -> usize {
    align(name.len() + 1) + align(GAIH_ADDRTUPLE_SIZE) * address_count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(family: AddressFamily, ifindex: i32) -> MachineAddress {
        MachineAddress {
            family,
            ifindex,
            bytes: vec![0; if family == AddressFamily::Inet { 4 } else { 16 }],
        }
    }

    #[test]
    fn count_addresses_honors_requested_family() {
        let addresses = vec![
            address(AddressFamily::Inet, 2),
            address(AddressFamily::Inet6, 3),
        ];
        assert_eq!(count_addresses(&addresses, AddressFamily::Unspec), 2);
        assert_eq!(count_addresses(&addresses, AddressFamily::Inet), 1);
    }

    #[test]
    fn avoid_deadlock_requires_privileged_activation_context() {
        assert!(avoid_deadlock(
            0,
            Some("systemd-machined.service"),
            Some("system")
        ));
        assert!(!avoid_deadlock(
            1000,
            Some("systemd-machined.service"),
            Some("system")
        ));
    }

    #[test]
    fn avoid_deadlock_rejects_other_units() {
        assert!(!avoid_deadlock(0, Some("other.service"), Some("system")));
    }

    #[test]
    fn scopeid_for_result_requires_single_ifindex() {
        assert_eq!(scopeid_for_result(&[7]), 7);
        assert_eq!(scopeid_for_result(&[7, 8]), 0);
    }

    #[test]
    fn response_buffer_size_includes_name_and_tuples() {
        let size = response_buffer_size("machine", 2);
        assert!(size > 2 * GAIH_ADDRTUPLE_SIZE + "machine".len());
    }

    #[test]
    fn inet_and_inet6_families_are_distinct() {
        assert_ne!(AddressFamily::Inet, AddressFamily::Inet6);
    }

    #[test]
    fn nss_status_variants_are_distinct() {
        assert_ne!(NssStatus::Success, NssStatus::NotFound);
    }

    #[test]
    fn count_addresses_can_return_zero() {
        let addresses = vec![address(AddressFamily::Inet6, 3)];
        assert_eq!(count_addresses(&addresses, AddressFamily::Inet), 0);
    }

    #[test]
    fn response_buffer_size_grows_with_more_addresses() {
        assert!(response_buffer_size("vm", 3) > response_buffer_size("vm", 1));
    }
}
