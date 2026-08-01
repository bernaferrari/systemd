// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/virt.c, src/basic/virt.h
//
// Virtualization type definitions, string table lookups, and the safe
// container-detection facade.
// Skipped: detect_vm/detect_virtualization (file I/O, CPUID),
//          running_in_userns/running_in_chroot (namespace/inode checks).

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::ffi_string_table::{self, Entry as FfiEntry};
use libc::c_char;

// SAFETY: this is the exact no-argument declaration from virt.h. The safe
// wrapper below validates the returned C enum value before constructing the
// corresponding Rust enum.
unsafe extern "C" {
    #[link_name = "detect_container"]
    safe fn c_detect_container() -> libc::c_int;
}

// ── Enum ──────────────────────────────────────────────────────────────────

/// Virtualization detection result, matching C's Virtualization enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Virtualization {
    None = 0,
    // VM types (1..=19)
    Kvm = 1,
    Amazon = 2,
    Qemu = 3,
    Bochs = 4,
    Xen = 5,
    Uml = 6,
    Vmware = 7,
    Oracle = 8,
    Microsoft = 9,
    Zvm = 10,
    Parallels = 11,
    Bhyve = 12,
    Qnx = 13,
    Acrn = 14,
    PowerVm = 15,
    Apple = 16,
    Sre = 17,
    Google = 18,
    VmOther = 19,
    // Container types (20..=30)
    SystemdNspawn = 20,
    LxcLibvirt = 21,
    Lxc = 22,
    Openvz = 23,
    Docker = 24,
    Podman = 25,
    Rkt = 26,
    Wsl = 27,
    Proot = 28,
    Pouch = 29,
    ContainerOther = 30,
}

// ── String table ────────────────────────────────────────────────────────────

macro_rules! virtualization_table {
    ($( $variant:ident => $name:literal ),+ $(,)?) => {
        const VIRTUALIZATION_TABLE: &[FfiEntry] = &[
            $((Virtualization::$variant as i32, concat!($name, "\0").as_bytes()),)+
        ];

        fn virtualization_from_raw(value: i32) -> Option<Virtualization> {
            match value {
                $(value if value == Virtualization::$variant as i32 => Some(Virtualization::$variant),)+
                _ => None,
            }
        }
    };
}

virtualization_table!(
    None => "none", Kvm => "kvm", Amazon => "amazon", Qemu => "qemu", Bochs => "bochs",
    Xen => "xen", Uml => "uml", Vmware => "vmware", Oracle => "oracle",
    Microsoft => "microsoft", Zvm => "zvm", Parallels => "parallels", Bhyve => "bhyve",
    Qnx => "qnx", Acrn => "acrn", PowerVm => "powervm", Apple => "apple", Sre => "sre",
    Google => "google", VmOther => "vm-other", SystemdNspawn => "systemd-nspawn",
    LxcLibvirt => "lxc-libvirt", Lxc => "lxc", Openvz => "openvz", Docker => "docker",
    Podman => "podman", Rkt => "rkt", Wsl => "wsl", Proot => "proot", Pouch => "pouch",
    ContainerOther => "container-other",
);

// ── Range constants ─────────────────────────────────────────────────────────

const VM_FIRST: i32 = Virtualization::Kvm as i32;
const VM_LAST: i32 = Virtualization::VmOther as i32;
const CONTAINER_FIRST: i32 = Virtualization::SystemdNspawn as i32;
const CONTAINER_LAST: i32 = Virtualization::ContainerOther as i32;

// ── Public API ──────────────────────────────────────────────────────────────

/// Convert a Virtualization value to its string representation.
/// Equivalent to C virtualization_to_string().
pub fn virtualization_to_string(v: Virtualization) -> Option<&'static str> {
    ffi_string_table::to_str(VIRTUALIZATION_TABLE, v as i32)
}

/// Parse a virtualization string to its enum value.
/// Equivalent to C virtualization_from_string().
/// Returns Err(-22) on failure (matches -EINVAL).
pub fn virtualization_from_string(s: &str) -> Result<Virtualization, i32> {
    ffi_string_table::from_str(VIRTUALIZATION_TABLE, s)
        .and_then(virtualization_from_raw)
        .ok_or(-libc::EINVAL)
}

/// Check if the given virtualization type is a VM.
/// Equivalent to C VIRTUALIZATION_IS_VM().
pub fn virtualization_is_vm(v: Virtualization) -> bool {
    let x = v as i32;
    x >= VM_FIRST && x <= VM_LAST
}

/// Check if the given virtualization type is a container.
/// Equivalent to C VIRTUALIZATION_IS_CONTAINER().
pub fn virtualization_is_container(v: Virtualization) -> bool {
    let x = v as i32;
    x >= CONTAINER_FIRST && x <= CONTAINER_LAST
}

/// Detect the current container environment using C's authoritative detector.
///
/// This retains `detect_container()`'s complete namespace, environment,
/// procfs, and runtime-marker policy instead of duplicating a partial subset
/// in Rust. Negative C errno returns are preserved unchanged.
pub fn detect_container() -> Result<Virtualization, i32> {
    let result = c_detect_container();
    if result < 0 {
        return Err(result);
    }

    virtualization_from_raw(result).ok_or(-libc::EIO)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_virtualization_to_string(value: libc::c_int) -> *const c_char {
    ffi_string_table::to_ptr(VIRTUALIZATION_TABLE, value)
}

/// # Safety
///
/// `name` must be null or point to a live NUL-terminated C string for the
/// duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_virtualization_from_string(name: *const c_char) -> libc::c_int {
    // SAFETY: this forwards the entry point's documented C-string contract.
    unsafe_ffi!(ffi_string_table::from_ptr(
        VIRTUALIZATION_TABLE,
        name,
        -libc::EINVAL
    ))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "C" fn rs_VIRTUALIZATION_IS_VM(value: libc::c_int) -> bool {
    (VM_FIRST..=VM_LAST).contains(&value)
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "C" fn rs_VIRTUALIZATION_IS_CONTAINER(value: libc::c_int) -> bool {
    (CONTAINER_FIRST..=CONTAINER_LAST).contains(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtualization_to_string_known() {
        assert_eq!(virtualization_to_string(Virtualization::Kvm), Some("kvm"));
        assert_eq!(
            virtualization_to_string(Virtualization::Docker),
            Some("docker")
        );
        assert_eq!(virtualization_to_string(Virtualization::None), Some("none"));
    }

    #[test]
    fn test_virtualization_to_string_all_entries() {
        for &(value, bytes) in VIRTUALIZATION_TABLE {
            let v = virtualization_from_raw(value).unwrap();
            let name = ffi_string_table::entry_str(bytes);
            assert_eq!(virtualization_to_string(v), Some(name));
        }
    }

    #[test]
    fn test_virtualization_from_string_known() {
        assert_eq!(virtualization_from_string("kvm"), Ok(Virtualization::Kvm));
        assert_eq!(
            virtualization_from_string("docker"),
            Ok(Virtualization::Docker)
        );
        assert_eq!(virtualization_from_string("none"), Ok(Virtualization::None));
    }

    #[test]
    fn test_virtualization_from_string_invalid() {
        assert_eq!(virtualization_from_string("unknown"), Err(-22));
        assert_eq!(virtualization_from_string(""), Err(-22));
    }

    #[test]
    fn test_virtualization_from_string_case_sensitive() {
        assert_eq!(virtualization_from_string("KVM"), Err(-22));
        assert_eq!(virtualization_from_string("Docker"), Err(-22));
    }

    #[test]
    fn test_virtualization_from_string_all_entries() {
        for &(value, bytes) in VIRTUALIZATION_TABLE {
            let v = virtualization_from_raw(value).unwrap();
            let name = ffi_string_table::entry_str(bytes);
            assert_eq!(virtualization_from_string(name), Ok(v));
        }
    }

    #[test]
    fn test_virtualization_roundtrip() {
        for &(value, bytes) in VIRTUALIZATION_TABLE {
            let v = virtualization_from_raw(value).unwrap();
            let name = ffi_string_table::entry_str(bytes);
            let resolved = virtualization_from_string(name).unwrap();
            assert_eq!(resolved, v);
            assert_eq!(virtualization_to_string(resolved), Some(name));
        }
    }

    #[test]
    fn test_virtualization_is_vm() {
        assert!(virtualization_is_vm(Virtualization::Kvm));
        assert!(virtualization_is_vm(Virtualization::Qemu));
        assert!(virtualization_is_vm(Virtualization::Xen));
        assert!(virtualization_is_vm(Virtualization::VmOther));
    }

    #[test]
    fn test_virtualization_is_not_vm() {
        assert!(!virtualization_is_vm(Virtualization::None));
        assert!(!virtualization_is_vm(Virtualization::Docker));
        assert!(!virtualization_is_vm(Virtualization::SystemdNspawn));
    }

    #[test]
    fn test_virtualization_is_container() {
        assert!(virtualization_is_container(Virtualization::SystemdNspawn));
        assert!(virtualization_is_container(Virtualization::Docker));
        assert!(virtualization_is_container(Virtualization::Podman));
        assert!(virtualization_is_container(Virtualization::ContainerOther));
    }

    #[test]
    fn test_virtualization_is_not_container() {
        assert!(!virtualization_is_container(Virtualization::None));
        assert!(!virtualization_is_container(Virtualization::Kvm));
        assert!(!virtualization_is_container(Virtualization::VmOther));
    }

    #[test]
    fn test_virtualization_none_is_neither() {
        assert!(!virtualization_is_vm(Virtualization::None));
        assert!(!virtualization_is_container(Virtualization::None));
    }

    #[test]
    fn test_virtualization_vm_range() {
        let vm_values: Vec<Virtualization> = VIRTUALIZATION_TABLE
            .iter()
            .filter_map(|(value, _)| virtualization_from_raw(*value))
            .filter(|value| virtualization_is_vm(*value))
            .collect();
        assert_eq!(vm_values.len(), 19);
    }

    #[test]
    fn test_virtualization_container_range() {
        let container_values: Vec<Virtualization> = VIRTUALIZATION_TABLE
            .iter()
            .filter_map(|(value, _)| virtualization_from_raw(*value))
            .filter(|value| virtualization_is_container(*value))
            .collect();
        assert_eq!(container_values.len(), 11);
    }
}
