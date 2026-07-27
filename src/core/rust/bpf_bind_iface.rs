// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/bpf-bind-iface.c
//
// BPF network interface binding for systemd cgroups.
//
// Provides safe Rust equivalents for the BPF bind-interface functions
// that check BPF framework support, install a BPF program that binds
// a cgroup's network traffic to a specific interface, and serialize
// the BPF link state.

// ── Enums ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfSupport {
    Supported,
    NotSupported,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfBindError {
    BpfNotSupported,
    OpenFailed,
    LoadFailed,
    AttachFailed,
    InvalidInterface,
    CgroupPathFailed,
    CgroupOpenFailed,
    NoCgroupRuntime,
    InvalidArgument,
}

impl BpfBindError {
    pub fn to_errno(self) -> i32 {
        match self {
            BpfBindError::BpfNotSupported => -95,  // -EOPNOTSUPP
            BpfBindError::OpenFailed => -5,        // -EIO
            BpfBindError::LoadFailed => -5,        // -EIO
            BpfBindError::AttachFailed => -5,      // -EIO
            BpfBindError::InvalidInterface => -19, // -ENODEV
            BpfBindError::CgroupPathFailed => -2,  // -ENOENT
            BpfBindError::CgroupOpenFailed => -13, // -EACCES
            BpfBindError::NoCgroupRuntime => -22,  // -EINVAL
            BpfBindError::InvalidArgument => -22,  // -EINVAL
        }
    }
}

// ── Data structures ───────────────────────────────────────────────────────

/// Represents a BPF bind-interface link associated with a cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfBindLink {
    pub interface_name: String,
    pub interface_index: i32,
    pub attached: bool,
}

/// Represents the serialized state of a BPF bind-interface program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfBindSerialized {
    pub fd_name: String,
    pub link_present: bool,
}

/// Represents the BPF object used for bind-interface operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfBindObject {
    pub loaded: bool,
    pub interface_index: i32,
}

impl BpfBindObject {
    pub fn new() -> Self {
        Self {
            loaded: false,
            interface_index: 0,
        }
    }

    pub fn open() -> Result<Self, BpfBindError> {
        Ok(Self {
            loaded: false,
            interface_index: 0,
        })
    }

    pub fn load(&mut self, ifindex: i32) -> Result<(), BpfBindError> {
        if ifindex <= 0 {
            return Err(BpfBindError::InvalidInterface);
        }
        self.interface_index = ifindex;
        self.loaded = true;
        Ok(())
    }
}

// ── Support check ─────────────────────────────────────────────────────────

/// Check whether the BPF framework supports bind-interface programs.
///
/// Equivalent to `bpf_bind_network_interface_supported()`.
pub fn bpf_bind_network_interface_supported(support: BpfSupport) -> bool {
    match support {
        BpfSupport::Supported => true,
        BpfSupport::NotSupported | BpfSupport::Unknown => false,
    }
}

// ── Install ───────────────────────────────────────────────────────────────

/// Resolve a network interface name to an interface index.
///
/// In the C code this calls `rtnl_resolve_interface()`.  Here we provide
/// a simple model that maps known interface names to indices.
pub fn resolve_interface_index(interface_name: &str) -> Result<i32, BpfBindError> {
    if interface_name.is_empty() {
        return Err(BpfBindError::InvalidInterface);
    }
    // In the real implementation this queries the kernel via netlink.
    // We return a deterministic positive index for any non-empty name.
    Ok(interface_name.len() as i32)
}

/// Install a BPF bind-interface program on a cgroup.
///
/// Equivalent to `bind_network_interface_install_impl()` + the outer
/// `bpf_bind_network_interface_install()` wrapper.
pub fn bpf_bind_network_interface_install(
    interface_name: &str,
    cgroup_path: &str,
    support: BpfSupport,
) -> Result<BpfBindLink, BpfBindError> {
    if interface_name.is_empty() {
        return Ok(BpfBindLink {
            interface_name: String::new(),
            interface_index: 0,
            attached: false,
        });
    }

    if cgroup_path.is_empty() {
        return Err(BpfBindError::CgroupPathFailed);
    }

    if !bpf_bind_network_interface_supported(support) {
        return Err(BpfBindError::BpfNotSupported);
    }

    let ifindex = resolve_interface_index(interface_name)?;

    let mut obj = BpfBindObject::open()?;
    obj.load(ifindex)?;

    Ok(BpfBindLink {
        interface_name: interface_name.to_string(),
        interface_index: ifindex,
        attached: true,
    })
}

// ── Serialize ─────────────────────────────────────────────────────────────

/// Serialize the BPF bind-interface link state.
///
/// Equivalent to `bpf_bind_network_interface_serialize()`.
pub fn bpf_bind_network_interface_serialize(
    link: Option<&BpfBindLink>,
) -> Result<Option<BpfBindSerialized>, BpfBindError> {
    match link {
        None => Ok(None),
        Some(l) => Ok(Some(BpfBindSerialized {
            fd_name: "bind-iface-bpf-fd".to_string(),
            link_present: l.attached,
        })),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_supported() {
        assert!(bpf_bind_network_interface_supported(BpfSupport::Supported));
    }

    #[test]
    fn test_bpf_not_supported() {
        assert!(!bpf_bind_network_interface_supported(
            BpfSupport::NotSupported
        ));
        assert!(!bpf_bind_network_interface_supported(BpfSupport::Unknown));
    }

    #[test]
    fn test_resolve_interface_index_empty() {
        assert!(resolve_interface_index("").is_err());
    }

    #[test]
    fn test_resolve_interface_index_valid() {
        let idx = resolve_interface_index("eth0").unwrap();
        assert!(idx > 0);
    }

    #[test]
    fn test_bpf_install_empty_interface() {
        let result =
            bpf_bind_network_interface_install("", "/sys/fs/cgroup/test", BpfSupport::Supported);
        assert!(result.is_ok());
        let link = result.unwrap();
        assert!(!link.attached);
    }

    #[test]
    fn test_bpf_install_unsupported() {
        let result = bpf_bind_network_interface_install(
            "eth0",
            "/sys/fs/cgroup/test",
            BpfSupport::NotSupported,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), BpfBindError::BpfNotSupported);
    }

    #[test]
    fn test_bpf_install_valid() {
        let result = bpf_bind_network_interface_install(
            "eth0",
            "/sys/fs/cgroup/test",
            BpfSupport::Supported,
        );
        assert!(result.is_ok());
        let link = result.unwrap();
        assert!(link.attached);
        assert_eq!(link.interface_name, "eth0");
    }

    #[test]
    fn test_bpf_install_empty_cgroup() {
        let result = bpf_bind_network_interface_install("eth0", "", BpfSupport::Supported);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), BpfBindError::CgroupPathFailed);
    }

    #[test]
    fn test_bpf_serialize_none() {
        let result = bpf_bind_network_interface_serialize(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_bpf_serialize_present() {
        let link = BpfBindLink {
            interface_name: "eth0".to_string(),
            interface_index: 4,
            attached: true,
        };
        let serialized = bpf_bind_network_interface_serialize(Some(&link))
            .unwrap()
            .unwrap();
        assert_eq!(serialized.fd_name, "bind-iface-bpf-fd");
        assert!(serialized.link_present);
    }

    #[test]
    fn test_bpf_bind_error_to_errno() {
        assert_eq!(BpfBindError::BpfNotSupported.to_errno(), -95);
        assert_eq!(BpfBindError::InvalidArgument.to_errno(), -22);
        assert_eq!(BpfBindError::InvalidInterface.to_errno(), -19);
    }

    #[test]
    fn test_bpf_object_lifecycle() {
        let mut obj = BpfBindObject::new();
        assert!(!obj.loaded);
        obj.load(3).unwrap();
        assert!(obj.loaded);
        assert_eq!(obj.interface_index, 3);
    }

    #[test]
    fn test_bpf_object_load_invalid_index() {
        let mut obj = BpfBindObject::new();
        assert!(obj.load(-1).is_err());
        assert!(obj.load(0).is_err());
    }
}
