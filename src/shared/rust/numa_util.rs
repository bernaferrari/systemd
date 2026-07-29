// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/numa-util.c, src/shared/numa-util.h
//
// NUMA (Non-Uniform Memory Access) policy utilities.
//
// Provides types and functions for managing NUMA memory policies,
// including policy validation, node mask conversion, and application
// of policies via set_mempolicy(2).

use crate::cpu_set_util::{CpuSet, CpuSetError};

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum fallback NUMA node index (CONFIG_NODES_SHIFT=10 on x86_64).
pub const NUMA_MAX_NODE_FALLBACK: u32 = 1023;

/// Sysfs path for NUMA node topology.
pub const NUMA_NODE_SYSFS_PATH: &str = "/sys/devices/system/node";

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from NUMA operations.
#[derive(Debug)]
pub enum NumaError {
    /// The system does not support NUMA (ENOSYS from get_mempolicy).
    NotSupported,
    /// An invalid policy was provided.
    InvalidPolicy,
    /// An I/O error occurred reading sysfs or other filesystem operation.
    Io(std::io::Error),
    /// An OS error with an errno code.
    Errno(i32),
    /// Out of memory.
    OutOfMemory,
    /// A NUMA node's CPU list could not be parsed or combined.
    CpuSet(CpuSetError),
}

impl std::fmt::Display for NumaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NumaError::NotSupported => write!(f, "NUMA not supported by kernel"),
            NumaError::InvalidPolicy => write!(f, "invalid NUMA policy"),
            NumaError::Io(e) => write!(f, "I/O error: {e}"),
            NumaError::Errno(code) => write!(f, "OS error (errno={code})"),
            NumaError::OutOfMemory => write!(f, "out of memory"),
            NumaError::CpuSet(e) => write!(f, "CPU set error: {e}"),
        }
    }
}

impl std::error::Error for NumaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NumaError::Io(e) => Some(e),
            NumaError::CpuSet(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for NumaError {
    fn from(e: std::io::Error) -> Self {
        NumaError::Io(e)
    }
}

impl From<CpuSetError> for NumaError {
    fn from(e: CpuSetError) -> Self {
        NumaError::CpuSet(e)
    }
}

// ── MpolType ──────────────────────────────────────────────────────────────

/// NUMA memory policy types from `<sys/mempolicy.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum MpolType {
    /// Default operating system page allocation policy.
    Default = 0,
    /// Prefer allocation from a specific node.
    Preferred = 1,
    /// Strict allocation from the specified node set.
    Bind = 2,
    /// Interleave page allocation across the specified node set.
    Interleave = 3,
    /// Local node allocation (preferred node is the node of the CPU).
    Local = 4,
    /// Prefer allocation from the supplied set of NUMA nodes.
    PreferredMany = 5,
    /// Interleave allocation using the kernel's weighted node distribution.
    WeightedInterleave = 6,
}

impl MpolType {
    /// All valid policy type values, as a range of raw i32 values.
    pub const MIN_RAW: i32 = 0;
    pub const MAX_RAW: i32 = 6;

    /// Check if a raw i32 value represents a valid policy type.
    pub fn is_valid_raw(raw: i32) -> bool {
        (Self::MIN_RAW..=Self::MAX_RAW).contains(&raw)
    }

    /// Try to convert a raw i32 into an [`MpolType`].
    pub fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Default),
            1 => Some(Self::Preferred),
            2 => Some(Self::Bind),
            3 => Some(Self::Interleave),
            4 => Some(Self::Local),
            5 => Some(Self::PreferredMany),
            6 => Some(Self::WeightedInterleave),
            _ => None,
        }
    }

    /// Convert to the raw i32 value for syscalls.
    pub fn as_raw(self) -> i32 {
        self as i32
    }

    /// Convert to a human-readable string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Preferred => "preferred",
            Self::Bind => "bind",
            Self::Interleave => "interleave",
            Self::Local => "local",
            Self::PreferredMany => "preferred-many",
            Self::WeightedInterleave => "weighted-interleave",
        }
    }

    /// Parse from a string name.
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "default" => Some(Self::Default),
            "preferred" => Some(Self::Preferred),
            "bind" => Some(Self::Bind),
            "interleave" => Some(Self::Interleave),
            "local" => Some(Self::Local),
            "preferred-many" => Some(Self::PreferredMany),
            "weighted-interleave" => Some(Self::WeightedInterleave),
            _ => None,
        }
    }

    /// Returns true if this policy type may omit the node set.
    pub fn allows_empty_nodes(self) -> bool {
        matches!(self, Self::Default | Self::Local | Self::Preferred)
    }

    /// Returns true if this policy type strictly requires a node set.
    pub fn requires_nodes(self) -> bool {
        !matches!(self, Self::Default | Self::Local | Self::Preferred)
    }
}

// ── NodeMask ──────────────────────────────────────────────────────────────

/// A bitmap representing a set of NUMA nodes.
///
/// Each bit `i` set in the mask indicates that NUMA node `i` is included.
/// The internal representation uses the target's `unsigned long` width, the
/// word format required by the `set_mempolicy(2)` ABI on both 32- and 64-bit
/// Linux targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeMask {
    /// Bitmap stored in the kernel ABI's `unsigned long` word format.
    words: Vec<libc::c_ulong>,
}

impl NodeMask {
    const BITS_PER_WORD: usize = std::mem::size_of::<libc::c_ulong>() * u8::BITS as usize;

    /// Create an empty node mask.
    pub fn new() -> Self {
        Self { words: Vec::new() }
    }

    /// Create a node mask with enough capacity for `max_node` nodes.
    pub fn with_capacity(max_node: u32) -> Self {
        let n_words = max_node as usize / Self::BITS_PER_WORD + 1;
        Self {
            words: vec![0; n_words],
        }
    }

    /// Set a node in the mask.
    pub fn set(&mut self, node: u32) {
        let word_idx = node as usize / Self::BITS_PER_WORD;
        let bit_idx = node as usize % Self::BITS_PER_WORD;
        if word_idx >= self.words.len() {
            self.words.resize(word_idx + 1, 0);
        }
        self.words[word_idx] |= 1 << bit_idx;
    }

    /// Test whether a node is set in the mask.
    pub fn is_set(&self, node: u32) -> bool {
        let word_idx = node as usize / Self::BITS_PER_WORD;
        let bit_idx = node as usize % Self::BITS_PER_WORD;
        self.words
            .get(word_idx)
            .is_some_and(|word| *word & (1 << bit_idx) != 0)
    }

    /// Return the number of nodes set in the mask.
    pub fn count(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Return the total number of bits (nodes) the mask can represent.
    pub fn capacity(&self) -> usize {
        self.words.len() * Self::BITS_PER_WORD
    }

    /// Return true if the mask is empty (no nodes set).
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }

    /// Iterate over the NUMA node indices present in the mask.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(|(word_index, word)| {
                (0..Self::BITS_PER_WORD).filter_map(move |bit_index| {
                    if word & (1 << bit_index) == 0 {
                        return None;
                    }

                    u32::try_from(word_index * Self::BITS_PER_WORD + bit_index).ok()
                })
            })
    }

    /// Convert to the `(maxnode, nodes)` format expected by `set_mempolicy(2)`.
    ///
    /// Returns `(maxnode, Option<&[libc::c_ulong]>)` where `maxnode` is
    /// `capacity + 1` (per kernel convention) and `nodes` is the kernel ABI
    /// word array. Returns `None` for the nodes slice when no nodes are set.
    pub fn to_mempolicy_format(&self) -> (usize, Option<&[libc::c_ulong]>) {
        if self.is_empty() {
            return (0, None);
        }
        let maxnode = self.capacity() + 1;
        (maxnode, Some(&self.words))
    }
}

impl Default for NodeMask {
    fn default() -> Self {
        Self::new()
    }
}

// ── NumaPolicy ────────────────────────────────────────────────────────────

/// A NUMA memory policy.
///
/// Encapsulates a policy type and an optional set of NUMA nodes.
/// Mirrors the C `NUMAPolicy` struct from `numa-util.h`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumaPolicy {
    /// The memory policy type.
    policy_type: MpolType,
    /// The set of NUMA nodes (empty if not applicable).
    nodes: NodeMask,
}

impl NumaPolicy {
    /// Create a new NUMA policy with the given type and node set.
    pub fn new(policy_type: MpolType, nodes: NodeMask) -> Self {
        Self { policy_type, nodes }
    }

    /// Create a default policy with no nodes.
    pub fn default_policy() -> Self {
        Self {
            policy_type: MpolType::Default,
            nodes: NodeMask::new(),
        }
    }

    /// Create a local policy with no nodes.
    pub fn local_policy() -> Self {
        Self {
            policy_type: MpolType::Local,
            nodes: NodeMask::new(),
        }
    }

    /// Create a preferred policy pointing to a single node.
    pub fn preferred_node(node: u32) -> Self {
        let mut mask = NodeMask::new();
        mask.set(node);
        Self {
            policy_type: MpolType::Preferred,
            nodes: mask,
        }
    }

    /// Create a bind policy for the given nodes.
    pub fn bind_nodes(nodes: NodeMask) -> Self {
        Self {
            policy_type: MpolType::Bind,
            nodes,
        }
    }

    /// Create an interleave policy for the given nodes.
    pub fn interleave_nodes(nodes: NodeMask) -> Self {
        Self {
            policy_type: MpolType::Interleave,
            nodes,
        }
    }

    /// Get the policy type.
    pub fn policy_type(&self) -> MpolType {
        self.policy_type
    }

    /// Get a reference to the node mask.
    pub fn nodes(&self) -> &NodeMask {
        &self.nodes
    }

    /// Check if this policy is valid.
    ///
    /// A policy is valid if:
    /// - The type is a valid mpol
    /// - If the type requires nodes (Bind, Interleave), nodes must be present
    /// - For Preferred with nodes, exactly one node must be set
    pub fn is_valid(&self) -> bool {
        if self.nodes.is_empty() && self.policy_type.requires_nodes() {
            return false;
        }

        if !self.nodes.is_empty()
            && self.policy_type == MpolType::Preferred
            && self.nodes.count() != 1
        {
            return false;
        }

        true
    }

    /// Convert to the `(mode, maxnode, nodes)` format expected by `set_mempolicy(2)`.
    ///
    /// For `Default`/`Local` policies, or `Preferred` without nodes,
    /// returns `(mode, 0, None)`.
    pub fn to_mempolicy(&self) -> (i32, usize, Option<&[libc::c_ulong]>) {
        if matches!(self.policy_type, MpolType::Default | MpolType::Local)
            || (self.policy_type == MpolType::Preferred && self.nodes.is_empty())
        {
            return (self.policy_type.as_raw(), 0, None);
        }

        let (maxnode, nodes) = self.nodes.to_mempolicy_format();
        (self.policy_type.as_raw(), maxnode, nodes)
    }
}

// ── Syscall wrappers ──────────────────────────────────────────────────────

/// Check whether the kernel supports NUMA memory policies.
///
/// Calls `get_mempolicy(2)` with no-op arguments. Returns `Ok(())` if
/// supported, or `Err(NumaError::NotSupported)` if `ENOSYS`.
#[cfg(target_os = "linux")]
pub fn numa_is_supported() -> Result<(), NumaError> {
    // SAFETY: the syscall explicitly permits all output pointers to be null
    // when no query flags request data, and no Rust memory is dereferenced.
    let ret = unsafe {
        libc::get_mempolicy(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            0,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) {
            return Err(NumaError::NotSupported);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn numa_is_supported() -> Result<(), NumaError> {
    Err(NumaError::NotSupported)
}

/// Apply a NUMA policy to the calling thread.
///
/// Wraps `set_mempolicy(2)`. Returns `Ok(())` on success.
///
/// # Errors
/// - `NumaError::NotSupported` if the kernel lacks NUMA support
/// - `NumaError::InvalidPolicy` if the policy is invalid
/// - `NumaError::Errno` or `NumaError::OutOfMemory` on syscall failure
#[cfg(target_os = "linux")]
pub fn apply_numa_policy(policy: &NumaPolicy) -> Result<(), NumaError> {
    numa_is_supported()?;

    if !policy.is_valid() {
        return Err(NumaError::InvalidPolicy);
    }

    let (mode, maxnode, nodes) = policy.to_mempolicy();

    // SAFETY: `nodes` either supplies a null pointer with `maxnode == 0`, or
    // borrows the policy's contiguous node-mask words for the duration of the
    // synchronous syscall. `maxnode` describes that same allocation.
    let ret = unsafe {
        libc::set_mempolicy(
            mode,
            nodes.map_or(std::ptr::null(), |n| n.as_ptr()),
            maxnode as libc::c_ulong,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(libc::EINVAL);
        if errno == libc::ENOMEM {
            return Err(NumaError::OutOfMemory);
        }
        if errno == libc::EINVAL
            && matches!(
                policy.policy_type(),
                MpolType::PreferredMany | MpolType::WeightedInterleave
            )
        {
            // Match the C compatibility behavior for kernels that predate
            // these policy modes: the syscall ABI exists, but not this mode.
            return Err(NumaError::Errno(libc::EOPNOTSUPP));
        }
        return Err(NumaError::Errno(errno));
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_numa_policy(_policy: &NumaPolicy) -> Result<(), NumaError> {
    Err(NumaError::NotSupported)
}

// ── Node discovery ────────────────────────────────────────────────────────

/// Read the CPUs associated with a NUMA node from sysfs.
pub fn numa_node_get_cpus(node: u32) -> Result<CpuSet, NumaError> {
    let cpulist = std::fs::read_to_string(format!("{NUMA_NODE_SYSFS_PATH}/node{node}/cpulist"))?;
    Ok(CpuSet::parse(&cpulist)?)
}

/// Return the union of CPUs associated with all nodes in a NUMA policy.
pub fn numa_to_cpu_set(policy: &NumaPolicy) -> Result<CpuSet, NumaError> {
    let mut cpus = CpuSet::new();

    for node in policy.nodes().iter() {
        cpus.add_set(&numa_node_get_cpus(node)?)?;
    }

    Ok(cpus)
}

/// Find the NUMA node containing a CPU.
///
/// Unreadable or malformed individual node CPU lists are ignored, matching
/// the C helper. If no node contains `cpu`, node zero is returned.
pub fn numa_get_node_from_cpu(cpu: u32) -> Result<u32, NumaError> {
    for entry in std::fs::read_dir(NUMA_NODE_SYSFS_PATH)?.flatten() {
        if !entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
            continue;
        }

        let name = entry.file_name();
        let Some(node) = name
            .to_str()
            .and_then(|name| name.strip_prefix("node"))
            .and_then(|suffix| suffix.parse::<u32>().ok())
        else {
            continue;
        };

        let Ok(cpus) = numa_node_get_cpus(node) else {
            continue;
        };
        if cpus.contains(cpu) {
            return Ok(node);
        }
    }

    Ok(0)
}

/// Discover the maximum NUMA node index by scanning `/sys/devices/system/node`.
///
/// Returns the highest node index found, or falls back to
/// [`NUMA_MAX_NODE_FALLBACK`] if the sysfs directory cannot be read.
pub fn numa_max_node() -> u32 {
    match std::fs::read_dir(NUMA_NODE_SYSFS_PATH) {
        Ok(entries) => {
            let mut max_node: u32 = 0;
            for entry in entries.flatten() {
                if !entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                    continue;
                }

                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if let Some(suffix) = name_str.strip_prefix("node") {
                    if let Ok(node) = suffix.parse::<u32>() {
                        max_node = max_node.max(node);
                    }
                }
            }
            max_node
        }
        Err(_) => NUMA_MAX_NODE_FALLBACK,
    }
}

/// Populate a [`NodeMask`] with all NUMA nodes up to the discovered maximum.
pub fn numa_mask_add_all(mask: &mut NodeMask) -> Result<(), NumaError> {
    let max = numa_max_node();
    for i in 0..=max {
        mask.set(i);
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpol_type_is_valid_raw() {
        for raw in 0..=6 {
            assert!(MpolType::is_valid_raw(raw), "raw={raw} should be valid");
        }
        assert!(!MpolType::is_valid_raw(-1));
        assert!(!MpolType::is_valid_raw(7));
        assert!(!MpolType::is_valid_raw(100));
    }

    #[test]
    fn test_mpol_type_from_raw() {
        assert_eq!(MpolType::from_raw(0), Some(MpolType::Default));
        assert_eq!(MpolType::from_raw(1), Some(MpolType::Preferred));
        assert_eq!(MpolType::from_raw(2), Some(MpolType::Bind));
        assert_eq!(MpolType::from_raw(3), Some(MpolType::Interleave));
        assert_eq!(MpolType::from_raw(4), Some(MpolType::Local));
        assert_eq!(MpolType::from_raw(5), Some(MpolType::PreferredMany));
        assert_eq!(MpolType::from_raw(6), Some(MpolType::WeightedInterleave));
        assert_eq!(MpolType::from_raw(-1), None);
        assert_eq!(MpolType::from_raw(99), None);
    }

    #[test]
    fn test_mpol_type_as_str() {
        assert_eq!(MpolType::Default.as_str(), "default");
        assert_eq!(MpolType::Preferred.as_str(), "preferred");
        assert_eq!(MpolType::Bind.as_str(), "bind");
        assert_eq!(MpolType::Interleave.as_str(), "interleave");
        assert_eq!(MpolType::Local.as_str(), "local");
        assert_eq!(MpolType::PreferredMany.as_str(), "preferred-many");
        assert_eq!(MpolType::WeightedInterleave.as_str(), "weighted-interleave");
    }

    #[test]
    fn test_mpol_type_from_str_name() {
        assert_eq!(MpolType::from_str_name("default"), Some(MpolType::Default));
        assert_eq!(
            MpolType::from_str_name("preferred"),
            Some(MpolType::Preferred)
        );
        assert_eq!(MpolType::from_str_name("bind"), Some(MpolType::Bind));
        assert_eq!(
            MpolType::from_str_name("interleave"),
            Some(MpolType::Interleave)
        );
        assert_eq!(MpolType::from_str_name("local"), Some(MpolType::Local));
        assert_eq!(
            MpolType::from_str_name("preferred-many"),
            Some(MpolType::PreferredMany)
        );
        assert_eq!(
            MpolType::from_str_name("weighted-interleave"),
            Some(MpolType::WeightedInterleave)
        );
        assert_eq!(MpolType::from_str_name("invalid"), None);
        assert_eq!(MpolType::from_str_name(""), None);
    }

    #[test]
    fn test_mpol_type_requires_nodes() {
        assert!(!MpolType::Default.requires_nodes());
        assert!(!MpolType::Local.requires_nodes());
        assert!(!MpolType::Preferred.requires_nodes());
        assert!(MpolType::Bind.requires_nodes());
        assert!(MpolType::Interleave.requires_nodes());
        assert!(MpolType::PreferredMany.requires_nodes());
        assert!(MpolType::WeightedInterleave.requires_nodes());
    }

    #[test]
    fn test_mpol_type_allows_empty_nodes() {
        assert!(MpolType::Default.allows_empty_nodes());
        assert!(MpolType::Local.allows_empty_nodes());
        assert!(MpolType::Preferred.allows_empty_nodes());
        assert!(!MpolType::Bind.allows_empty_nodes());
        assert!(!MpolType::Interleave.allows_empty_nodes());
        assert!(!MpolType::PreferredMany.allows_empty_nodes());
        assert!(!MpolType::WeightedInterleave.allows_empty_nodes());
    }

    #[test]
    fn test_node_mask_set_and_test() {
        let mut mask = NodeMask::new();
        assert!(mask.is_empty());

        mask.set(0);
        mask.set(3);
        mask.set(127);
        assert!(mask.is_set(0));
        assert!(mask.is_set(3));
        assert!(mask.is_set(127));
        assert!(!mask.is_set(1));
        assert!(!mask.is_set(64));
        assert!(!mask.is_set(126));
        assert_eq!(mask.count(), 3);
    }

    #[test]
    fn test_node_mask_with_capacity() {
        let mut mask = NodeMask::with_capacity(1023);
        assert_eq!(mask.capacity(), 1024);
        assert_eq!(mask.count(), 0);

        mask.set(1023);
        assert!(mask.is_set(1023));
        assert_eq!(mask.count(), 1);
    }

    #[test]
    fn test_node_mask_to_mempolicy_format() {
        let mut mask = NodeMask::new();
        let (maxnode, nodes) = mask.to_mempolicy_format();
        assert_eq!(maxnode, 0);
        assert!(nodes.is_none());

        mask.set(0);
        mask.set(1);
        let (maxnode, nodes) = mask.to_mempolicy_format();
        assert!(nodes.is_some());
        assert!(maxnode > 0);
    }

    #[test]
    fn test_node_mask_iter() {
        let mut mask = NodeMask::new();
        mask.set(1);
        mask.set(64);
        mask.set(127);
        assert_eq!(mask.iter().collect::<Vec<_>>(), vec![1, 64, 127]);
    }

    #[test]
    fn test_node_mask_default() {
        let mask = NodeMask::default();
        assert!(mask.is_empty());
        assert_eq!(mask.count(), 0);
    }

    #[test]
    fn test_numa_policy_default_is_valid() {
        let p = NumaPolicy::default_policy();
        assert!(p.is_valid());
        assert_eq!(p.policy_type(), MpolType::Default);
        assert!(p.nodes().is_empty());
    }

    #[test]
    fn test_numa_policy_local_is_valid() {
        let p = NumaPolicy::local_policy();
        assert!(p.is_valid());
        assert_eq!(p.policy_type(), MpolType::Local);
    }

    #[test]
    fn test_numa_policy_preferred_single_node() {
        let p = NumaPolicy::preferred_node(0);
        assert!(p.is_valid());
        assert_eq!(p.nodes().count(), 1);
        assert!(p.nodes().is_set(0));
    }

    #[test]
    fn test_numa_policy_preferred_multi_node_invalid() {
        let mut mask = NodeMask::new();
        mask.set(0);
        mask.set(1);
        let p = NumaPolicy::new(MpolType::Preferred, mask);
        assert!(!p.is_valid());
    }

    #[test]
    fn test_numa_policy_bind_requires_nodes() {
        let p = NumaPolicy::new(MpolType::Bind, NodeMask::new());
        assert!(!p.is_valid());

        let mut mask = NodeMask::new();
        mask.set(0);
        mask.set(1);
        let p = NumaPolicy::bind_nodes(mask);
        assert!(p.is_valid());
    }

    #[test]
    fn test_numa_policy_interleave_requires_nodes() {
        let p = NumaPolicy::new(MpolType::Interleave, NodeMask::new());
        assert!(!p.is_valid());

        let mut mask = NodeMask::new();
        mask.set(0);
        mask.set(1);
        mask.set(2);
        let p = NumaPolicy::interleave_nodes(mask);
        assert!(p.is_valid());
    }

    #[test]
    fn test_numa_policy_to_mempolicy_default() {
        let p = NumaPolicy::default_policy();
        let (mode, maxnode, nodes) = p.to_mempolicy();
        assert_eq!(mode, MpolType::Default.as_raw());
        assert_eq!(maxnode, 0);
        assert!(nodes.is_none());
    }

    #[test]
    fn test_numa_policy_to_mempolicy_local() {
        let p = NumaPolicy::local_policy();
        let (mode, maxnode, nodes) = p.to_mempolicy();
        assert_eq!(mode, MpolType::Local.as_raw());
        assert_eq!(maxnode, 0);
        assert!(nodes.is_none());
    }

    #[test]
    fn test_numa_policy_to_mempolicy_ignores_nodes_for_default_and_local() {
        let mut mask = NodeMask::new();
        mask.set(3);

        for policy_type in [MpolType::Default, MpolType::Local] {
            let p = NumaPolicy::new(policy_type, mask.clone());
            let (mode, maxnode, nodes) = p.to_mempolicy();
            assert_eq!(mode, policy_type.as_raw());
            assert_eq!(maxnode, 0);
            assert!(nodes.is_none());
        }
    }

    #[test]
    fn test_numa_policy_to_mempolicy_with_nodes() {
        let mut mask = NodeMask::new();
        mask.set(0);
        mask.set(2);
        let p = NumaPolicy::new(MpolType::Bind, mask);
        let (mode, maxnode, nodes) = p.to_mempolicy();
        assert_eq!(mode, MpolType::Bind.as_raw());
        assert!(maxnode > 0);
        assert!(nodes.is_some());
    }

    #[test]
    fn test_numa_error_display() {
        let e = NumaError::NotSupported;
        assert!(!e.to_string().is_empty());

        let e = NumaError::InvalidPolicy;
        assert!(e.to_string().contains("invalid"));

        let e = NumaError::Errno(12);
        assert!(e.to_string().contains("12"));
    }

    #[test]
    fn test_numa_mask_add_all() {
        let mut mask = NodeMask::new();
        numa_mask_add_all(&mut mask).unwrap();
        assert!(mask.capacity() > 0 || mask.count() > 0);
    }

    #[test]
    fn test_numa_max_node_fallback() {
        let max = numa_max_node();
        assert!(max <= NUMA_MAX_NODE_FALLBACK);
    }
}
