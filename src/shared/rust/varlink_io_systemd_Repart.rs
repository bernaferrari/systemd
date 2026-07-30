// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Repart.c
//
// Varlink interface definition for io.systemd.Repart.
//
// API for declaratively re-partitioning disks using systemd-repart.
// Provides the Run method for executing repartitioning (with optional
// progress updates), and ListCandidateDevices for discovering available
// block devices.

// ── Constants ─────────────────────────────────────────────────────────────

/// Fully qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.Repart";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Progress phase identifiers sent during the Run method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressPhase {
    LoadingDefinitions,
    LoadingTable,
    OpeningCopyBlockSources,
    AcquiringPartitionLabels,
    Minimizing,
    Placing,
    WipingDisk,
    WipingPartition,
    CopyingPartition,
    FormattingPartition,
    AdjustingPartition,
    WritingTable,
    RereadingTable,
}

impl ProgressPhase {
    /// All known values.
    pub const VALUES: &[Self] = &[
        Self::LoadingDefinitions,
        Self::LoadingTable,
        Self::OpeningCopyBlockSources,
        Self::AcquiringPartitionLabels,
        Self::Minimizing,
        Self::Placing,
        Self::WipingDisk,
        Self::WipingPartition,
        Self::CopyingPartition,
        Self::FormattingPartition,
        Self::AdjustingPartition,
        Self::WritingTable,
        Self::RereadingTable,
    ];

    /// Parse from the varlink wire string.
    #[expect(
        clippy::should_implement_trait,
        reason = "retain the generated inherent API alongside FromStr"
    )]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "loading_definitions" => Ok(Self::LoadingDefinitions),
            "loading_table" => Ok(Self::LoadingTable),
            "opening_copy_block_sources" => Ok(Self::OpeningCopyBlockSources),
            "acquiring_partition_labels" => Ok(Self::AcquiringPartitionLabels),
            "minimizing" => Ok(Self::Minimizing),
            "placing" => Ok(Self::Placing),
            "wiping_disk" => Ok(Self::WipingDisk),
            "wiping_partition" => Ok(Self::WipingPartition),
            "copying_partition" => Ok(Self::CopyingPartition),
            "formatting_partition" => Ok(Self::FormattingPartition),
            "adjusting_partition" => Ok(Self::AdjustingPartition),
            "writing_table" => Ok(Self::WritingTable),
            "rereading_table" => Ok(Self::RereadingTable),
            _ => Err(format!("unknown ProgressPhase: {s}")),
        }
    }

    /// Return the varlink wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LoadingDefinitions => "loading_definitions",
            Self::LoadingTable => "loading_table",
            Self::OpeningCopyBlockSources => "opening_copy_block_sources",
            Self::AcquiringPartitionLabels => "acquiring_partition_labels",
            Self::Minimizing => "minimizing",
            Self::Placing => "placing",
            Self::WipingDisk => "wiping_disk",
            Self::WipingPartition => "wiping_partition",
            Self::CopyingPartition => "copying_partition",
            Self::FormattingPartition => "formatting_partition",
            Self::AdjustingPartition => "adjusting_partition",
            Self::WritingTable => "writing_table",
            Self::RereadingTable => "rereading_table",
        }
    }
}

/// Behavior for disks that are completely empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyMode {
    /// Refuse to operate on disks without an existing partition table.
    Refuse,
    /// Create a new partition table if one doesn't already exist.
    Allow,
    /// Require a completely empty disk; refuse if a table exists.
    Require,
    /// Always create a new partition table, potentially overwriting an existing one.
    Force,
}

impl EmptyMode {
    /// All known values.
    pub const VALUES: &[Self] = &[Self::Refuse, Self::Allow, Self::Require, Self::Force];

    /// Parse from the varlink wire string.
    #[expect(
        clippy::should_implement_trait,
        reason = "retain the generated inherent API alongside FromStr"
    )]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "refuse" => Ok(Self::Refuse),
            "allow" => Ok(Self::Allow),
            "require" => Ok(Self::Require),
            "force" => Ok(Self::Force),
            _ => Err(format!("unknown EmptyMode: {s}")),
        }
    }

    /// Return the varlink wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
            Self::Allow => "allow",
            Self::Require => "require",
            Self::Force => "force",
        }
    }
}

// ── Method identifiers ────────────────────────────────────────────────────

pub const METHOD_RUN: &str = "Run";
pub const METHOD_LIST_CANDIDATE_DEVICES: &str = "ListCandidateDevices";

/// All method names defined by this interface.
pub fn method_names() -> &'static [&'static str] {
    &[METHOD_RUN, METHOD_LIST_CANDIDATE_DEVICES]
}

/// Check whether a method name belongs to this interface.
pub fn has_method(name: &str) -> bool {
    method_names().contains(&name)
}

/// Typed method identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepartMethod {
    Run,
    ListCandidateDevices,
}

impl RepartMethod {
    /// Return the varlink method name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Run => METHOD_RUN,
            Self::ListCandidateDevices => METHOD_LIST_CANDIDATE_DEVICES,
        }
    }

    /// Whether the method supports the "more" flag (progress streaming).
    pub fn supports_more(&self) -> bool {
        matches!(self, Self::Run)
    }

    /// Whether the method requires the "more" flag (streaming output).
    pub fn requires_more(&self) -> bool {
        matches!(self, Self::ListCandidateDevices)
    }
}

/// Parse a method name into a typed identifier.
pub fn parse_method(name: &str) -> Result<RepartMethod, String> {
    match name {
        METHOD_RUN => Ok(RepartMethod::Run),
        METHOD_LIST_CANDIDATE_DEVICES => Ok(RepartMethod::ListCandidateDevices),
        _ => Err(format!("unknown method: {name}")),
    }
}

// ── Method I/O structs ────────────────────────────────────────────────────

/// Input parameters for the Run method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInput {
    /// Full path to the block device node.
    pub node: Option<String>,
    /// Empty disk behavior.
    pub empty: EmptyMode,
    /// Whether to perform a dry run (no writes).
    pub dry_run: bool,
    /// Seed value for deriving UUIDs.
    pub seed: Option<String>,
    /// Paths to definition file directories.
    pub definitions: Vec<String>,
    /// Auto-defer partitions labelled "empty".
    pub defer_partitions_empty: Option<bool>,
    /// Auto-defer partitions marked for factory reset.
    pub defer_partitions_factory_reset: Option<bool>,
}

impl RunInput {
    /// Create a dry-run input with no node and empty definitions.
    pub fn new_dry_run() -> Self {
        Self {
            node: None,
            empty: EmptyMode::Refuse,
            dry_run: true,
            seed: None,
            definitions: Vec::new(),
            defer_partitions_empty: None,
            defer_partitions_factory_reset: None,
        }
    }

    /// Validate the input. If dry_run is false, node must be set.
    pub fn validate(&self) -> Result<(), String> {
        if !self.dry_run && self.node.is_none() {
            return Err("node is required when dryRun is false".to_string());
        }
        Ok(())
    }
}

/// Output from the Run method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    /// Minimal disk size required (dry-run mode).
    pub minimal_size_bytes: Option<i64>,
    /// Size of the selected block device (dry-run mode).
    pub current_size_bytes: Option<i64>,
    /// Progress phase (with "more" flag).
    pub phase: Option<ProgressPhase>,
    /// Object identifier (with "more" flag).
    pub object: Option<String>,
    /// Progress percentage (with "more" flag).
    pub progress: Option<i64>,
}

/// Input for the ListCandidateDevices method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListCandidateDevicesInput {
    /// Whether to exclude the root disk.
    pub ignore_root: Option<bool>,
    /// Whether to exclude empty block devices.
    pub ignore_empty: Option<bool>,
}

impl ListCandidateDevicesInput {
    /// Create a new input with default filters.
    pub fn new() -> Self {
        Self {
            ignore_root: None,
            ignore_empty: None,
        }
    }
}

impl Default for ListCandidateDevicesInput {
    fn default() -> Self {
        Self::new()
    }
}

/// Output for the ListCandidateDevices method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateDevice {
    /// Device node path.
    pub node: String,
    /// Symlinks pointing to the device node.
    pub symlinks: Vec<String>,
    /// Linux kernel disk sequence number.
    pub diskseq: Option<i64>,
    /// Size of the block device in bytes.
    pub size_bytes: Option<i64>,
    /// Device vendor string.
    pub vendor: Option<String>,
    /// Device model string.
    pub model: Option<String>,
    /// Device subsystem.
    pub subsystem: Option<String>,
}

// ── Error types ───────────────────────────────────────────────────────────

/// Errors defined by this interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepartError {
    NoCandidateDevices,
    ConflictingDiskLabelPresent,
    InsufficientFreeSpace,
    DiskTooSmall,
}

impl RepartError {
    /// Parse from the varlink error string.
    #[expect(
        clippy::should_implement_trait,
        reason = "retain the generated inherent API alongside FromStr"
    )]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "NoCandidateDevices" => Ok(Self::NoCandidateDevices),
            "ConflictingDiskLabelPresent" => Ok(Self::ConflictingDiskLabelPresent),
            "InsufficientFreeSpace" => Ok(Self::InsufficientFreeSpace),
            "DiskTooSmall" => Ok(Self::DiskTooSmall),
            _ => Err(format!("unknown error: {s}")),
        }
    }

    /// Return the varlink error string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoCandidateDevices => "NoCandidateDevices",
            Self::ConflictingDiskLabelPresent => "ConflictingDiskLabelPresent",
            Self::InsufficientFreeSpace => "InsufficientFreeSpace",
            Self::DiskTooSmall => "DiskTooSmall",
        }
    }
}

/// All error names.
pub fn error_names() -> &'static [&'static str] {
    &[
        "NoCandidateDevices",
        "ConflictingDiskLabelPresent",
        "InsufficientFreeSpace",
        "DiskTooSmall",
    ]
}

macro_rules! impl_varlink_from_str {
    ($($ty:ty),+ $(,)?) => {$(
        impl std::str::FromStr for $ty {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                <$ty>::from_str(s)
            }
        }
    )+};
}

impl_varlink_from_str!(ProgressPhase, EmptyMode, RepartError);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_from_str_matches_wire_parsers() {
        assert_eq!(
            "loading_definitions".parse::<ProgressPhase>(),
            Ok(ProgressPhase::LoadingDefinitions)
        );
        assert_eq!("refuse".parse::<EmptyMode>(), Ok(EmptyMode::Refuse));
        assert_eq!(
            "NoCandidateDevices".parse::<RepartError>(),
            Ok(RepartError::NoCandidateDevices)
        );
    }

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Repart");
    }

    #[test]
    fn test_progress_phase_roundtrip() {
        for v in ProgressPhase::VALUES {
            assert_eq!(ProgressPhase::from_str(v.as_str()), Ok(*v));
        }
        assert!(ProgressPhase::from_str("bogus").is_err());
    }

    #[test]
    fn test_empty_mode_roundtrip() {
        for v in EmptyMode::VALUES {
            assert_eq!(EmptyMode::from_str(v.as_str()), Ok(*v));
        }
        assert!(EmptyMode::from_str("bogus").is_err());
    }

    #[test]
    fn test_method_names() {
        assert_eq!(method_names().len(), 2);
        assert!(has_method("Run"));
        assert!(has_method("ListCandidateDevices"));
        assert!(!has_method("Unknown"));
    }

    #[test]
    fn test_parse_method() {
        assert_eq!(parse_method("Run"), Ok(RepartMethod::Run));
        assert_eq!(
            parse_method("ListCandidateDevices"),
            Ok(RepartMethod::ListCandidateDevices),
        );
        assert!(parse_method("bogus").is_err());
    }

    #[test]
    fn test_method_name_roundtrip() {
        for name in method_names() {
            let m = parse_method(name).unwrap();
            assert_eq!(m.name(), *name);
        }
    }

    #[test]
    fn test_run_input_validate_dry_run() {
        let input = RunInput::new_dry_run();
        assert!(input.validate().is_ok());
    }

    #[test]
    fn test_run_input_validate_no_node_real_run() {
        let input = RunInput {
            node: None,
            empty: EmptyMode::Refuse,
            dry_run: false,
            seed: None,
            definitions: vec![],
            defer_partitions_empty: None,
            defer_partitions_factory_reset: None,
        };
        assert!(input.validate().is_err());
    }

    #[test]
    fn test_run_input_validate_with_node_real_run() {
        let mut input = RunInput::new_dry_run();
        input.node = Some("/dev/sda".to_string());
        input.dry_run = false;
        assert!(input.validate().is_ok());
    }

    #[test]
    fn test_list_candidate_devices_input_default() {
        let input = ListCandidateDevicesInput::default();
        assert_eq!(input.ignore_root, None);
        assert_eq!(input.ignore_empty, None);
    }

    #[test]
    fn test_error_roundtrip() {
        for name in error_names() {
            let e = RepartError::from_str(name).unwrap();
            assert_eq!(e.as_str(), *name);
        }
    }

    #[test]
    fn test_supports_more_flags() {
        assert!(RepartMethod::Run.supports_more());
        assert!(!RepartMethod::ListCandidateDevices.supports_more());
    }

    #[test]
    fn test_requires_more_flags() {
        assert!(!RepartMethod::Run.requires_more());
        assert!(RepartMethod::ListCandidateDevices.requires_more());
    }
}
