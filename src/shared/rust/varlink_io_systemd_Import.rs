// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Import.c
//
// Varlink interface definition for io.systemd.Import.
//
// Manages image transfer operations including downloading, importing,
// and exporting disk images and tarballs with verification support.

// ── Interface metadata ─────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.Import";

/// Method names defined by this interface
pub const METHOD_LIST_TRANSFERS: &str = "ListTransfers";
pub const METHOD_PULL: &str = "Pull";

/// All method names in this interface
pub const METHODS: &[&str] = &[METHOD_LIST_TRANSFERS, METHOD_PULL];

// ── Enums ──────────────────────────────────────────────────────────────────

/// Image classification types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageClass {
    /// An image to boot as a system on baremetal, in a VM or as a container
    Machine,
    /// A portable service image
    Portable,
    /// A system extension image
    Sysext,
    /// A configuration extension image
    Confext,
}

impl ImageClass {
    /// All variants of ImageClass
    pub const ALL: &[ImageClass] = &[
        ImageClass::Machine,
        ImageClass::Portable,
        ImageClass::Sysext,
        ImageClass::Confext,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            ImageClass::Machine => "machine",
            ImageClass::Portable => "portable",
            ImageClass::Sysext => "sysext",
            ImageClass::Confext => "confext",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "machine" => Some(ImageClass::Machine),
            "portable" => Some(ImageClass::Portable),
            "sysext" => Some(ImageClass::Sysext),
            "confext" => Some(ImageClass::Confext),
            _ => None,
        }
    }
}

/// Remote resource type for transfer operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteType {
    /// Raw binary disk images, typically in a GPT envelope
    Raw,
    /// A tarball, optionally compressed
    Tar,
}

impl RemoteType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RemoteType::Raw => "raw",
            RemoteType::Tar => "tar",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "raw" => Some(RemoteType::Raw),
            "tar" => Some(RemoteType::Tar),
            _ => None,
        }
    }
}

/// Transfer operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    ImportTar,
    ImportRaw,
    ImportFs,
    ExportTar,
    ExportRaw,
    PullTar,
    PullRaw,
}

impl TransferType {
    /// All variants of TransferType
    pub const ALL: &[TransferType] = &[
        TransferType::ImportTar,
        TransferType::ImportRaw,
        TransferType::ImportFs,
        TransferType::ExportTar,
        TransferType::ExportRaw,
        TransferType::PullTar,
        TransferType::PullRaw,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            TransferType::ImportTar => "import_tar",
            TransferType::ImportRaw => "import_raw",
            TransferType::ImportFs => "import_fs",
            TransferType::ExportTar => "export_tar",
            TransferType::ExportRaw => "export_raw",
            TransferType::PullTar => "pull_tar",
            TransferType::PullRaw => "pull_raw",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "import_tar" => Some(TransferType::ImportTar),
            "import_raw" => Some(TransferType::ImportRaw),
            "import_fs" => Some(TransferType::ImportFs),
            "export_tar" => Some(TransferType::ExportTar),
            "export_raw" => Some(TransferType::ExportRaw),
            "pull_tar" => Some(TransferType::PullTar),
            "pull_raw" => Some(TransferType::PullRaw),
            _ => None,
        }
    }

    /// Returns true if this transfer type is an import operation
    pub fn is_import(&self) -> bool {
        matches!(
            self,
            TransferType::ImportTar | TransferType::ImportRaw | TransferType::ImportFs
        )
    }

    /// Returns true if this transfer type is an export operation
    pub fn is_export(&self) -> bool {
        matches!(self, TransferType::ExportTar | TransferType::ExportRaw)
    }

    /// Returns true if this transfer type is a pull (download) operation
    pub fn is_pull(&self) -> bool {
        matches!(self, TransferType::PullTar | TransferType::PullRaw)
    }
}

/// Image verification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageVerify {
    /// No verification
    No,
    /// Verify checksum only (SHA256SUMS), no signature check
    Checksum,
    /// Verify checksum and signature of checksum file
    Signature,
}

impl ImageVerify {
    pub fn as_str(&self) -> &'static str {
        match self {
            ImageVerify::No => "no",
            ImageVerify::Checksum => "checksum",
            ImageVerify::Signature => "signature",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "no" => Some(ImageVerify::No),
            "checksum" => Some(ImageVerify::Checksum),
            "signature" => Some(ImageVerify::Signature),
            _ => None,
        }
    }

    /// Returns the strictness level (higher = more thorough)
    pub fn strictness(&self) -> u8 {
        match self {
            ImageVerify::No => 0,
            ImageVerify::Checksum => 1,
            ImageVerify::Signature => 2,
        }
    }
}

// ── Structs ────────────────────────────────────────────────────────────────

/// Log message associated with a transfer operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogMessage {
    /// The log message text
    pub message: String,
    /// BSD syslog priority level
    pub priority: i64,
}

impl LogMessage {
    /// Create a new log message
    pub fn new(message: String, priority: i64) -> Self {
        Self { message, priority }
    }

    /// Validate the priority is within BSD syslog range (0-7)
    pub fn validate(&self) -> Result<(), ImportError> {
        if !(0..=7).contains(&self.priority) {
            return Err(ImportError::InvalidPriority(self.priority));
        }
        if self.message.is_empty() {
            return Err(ImportError::EmptyMessage);
        }
        Ok(())
    }
}

/// Input parameters for the Pull method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullInput {
    /// The remote URL to download from
    pub remote: String,
    /// The local image name to download to
    pub local: Option<String>,
    /// The type of the resource
    pub remote_type: RemoteType,
    /// The image class
    pub class: ImageClass,
    /// How thoroughly to verify the download
    pub verify: Option<ImageVerify>,
    /// Whether to overwrite existing images
    pub force: Option<bool>,
    /// Whether to make the image read-only
    pub read_only: Option<bool>,
    /// Whether to keep a pristine download copy
    pub keep_download: Option<bool>,
    /// Root directory for images
    pub image_root: Option<String>,
}

/// Output from the Pull method
#[derive(Debug, Clone)]
pub struct PullOutput {
    /// Progress update as percent value
    pub progress: Option<f64>,
    /// A log message about the ongoing transfer
    pub log: Option<LogMessage>,
    /// The numeric ID of this download
    pub id: Option<i64>,
}

/// Transfer information returned by ListTransfers
#[derive(Debug, Clone)]
pub struct TransferInfo {
    /// Unique numeric identifier for the ongoing transfer
    pub id: i64,
    /// The type of transfer
    pub transfer_type: TransferType,
    /// The remote URL
    pub remote: String,
    /// The local image name
    pub local: String,
    /// The class of the image
    pub class: ImageClass,
    /// Progress in percent
    pub percent: f64,
}

// ── Error types ────────────────────────────────────────────────────────────

/// Errors for the io.systemd.Import interface
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// A transfer for the specified file is already ongoing
    AlreadyInProgress { remote: String },
    /// The transfer has been cancelled on user request
    TransferCancelled,
    /// The transfer failed
    TransferFailed,
    /// No currently ongoing transfer
    NoTransfers,
    /// Invalid priority value
    InvalidPriority(i64),
    /// Empty log message
    EmptyMessage,
}

impl ImportError {
    /// Returns the varlink error ID string
    pub fn error_id(&self) -> &'static str {
        match self {
            ImportError::AlreadyInProgress { .. } => "io.systemd.Import.AlreadyInProgress",
            ImportError::TransferCancelled => "io.systemd.Import.TransferCancelled",
            ImportError::TransferFailed => "io.systemd.Import.TransferFailed",
            ImportError::NoTransfers => "io.systemd.Import.NoTransfers",
            ImportError::InvalidPriority(_) => "io.systemd.Import.InvalidPriority",
            ImportError::EmptyMessage => "io.systemd.Import.EmptyMessage",
        }
    }
}

/// All varlink error IDs for this interface
pub const ERROR_IDS: &[&str] = &[
    "io.systemd.Import.AlreadyInProgress",
    "io.systemd.Import.TransferCancelled",
    "io.systemd.Import.TransferFailed",
    "io.systemd.Import.NoTransfers",
];

// ── Helper functions ───────────────────────────────────────────────────────

/// Validate a URL for transfer operations
pub fn validate_remote_url(url: &str) -> Result<(), ImportError> {
    if url.is_empty() {
        return Err(ImportError::TransferFailed);
    }
    if !url.contains(':') {
        return Err(ImportError::TransferFailed);
    }
    Ok(())
}

/// Validate an image name for local operations
pub fn validate_image_name(name: &str) -> Result<(), ImportError> {
    if name.is_empty() {
        return Err(ImportError::TransferFailed);
    }
    if name.contains('/') || name.contains('\0') {
        return Err(ImportError::TransferFailed);
    }
    Ok(())
}

/// Compute effective verification level, defaulting to signature
pub fn effective_verify_level(verify: Option<ImageVerify>) -> ImageVerify {
    verify.unwrap_or(ImageVerify::Signature)
}

/// Check if a progress value is within valid range [0.0, 100.0]
pub fn is_valid_progress(percent: f64) -> bool {
    (0.0..=100.0).contains(&percent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Import");
    }

    #[test]
    fn test_image_class_roundtrip() {
        for cls in ImageClass::ALL {
            assert_eq!(ImageClass::from_str(cls.as_str()), Some(*cls));
        }
        assert_eq!(ImageClass::ALL.len(), 4);
    }

    #[test]
    fn test_image_class_from_str_invalid() {
        assert_eq!(ImageClass::from_str("invalid"), None);
        assert_eq!(ImageClass::from_str(""), None);
    }

    #[test]
    fn test_remote_type_roundtrip() {
        assert_eq!(
            RemoteType::from_str(RemoteType::Raw.as_str()),
            Some(RemoteType::Raw)
        );
        assert_eq!(
            RemoteType::from_str(RemoteType::Tar.as_str()),
            Some(RemoteType::Tar)
        );
        assert_eq!(RemoteType::from_str("unknown"), None);
    }

    #[test]
    fn test_transfer_type_categories() {
        assert!(TransferType::ImportTar.is_import());
        assert!(TransferType::ImportRaw.is_import());
        assert!(TransferType::ImportFs.is_import());
        assert!(!TransferType::ExportTar.is_import());

        assert!(TransferType::ExportTar.is_export());
        assert!(TransferType::ExportRaw.is_export());
        assert!(!TransferType::PullTar.is_export());

        assert!(TransferType::PullTar.is_pull());
        assert!(TransferType::PullRaw.is_pull());
        assert!(!TransferType::ImportTar.is_pull());
    }

    #[test]
    fn test_transfer_type_all_roundtrip() {
        for tt in TransferType::ALL {
            assert_eq!(TransferType::from_str(tt.as_str()), Some(*tt));
        }
        assert_eq!(TransferType::ALL.len(), 7);
    }

    #[test]
    fn test_image_verify_strictness() {
        assert!(ImageVerify::Signature.strictness() > ImageVerify::Checksum.strictness());
        assert!(ImageVerify::Checksum.strictness() > ImageVerify::No.strictness());
    }

    #[test]
    fn test_image_verify_roundtrip() {
        assert_eq!(ImageVerify::from_str("no"), Some(ImageVerify::No));
        assert_eq!(
            ImageVerify::from_str("checksum"),
            Some(ImageVerify::Checksum)
        );
        assert_eq!(
            ImageVerify::from_str("signature"),
            Some(ImageVerify::Signature)
        );
        assert_eq!(ImageVerify::from_str("bogus"), None);
    }

    #[test]
    fn test_log_message_validation() {
        let valid = LogMessage::new("hello".into(), 3);
        assert!(valid.validate().is_ok());

        let bad_priority = LogMessage::new("hello".into(), 9);
        assert!(bad_priority.validate().is_err());

        let empty_msg = LogMessage::new(String::new(), 3);
        assert!(empty_msg.validate().is_err());
    }

    #[test]
    fn test_import_error_ids() {
        let err = ImportError::AlreadyInProgress {
            remote: "http://example.com".into(),
        };
        assert!(err.error_id().ends_with("AlreadyInProgress"));
        assert!(
            ImportError::TransferCancelled
                .error_id()
                .contains("TransferCancelled")
        );
        assert!(ImportError::NoTransfers.error_id().contains("NoTransfers"));
    }

    #[test]
    fn test_validate_remote_url() {
        assert!(validate_remote_url("http://example.com/image.raw").is_ok());
        assert!(validate_remote_url("https://example.com/image.tar").is_ok());
        assert!(validate_remote_url("file:///path/to/image.raw").is_ok());
        assert!(validate_remote_url("").is_err());
        assert!(validate_remote_url("nocolon").is_err());
    }

    #[test]
    fn test_validate_image_name() {
        assert!(validate_image_name("myimage").is_ok());
        assert!(validate_image_name("my-image").is_ok());
        assert!(validate_image_name("my_image").is_ok());
        assert!(validate_image_name("").is_err());
        assert!(validate_image_name("has/slash").is_err());
        assert!(validate_image_name("null\0byte").is_err());
    }

    #[test]
    fn test_effective_verify_level() {
        assert_eq!(effective_verify_level(None), ImageVerify::Signature);
        assert_eq!(
            effective_verify_level(Some(ImageVerify::No)),
            ImageVerify::No
        );
        assert_eq!(
            effective_verify_level(Some(ImageVerify::Checksum)),
            ImageVerify::Checksum
        );
    }

    #[test]
    fn test_is_valid_progress() {
        assert!(is_valid_progress(0.0));
        assert!(is_valid_progress(50.0));
        assert!(is_valid_progress(100.0));
        assert!(!is_valid_progress(-1.0));
        assert!(!is_valid_progress(100.1));
    }

    #[test]
    fn test_methods_and_errors_constants() {
        assert_eq!(METHODS.len(), 2);
        assert!(METHODS.contains(&METHOD_LIST_TRANSFERS));
        assert!(METHODS.contains(&METHOD_PULL));
        assert_eq!(ERROR_IDS.len(), 4);
    }
}
