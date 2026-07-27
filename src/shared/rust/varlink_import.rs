// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Import.c
//
// Varlink interface definition for io.systemd.Import.
//
// APIs for importing, exporting, and transferring disk images, including
// support for tar and raw formats, various image classes, and verification.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the Import service.
pub const INTERFACE_NAME: &str = "io.systemd.Import";

/// Method name for ListTransfers.
pub const METHOD_LIST_TRANSFERS: &str = "io.systemd.Import.ListTransfers";

/// Method name for Pull.
pub const METHOD_PULL: &str = "io.systemd.Import.Pull";

/// Error: a transfer for the specified file is already ongoing.
pub const ERROR_ALREADY_IN_PROGRESS: &str = "io.systemd.Import.AlreadyInProgress";

/// Error: the transfer has been cancelled on user request.
pub const ERROR_TRANSFER_CANCELLED: &str = "io.systemd.Import.TransferCancelled";

/// Error: the transfer failed.
pub const ERROR_TRANSFER_FAILED: &str = "io.systemd.Import.TransferFailed";

/// Error: no currently ongoing transfer.
pub const ERROR_NO_TRANSFERS: &str = "io.systemd.Import.NoTransfers";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Image class enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageClass {
    /// An image to boot as a system on baremetal, in a VM or as a container.
    Machine,
    /// A portable service image.
    Portable,
    /// A system extension image.
    Sysext,
    /// A configuration extension image.
    Confext,
}

impl ImageClass {
    /// Parse an image class from its varlink string representation.
    pub fn from_str(s: &str) -> Result<ImageClass, i32> {
        match s {
            "machine" => Ok(ImageClass::Machine),
            "portable" => Ok(ImageClass::Portable),
            "sysext" => Ok(ImageClass::Sysext),
            "confext" => Ok(ImageClass::Confext),
            _ => Err(-22),
        }
    }

    /// Convert to the varlink string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ImageClass::Machine => "machine",
            ImageClass::Portable => "portable",
            ImageClass::Sysext => "sysext",
            ImageClass::Confext => "confext",
        }
    }

    /// All variants in varlink definition order.
    pub fn all_variants() -> &'static [ImageClass] {
        &[
            ImageClass::Machine,
            ImageClass::Portable,
            ImageClass::Sysext,
            ImageClass::Confext,
        ]
    }
}

/// Remote resource type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteType {
    /// Raw binary disk image, typically in a GPT envelope.
    Raw,
    /// A tarball, optionally compressed.
    Tar,
}

impl RemoteType {
    /// Parse a remote type from its varlink string representation.
    pub fn from_str(s: &str) -> Result<RemoteType, i32> {
        match s {
            "raw" => Ok(RemoteType::Raw),
            "tar" => Ok(RemoteType::Tar),
            _ => Err(-22),
        }
    }

    /// Convert to the varlink string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            RemoteType::Raw => "raw",
            RemoteType::Tar => "tar",
        }
    }
}

/// Transfer type enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    /// A local import of a tarball.
    ImportTar,
    /// A local import of a raw disk image.
    ImportRaw,
    /// A local import of a file system tree.
    ImportFs,
    /// A local export of a tarball.
    ExportTar,
    /// A local export of a raw disk image.
    ExportRaw,
    /// A download of a tarball.
    PullTar,
    /// A download of a raw disk image.
    PullRaw,
}

impl TransferType {
    /// Parse a transfer type from its varlink string representation.
    pub fn from_str(s: &str) -> Result<TransferType, i32> {
        match s {
            "import_tar" => Ok(TransferType::ImportTar),
            "import_raw" => Ok(TransferType::ImportRaw),
            "import_fs" => Ok(TransferType::ImportFs),
            "export_tar" => Ok(TransferType::ExportTar),
            "export_raw" => Ok(TransferType::ExportRaw),
            "pull_tar" => Ok(TransferType::PullTar),
            "pull_raw" => Ok(TransferType::PullRaw),
            _ => Err(-22),
        }
    }

    /// Convert to the varlink string representation.
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

    /// Check if this is an import transfer type.
    pub fn is_import(&self) -> bool {
        matches!(
            self,
            TransferType::ImportTar | TransferType::ImportRaw | TransferType::ImportFs
        )
    }

    /// Check if this is an export transfer type.
    pub fn is_export(&self) -> bool {
        matches!(self, TransferType::ExportTar | TransferType::ExportRaw)
    }

    /// Check if this is a pull (download) transfer type.
    pub fn is_pull(&self) -> bool {
        matches!(self, TransferType::PullTar | TransferType::PullRaw)
    }
}

/// Image verification level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageVerify {
    /// No verification.
    No,
    /// Verify downloads match checksum file (SHA256SUMS).
    Checksum,
    /// Verify checksums AND check signature of checksum file.
    Signature,
}

impl ImageVerify {
    /// Parse an image verify level from its varlink string representation.
    pub fn from_str(s: &str) -> Result<ImageVerify, i32> {
        match s {
            "no" => Ok(ImageVerify::No),
            "checksum" => Ok(ImageVerify::Checksum),
            "signature" => Ok(ImageVerify::Signature),
            _ => Err(-22),
        }
    }

    /// Convert to the varlink string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ImageVerify::No => "no",
            ImageVerify::Checksum => "checksum",
            ImageVerify::Signature => "signature",
        }
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Log message from a transfer operation.
#[derive(Debug, Clone)]
pub struct LogMessage {
    /// The log message text.
    pub message: String,
    /// The priority (BSD syslog level).
    pub priority: i64,
}

impl LogMessage {
    /// Create a new log message.
    pub fn new(message: impl Into<String>, priority: i64) -> Self {
        Self {
            message: message.into(),
            priority,
        }
    }

    /// Validate that the priority is in valid BSD syslog range (0-7).
    pub fn validate(&self) -> Result<(), i32> {
        if !(0..=7).contains(&self.priority) {
            return Err(-22);
        }
        Ok(())
    }
}

/// A transfer list entry returned by ListTransfers.
#[derive(Debug, Clone)]
pub struct TransferEntry {
    /// A unique numeric identifier for the ongoing transfer.
    pub id: i64,
    /// The type of transfer.
    pub transfer_type: TransferType,
    /// The remote URL.
    pub remote: String,
    /// The local image name.
    pub local: String,
    /// The image class.
    pub class: ImageClass,
    /// Progress in percent (0.0 - 100.0).
    pub percent: f64,
}

impl TransferEntry {
    /// Validate the transfer entry fields.
    pub fn validate(&self) -> Result<(), i32> {
        if self.remote.is_empty() {
            return Err(-22);
        }
        if self.local.is_empty() {
            return Err(-22);
        }
        if self.percent < 0.0 || self.percent > 100.0 {
            return Err(-22);
        }
        Ok(())
    }

    /// Check if the transfer is complete (100%).
    pub fn is_complete(&self) -> bool {
        self.percent >= 100.0
    }
}

/// Parameters for the Pull method.
#[derive(Debug, Clone, Default)]
pub struct PullParams {
    /// The remote URL to download from.
    pub remote: Option<String>,
    /// The local image name to download to.
    pub local: Option<String>,
    /// The type of the resource.
    pub remote_type: Option<RemoteType>,
    /// The image class.
    pub class: Option<ImageClass>,
    /// How thoroughly to verify the download.
    pub verify: Option<ImageVerify>,
    /// If true, an existing image by the local name is deleted.
    pub force: Option<bool>,
    /// Whether to make the image read-only after downloading.
    pub read_only: Option<bool>,
    /// Whether to keep a pristine copy of the download.
    pub keep_download: Option<bool>,
    /// Root directory for images.
    pub image_root: Option<String>,
}

impl PullParams {
    /// Create a new empty PullParams.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate that required fields are present.
    pub fn validate(&self) -> Result<(), i32> {
        if self.remote.is_none() {
            return Err(-22);
        }
        if self.remote_type.is_none() {
            return Err(-22);
        }
        if self.class.is_none() {
            return Err(-22);
        }
        Ok(())
    }
}

// ── Interface definition ──────────────────────────────────────────────────

/// Returns the Varlink interface definition as a JSON string.
pub fn get_interface_definition() -> &'static str {
    r#"{
  "types": [
    {
      "name": "ImageClass",
      "type": "enum",
      "values": ["machine", "portable", "sysext", "confext"]
    },
    {
      "name": "RemoteType",
      "type": "enum",
      "values": ["raw", "tar"]
    },
    {
      "name": "TransferType",
      "type": "enum",
      "values": ["import_tar", "import_raw", "import_fs", "export_tar", "export_raw", "pull_tar", "pull_raw"]
    },
    {
      "name": "ImageVerify",
      "type": "enum",
      "values": ["no", "checksum", "signature"]
    },
    {
      "name": "LogMessage",
      "type": "struct",
      "fields": {
        "message": { "type": "string" },
        "priority": { "type": "int" }
      }
    }
  ],
  "methods": {
    "ListTransfers": {
      "parameters": {
        "class": { "type": "ImageClass", "nullable": true }
      },
      "return": {
        "id": { "type": "int" },
        "type": { "type": "TransferType" },
        "remote": { "type": "string" },
        "local": { "type": "string" },
        "class": { "type": "ImageClass" },
        "percent": { "type": "float" }
      },
      "flags": ["more"]
    },
    "Pull": {
      "parameters": {
        "remote": { "type": "string" },
        "local": { "type": "string", "nullable": true },
        "type": { "type": "RemoteType" },
        "class": { "type": "ImageClass" },
        "verify": { "type": "ImageVerify", "nullable": true },
        "force": { "type": "bool", "nullable": true },
        "readOnly": { "type": "bool", "nullable": true },
        "keepDownload": { "type": "bool", "nullable": true },
        "imageRoot": { "type": "string", "nullable": true }
      },
      "return": {
        "progress": { "type": "float", "nullable": true },
        "log": { "type": "LogMessage", "nullable": true },
        "id": { "type": "int", "nullable": true }
      },
      "flags": ["more"]
    }
  },
  "errors": {
    "AlreadyInProgress": {
      "description": "A transfer for the specified file is already ongoing.",
      "fields": { "remote": { "type": "string" } }
    },
    "TransferCancelled": {
      "description": "The transfer has been cancelled on user request."
    },
    "TransferFailed": {
      "description": "The transfer failed."
    },
    "NoTransfers": {
      "description": "No currently ongoing transfer."
    }
  },
  "interface": "io.systemd.Import",
  "description": "APIs for importing and transferring disk images."
}"#
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Check if a short method name belongs to this interface.
pub fn is_method(name: &str) -> bool {
    matches!(name, "ListTransfers" | "Pull")
}

/// Look up the fully qualified method name from a short name.
pub fn qualified_method(short: &str) -> Result<&'static str, i32> {
    match short {
        "ListTransfers" => Ok(METHOD_LIST_TRANSFERS),
        "Pull" => Ok(METHOD_PULL),
        _ => Err(-22),
    }
}

/// Check if a fully qualified error name belongs to this interface.
pub fn is_error(name: &str) -> bool {
    matches!(
        name,
        ERROR_ALREADY_IN_PROGRESS
            | ERROR_TRANSFER_CANCELLED
            | ERROR_TRANSFER_FAILED
            | ERROR_NO_TRANSFERS
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Import");
    }

    #[test]
    fn test_method_constants() {
        assert_eq!(METHOD_LIST_TRANSFERS, "io.systemd.Import.ListTransfers");
        assert_eq!(METHOD_PULL, "io.systemd.Import.Pull");
    }

    #[test]
    fn test_error_constants() {
        assert_eq!(
            ERROR_ALREADY_IN_PROGRESS,
            "io.systemd.Import.AlreadyInProgress"
        );
        assert_eq!(
            ERROR_TRANSFER_CANCELLED,
            "io.systemd.Import.TransferCancelled"
        );
        assert_eq!(ERROR_TRANSFER_FAILED, "io.systemd.Import.TransferFailed");
        assert_eq!(ERROR_NO_TRANSFERS, "io.systemd.Import.NoTransfers");
    }

    #[test]
    fn test_image_class_from_str() {
        assert_eq!(ImageClass::from_str("machine"), Ok(ImageClass::Machine));
        assert_eq!(ImageClass::from_str("portable"), Ok(ImageClass::Portable));
        assert_eq!(ImageClass::from_str("sysext"), Ok(ImageClass::Sysext));
        assert_eq!(ImageClass::from_str("confext"), Ok(ImageClass::Confext));
        assert!(ImageClass::from_str("invalid").is_err());
    }

    #[test]
    fn test_image_class_roundtrip() {
        for v in ImageClass::all_variants() {
            assert_eq!(ImageClass::from_str(v.as_str()), Ok(*v));
        }
    }

    #[test]
    fn test_remote_type_from_str() {
        assert_eq!(RemoteType::from_str("raw"), Ok(RemoteType::Raw));
        assert_eq!(RemoteType::from_str("tar"), Ok(RemoteType::Tar));
        assert!(RemoteType::from_str("zip").is_err());
    }

    #[test]
    fn test_transfer_type_from_str() {
        assert_eq!(
            TransferType::from_str("import_tar"),
            Ok(TransferType::ImportTar)
        );
        assert_eq!(
            TransferType::from_str("pull_raw"),
            Ok(TransferType::PullRaw)
        );
        assert!(TransferType::from_str("invalid").is_err());
    }

    #[test]
    fn test_transfer_type_categories() {
        assert!(TransferType::ImportTar.is_import());
        assert!(TransferType::ImportRaw.is_import());
        assert!(TransferType::ImportFs.is_import());
        assert!(!TransferType::PullTar.is_import());

        assert!(TransferType::ExportTar.is_export());
        assert!(TransferType::ExportRaw.is_export());
        assert!(!TransferType::ImportTar.is_export());

        assert!(TransferType::PullTar.is_pull());
        assert!(TransferType::PullRaw.is_pull());
        assert!(!TransferType::ImportTar.is_pull());
    }

    #[test]
    fn test_image_verify_from_str() {
        assert_eq!(ImageVerify::from_str("no"), Ok(ImageVerify::No));
        assert_eq!(ImageVerify::from_str("checksum"), Ok(ImageVerify::Checksum));
        assert_eq!(
            ImageVerify::from_str("signature"),
            Ok(ImageVerify::Signature)
        );
        assert!(ImageVerify::from_str("full").is_err());
    }

    #[test]
    fn test_log_message_new() {
        let msg = LogMessage::new("download complete", 6);
        assert_eq!(msg.message, "download complete");
        assert_eq!(msg.priority, 6);
    }

    #[test]
    fn test_log_message_validate() {
        let valid = LogMessage::new("ok", 3);
        assert!(valid.validate().is_ok());

        let invalid_high = LogMessage::new("bad", 8);
        assert!(invalid_high.validate().is_err());

        let invalid_neg = LogMessage::new("bad", -1);
        assert!(invalid_neg.validate().is_err());

        let boundary_0 = LogMessage::new("ok", 0);
        assert!(boundary_0.validate().is_ok());

        let boundary_7 = LogMessage::new("ok", 7);
        assert!(boundary_7.validate().is_ok());
    }

    #[test]
    fn test_transfer_entry_validate() {
        let entry = TransferEntry {
            id: 1,
            transfer_type: TransferType::PullTar,
            remote: "https://example.com/image.tar".into(),
            local: "myimage".into(),
            class: ImageClass::Machine,
            percent: 50.0,
        };
        assert!(entry.validate().is_ok());
        assert!(!entry.is_complete());
    }

    #[test]
    fn test_transfer_entry_complete() {
        let entry = TransferEntry {
            id: 2,
            transfer_type: TransferType::PullRaw,
            remote: "https://example.com/image.raw".into(),
            local: "myimage".into(),
            class: ImageClass::Sysext,
            percent: 100.0,
        };
        assert!(entry.is_complete());
    }

    #[test]
    fn test_transfer_entry_invalid_percent() {
        let entry = TransferEntry {
            id: 3,
            transfer_type: TransferType::ImportTar,
            remote: "url".into(),
            local: "name".into(),
            class: ImageClass::Machine,
            percent: 150.0,
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_transfer_entry_empty_remote() {
        let entry = TransferEntry {
            id: 4,
            transfer_type: TransferType::ImportTar,
            remote: String::new(),
            local: "name".into(),
            class: ImageClass::Machine,
            percent: 50.0,
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_pull_params_validate() {
        let mut p = PullParams::new();
        assert!(p.validate().is_err()); // missing required

        p.remote = Some("https://example.com/image.tar".into());
        assert!(p.validate().is_err()); // still missing type and class

        p.remote_type = Some(RemoteType::Tar);
        assert!(p.validate().is_err()); // still missing class

        p.class = Some(ImageClass::Machine);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_is_method() {
        assert!(is_method("ListTransfers"));
        assert!(is_method("Pull"));
        assert!(!is_method("Push"));
    }

    #[test]
    fn test_qualified_method() {
        assert_eq!(qualified_method("ListTransfers"), Ok(METHOD_LIST_TRANSFERS));
        assert_eq!(qualified_method("Pull"), Ok(METHOD_PULL));
        assert!(qualified_method("Push").is_err());
    }

    #[test]
    fn test_is_error() {
        assert!(is_error(ERROR_ALREADY_IN_PROGRESS));
        assert!(is_error(ERROR_TRANSFER_CANCELLED));
        assert!(is_error(ERROR_TRANSFER_FAILED));
        assert!(is_error(ERROR_NO_TRANSFERS));
        assert!(!is_error("io.systemd.Import.Unknown"));
    }

    #[test]
    fn test_interface_definition_contents() {
        let def = get_interface_definition();
        assert!(def.contains("io.systemd.Import"));
        assert!(def.contains("ListTransfers"));
        assert!(def.contains("Pull"));
        assert!(def.contains("ImageClass"));
        assert!(def.contains("RemoteType"));
        assert!(def.contains("TransferType"));
        assert!(def.contains("ImageVerify"));
        assert!(def.contains("LogMessage"));
        assert!(def.contains("AlreadyInProgress"));
    }
}
