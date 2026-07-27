// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/discover-image.c, src/shared/discover-image.h
//
// Image discovery, management, and search path resolution.
//
// Handles finding system images (machines, portables, sysexts, confexts)
// in their configured search paths, as well as image lifecycle operations
// such as rename, clone, and read-only toggling.

// ── Constants ─────────────────────────────────────────────────────────────

/// Auxiliary file suffixes associated with images.
pub const AUXILIARY_SUFFIXES: &[&str] = &[
    ".nspawn",
    ".oci-config",
    ".roothash",
    ".roothash.p7s",
    ".usrhash",
    ".usrhash.p7s",
    ".verity",
    ".raw.tpmstate",
    ".raw.efinvramstate",
];

/// Valid characters for image names.
pub const IMAGE_NAME_VALID_CHARS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@:";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Types of images that systemd can manage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageType {
    /// A plain directory tree.
    Directory,
    /// A btrfs subvolume.
    Subvolume,
    /// A raw disk image file (.raw).
    Raw,
    /// A block device.
    Block,
    /// A directory-based mstack image (.mstack).
    Mstack,
}

impl ImageType {
    /// Convert to a static string representation.
    pub const fn to_str(self) -> &'static str {
        match self {
            ImageType::Directory => "directory",
            ImageType::Subvolume => "subvolume",
            ImageType::Raw => "raw",
            ImageType::Block => "block",
            ImageType::Mstack => "mstack",
        }
    }
}

impl std::fmt::Display for ImageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}

/// Classes of images, determining search paths and policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageClass {
    /// Container or VM machine images.
    Machine,
    /// Portable service images.
    Portable,
    /// System extension images.
    Sysext,
    /// Configuration extension images.
    Confext,
}

impl ImageClass {
    /// Convert to a static string representation.
    pub const fn to_str(self) -> &'static str {
        match self {
            ImageClass::Machine => "machine",
            ImageClass::Portable => "portable",
            ImageClass::Sysext => "sysext",
            ImageClass::Confext => "confext",
        }
    }

    /// Return the class suffix (e.g. ".sysext"), if any.
    pub const fn class_suffix(self) -> Option<&'static str> {
        match self {
            ImageClass::Sysext => Some(".sysext"),
            ImageClass::Confext => Some(".confext"),
            _ => None,
        }
    }

    /// Return the directory name for this image class.
    pub const fn dirname(self) -> &'static str {
        match self {
            ImageClass::Machine => "machines",
            ImageClass::Portable => "portables",
            ImageClass::Sysext => "extensions",
            ImageClass::Confext => "confexts",
        }
    }

    /// Return the persistent image root directory.
    pub const fn root(self) -> &'static str {
        match self {
            ImageClass::Machine => "/var/lib/machines",
            ImageClass::Portable => "/var/lib/portables",
            ImageClass::Sysext => "/var/lib/extensions",
            ImageClass::Confext => "/var/lib/confexts",
        }
    }

    /// Return the runtime image root directory.
    pub const fn root_runtime(self) -> &'static str {
        match self {
            ImageClass::Machine => "/run/machines",
            ImageClass::Portable => "/run/portables",
            ImageClass::Sysext => "/run/extensions",
            ImageClass::Confext => "/run/confexts",
        }
    }

    /// Return the standard search paths for this image class.
    pub fn search_paths(&self) -> Vec<&'static str> {
        match self {
            ImageClass::Machine => vec![
                "/etc/machines",
                "/run/machines",
                "/var/lib/machines",
                "/var/lib/container",
                "/usr/local/lib/machines",
                "/usr/lib/machines",
            ],
            ImageClass::Portable => vec![
                "/etc/portables",
                "/run/portables",
                "/var/lib/portables",
                "/usr/local/lib/portables",
                "/usr/lib/portables",
            ],
            ImageClass::Sysext => vec!["/etc/extensions", "/run/extensions", "/var/lib/extensions"],
            ImageClass::Confext => vec![
                "/run/confexts",
                "/var/lib/confexts",
                "/usr/local/lib/confexts",
                "/usr/lib/confexts",
            ],
        }
    }

    /// Return the initrd-specific search paths (differs only for sysext/confext).
    pub fn search_paths_initrd(&self) -> Vec<&'static str> {
        match self {
            ImageClass::Machine | ImageClass::Portable => self.search_paths(),
            ImageClass::Sysext => vec![
                "/etc/extensions",
                "/run/extensions",
                "/var/lib/extensions",
                "/.extra/sysext",
                "/.extra/global_sysext",
            ],
            ImageClass::Confext => vec![
                "/run/confexts",
                "/var/lib/confexts",
                "/usr/local/lib/confexts",
                "/.extra/confext",
                "/.extra/global_confext",
            ],
        }
    }
}

/// Error type for image operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageError {
    /// Image not found.
    NotFound(String),
    /// Invalid image path.
    InvalidPath(String),
    /// Image is read-only.
    ReadOnly,
    /// I/O error.
    Io(String),
    /// Invalid image name.
    InvalidName(String),
    /// Image already exists (for clone/rename).
    AlreadyExists(String),
    /// Operation not supported for this image type.
    NotSupported,
    /// Medium type not recognized.
    MediumType,
}

impl std::fmt::Display for ImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageError::NotFound(name) => write!(f, "Image not found: {name}"),
            ImageError::InvalidPath(path) => write!(f, "Invalid image path: {path}"),
            ImageError::ReadOnly => write!(f, "Image is read-only"),
            ImageError::Io(msg) => write!(f, "I/O error: {msg}"),
            ImageError::InvalidName(name) => write!(f, "Invalid image name: {name}"),
            ImageError::AlreadyExists(name) => write!(f, "Image already exists: {name}"),
            ImageError::NotSupported => write!(f, "Operation not supported"),
            ImageError::MediumType => write!(f, "Unrecognized image format"),
        }
    }
}

impl std::error::Error for ImageError {}

// ── Image struct ──────────────────────────────────────────────────────────

/// A discovered or constructed system image.
#[derive(Debug, Clone)]
pub struct Image {
    /// Short name of the image (without format suffixes).
    pub name: String,
    /// Absolute path to the image on disk.
    pub path: std::path::PathBuf,
    /// The type of image (directory, subvolume, raw, block, mstack).
    pub image_type: ImageType,
    /// The image class (machine, portable, sysext, confext).
    pub class: ImageClass,
    /// Whether the image is marked read-only.
    pub read_only: bool,
    /// Creation time of the image (microseconds since epoch, if known).
    pub crtime: Option<u64>,
    /// Modification time of the image (microseconds since epoch, if known).
    pub mtime: Option<u64>,
    /// Disk usage in bytes (None = unknown).
    pub usage: Option<u64>,
    /// Exclusive disk usage in bytes (None = unknown).
    pub usage_exclusive: Option<u64>,
    /// Disk quota limit in bytes (None = unlimited).
    pub limit: Option<u64>,
    /// Exclusive disk quota limit in bytes (None = unlimited).
    pub limit_exclusive: Option<u64>,
    /// Hostname read from the image's /etc/hostname.
    pub hostname: Option<String>,
    /// Machine ID read from the image.
    pub machine_id: Option<[u8; 16]>,
    /// Machine info key-value pairs from /etc/machine-info.
    pub machine_info: Vec<(String, String)>,
    /// OS release key-value pairs from /etc/os-release.
    pub os_release: Vec<(String, String)>,
    /// Whether metadata has been successfully read.
    pub metadata_valid: bool,
    /// Whether the image was found via search path discovery.
    pub discoverable: bool,
    /// Whether the image is owned by a foreign UID range.
    pub foreign_uid_owned: bool,
}

impl Image {
    /// Create a new image with the given essential fields.
    pub fn new(
        name: impl Into<String>,
        path: impl Into<std::path::PathBuf>,
        image_type: ImageType,
        class: ImageClass,
    ) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            image_type,
            class,
            read_only: false,
            crtime: None,
            mtime: None,
            usage: None,
            usage_exclusive: None,
            limit: None,
            limit_exclusive: None,
            hostname: None,
            machine_id: None,
            machine_info: Vec::new(),
            os_release: Vec::new(),
            metadata_valid: false,
            discoverable: false,
            foreign_uid_owned: false,
        }
    }

    /// Builder: set read-only flag.
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Check if the image name starts with '.' (hidden).
    pub fn is_hidden(&self) -> bool {
        self.name.starts_with('.')
    }

    /// Check if the image is effectively read-only.
    ///
    /// Hidden images are always considered read-only, regardless of the
    /// `read_only` flag. This matches the C implementation's policy.
    pub fn is_read_only(&self) -> bool {
        self.is_hidden() || self.read_only
    }

    /// Check if this image lives under /usr (vendor-supplied).
    pub fn is_vendor(&self) -> bool {
        self.path.to_str().is_some_and(|p| p.starts_with("/usr"))
    }

    /// Check if this image represents the host root filesystem.
    pub fn is_host(&self) -> bool {
        self.name == ".host" || self.path.to_str().is_some_and(|p| p == "/")
    }

    /// Generate the path to an auxiliary file for this image.
    pub fn auxiliary_path(&self, suffix: &str) -> Option<std::path::PathBuf> {
        let dir = self.path.parent()?;
        let filename = format!("{}{suffix}", self.name);
        Some(dir.join(filename))
    }

    /// Simplify the stored path (remove trailing slashes, redundant components).
    pub fn simplify_path(&mut self) {
        let simplified = path_simplify(self.path.to_str().unwrap_or(""));
        self.path = std::path::PathBuf::from(simplified);
    }
}

// ── Path utilities ────────────────────────────────────────────────────────

/// Remove redundant path components (trailing slashes, repeated slashes).
fn path_simplify(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    let mut last_was_slash = false;

    for ch in path.chars() {
        if ch == '/' {
            if !last_was_slash {
                result.push(ch);
            }
            last_was_slash = true;
        } else {
            result.push(ch);
            last_was_slash = false;
        }
    }

    // Remove trailing slash (but keep "/" itself)
    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }

    result
}

/// Check if a string is a valid image name.
///
/// Valid image names consist of alphanumeric characters, hyphens, underscores,
/// dots, at-signs, and colons, and must not be empty.
pub fn image_name_is_valid(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    name.bytes().all(|b| IMAGE_NAME_VALID_CHARS.contains(&b))
}

/// Extract the image basename from a path, stripping optional class suffix
/// and format suffixes.
///
/// Returns `(basename, suffix)` on success.
pub fn extract_image_basename(
    path: &str,
    class_suffix: Option<&str>,
    format_suffixes: &[&str],
) -> Result<(String, String), ImageError> {
    let filename = std::path::Path::new(path)
        .file_name()
        .ok_or_else(|| ImageError::InvalidPath(path.to_string()))?
        .to_str()
        .ok_or_else(|| ImageError::InvalidPath(path.to_string()))?;

    let mut name = filename.to_string();
    let mut suffix = String::new();

    // Strip format suffix (required if format_suffixes is non-empty)
    if !format_suffixes.is_empty() {
        let matched = format_suffixes
            .iter()
            .find(|s| name.ends_with(*s))
            .ok_or(ImageError::MediumType)?;

        suffix = matched.to_string();
        let new_len = name.len() - matched.len();
        name.truncate(new_len);
    }

    // Strip class suffix (optional)
    if let Some(cs) = class_suffix {
        if let Some(rest) = name.strip_suffix(cs) {
            suffix = format!("{cs}{suffix}");
            name = rest.to_string();
        }
    }

    if !image_name_is_valid(&name) {
        return Err(ImageError::InvalidName(name));
    }

    Ok((name, suffix))
}

// ── Search path utilities ─────────────────────────────────────────────────

/// Generate the list of possible filenames for a given image name and class.
///
/// For a name like "foo" with class Sysext, this produces:
/// `["foo.sysext", "foo.sysext.raw", "foo.sysext.mstack", "foo.sysext.v",
///   "foo", "foo.raw", "foo.mstack", "foo.v", ...]`
pub fn make_possible_filenames(class: ImageClass, image_name: &str) -> Vec<String> {
    let class_suffix = class.class_suffix();
    let version_suffixes = ["", ".v"];
    let format_suffixes = ["", ".raw", ".mstack"];
    let mut result = Vec::with_capacity(16);

    for v_suffix in version_suffixes {
        for format_suffix in format_suffixes {
            // With class suffix
            if let Some(cs) = class_suffix {
                result.push(format!("{image_name}{cs}{format_suffix}{v_suffix}"));
            }
            // Without class suffix
            result.push(format!("{image_name}{format_suffix}{v_suffix}"));
        }
    }

    result
}

/// Check if a path is within any of the search paths for the given class.
pub fn image_in_search_path(path: &str, class: ImageClass) -> bool {
    let search_paths = class.search_paths();
    for sp in &search_paths {
        if let Some(rest) = path.strip_prefix(sp) {
            let rest = rest.trim_start_matches('/');
            // Must have at least one path component after the search path
            let without_slashes: String = rest.chars().take_while(|&c| c != '/').collect();
            if !without_slashes.is_empty() {
                // The rest must be a single filename (possibly with trailing slash)
                let remaining = &rest[without_slashes.len()..];
                if remaining.chars().all(|c| c == '/') {
                    return true;
                }
            }
        }
    }
    false
}

// ── Image name validation edge cases ──────────────────────────────────────

/// Check if an image name should be rejected for clone/rename operations.
pub fn image_name_reject_for_clone(name: &str) -> bool {
    name == ".host" || !image_name_is_valid(name)
}

// ── Auxiliary file utilities ──────────────────────────────────────────────

/// Generate auxiliary file paths for an image given its base name and path.
pub fn auxiliary_file_paths(name: &str, path: &str) -> Vec<String> {
    let dir = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_str().unwrap_or(""))
        .unwrap_or("");

    AUXILIARY_SUFFIXES
        .iter()
        .map(|suffix| {
            let filename = format!("{name}{suffix}");
            std::path::Path::new(dir)
                .join(&filename)
                .to_str()
                .unwrap_or("")
                .to_string()
        })
        .collect()
}

// ── Image construction helpers ────────────────────────────────────────────

/// Determine if a directory entry represents a recognized image format.
///
/// Returns `Some(ImageType)` if the filename matches a known pattern, `None` otherwise.
pub fn classify_image_by_filename(
    filename: &str,
    class: ImageClass,
) -> Result<Option<ImageType>, ImageError> {
    if filename.starts_with('.') {
        return Ok(None);
    }

    // .raw files are regular file images
    if filename.ends_with(".raw") {
        let (name, _suffix) = extract_image_basename(filename, class.class_suffix(), &[".raw"])?;
        if image_name_is_valid(&name) {
            return Ok(Some(ImageType::Raw));
        }
        return Err(ImageError::InvalidName(filename.to_string()));
    }

    // .mstack directories
    if filename.ends_with(".mstack") {
        let (name, _suffix) = extract_image_basename(filename, class.class_suffix(), &[".mstack"])?;
        if image_name_is_valid(&name) {
            return Ok(Some(ImageType::Mstack));
        }
        return Err(ImageError::InvalidName(filename.to_string()));
    }

    // .v versioned directories — these need special pick logic
    if filename.ends_with(".v") {
        // Strip the .v suffix for basename extraction
        let without_v = &filename[..filename.len() - 2];
        let (name, _suffix) =
            extract_image_basename(without_v, class.class_suffix(), &[".raw", ".mstack", ""])?;
        if image_name_is_valid(&name) {
            return Ok(Some(ImageType::Directory));
        }
        return Err(ImageError::InvalidName(filename.to_string()));
    }

    // Plain directories without format suffix
    let (name, _suffix) = extract_image_basename(filename, class.class_suffix(), &[""])?;
    if image_name_is_valid(&name) {
        return Ok(Some(ImageType::Directory));
    }

    Ok(None)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_type_to_str() {
        assert_eq!(ImageType::Directory.to_str(), "directory");
        assert_eq!(ImageType::Subvolume.to_str(), "subvolume");
        assert_eq!(ImageType::Raw.to_str(), "raw");
        assert_eq!(ImageType::Block.to_str(), "block");
        assert_eq!(ImageType::Mstack.to_str(), "mstack");
    }

    #[test]
    fn test_image_class_to_str() {
        assert_eq!(ImageClass::Machine.to_str(), "machine");
        assert_eq!(ImageClass::Portable.to_str(), "portable");
        assert_eq!(ImageClass::Sysext.to_str(), "sysext");
        assert_eq!(ImageClass::Confext.to_str(), "confext");
    }

    #[test]
    fn test_image_class_suffix() {
        assert_eq!(ImageClass::Machine.class_suffix(), None);
        assert_eq!(ImageClass::Portable.class_suffix(), None);
        assert_eq!(ImageClass::Sysext.class_suffix(), Some(".sysext"));
        assert_eq!(ImageClass::Confext.class_suffix(), Some(".confext"));
    }

    #[test]
    fn test_image_class_dirname() {
        assert_eq!(ImageClass::Machine.dirname(), "machines");
        assert_eq!(ImageClass::Portable.dirname(), "portables");
        assert_eq!(ImageClass::Sysext.dirname(), "extensions");
        assert_eq!(ImageClass::Confext.dirname(), "confexts");
    }

    #[test]
    fn test_image_class_root() {
        assert_eq!(ImageClass::Machine.root(), "/var/lib/machines");
        assert_eq!(ImageClass::Portable.root(), "/var/lib/portables");
        assert_eq!(ImageClass::Sysext.root(), "/var/lib/extensions");
        assert_eq!(ImageClass::Confext.root(), "/var/lib/confexts");
    }

    #[test]
    fn test_image_class_root_runtime() {
        assert_eq!(ImageClass::Machine.root_runtime(), "/run/machines");
        assert_eq!(ImageClass::Portable.root_runtime(), "/run/portables");
        assert_eq!(ImageClass::Sysext.root_runtime(), "/run/extensions");
        assert_eq!(ImageClass::Confext.root_runtime(), "/run/confexts");
    }

    #[test]
    fn test_search_paths_machine() {
        let paths = ImageClass::Machine.search_paths();
        assert_eq!(paths.len(), 6);
        assert_eq!(paths[0], "/etc/machines");
        assert_eq!(paths[1], "/run/machines");
        assert_eq!(paths[2], "/var/lib/machines");
        assert!(paths.contains(&"/var/lib/container"));
    }

    #[test]
    fn test_search_paths_sysext() {
        let paths = ImageClass::Sysext.search_paths();
        assert_eq!(paths.len(), 3);
        assert!(paths.contains(&"/etc/extensions"));
        // No /usr paths for sysext (recursive overlay risk)
        assert!(!paths.iter().any(|p| p.starts_with("/usr")));
    }

    #[test]
    fn test_search_paths_initrd_sysext() {
        let paths = ImageClass::Sysext.search_paths_initrd();
        assert!(paths.contains(&"/.extra/sysext"));
        assert!(paths.contains(&"/.extra/global_sysext"));
        assert!(paths.len() == 5);
    }

    #[test]
    fn test_search_paths_initrd_confext() {
        let paths = ImageClass::Confext.search_paths_initrd();
        assert!(paths.contains(&"/.extra/confext"));
        assert!(paths.contains(&"/.extra/global_confext"));
        assert!(!paths.iter().any(|p| *p == "/usr/lib/confexts"));
    }

    #[test]
    fn test_image_name_is_valid() {
        assert!(image_name_is_valid("myimage"));
        assert!(image_name_is_valid("my-image_v2"));
        assert!(image_name_is_valid("my.image"));
        assert!(image_name_is_valid("my@image:tag"));
        assert!(!image_name_is_valid(""));
        assert!(!image_name_is_valid("my image")); // space invalid
        assert!(!image_name_is_valid("my/image")); // slash invalid
        assert!(!image_name_is_valid(&"x".repeat(256))); // too long
    }

    #[test]
    fn test_extract_basename_raw() {
        let (name, suffix) =
            extract_image_basename("/var/lib/machines/test.raw", None, &[".raw"]).unwrap();
        assert_eq!(name, "test");
        assert_eq!(suffix, ".raw");
    }

    #[test]
    fn test_extract_basename_with_class_suffix() {
        let (name, suffix) = extract_image_basename(
            "/var/lib/extensions/foo.sysext.raw",
            Some(".sysext"),
            &[".raw"],
        )
        .unwrap();
        assert_eq!(name, "foo");
        assert_eq!(suffix, ".sysext.raw");
    }

    #[test]
    fn test_extract_basename_no_format_suffix() {
        let (name, suffix) = extract_image_basename("/var/lib/machines/mydir", None, &[]).unwrap();
        assert_eq!(name, "mydir");
        assert_eq!(suffix, "");
    }

    #[test]
    fn test_extract_basename_invalid() {
        let result = extract_image_basename("/var/lib/machines/!bad.raw", None, &[".raw"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_make_possible_filenames() {
        let names = make_possible_filenames(ImageClass::Machine, "test");
        assert!(names.contains(&"test".to_string()));
        assert!(names.contains(&"test.raw".to_string()));
        assert!(names.contains(&"test.mstack".to_string()));
        assert!(names.contains(&"test.v".to_string()));
        assert!(names.contains(&"test.raw.v".to_string()));
    }

    #[test]
    fn test_make_possible_filenames_with_class_suffix() {
        let names = make_possible_filenames(ImageClass::Sysext, "ext");
        assert!(names.contains(&"ext.sysext".to_string()));
        assert!(names.contains(&"ext.sysext.raw".to_string()));
        assert!(names.contains(&"ext".to_string()));
        assert!(names.contains(&"ext.raw".to_string()));
    }

    #[test]
    fn test_image_hidden() {
        let img = Image::new(
            ".hidden",
            "/var/lib/machines/.hidden",
            ImageType::Directory,
            ImageClass::Machine,
        );
        assert!(img.is_hidden());
        assert!(img.is_read_only());

        let img = Image::new(
            "visible",
            "/var/lib/machines/visible",
            ImageType::Directory,
            ImageClass::Machine,
        );
        assert!(!img.is_hidden());
        assert!(!img.is_read_only());
    }

    #[test]
    fn test_image_vendor() {
        let img = Image::new(
            "vendor",
            "/usr/lib/machines/vendor",
            ImageType::Directory,
            ImageClass::Machine,
        );
        assert!(img.is_vendor());

        let img = Image::new(
            "local",
            "/var/lib/machines/local",
            ImageType::Directory,
            ImageClass::Machine,
        );
        assert!(!img.is_vendor());
    }

    #[test]
    fn test_image_host() {
        let img = Image::new(".host", "/", ImageType::Directory, ImageClass::Machine);
        assert!(img.is_host());

        let img = Image::new(
            "other",
            "/var/lib/machines/other",
            ImageType::Directory,
            ImageClass::Machine,
        );
        assert!(!img.is_host());

        let img = Image::new("slash", "/", ImageType::Directory, ImageClass::Machine);
        assert!(img.is_host());
    }

    #[test]
    fn test_auxiliary_path() {
        let img = Image::new(
            "myimage",
            "/var/lib/machines/myimage.raw",
            ImageType::Raw,
            ImageClass::Machine,
        );
        assert_eq!(
            img.auxiliary_path(".nspawn"),
            Some(std::path::PathBuf::from("/var/lib/machines/myimage.nspawn"))
        );
        assert_eq!(
            img.auxiliary_path(".roothash"),
            Some(std::path::PathBuf::from(
                "/var/lib/machines/myimage.roothash"
            ))
        );
    }

    #[test]
    fn test_auxiliary_file_paths() {
        let paths = auxiliary_file_paths("test", "/var/lib/machines/test.raw");
        assert!(paths.contains(&"/var/lib/machines/test.nspawn".to_string()));
        assert!(paths.contains(&"/var/lib/machines/test.roothash".to_string()));
        assert!(paths.contains(&"/var/lib/machines/test.verity".to_string()));
        assert_eq!(paths.len(), AUXILIARY_SUFFIXES.len());
    }

    #[test]
    fn test_image_in_search_path() {
        assert!(image_in_search_path(
            "/var/lib/machines/myimage",
            ImageClass::Machine
        ));
        assert!(image_in_search_path(
            "/var/lib/machines/myimage/",
            ImageClass::Machine
        ));
        assert!(!image_in_search_path(
            "/var/lib/machines",
            ImageClass::Machine
        ));
        assert!(!image_in_search_path(
            "/tmp/machines/myimage",
            ImageClass::Machine
        ));
    }

    #[test]
    fn test_classify_image_by_filename_raw() {
        assert_eq!(
            classify_image_by_filename("test.raw", ImageClass::Machine).unwrap(),
            Some(ImageType::Raw)
        );
        assert_eq!(
            classify_image_by_filename("test.sysext.raw", ImageClass::Sysext).unwrap(),
            Some(ImageType::Raw)
        );
    }

    #[test]
    fn test_classify_image_by_filename_mstack() {
        assert_eq!(
            classify_image_by_filename("test.mstack", ImageClass::Machine).unwrap(),
            Some(ImageType::Mstack)
        );
    }

    #[test]
    fn test_classify_image_by_filename_directory() {
        assert_eq!(
            classify_image_by_filename("test", ImageClass::Machine).unwrap(),
            Some(ImageType::Directory)
        );
    }

    #[test]
    fn test_classify_image_by_filename_hidden() {
        assert_eq!(
            classify_image_by_filename(".hidden", ImageClass::Machine).unwrap(),
            None
        );
    }

    #[test]
    fn test_path_simplify() {
        assert_eq!(path_simplify("/var/lib/machines/"), "/var/lib/machines");
        assert_eq!(path_simplify("/var//lib///machines"), "/var/lib/machines");
        assert_eq!(path_simplify("/"), "/");
        assert_eq!(path_simplify("/var/lib/machines"), "/var/lib/machines");
    }

    #[test]
    fn test_image_simplify_path() {
        let mut img = Image::new(
            "test",
            "/var/lib//machines//test/",
            ImageType::Directory,
            ImageClass::Machine,
        );
        img.simplify_path();
        assert_eq!(img.path.to_str().unwrap(), "/var/lib/machines/test");
    }

    #[test]
    fn test_image_error_display() {
        assert_eq!(
            ImageError::NotFound("foo".to_string()).to_string(),
            "Image not found: foo"
        );
        assert_eq!(ImageError::ReadOnly.to_string(), "Image is read-only");
        assert_eq!(
            ImageError::NotSupported.to_string(),
            "Operation not supported"
        );
    }

    #[test]
    fn test_image_name_reject_for_clone() {
        assert!(image_name_reject_for_clone(".host"));
        assert!(image_name_reject_for_clone(""));
        assert!(image_name_reject_for_clone("bad name"));
        assert!(!image_name_reject_for_clone("valid-name"));
    }

    #[test]
    fn test_auxiliary_suffixes_count() {
        // Verify all known auxiliary suffixes are present
        assert_eq!(AUXILIARY_SUFFIXES.len(), 9);
        assert!(AUXILIARY_SUFFIXES.contains(&".nspawn"));
        assert!(AUXILIARY_SUFFIXES.contains(&".roothash"));
        assert!(AUXILIARY_SUFFIXES.contains(&".verity"));
    }
}
