// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/binfmt/binfmt.c
//
// Register binary formats with the kernel.

use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    fs, io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

/// Path to the binfmt_misc register file.
pub const BINFMT_REGISTER_PATH: &str = "/proc/sys/fs/binfmt_misc/register";
/// Path to the binfmt_misc status file (used for flushing and unregistering).
pub const BINFMT_STATUS_PATH: &str = "/proc/sys/fs/binfmt_misc/status";
/// Base path for individual binfmt rules.
pub const BINFMT_MISC_PATH: &str = "/proc/sys/fs/binfmt_misc";
/// Characters that indicate a comment line.
pub const COMMENT_CHARS: &[char] = &['#', ';'];
/// Reserved rule names that are not allowed.
pub const RESERVED_NAMES: &[&str] = &["register", "status"];

/// Configuration file display mode (mirrors CatFlags from C).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CatConfigMode {
    /// No cat-config display.
    #[default]
    Off,
    /// Show configuration files.
    On,
    /// Show TLDR (brief) configuration.
    Tldr,
}

/// Parsed command-line arguments for `systemd-binfmt`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BinfmtArgs {
    /// Whether to unregister all existing entries.
    pub unregister: bool,
    /// Cat-config display mode.
    pub cat_flags: CatConfigMode,
    /// Configuration files to apply.
    pub config_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseBinfmtError {
    HelpRequested,
    VersionRequested,
    InvalidArguments,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRuleName;

impl std::fmt::Display for InvalidRuleName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid binfmt rule name")
    }
}

impl std::error::Error for InvalidRuleName {}

/// Parse UTF-8 command-line arguments, primarily for callers and unit tests.
pub fn parse_binfmt_args(args: &[&str]) -> Result<BinfmtArgs, ParseBinfmtError> {
    parse_binfmt_os_args(
        &args
            .iter()
            .map(|arg| OsString::from(*arg))
            .collect::<Vec<OsString>>(),
    )
}

/// Parse command-line arguments without requiring configuration paths to be
/// UTF-8. The kernel and the C implementation both treat paths as byte strings.
pub fn parse_binfmt_os_args(args: &[OsString]) -> Result<BinfmtArgs, ParseBinfmtError> {
    let mut result = BinfmtArgs::default();
    let mut positional_only = false;

    for arg in args {
        let bytes = arg.as_os_str().as_bytes();
        if positional_only {
            result.config_files.push(PathBuf::from(arg.as_os_str()));
            continue;
        }

        match bytes {
            b"--" => positional_only = true,
            b"--unregister" => result.unregister = true,
            b"--cat-config" => result.cat_flags = CatConfigMode::On,
            b"--tldr" => result.cat_flags = CatConfigMode::Tldr,
            b"--no-pager" => {}
            b"--help" | b"-h" => return Err(ParseBinfmtError::HelpRequested),
            b"--version" => return Err(ParseBinfmtError::VersionRequested),
            value if value.starts_with(b"-") => return Err(ParseBinfmtError::InvalidArguments),
            _ => result.config_files.push(PathBuf::from(arg.as_os_str())),
        }
    }

    if (result.unregister || result.cat_flags != CatConfigMode::Off)
        && !result.config_files.is_empty()
    {
        return Err(ParseBinfmtError::InvalidArguments);
    }

    Ok(result)
}

/// Extract and validate the rule name from a binfmt rule.
pub fn extract_rule_name(rule: &str) -> Result<String, InvalidRuleName> {
    let name = extract_rule_name_bytes(rule.as_bytes())?;
    String::from_utf8(name.to_vec()).map_err(|_| InvalidRuleName)
}

/// Extract and validate a rule name using the kernel protocol's byte
/// delimiter. Configuration files need not be UTF-8.
pub fn extract_rule_name_bytes(rule: &[u8]) -> Result<&[u8], InvalidRuleName> {
    let (&delimiter, rest) = rule.split_first().ok_or(InvalidRuleName)?;
    let name_end = rest
        .iter()
        .position(|byte| *byte == delimiter)
        .unwrap_or(rest.len());
    let name = &rest[..name_end];

    if !is_valid_rule_name_bytes(name) {
        return Err(InvalidRuleName);
    }

    Ok(name)
}

/// Check if a rule name is valid (non-empty, valid filename, not reserved).
pub fn is_valid_rule_name(name: &str) -> bool {
    is_valid_rule_name_bytes(name.as_bytes())
}

fn is_valid_rule_name_bytes(name: &[u8]) -> bool {
    !name.is_empty()
        && !RESERVED_NAMES
            .iter()
            .any(|reserved| name == reserved.as_bytes())
        && !name.contains(&b'/')
        && !name.contains(&0)
        && name != b"."
        && name != b".."
        && name.len() <= 255 // Linux NAME_MAX, matching filename_is_valid().
}

/// Check if a line is a comment or empty (should be skipped).
pub fn is_comment_or_empty(line: &str) -> bool {
    is_comment_or_empty_bytes(line.as_bytes())
}

/// Build the path for deleting a specific binfmt rule.
pub fn rule_delete_path(name: &str) -> PathBuf {
    rule_delete_path_bytes(name.as_bytes())
}

fn rule_delete_path_bytes(name: &[u8]) -> PathBuf {
    Path::new(BINFMT_MISC_PATH).join(OsStr::from_bytes(name))
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

pub fn is_comment_or_empty_bytes(line: &[u8]) -> bool {
    let trimmed = trim_ascii_whitespace(line);
    trimmed.is_empty() || matches!(trimmed.first(), Some(b'#' | b';'))
}

/// Return binfmt.d directories in the same priority order as CONF_PATHS_STRV.
///
/// The first directory wins for a file basename.
pub fn conf_paths() -> Vec<PathBuf> {
    ["/etc", "/run", "/usr/local/lib", "/usr/lib"]
        .into_iter()
        .map(|prefix| Path::new(prefix).join("binfmt.d"))
        .collect()
}

fn is_masked(path: &Path) -> bool {
    fs::read_link(path)
        .map(|target| target == Path::new("/dev/null"))
        .unwrap_or(false)
}

fn is_conf_file(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.as_bytes().ends_with(b".conf"))
}

/// Select the effective binfmt.d configuration files.
///
/// Directories are considered from highest to lowest priority. A basename
/// encountered in a higher-priority directory masks all lower-priority copies;
/// a `/dev/null` symlink masks that basename without producing a file. The
/// resulting effective files are sorted by basename just like `conf_files_list`.
pub fn config_files_from_dirs(dirs: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    let mut seen = HashSet::<OsString>::new();
    let mut files = Vec::new();

    for dir in dirs {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            if !is_conf_file(&path) || !seen.insert(name) {
                continue;
            }

            if is_masked(&path) {
                continue;
            }

            // conf_files_list_strv() claims the highest-priority matching
            // directory entry before opening it. Keep that behavior even for
            // a broken symlink or a non-regular entry: apply_file() reports
            // the subsequent open failure and must not fall through to a
            // lower-priority file with the same name.
            files.push(path);
        }
    }

    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(files)
}

/// Resolve one explicit configuration argument using the normal binfmt.d
/// search path. Only absolute arguments bypass that search, matching
/// `search_and_fopen()`: a relative `subdir/file.conf` is looked up below
/// each configured binfmt.d directory rather than relative to the process
/// working directory.
pub fn resolve_explicit_config_file(filename: impl AsRef<Path>) -> io::Result<PathBuf> {
    resolve_explicit_config_file_from_dirs(filename.as_ref(), &conf_paths())
}

fn resolve_explicit_config_file_from_dirs(
    requested: &Path,
    directories: &[PathBuf],
) -> io::Result<PathBuf> {
    if requested.is_absolute() {
        return Ok(requested.to_path_buf());
    }

    for dir in directories {
        let candidate = dir.join(requested);
        match fs::metadata(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("configuration file {requested:?} was not found"),
    ))
}

#[cfg(not(target_os = "linux"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "binfmt_misc is only supported on Linux",
    )
}

/// Validate that binfmt_misc is mounted and writable without triggering an
/// automount. `Ok(false)` is the normal, non-fatal unavailable state.
#[cfg(target_os = "linux")]
pub fn binfmt_mounted_and_writable() -> io::Result<bool> {
    use rustix::fs::{Access, AtFlags, Mode, OFlags, accessat, fstatfs, open};
    use rustix::io::Errno;

    let file = match open(
        BINFMT_MISC_PATH,
        OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::PATH,
        Mode::empty(),
    ) {
        Ok(file) => file,
        Err(Errno::NOENT | Errno::LOOP | Errno::ACCESS | Errno::PERM) => return Ok(false),
        Err(error) => return Err(io::Error::from(error)),
    };

    if fstatfs(&file).map_err(io::Error::from)?.f_type as u64 != 0x4249_4e4d {
        return Ok(false);
    }

    match accessat(&file, "", Access::WRITE_OK, AtFlags::EMPTY_PATH) {
        Ok(()) => Ok(true),
        Err(Errno::ROFS | Errno::ACCESS | Errno::PERM) => Ok(false),
        Err(error) => Err(io::Error::from(error)),
    }
}

/// Non-Linux builds must never pretend that binfmt_misc operations succeeded.
#[cfg(not(target_os = "linux"))]
pub fn binfmt_mounted_and_writable() -> io::Result<bool> {
    Err(unsupported())
}

/// Disable (unregister) all binfmt rules. Unlike the normal startup flush,
/// failures are returned to the caller.
#[cfg(target_os = "linux")]
pub fn disable_binfmt() -> io::Result<()> {
    if !binfmt_mounted_and_writable()? {
        return Ok(());
    }
    fs::write(BINFMT_STATUS_PATH, "-1")
}

#[cfg(not(target_os = "linux"))]
pub fn disable_binfmt() -> io::Result<()> {
    Err(unsupported())
}

/// Flush all binfmt rules before applying the effective configuration. Startup
/// callers intentionally warn and continue if this operation fails.
#[cfg(target_os = "linux")]
pub fn flush_binfmt() -> io::Result<()> {
    fs::write(BINFMT_STATUS_PATH, "-1")
}

#[cfg(not(target_os = "linux"))]
pub fn flush_binfmt() -> io::Result<()> {
    Err(unsupported())
}

/// Delete an existing rule (best effort), then register the requested rule.
/// Deletion failures other than ENOENT are intentionally ignored: this is the
/// C implementation's policy, because a successful register is authoritative.
#[cfg(target_os = "linux")]
pub fn apply_rule(rule: &str) -> io::Result<()> {
    apply_rule_bytes(rule.as_bytes())
}

/// Byte-preserving form of [`apply_rule`] for configuration-file input.
#[cfg(target_os = "linux")]
pub fn apply_rule_bytes(rule: &[u8]) -> io::Result<()> {
    let name = extract_rule_name_bytes(rule)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid binfmt rule name"))?;

    if let Err(error) = fs::write(rule_delete_path_bytes(name), "-1")
        && error.kind() != io::ErrorKind::NotFound
    {
        eprintln!(
            "binfmt: failed to delete rule {:?}, ignoring: {error}",
            OsStr::from_bytes(name)
        );
    }

    fs::write(BINFMT_REGISTER_PATH, rule)
}

#[cfg(not(target_os = "linux"))]
pub fn apply_rule(_rule: &str) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_rule_bytes(_rule: &[u8]) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "systemd-binfmt-rs-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn parses_and_validates_rules() {
        assert_eq!(
            extract_rule_name(":java:M::\u{cafe}::/usr/bin/java:").unwrap(),
            "java"
        );
        assert!(extract_rule_name(":register:...").is_err());
        assert!(extract_rule_name(":a/b:...").is_err());
        assert!(!is_valid_rule_name(&"x".repeat(256)));
        assert_eq!(
            extract_rule_name_bytes(b"\xffraw\xffM\xff"),
            Ok(&b"raw"[..])
        );
        assert!(is_comment_or_empty("  # comment"));
        assert!(!is_comment_or_empty(":java:M::"));
    }

    #[test]
    fn rejects_conflicting_command_line_modes() {
        assert!(parse_binfmt_args(&["--unregister", "file.conf"]).is_err());
        assert_eq!(
            parse_binfmt_args(&["--tldr"]).unwrap().cat_flags,
            CatConfigMode::Tldr
        );
        assert_eq!(
            parse_binfmt_args(&["--version"]),
            Err(ParseBinfmtError::VersionRequested)
        );
        assert_eq!(
            parse_binfmt_args(&["--help"]),
            Err(ParseBinfmtError::HelpRequested)
        );
        assert_eq!(
            parse_binfmt_args(&["--", "-literal.conf"])
                .unwrap()
                .config_files,
            vec![PathBuf::from("-literal.conf")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_configuration_arguments() {
        use std::os::unix::ffi::OsStringExt;

        let path = OsString::from_vec(b"\xff.conf".to_vec());
        assert_eq!(
            parse_binfmt_os_args(std::slice::from_ref(&path))
                .unwrap()
                .config_files,
            vec![PathBuf::from(path)]
        );
    }

    #[test]
    fn selects_only_the_highest_priority_copy_of_each_file() {
        let high = temporary_directory("high");
        let low = temporary_directory("low");
        fs::write(high.join("10-first.conf"), "high").unwrap();
        fs::write(low.join("10-first.conf"), "low").unwrap();
        fs::write(low.join("20-second.conf"), "second").unwrap();

        let files = config_files_from_dirs(&[high.clone(), low.clone()]);
        assert_eq!(
            files.unwrap(),
            vec![high.join("10-first.conf"), low.join("20-second.conf")]
        );

        fs::remove_dir_all(high).unwrap();
        fs::remove_dir_all(low).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dev_null_mask_hides_lower_priority_configuration() {
        use std::os::unix::fs::symlink;

        let high = temporary_directory("mask-high");
        let low = temporary_directory("mask-low");
        symlink("/dev/null", high.join("20-mask.conf")).unwrap();
        fs::write(low.join("20-mask.conf"), "low").unwrap();

        assert!(
            config_files_from_dirs(&[high.clone(), low.clone()])
                .unwrap()
                .is_empty()
        );

        fs::remove_dir_all(high).unwrap();
        fs::remove_dir_all(low).unwrap();
    }

    #[test]
    fn directory_enumeration_errors_are_not_silently_ignored() {
        let directory = temporary_directory("enumeration-error");
        let not_a_directory = directory.join("regular-file");
        fs::write(&not_a_directory, "").unwrap();

        assert!(config_files_from_dirs(&[not_a_directory]).is_err());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn relative_explicit_paths_are_resolved_under_binfmt_d() {
        // search_and_fopen() prepends every configured search directory to a
        // relative name, even one which contains a slash. Keep this helper's
        // behavior deliberately separate from the process working directory.
        let directory = temporary_directory("relative-explicit");
        let nested = directory.join("subdir");
        fs::create_dir(&nested).unwrap();
        let expected = nested.join("example.conf");
        fs::write(&expected, "rule").unwrap();

        assert_eq!(
            resolve_explicit_config_file_from_dirs(
                Path::new("subdir/example.conf"),
                std::slice::from_ref(&directory)
            )
            .unwrap(),
            expected
        );

        fs::remove_dir_all(directory).unwrap();
    }
}
