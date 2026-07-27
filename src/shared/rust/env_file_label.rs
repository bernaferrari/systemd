// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/basic/env-file.c, src/basic/env-file.h,
//            src/basic/label-util.c, src/basic/label-util.h,
//            src/shared/selinux-util.c, src/shared/selinux-util.h

use crate::ffi::*;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::locale_setup::etc_vconsole_conf;
use crate::selinux_util::{
    mac_selinux_create_file_clear, mac_selinux_create_file_prepare, ContextError, AT_FDCWD, S_IFREG,
};

const DEFAULT_FILE_MODE: libc::mode_t = 0o644;
const SHELL_NEED_ESCAPE: &str = "\"\\`$";
const SHELL_NEED_QUOTES: &str = "\"\\`$*?['()<>|&;!]";
const VCONSOLE_CONF_HEADERS: [&str; 2] = [
    "# Written by systemd-localed(8) or systemd-firstboot(1), read by systemd-localed",
    "# and systemd-vconsole-setup(8). Use localectl(1) to update this file.",
];

static TEMPFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum EnvFileLabelError {
    EmptyFileName,
    InvalidDirectoryFd(RawFd),
    InvalidHeader(String),
    EmbeddedNul(&'static str),
    Io(io::Error),
    Selinux(ContextError),
}

impl std::fmt::Display for EnvFileLabelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyFileName => write!(f, "empty file name"),
            Self::InvalidDirectoryFd(fd) => write!(f, "invalid directory fd: {fd}"),
            Self::InvalidHeader(header) => write!(f, "invalid header line: {header:?}"),
            Self::EmbeddedNul(field) => write!(f, "embedded NUL byte in {field}"),
            Self::Io(err) => err.fmt(f),
            Self::Selinux(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for EnvFileLabelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Selinux(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for EnvFileLabelError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ContextError> for EnvFileLabelError {
    fn from(value: ContextError) -> Self {
        Self::Selinux(value)
    }
}

struct SelinuxCreateFileGuard;

impl SelinuxCreateFileGuard {
    fn prepare(path: &Path) -> Result<Self, EnvFileLabelError> {
        let path_str = path
            .to_str()
            .ok_or(EnvFileLabelError::EmbeddedNul("path"))?;
        mac_selinux_create_file_prepare(path_str, S_IFREG)?;
        Ok(Self)
    }
}

impl Drop for SelinuxCreateFileGuard {
    fn drop(&mut self) {
        mac_selinux_create_file_clear();
    }
}

pub fn write_env_file_label<I, H, J, E>(
    dir_fd: RawFd,
    fname: &Path,
    headers: I,
    entries: J,
) -> Result<(), EnvFileLabelError>
where
    I: IntoIterator<Item = H>,
    H: AsRef<str>,
    J: IntoIterator<Item = E>,
    E: AsRef<str>,
{
    validate_dir_fd(dir_fd)?;
    validate_fname(fname)?;

    let _label_guard = SelinuxCreateFileGuard::prepare(fname)?;
    write_env_file(dir_fd, fname, headers, entries)
}

pub fn write_vconsole_conf_label<J, E>(entries: J) -> Result<(), EnvFileLabelError>
where
    J: IntoIterator<Item = E>,
    E: AsRef<str>,
{
    write_env_file_label(
        AT_FDCWD,
        etc_vconsole_conf(),
        VCONSOLE_CONF_HEADERS,
        entries,
    )
}

fn write_env_file<I, H, J, E>(
    dir_fd: RawFd,
    fname: &Path,
    headers: I,
    entries: J,
) -> Result<(), EnvFileLabelError>
where
    I: IntoIterator<Item = H>,
    H: AsRef<str>,
    J: IntoIterator<Item = E>,
    E: AsRef<str>,
{
    let rendered = render_env_file(headers, entries)?;
    write_atomically_at(dir_fd, fname, rendered.as_bytes())
}

fn render_env_file<I, H, J, E>(headers: I, entries: J) -> Result<String, EnvFileLabelError>
where
    I: IntoIterator<Item = H>,
    H: AsRef<str>,
    J: IntoIterator<Item = E>,
    E: AsRef<str>,
{
    let mut rendered = String::new();

    for header in headers {
        let header = header.as_ref();
        if !header.is_empty() && !header.starts_with('#') {
            return Err(EnvFileLabelError::InvalidHeader(header.to_string()));
        }

        rendered.push_str(header);
        rendered.push('\n');
    }

    for entry in entries {
        write_env_var(&mut rendered, entry.as_ref());
    }

    Ok(rendered)
}

fn write_env_var(rendered: &mut String, entry: &str) {
    match entry.split_once('=') {
        None => {
            rendered.push_str(entry);
            rendered.push('\n');
        }
        Some((key, value)) => {
            rendered.push_str(key);
            rendered.push('=');
            push_escaped_value(rendered, value);
            rendered.push('\n');
        }
    }
}

fn push_escaped_value(rendered: &mut String, value: &str) {
    if needs_quotes(value) {
        rendered.push('"');
        for ch in value.chars() {
            if SHELL_NEED_ESCAPE.contains(ch) {
                rendered.push('\\');
            }
            rendered.push(ch);
        }
        rendered.push('"');
    } else {
        rendered.push_str(value);
    }
}

fn needs_quotes(value: &str) -> bool {
    value
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || SHELL_NEED_QUOTES.contains(ch))
}

fn write_atomically_at(dir_fd: RawFd, fname: &Path, data: &[u8]) -> Result<(), EnvFileLabelError> {
    let target = path_to_cstring(fname)?;

    for attempt in 0..128u32 {
        let temp_name = temporary_name(fname, attempt);
        let temp = CString::new(temp_name).map_err(|_| EnvFileLabelError::EmbeddedNul("path"))?;

        match open_tempfile(dir_fd, &temp) {
            Ok(mut file) => {
                let write_result = (|| -> io::Result<()> {
                    file.write_all(data)?;
                    file.sync_all()?;
                    Ok(())
                })();

                if let Err(err) = write_result {
                    unlink_at(dir_fd, &temp);
                    return Err(err.into());
                }

                let rename_result =
                    unsafe { libc::renameat(dir_fd, temp.as_ptr(), dir_fd, target.as_ptr()) };
                if rename_result < 0 {
                    let err = io::Error::last_os_error();
                    unlink_at(dir_fd, &temp);
                    return Err(err.into());
                }

                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate unique temporary file name",
    )
    .into())
}

fn open_tempfile(dir_fd: RawFd, temp_name: &CString) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir_fd,
            temp_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            DEFAULT_FILE_MODE as u32,
        )
    };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { File::from_raw_fd(fd) })
}

fn unlink_at(dir_fd: RawFd, path: &CString) {
    let _ = unsafe { libc::unlinkat(dir_fd, path.as_ptr(), 0) };
}

fn validate_dir_fd(dir_fd: RawFd) -> Result<(), EnvFileLabelError> {
    if dir_fd == AT_FDCWD {
        return Ok(());
    }

    let result = unsafe { libc::fcntl(dir_fd, libc::F_GETFD) };
    if result < 0 {
        return Err(EnvFileLabelError::InvalidDirectoryFd(dir_fd));
    }

    Ok(())
}

fn validate_fname(fname: &Path) -> Result<(), EnvFileLabelError> {
    let bytes = fname.as_os_str().as_bytes();
    if bytes.is_empty() {
        return Err(EnvFileLabelError::EmptyFileName);
    }

    if bytes.contains(&0) {
        return Err(EnvFileLabelError::EmbeddedNul("path"));
    }

    Ok(())
}

fn path_to_cstring(path: &Path) -> Result<CString, EnvFileLabelError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| EnvFileLabelError::EmbeddedNul("path"))
}

fn temporary_name(fname: &Path, attempt: u32) -> Vec<u8> {
    let stem = fname
        .file_name()
        .map(|name| name.as_bytes())
        .filter(|name| !name.is_empty())
        .unwrap_or(b"env-file");

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let counter = TEMPFILE_COUNTER.fetch_add(1, Ordering::Relaxed);

    format!(
        ".#{}.tmp.{:x}.{:x}.{:x}",
        String::from_utf8_lossy(stem),
        std::process::id(),
        nanos,
        counter + u64::from(attempt)
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::fd::AsRawFd;

    #[test]
    fn simple_values_are_not_quoted() {
        let mut rendered = String::new();
        push_escaped_value(&mut rendered, "value");
        assert_eq!(rendered, "value");
    }

    #[test]
    fn whitespace_values_are_quoted() {
        let mut rendered = String::new();
        push_escaped_value(&mut rendered, "two words");
        assert_eq!(rendered, "\"two words\"");
    }

    #[test]
    fn shell_metacharacters_are_quoted() {
        let mut rendered = String::new();
        push_escaped_value(&mut rendered, "a*b");
        assert_eq!(rendered, "\"a*b\"");
    }

    #[test]
    fn quoted_values_escape_special_characters() {
        let mut rendered = String::new();
        push_escaped_value(&mut rendered, "\"\\`$");
        assert_eq!(rendered, "\"\\\"\\\\\\`\\$\"");
    }

    #[test]
    fn control_characters_trigger_quoting() {
        assert!(needs_quotes("hello\nworld"));
    }

    #[test]
    fn entries_without_equals_use_fallback_format() {
        let mut rendered = String::new();
        write_env_var(&mut rendered, "JUST_TEXT");
        assert_eq!(rendered, "JUST_TEXT\n");
    }

    #[test]
    fn entries_preserve_key_and_escape_only_value() {
        let mut rendered = String::new();
        write_env_var(&mut rendered, "KEY=hello world");
        assert_eq!(rendered, "KEY=\"hello world\"\n");
    }

    #[test]
    fn render_env_file_writes_headers_and_entries() {
        let rendered = render_env_file(["# header", ""], ["A=1", "B=two words"]).unwrap();
        assert_eq!(rendered, "# header\n\nA=1\nB=\"two words\"\n");
    }

    #[test]
    fn render_env_file_rejects_non_comment_headers() {
        let err = render_env_file(["not-a-comment"], std::iter::empty::<&str>()).unwrap_err();
        assert!(matches!(err, EnvFileLabelError::InvalidHeader(_)));
    }

    #[test]
    fn validate_fname_rejects_empty_paths() {
        let err = validate_fname(Path::new("")).unwrap_err();
        assert!(matches!(err, EnvFileLabelError::EmptyFileName));
    }

    #[test]
    fn validate_dir_fd_rejects_invalid_fd() {
        let err = validate_dir_fd(-2).unwrap_err();
        assert!(matches!(err, EnvFileLabelError::InvalidDirectoryFd(-2)));
    }

    #[test]
    fn temporary_names_are_hidden_and_unique() {
        let a = temporary_name(Path::new("test.conf"), 0);
        let b = temporary_name(Path::new("test.conf"), 1);
        assert_ne!(a, b);
        assert!(String::from_utf8(a)
            .unwrap()
            .starts_with(".#test.conf.tmp."));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn write_atomically_at_replaces_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env.conf");
        fs::write(&path, "OLD=1\n").unwrap();

        write_atomically_at(AT_FDCWD, &path, b"NEW=2\n").unwrap();

        assert_eq!(fs::read_to_string(path).unwrap(), "NEW=2\n");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn write_env_file_label_writes_relative_to_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let result = write_env_file_label(AT_FDCWD, Path::new("env.conf"), ["# header"], ["A=1"]);

        std::env::set_current_dir(old_cwd).unwrap();
        result.unwrap();

        assert_eq!(
            fs::read_to_string(dir.path().join("env.conf")).unwrap(),
            "# header\nA=1\n"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn write_env_file_label_writes_relative_to_directory_fd() {
        let dir = tempfile::tempdir().unwrap();
        let dir_file = File::open(dir.path()).unwrap();

        write_env_file_label(
            dir_file.as_raw_fd(),
            Path::new("nested.conf"),
            ["# header"],
            ["A=two words"],
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(dir.path().join("nested.conf")).unwrap(),
            "# header\nA=\"two words\"\n"
        );
    }

    #[test]
    fn vconsole_headers_match_c_source() {
        assert_eq!(
            VCONSOLE_CONF_HEADERS,
            [
                "# Written by systemd-localed(8) or systemd-firstboot(1), read by systemd-localed",
                "# and systemd-vconsole-setup(8). Use localectl(1) to update this file.",
            ]
        );
    }
}
