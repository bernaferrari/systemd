// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/update-done/update-done.c

use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidArgument(&'static str),
    MissingRootValue,
    UnexpectedArgument(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(msg) => f.write_str(msg),
            Self::MissingRootValue => f.write_str("--root requires a value"),
            Self::UnexpectedArgument(arg) => write!(f, "unexpected argument: {arg}"),
        }
    }
}

impl std::error::Error for Error {}

pub const USR_PATH: &str = "/usr";
pub const TARGET_DIRS: [&str; 2] = ["/etc/", "/var/"];
pub const UPDATED_FILENAME: &str = ".updated";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    pub sec: i64,
    pub nsec: i64,
}

impl Timestamp {
    pub const fn new(sec: i64, nsec: i64) -> Self {
        Self { sec, nsec }
    }

    pub const fn as_nanos(self) -> i128 {
        self.sec as i128 * 1_000_000_000 + self.nsec as i128
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateTarget {
    pub directory: String,
    pub resolved_directory: PathBuf,
    pub updated_file: PathBuf,
    pub contents: String,
}

pub fn parse_args<I, S>(args: I) -> Result<Config>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut root = None;
    let mut it = args.into_iter().map(|s| s.as_ref().to_owned()).peekable();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--root" => {
                let value = it.next().ok_or(Error::MissingRootValue)?;
                root = Some(parse_root(&value)?);
            }
            _ if let Some(value) = arg.strip_prefix("--root=") => {
                root = Some(parse_root(value)?);
            }
            "-h" | "--help" | "--version" => {}
            other => return Err(Error::UnexpectedArgument(other.to_owned())),
        }
    }
    Ok(Config { root })
}

fn parse_root(value: &str) -> Result<PathBuf> {
    if value.is_empty() {
        return Err(Error::InvalidArgument("root path must not be empty"));
    }
    if !value.starts_with('/') {
        return Err(Error::InvalidArgument("root path must be absolute"));
    }
    Ok(PathBuf::from(value))
}

pub fn resolve_under_root(root: Option<&Path>, absolute: &str) -> PathBuf {
    match root {
        Some(root) => root.join(absolute.trim_start_matches('/')),
        None => PathBuf::from(absolute),
    }
}

pub fn updated_file_path(dir: &Path) -> PathBuf {
    dir.join(UPDATED_FILENAME)
}

pub fn build_updated_contents(dir: &str, ts: Timestamp) -> String {
    format!(
        "# This file was created by systemd-update-done. The timestamp below is the\n# modification time of /usr/ for which the most recent updates of {} have\n# been applied. See man:systemd-update-done.service(8) for details.\nTIMESTAMP_NSEC={}\n",
        dir,
        ts.as_nanos()
    )
}

pub fn plan_updates(config: &Config, usr_timestamp: Timestamp) -> Vec<UpdateTarget> {
    TARGET_DIRS
        .iter()
        .map(|dir| {
            let resolved_directory = resolve_under_root(config.root.as_deref(), dir);
            let updated_file = updated_file_path(&resolved_directory);
            UpdateTarget {
                directory: (*dir).to_owned(),
                resolved_directory,
                updated_file,
                contents: build_updated_contents(dir, usr_timestamp),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_arguments() {
        assert_eq!(parse_args(Vec::<&str>::new()).unwrap(), Config::default());
    }

    #[test]
    fn parses_root_equals_form() {
        let config = parse_args(["--root=/sysroot"]).unwrap();
        assert_eq!(config.root, Some(PathBuf::from("/sysroot")));
    }

    #[test]
    fn parses_root_split_form() {
        let config = parse_args(["--root", "/alt"]).unwrap();
        assert_eq!(config.root, Some(PathBuf::from("/alt")));
    }

    #[test]
    fn rejects_relative_root() {
        assert_eq!(
            parse_args(["--root=tmp"]).unwrap_err(),
            Error::InvalidArgument("root path must be absolute")
        );
    }

    #[test]
    fn resolves_under_root() {
        assert_eq!(
            resolve_under_root(Some(Path::new("/sysroot")), "/etc/"),
            PathBuf::from("/sysroot/etc/")
        );
    }

    #[test]
    fn builds_updated_file_path() {
        assert_eq!(
            updated_file_path(Path::new("/etc")),
            PathBuf::from("/etc/.updated")
        );
    }

    #[test]
    fn builds_contents_with_nanoseconds() {
        let text = build_updated_contents("/etc/", Timestamp::new(2, 3));
        assert!(text.contains("/etc/"));
        assert!(text.contains("TIMESTAMP_NSEC=2000000003"));
    }

    #[test]
    fn plans_two_update_targets() {
        let plan = plan_updates(
            &Config {
                root: Some(PathBuf::from("/sysroot")),
            },
            Timestamp::new(1, 0),
        );
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].updated_file, PathBuf::from("/sysroot/etc/.updated"));
        assert_eq!(plan[1].updated_file, PathBuf::from("/sysroot/var/.updated"));
    }
}
