// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/volatile-root/volatile-root.c

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidMode(String),
    InvalidPath(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMode(v) => write!(f, "invalid volatile mode: {v}"),
            Self::InvalidPath(v) => f.write_str(v),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolatileMode {
    No,
    Yes,
    Overlay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountStep {
    EnsureDirectory(&'static str),
    MountTmpfs { target: &'static str },
    BindUsr { source: String },
    Overlay { target: String, lowerdir: String },
    ReplaceRoot { target: String },
}

pub fn parse_mode(value: &str) -> Result<VolatileMode> {
    match value {
        "no" | "false" => Ok(VolatileMode::No),
        "yes" | "true" => Ok(VolatileMode::Yes),
        "overlay" => Ok(VolatileMode::Overlay),
        _ => Err(Error::InvalidMode(value.into())),
    }
}

pub fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::InvalidPath("directory name cannot be empty"));
    }
    if !path.starts_with('/') {
        return Err(Error::InvalidPath("directory must be absolute"));
    }
    if path == "/" {
        return Err(Error::InvalidPath("directory cannot be the root directory"));
    }
    Ok(())
}

pub fn plan(mode: VolatileMode, path: &str, old_usr: &str) -> Result<Vec<MountStep>> {
    validate_path(path)?;
    Ok(match mode {
        VolatileMode::No => Vec::new(),
        VolatileMode::Yes => vec![
            MountStep::EnsureDirectory("/run/systemd/volatile-sysroot"),
            MountStep::MountTmpfs {
                target: "/run/systemd/volatile-sysroot",
            },
            MountStep::BindUsr {
                source: old_usr.into(),
            },
            MountStep::ReplaceRoot {
                target: path.into(),
            },
        ],
        VolatileMode::Overlay => vec![
            MountStep::EnsureDirectory("/run/systemd/overlay-sysroot"),
            MountStep::MountTmpfs {
                target: "/run/systemd/overlay-sysroot",
            },
            MountStep::Overlay {
                target: path.into(),
                lowerdir: path.into(),
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yes_mode() {
        assert_eq!(parse_mode("yes").unwrap(), VolatileMode::Yes);
    }
    #[test]
    fn parses_overlay_mode() {
        assert_eq!(parse_mode("overlay").unwrap(), VolatileMode::Overlay);
    }
    #[test]
    fn rejects_unknown_mode() {
        assert!(matches!(parse_mode("maybe"), Err(Error::InvalidMode(_))));
    }
    #[test]
    fn rejects_empty_path() {
        assert!(matches!(validate_path(""), Err(Error::InvalidPath(_))));
    }
    #[test]
    fn rejects_relative_path() {
        assert!(matches!(
            validate_path("sysroot"),
            Err(Error::InvalidPath(_))
        ));
    }
    #[test]
    fn rejects_root_path() {
        assert!(matches!(validate_path("/"), Err(Error::InvalidPath(_))));
    }
    #[test]
    fn yes_plan_contains_replace_root() {
        assert!(
            plan(VolatileMode::Yes, "/sysroot", "/old/usr")
                .unwrap()
                .iter()
                .any(|s| matches!(s, MountStep::ReplaceRoot { .. }))
        );
    }
    #[test]
    fn overlay_plan_contains_overlay_step() {
        assert!(
            plan(VolatileMode::Overlay, "/sysroot", "/old/usr")
                .unwrap()
                .iter()
                .any(|s| matches!(s, MountStep::Overlay { .. }))
        );
    }
}
