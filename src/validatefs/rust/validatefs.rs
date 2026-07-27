// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/validatefs/validatefs.c

use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidRoot,
    MissingTarget,
    InvalidTarget,
    MountPointMismatch {
        expected: Vec<String>,
        actual: String,
    },
    GptLabelMismatch {
        expected: Vec<String>,
        actual: String,
    },
    GptTypeMismatch {
        expected: Vec<String>,
        actual: Option<String>,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRoot => f.write_str("--root must be 'auto' or an absolute path"),
            Self::MissingTarget => f.write_str("expected exactly one mount point"),
            Self::InvalidTarget => f.write_str("target must be absolute and normalized"),
            Self::MountPointMismatch { actual, .. } => write!(f, "mount point mismatch: {actual}"),
            Self::GptLabelMismatch { actual, .. } => write!(f, "GPT label mismatch: {actual}"),
            Self::GptTypeMismatch { actual, .. } => write!(f, "GPT type mismatch: {:?}", actual),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidateFields {
    pub gpt_type_uuids: Vec<String>,
    pub gpt_labels: Vec<String>,
    pub mount_points: Vec<String>,
}

impl ValidateFields {
    pub fn has_constraints(&self) -> bool {
        !(self.gpt_type_uuids.is_empty()
            && self.gpt_labels.is_empty()
            && self.mount_points.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeMetadata {
    pub path: String,
    pub gpt_label: Option<String>,
    pub gpt_type_uuid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub target: Option<String>,
    pub root: Option<PathBuf>,
}

pub fn parse_args(args: &[&str], in_initrd: bool) -> Result<Config> {
    let mut root = None;
    let mut target = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--root" => {
                i += 1;
                let value = args.get(i).ok_or(Error::InvalidRoot)?;
                root = Some(parse_root(value, in_initrd)?);
            }
            arg if arg.starts_with("--root=") => {
                root = Some(parse_root(&arg[7..], in_initrd)?);
            }
            arg if arg.starts_with('/') => target = Some(arg.to_owned()),
            _ => return Err(Error::InvalidTarget),
        }
        i += 1;
    }
    let target = target.ok_or(Error::MissingTarget)?;
    if !is_normalized_absolute(&target) {
        return Err(Error::InvalidTarget);
    }
    Ok(Config {
        target: Some(target),
        root,
    })
}

fn parse_root(value: &str, in_initrd: bool) -> Result<PathBuf> {
    if value == "auto" {
        return Ok(if in_initrd {
            PathBuf::from("/sysroot")
        } else {
            PathBuf::from("/")
        });
    }
    if value.starts_with('/') {
        return Ok(PathBuf::from(value));
    }
    Err(Error::InvalidRoot)
}

fn is_normalized_absolute(path: &str) -> bool {
    path.starts_with('/') && !path.contains("//") && !path.contains("/./") && !path.contains("/../")
}

pub fn validate_mount_point(
    path: &str,
    fields: &ValidateFields,
    root: Option<&Path>,
) -> Result<()> {
    if fields.mount_points.is_empty() {
        return Ok(());
    }
    let matches = fields.mount_points.iter().any(|candidate| {
        let candidate = match root {
            Some(root) if root != Path::new("/") => root
                .join(candidate.trim_start_matches('/'))
                .display()
                .to_string(),
            _ => candidate.clone(),
        };
        candidate == path
    });
    if matches {
        Ok(())
    } else {
        Err(Error::MountPointMismatch {
            expected: fields.mount_points.clone(),
            actual: path.to_owned(),
        })
    }
}

pub fn validate_gpt_label(actual: Option<&str>, fields: &ValidateFields) -> Result<()> {
    if fields.gpt_labels.is_empty() || fields.gpt_labels.iter().any(|v| Some(v.as_str()) == actual)
    {
        Ok(())
    } else {
        Err(Error::GptLabelMismatch {
            expected: fields.gpt_labels.clone(),
            actual: actual.unwrap_or_default().to_owned(),
        })
    }
}

pub fn validate_gpt_type(actual: Option<&str>, fields: &ValidateFields) -> Result<()> {
    if fields.gpt_type_uuids.is_empty()
        || fields
            .gpt_type_uuids
            .iter()
            .any(|v| Some(v.as_str()) == actual)
    {
        Ok(())
    } else {
        Err(Error::GptTypeMismatch {
            expected: fields.gpt_type_uuids.clone(),
            actual: actual.map(str::to_owned),
        })
    }
}

pub fn validate_probe(
    metadata: &ProbeMetadata,
    fields: &ValidateFields,
    root: Option<&Path>,
) -> Result<()> {
    validate_mount_point(&metadata.path, fields, root)?;
    validate_gpt_label(metadata.gpt_label.as_deref(), fields)?;
    validate_gpt_type(metadata.gpt_type_uuid.as_deref(), fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_root_uses_sysroot_in_initrd() {
        assert_eq!(
            parse_args(&["--root=auto", "/sysroot/usr"], true)
                .unwrap()
                .root,
            Some(PathBuf::from("/sysroot"))
        );
    }
    #[test]
    fn rejects_relative_root() {
        assert_eq!(
            parse_args(&["--root=tmp", "/x"], false).unwrap_err(),
            Error::InvalidRoot
        );
    }
    #[test]
    fn rejects_missing_target() {
        assert_eq!(
            parse_args(&["--root=/sysroot"], false).unwrap_err(),
            Error::MissingTarget
        );
    }
    #[test]
    fn accepts_normalized_absolute_target() {
        assert_eq!(
            parse_args(&["/mnt/data"], false).unwrap().target.as_deref(),
            Some("/mnt/data")
        );
    }
    #[test]
    fn mount_point_validation_respects_root() {
        let fields = ValidateFields {
            mount_points: vec!["/var".into()],
            ..Default::default()
        };
        assert!(validate_mount_point("/sysroot/var", &fields, Some(Path::new("/sysroot"))).is_ok());
    }
    #[test]
    fn gpt_label_validation_fails_for_wrong_label() {
        let fields = ValidateFields {
            gpt_labels: vec!["root".into()],
            ..Default::default()
        };
        assert!(matches!(
            validate_gpt_label(Some("home"), &fields),
            Err(Error::GptLabelMismatch { .. })
        ));
    }
    #[test]
    fn gpt_type_validation_passes_when_unset() {
        assert!(validate_gpt_type(None, &ValidateFields::default()).is_ok());
    }
    #[test]
    fn full_probe_validation_passes() {
        let fields = ValidateFields {
            gpt_type_uuids: vec!["uuid-a".into()],
            gpt_labels: vec!["root".into()],
            mount_points: vec!["/mnt".into()],
        };
        let metadata = ProbeMetadata {
            path: "/mnt".into(),
            gpt_label: Some("root".into()),
            gpt_type_uuid: Some("uuid-a".into()),
        };
        assert!(validate_probe(&metadata, &fields, None).is_ok());
    }
}
