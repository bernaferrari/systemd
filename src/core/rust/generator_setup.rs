// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/generator-setup.c

use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LookupPaths {
    pub search_path: Vec<PathBuf>,
    pub persistent_config: Option<PathBuf>,
    pub runtime_config: Option<PathBuf>,
    pub persistent_attached: Option<PathBuf>,
    pub runtime_attached: Option<PathBuf>,
    pub generator: Option<PathBuf>,
    pub generator_early: Option<PathBuf>,
    pub generator_late: Option<PathBuf>,
    pub transient: Option<PathBuf>,
    pub persistent_control: Option<PathBuf>,
    pub runtime_control: Option<PathBuf>,
    pub root_dir: Option<PathBuf>,
    pub temporary_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupPathsError {
    MissingGeneratorDirectories,
    CreateDirectory { path: PathBuf, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorPathReport {
    pub touched_paths: Vec<PathBuf>,
}

impl LookupPaths {
    fn generator_triplet(&self) -> Option<[&Path; 3]> {
        Some([
            self.generator.as_deref()?,
            self.generator_early.as_deref()?,
            self.generator_late.as_deref()?,
        ])
    }
}

pub fn lookup_paths_mkdir_generator(
    paths: &LookupPaths,
) -> Result<GeneratorPathReport, LookupPathsError> {
    let triplet = paths
        .generator_triplet()
        .ok_or(LookupPathsError::MissingGeneratorDirectories)?;

    let mut touched_paths = Vec::with_capacity(3);
    let mut first_error = None;

    for path in triplet {
        match fs::create_dir_all(path) {
            Ok(()) => touched_paths.push(path.to_path_buf()),
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(LookupPathsError::CreateDirectory {
                        path: path.to_path_buf(),
                        message: error.to_string(),
                    });
                }
            }
        }
    }

    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(GeneratorPathReport { touched_paths })
    }
}

pub fn lookup_paths_trim_generator(paths: &LookupPaths) -> Result<GeneratorPathReport, Infallible> {
    let mut touched_paths = Vec::new();

    for path in [
        paths.generator.as_deref(),
        paths.generator_early.as_deref(),
        paths.generator_late.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let _ = fs::remove_dir(path);
        touched_paths.push(path.to_path_buf());
    }

    Ok(GeneratorPathReport { touched_paths })
}

pub fn lookup_paths_flush_generator(
    paths: &LookupPaths,
) -> Result<GeneratorPathReport, Infallible> {
    let mut touched_paths = Vec::new();

    for path in [
        paths.generator.as_deref(),
        paths.generator_early.as_deref(),
        paths.generator_late.as_deref(),
        paths.temporary_dir.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let _ = fs::remove_dir_all(path);
        touched_paths.push(path.to_path_buf());
    }

    Ok(GeneratorPathReport { touched_paths })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "systemd-core-rs-{name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("temp root must be created");
        root
    }

    fn sample_paths(root: &Path) -> LookupPaths {
        LookupPaths {
            generator: Some(root.join("generator")),
            generator_early: Some(root.join("generator.early")),
            generator_late: Some(root.join("generator.late")),
            temporary_dir: Some(root.join("tmp")),
            ..LookupPaths::default()
        }
    }

    #[test]
    fn mkdir_requires_all_three_generator_directories() {
        let paths = LookupPaths::default();

        let error = lookup_paths_mkdir_generator(&paths).expect_err("must fail");

        assert_eq!(error, LookupPathsError::MissingGeneratorDirectories);
    }

    #[test]
    fn mkdir_creates_all_generator_directories() {
        let root = temp_root("mkdir-all");
        let paths = sample_paths(&root);

        let report = lookup_paths_mkdir_generator(&paths).expect("must succeed");

        assert_eq!(report.touched_paths.len(), 3);
        assert!(paths.generator.as_ref().expect("generator").is_dir());
        assert!(
            paths
                .generator_early
                .as_ref()
                .expect("generator_early")
                .is_dir()
        );
        assert!(
            paths
                .generator_late
                .as_ref()
                .expect("generator_late")
                .is_dir()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mkdir_keeps_gather_semantics_by_continuing_after_failure() {
        let root = temp_root("mkdir-gather");
        let mut paths = sample_paths(&root);
        let blocker = root.join("blocked");
        fs::write(&blocker, b"not a directory").expect("must create blocker file");
        paths.generator_early = Some(blocker.clone());

        let error = lookup_paths_mkdir_generator(&paths).expect_err("must fail");

        match error {
            LookupPathsError::CreateDirectory { path, .. } => assert_eq!(path, blocker),
            _ => panic!("unexpected error kind"),
        }
        assert!(paths.generator.as_ref().expect("generator").is_dir());
        assert!(
            paths
                .generator_late
                .as_ref()
                .expect("generator_late")
                .is_dir()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn trim_removes_empty_generator_directories() {
        let root = temp_root("trim-empty");
        let paths = sample_paths(&root);
        lookup_paths_mkdir_generator(&paths).expect("must create dirs");

        let report = lookup_paths_trim_generator(&paths).expect("infallible");

        assert_eq!(report.touched_paths.len(), 3);
        assert!(!paths.generator.as_ref().expect("generator").exists());
        assert!(
            !paths
                .generator_early
                .as_ref()
                .expect("generator_early")
                .exists()
        );
        assert!(
            !paths
                .generator_late
                .as_ref()
                .expect("generator_late")
                .exists()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn trim_leaves_non_empty_directories_in_place() {
        let root = temp_root("trim-non-empty");
        let paths = sample_paths(&root);
        lookup_paths_mkdir_generator(&paths).expect("must create dirs");
        fs::write(
            paths
                .generator
                .as_ref()
                .expect("generator")
                .join("unit.service"),
            b"[Unit]",
        )
        .expect("must create file");

        let _ = lookup_paths_trim_generator(&paths).expect("infallible");

        assert!(paths.generator.as_ref().expect("generator").exists());
        assert!(
            !paths
                .generator_early
                .as_ref()
                .expect("generator_early")
                .exists()
        );
        assert!(
            !paths
                .generator_late
                .as_ref()
                .expect("generator_late")
                .exists()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn flush_removes_generator_trees_recursively() {
        let root = temp_root("flush-recursive");
        let paths = sample_paths(&root);
        lookup_paths_mkdir_generator(&paths).expect("must create dirs");
        let nested = paths
            .generator
            .as_ref()
            .expect("generator")
            .join("nested/unit.service");
        fs::create_dir_all(nested.parent().expect("nested dir")).expect("must create nested dir");
        fs::write(&nested, b"content").expect("must create nested file");

        let _ = lookup_paths_flush_generator(&paths).expect("infallible");

        assert!(!paths.generator.as_ref().expect("generator").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn flush_also_removes_temporary_directory() {
        let root = temp_root("flush-temp");
        let paths = sample_paths(&root);
        let temporary = paths.temporary_dir.as_ref().expect("tmp");
        fs::create_dir_all(temporary.join("subdir")).expect("must create temp dir");
        fs::write(temporary.join("subdir/file"), b"x").expect("must create temp file");

        let report = lookup_paths_flush_generator(&paths).expect("infallible");

        assert_eq!(report.touched_paths.len(), 4);
        assert!(!temporary.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn trim_and_flush_ignore_missing_directories() {
        let root = temp_root("ignore-missing");
        let paths = sample_paths(&root);

        let trim = lookup_paths_trim_generator(&paths).expect("infallible");
        let flush = lookup_paths_flush_generator(&paths).expect("infallible");

        assert_eq!(trim.touched_paths.len(), 3);
        assert_eq!(flush.touched_paths.len(), 4);
        let _ = fs::remove_dir_all(root);
    }
}
