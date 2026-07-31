// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/generator-setup.c

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::ffi::OsString;
use std::fs::{self, DirBuilder};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

/// The mode passed by C's `lookup_paths_mkdir_generator()` to `mkdir_p_label()`.
///
/// As with `mkdir(2)`, the process umask may remove permissions from this mode.
const GENERATOR_DIRECTORY_MODE: u32 = 0o755;

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
    UnsafeGeneratorDirectory { path: PathBuf },
    CreateDirectory { path: PathBuf, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorPathReport {
    pub touched_paths: Vec<PathBuf>,
}

/// Best-effort result of C's `conf_files_list_strv()` policy as used by
/// `execute_directories()` for generators.
///
/// Search directories are ordered from highest to lowest priority. The
/// executable list is ordered by basename, independently of directory walk
/// order. Diagnostics are retained for the startup owner to log without
/// turning a single unreadable entry into a fatal generator-enumeration error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeneratorDiscoveryReport {
    pub executables: Vec<PathBuf>,
    pub masked_names: Vec<OsString>,
    pub ignored_errors: Vec<(PathBuf, String)>,
}

/// Immutable argv contract for one unit generator.
///
/// The runner supplies `executable` as argv[0], followed by normal, early,
/// and late output directories in exactly the order documented by
/// systemd.generator(7) and used by `manager_execute_generators()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorInvocation {
    pub executable: PathBuf,
    pub output_directory: PathBuf,
    pub early_output_directory: PathBuf,
    pub late_output_directory: PathBuf,
}

impl GeneratorInvocation {
    /// Return the exact four positional arguments consumed by a generator:
    /// executable/argv[0], normal output, early output, and late output.
    pub fn argv(&self) -> [&Path; 4] {
        [
            &self.executable,
            &self.output_directory,
            &self.early_output_directory,
            &self.late_output_directory,
        ]
    }
}

/// Prepared generator execution inputs together with discovery diagnostics
/// that the startup owner must log or account for before spawning children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedGeneratorRun {
    pub discovery: GeneratorDiscoveryReport,
    pub invocations: Vec<GeneratorInvocation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorRuntimeScope {
    System,
    User,
}

/// Facts that C's `build_generator_environment()` adds after copying the
/// manager's transient environment. Callers own virtualization detection and
/// architecture naming so this pure builder cannot silently invent them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorEnvironmentFacts {
    pub scope: GeneratorRuntimeScope,
    pub in_initrd: bool,
    pub soft_reboots_count: u32,
    pub first_boot: Option<bool>,
    pub virtualization: Option<String>,
    pub confidential_virtualization: Option<String>,
    pub architecture: String,
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

#[cfg(unix)]
fn metadata_may_be_dev_null(metadata: &fs::Metadata) -> bool {
    // Match C's deliberately conservative stat_may_be_dev_null(): any
    // character device is treated as a mask rather than hard-coding the
    // major/minor pair of /dev/null.
    metadata.file_type().is_char_device()
}

#[cfg(not(unix))]
fn metadata_may_be_dev_null(_metadata: &fs::Metadata) -> bool {
    false
}

/// Enumerate generator executables with the precedence and masking rules used
/// by C's `execute_directories()`.
///
/// A valid entry in an earlier directory overrides the same basename in later
/// directories. An empty regular file or a node resolving to `/dev/null`
/// masks all lower-priority entries. An invalid or non-executable entry does
/// *not* mask a valid lower-priority generator.
pub fn discover_generator_executables(search_directories: &[PathBuf]) -> GeneratorDiscoveryReport {
    let mut selected = BTreeMap::<OsString, PathBuf>::new();
    let mut masked = BTreeSet::<OsString>::new();
    let mut ignored_errors = Vec::new();

    for directory in search_directories {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                ignored_errors.push((directory.clone(), error.to_string()));
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    ignored_errors.push((directory.clone(), error.to_string()));
                    continue;
                }
            };
            let name = entry.file_name();
            if selected.contains_key(&name) || masked.contains(&name) {
                continue;
            }

            let path = entry.path();
            let metadata = match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    ignored_errors.push((path, error.to_string()));
                    continue;
                }
            };

            if metadata_may_be_dev_null(&metadata) || (metadata.is_file() && metadata.len() == 0) {
                masked.insert(name);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }

            #[cfg(unix)]
            if metadata.mode() & 0o111 == 0 {
                continue;
            }

            selected.insert(name, path);
        }
    }

    GeneratorDiscoveryReport {
        executables: selected.into_values().collect(),
        masked_names: masked.into_iter().collect(),
        ignored_errors,
    }
}

/// Prepare generator argv only after all three output directories have been
/// created successfully. This function does not execute anything: the PID 1
/// caller must still provide C's fork/reset-signals/new-mount-namespace/slave
/// propagation/private-tmp/read-only-remount contract before consuming it.
pub fn prepare_generator_invocations(
    paths: &LookupPaths,
    search_directories: &[PathBuf],
) -> Result<Vec<GeneratorInvocation>, LookupPathsError> {
    Ok(prepare_generator_run(paths, search_directories)?.invocations)
}

/// Prepare generator argv and retain discovery diagnostics for the caller.
pub fn prepare_generator_run(
    paths: &LookupPaths,
    search_directories: &[PathBuf],
) -> Result<PreparedGeneratorRun, LookupPathsError> {
    let discovery = discover_generator_executables(search_directories);
    if discovery.executables.is_empty() {
        return Ok(PreparedGeneratorRun {
            discovery,
            invocations: Vec::new(),
        });
    }

    let [output, early, late] = paths
        .generator_triplet()
        .ok_or(LookupPathsError::MissingGeneratorDirectories)?;
    lookup_paths_mkdir_generator(paths)?;

    let invocations = discovery
        .executables
        .iter()
        .cloned()
        .map(|executable| GeneratorInvocation {
            executable,
            output_directory: output.to_path_buf(),
            early_output_directory: early.to_path_buf(),
            late_output_directory: late.to_path_buf(),
        })
        .collect();

    Ok(PreparedGeneratorRun {
        discovery,
        invocations,
    })
}

pub fn build_generator_environment(
    transient_environment: impl IntoIterator<Item = (String, String)>,
    facts: &GeneratorEnvironmentFacts,
) -> BTreeMap<String, String> {
    let mut environment: BTreeMap<String, String> = transient_environment.into_iter().collect();
    environment.insert(
        "SYSTEMD_SCOPE".to_string(),
        match facts.scope {
            GeneratorRuntimeScope::System => "system",
            GeneratorRuntimeScope::User => "user",
        }
        .to_string(),
    );

    if facts.scope == GeneratorRuntimeScope::System {
        environment.insert(
            "SYSTEMD_IN_INITRD".to_string(),
            u8::from(facts.in_initrd).to_string(),
        );
        if facts.soft_reboots_count > 0 {
            environment.insert(
                "SYSTEMD_SOFT_REBOOTS_COUNT".to_string(),
                facts.soft_reboots_count.to_string(),
            );
        }
        if let Some(first_boot) = facts.first_boot {
            environment.insert(
                "SYSTEMD_FIRST_BOOT".to_string(),
                u8::from(first_boot).to_string(),
            );
        }
    }

    if let Some(virtualization) = &facts.virtualization {
        environment.insert("SYSTEMD_VIRTUALIZATION".to_string(), virtualization.clone());
    }
    if let Some(confidential_virtualization) = &facts.confidential_virtualization {
        environment.insert(
            "SYSTEMD_CONFIDENTIAL_VIRTUALIZATION".to_string(),
            confidential_virtualization.clone(),
        );
    }
    environment.insert(
        "SYSTEMD_ARCHITECTURE".to_string(),
        facts.architecture.clone(),
    );
    environment
}

/// Safely mirror the path acceptance rules used by C's `mkdir_p_label()`.
///
/// `mkdir_p_label()` rejects a path containing a `..` component before it
/// creates parents. Keeping that rejection here prevents a generator path
/// supplied by a higher-level model from escaping its intended directory.
fn generator_path_is_safe(path: &Path) -> bool {
    !path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
}

/// Create a generator directory and any missing parents with C's requested
/// mode. `std::fs::create_dir_all()` uses the platform default mode instead,
/// which can create group- or world-writable directories under a permissive
/// umask.
fn mkdir_generator_path(path: &Path) -> std::io::Result<()> {
    let mut current = PathBuf::new();

    for component in path.components() {
        current.push(component.as_os_str());

        if current.as_os_str().is_empty() || current.is_dir() {
            continue;
        }

        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        builder.mode(GENERATOR_DIRECTORY_MODE);
        match builder.create(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && current.is_dir() => {
                // Match C's `mkdir_p_label()`: a directory created by a
                // concurrent caller between the existence check and mkdir is
                // accepted.
            }
            Err(error) => return Err(error),
        }
    }

    Ok(())
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
        if !generator_path_is_safe(path) {
            if first_error.is_none() {
                first_error = Some(LookupPathsError::UnsafeGeneratorDirectory {
                    path: path.to_path_buf(),
                });
            }
            continue;
        }

        match mkdir_generator_path(path) {
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
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};
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

    fn write_generator(path: &Path, executable: bool) {
        fs::write(path, b"#!/bin/sh\nexit 0\n").expect("must write generator");
        #[cfg(unix)]
        fs::set_permissions(
            path,
            PermissionsExt::from_mode(if executable { 0o755 } else { 0o644 }),
        )
        .expect("must set generator mode");
        #[cfg(not(unix))]
        let _ = executable;
    }

    #[test]
    fn mkdir_requires_all_three_generator_directories() {
        let paths = LookupPaths::default();

        let error = lookup_paths_mkdir_generator(&paths).expect_err("must fail");

        assert_eq!(error, LookupPathsError::MissingGeneratorDirectories);
    }

    #[cfg(unix)]
    #[test]
    fn discovery_matches_c_priority_masking_and_basename_order() {
        let root = temp_root("discovery-priority");
        let high = root.join("high");
        let low = root.join("low");
        fs::create_dir_all(&high).unwrap();
        fs::create_dir_all(&low).unwrap();

        write_generator(&low.join("30-overridden"), true);
        write_generator(&high.join("30-overridden"), true);
        write_generator(&low.join("10-empty-masked"), true);
        fs::write(high.join("10-empty-masked"), b"").unwrap();
        write_generator(&low.join("20-dev-null-masked"), true);
        symlink("/dev/null", high.join("20-dev-null-masked")).unwrap();
        write_generator(&low.join("40-nonexec-does-not-mask"), true);
        write_generator(&high.join("40-nonexec-does-not-mask"), false);
        write_generator(&low.join("90-last"), true);

        let report = discover_generator_executables(&[high.clone(), low.clone()]);
        let selected: Vec<_> = report
            .executables
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            selected,
            ["30-overridden", "40-nonexec-does-not-mask", "90-last"]
        );
        assert_eq!(report.executables[0], high.join("30-overridden"));
        assert_eq!(report.executables[1], low.join("40-nonexec-does-not-mask"));
        assert_eq!(
            report.masked_names,
            [
                OsString::from("10-empty-masked"),
                OsString::from("20-dev-null-masked")
            ]
        );
        assert!(report.ignored_errors.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn preparing_invocations_owns_c_argv_order_and_creates_outputs() {
        let root = temp_root("prepare-invocations");
        let binaries = root.join("binaries");
        fs::create_dir_all(&binaries).unwrap();
        write_generator(&binaries.join("50-example"), true);
        let paths = sample_paths(&root.join("outputs"));

        let invocations = prepare_generator_invocations(&paths, &[binaries]).unwrap();

        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].executable.file_name().unwrap(), "50-example");
        assert_eq!(
            invocations[0].output_directory,
            paths.generator.clone().unwrap()
        );
        assert_eq!(
            invocations[0].early_output_directory,
            paths.generator_early.clone().unwrap()
        );
        assert_eq!(
            invocations[0].late_output_directory,
            paths.generator_late.clone().unwrap()
        );
        assert_eq!(
            invocations[0].argv(),
            [
                &invocations[0].executable,
                &invocations[0].output_directory,
                &invocations[0].early_output_directory,
                &invocations[0].late_output_directory,
            ]
        );
        assert!(invocations[0].output_directory.is_dir());
        assert!(invocations[0].early_output_directory.is_dir());
        assert!(invocations[0].late_output_directory.is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn prepared_generator_run_retains_discovery_diagnostics() {
        let root = temp_root("prepared-run-diagnostics");
        let binaries = root.join("binaries");
        fs::create_dir_all(&binaries).unwrap();
        write_generator(&binaries.join("50-example"), true);
        let paths = sample_paths(&root.join("outputs"));

        let run = prepare_generator_run(&paths, &[binaries]).unwrap();

        assert_eq!(run.discovery.executables.len(), 1);
        assert!(run.discovery.masked_names.is_empty());
        assert!(run.discovery.ignored_errors.is_empty());
        assert_eq!(run.invocations.len(), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn generator_environment_overrides_transient_manager_values_like_c() {
        let facts = GeneratorEnvironmentFacts {
            scope: GeneratorRuntimeScope::System,
            in_initrd: true,
            soft_reboots_count: 2,
            first_boot: Some(false),
            virtualization: Some("vm:kvm".to_string()),
            confidential_virtualization: Some("sev".to_string()),
            architecture: "x86-64".to_string(),
        };
        let environment = build_generator_environment(
            [
                ("KEEP".to_string(), "yes".to_string()),
                ("SYSTEMD_SCOPE".to_string(), "wrong".to_string()),
            ],
            &facts,
        );

        assert_eq!(environment.get("KEEP").map(String::as_str), Some("yes"));
        assert_eq!(
            environment.get("SYSTEMD_SCOPE").map(String::as_str),
            Some("system")
        );
        assert_eq!(
            environment.get("SYSTEMD_IN_INITRD").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            environment
                .get("SYSTEMD_SOFT_REBOOTS_COUNT")
                .map(String::as_str),
            Some("2")
        );
        assert_eq!(
            environment.get("SYSTEMD_FIRST_BOOT").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            environment
                .get("SYSTEMD_VIRTUALIZATION")
                .map(String::as_str),
            Some("vm:kvm")
        );
        assert_eq!(
            environment
                .get("SYSTEMD_CONFIDENTIAL_VIRTUALIZATION")
                .map(String::as_str),
            Some("sev")
        );
        assert_eq!(
            environment.get("SYSTEMD_ARCHITECTURE").map(String::as_str),
            Some("x86-64")
        );
    }

    #[test]
    fn user_generator_environment_omits_system_only_facts() {
        let facts = GeneratorEnvironmentFacts {
            scope: GeneratorRuntimeScope::User,
            in_initrd: true,
            soft_reboots_count: 7,
            first_boot: Some(true),
            virtualization: None,
            confidential_virtualization: None,
            architecture: "aarch64".to_string(),
        };
        let environment = build_generator_environment([], &facts);

        assert_eq!(
            environment.get("SYSTEMD_SCOPE").map(String::as_str),
            Some("user")
        );
        assert!(!environment.contains_key("SYSTEMD_IN_INITRD"));
        assert!(!environment.contains_key("SYSTEMD_SOFT_REBOOTS_COUNT"));
        assert!(!environment.contains_key("SYSTEMD_FIRST_BOOT"));
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
        #[cfg(unix)]
        for path in paths
            .generator_triplet()
            .expect("all generator directories")
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(path)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode & 0o022,
                0,
                "C requests 0755, which never grants group or other write access"
            );
        }
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
    fn mkdir_rejects_parent_traversal_and_continues_gathering() {
        let root = temp_root("mkdir-parent-traversal");
        let mut paths = sample_paths(&root);
        let traversal = root.join("outside").join("..").join("escaped");
        paths.generator_early = Some(traversal.clone());

        let error = lookup_paths_mkdir_generator(&paths).expect_err("must reject traversal");

        assert_eq!(
            error,
            LookupPathsError::UnsafeGeneratorDirectory { path: traversal }
        );
        assert!(paths.generator.as_ref().expect("generator").is_dir());
        assert!(
            paths
                .generator_late
                .as_ref()
                .expect("generator_late")
                .is_dir()
        );
        assert!(!root.join("escaped").exists());
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
