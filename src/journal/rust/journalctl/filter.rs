// SPDX-License-Identifier: LGPL-2.1-or-later

use super::model::{JournalctlArgs, ParseArgvError};
use crate::journalctl_filter::{
    FilterBuildError, excluded_syslog_identifier_set, facility_match_terms, priority_match_terms,
    split_match_terms, syslog_identifier_terms,
};
use nix::libc;
use std::collections::BTreeSet;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use systemd_shared_rs::exec_util::is_executable;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterPlan {
    pub scope: Option<ScopePlan>,
    pub unit_matches: Option<UnitMatchPlan>,
    pub transport: Option<TransportFilter>,
    pub priority_terms: Vec<String>,
    pub facility_terms: Vec<String>,
    pub identifier_terms: Vec<String>,
    pub exclude_identifiers: BTreeSet<String>,
    pub match_groups: Vec<Vec<FilterMatchTerm>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopePlan {
    Boot { id: Option<[u8; 16]>, offset: i32 },
    Invocation { id: Option<[u8; 16]>, offset: i32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitMatchPlan {
    pub system_units: Vec<String>,
    pub user_units: Vec<String>,
    pub coredump_uid_relaxed: bool,
    pub mangle_warn: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportFilter {
    Kernel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterMatchTerm {
    Field(String),
    AbsolutePath(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterBackendOp {
    FlushMatches,
    AddScopeInvocation { id: Option<[u8; 16]>, offset: i32 },
    AddScopeBoot { id: Option<[u8; 16]>, offset: i32 },
    AddUnitMatches(UnitMatchPlan),
    AddTransportKernel,
    AddMatch(String),
    AddDisjunction,
    AddConjunction,
    SetExcludeIdentifiers(BTreeSet<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterApplyError {
    UnresolvedAbsolutePathTerm,
    BackendFailure(&'static str),
}

pub trait FilterBackend {
    fn flush_matches(&mut self) -> Result<(), FilterApplyError>;
    fn add_scope_invocation(
        &mut self,
        id: Option<[u8; 16]>,
        offset: i32,
    ) -> Result<(), FilterApplyError>;
    fn add_scope_boot(&mut self, id: Option<[u8; 16]>, offset: i32)
    -> Result<(), FilterApplyError>;
    fn add_unit_matches(&mut self, units: &UnitMatchPlan) -> Result<(), FilterApplyError>;
    fn add_transport_kernel(&mut self) -> Result<(), FilterApplyError>;
    fn add_match(&mut self, term: &str) -> Result<(), FilterApplyError>;
    fn add_disjunction(&mut self) -> Result<(), FilterApplyError>;
    fn add_conjunction(&mut self) -> Result<(), FilterApplyError>;
    fn set_exclude_identifiers(
        &mut self,
        identifiers: &BTreeSet<String>,
    ) -> Result<(), FilterApplyError>;
}

#[derive(Debug, Default)]
pub struct RecordingFilterBackend {
    ops: Vec<FilterBackendOp>,
}

impl RecordingFilterBackend {
    fn into_ops(self) -> Vec<FilterBackendOp> {
        self.ops
    }
}

impl FilterBackend for RecordingFilterBackend {
    fn flush_matches(&mut self) -> Result<(), FilterApplyError> {
        self.ops.push(FilterBackendOp::FlushMatches);
        Ok(())
    }

    fn add_scope_invocation(
        &mut self,
        id: Option<[u8; 16]>,
        offset: i32,
    ) -> Result<(), FilterApplyError> {
        self.ops
            .push(FilterBackendOp::AddScopeInvocation { id, offset });
        Ok(())
    }

    fn add_scope_boot(
        &mut self,
        id: Option<[u8; 16]>,
        offset: i32,
    ) -> Result<(), FilterApplyError> {
        self.ops.push(FilterBackendOp::AddScopeBoot { id, offset });
        Ok(())
    }

    fn add_unit_matches(&mut self, units: &UnitMatchPlan) -> Result<(), FilterApplyError> {
        self.ops
            .push(FilterBackendOp::AddUnitMatches(units.clone()));
        Ok(())
    }

    fn add_transport_kernel(&mut self) -> Result<(), FilterApplyError> {
        self.ops.push(FilterBackendOp::AddTransportKernel);
        Ok(())
    }

    fn add_match(&mut self, term: &str) -> Result<(), FilterApplyError> {
        self.ops.push(FilterBackendOp::AddMatch(term.to_string()));
        Ok(())
    }

    fn add_disjunction(&mut self) -> Result<(), FilterApplyError> {
        self.ops.push(FilterBackendOp::AddDisjunction);
        Ok(())
    }

    fn add_conjunction(&mut self) -> Result<(), FilterApplyError> {
        self.ops.push(FilterBackendOp::AddConjunction);
        Ok(())
    }

    fn set_exclude_identifiers(
        &mut self,
        identifiers: &BTreeSet<String>,
    ) -> Result<(), FilterApplyError> {
        self.ops
            .push(FilterBackendOp::SetExcludeIdentifiers(identifiers.clone()));
        Ok(())
    }
}

fn apply_filter_plan<B: FilterBackend>(
    plan: &FilterPlan,
    backend: &mut B,
) -> Result<(), FilterApplyError> {
    backend.flush_matches()?;

    if let Some(scope) = &plan.scope {
        match scope {
            ScopePlan::Invocation { id, offset } => backend.add_scope_invocation(*id, *offset)?,
            ScopePlan::Boot { id, offset } => backend.add_scope_boot(*id, *offset)?,
        }
        backend.add_conjunction()?;
    }

    if let Some(units) = &plan.unit_matches {
        backend.add_unit_matches(units)?;
        backend.add_conjunction()?;
    }

    if matches!(plan.transport, Some(TransportFilter::Kernel)) {
        backend.add_transport_kernel()?;
        backend.add_conjunction()?;
    }

    if !plan.identifier_terms.is_empty() {
        for term in &plan.identifier_terms {
            backend.add_match(term)?;
            backend.add_disjunction()?;
        }
        backend.add_conjunction()?;
    }

    backend.set_exclude_identifiers(&plan.exclude_identifiers)?;

    if !plan.priority_terms.is_empty() {
        for term in &plan.priority_terms {
            backend.add_match(term)?;
        }
        backend.add_conjunction()?;
    }

    if !plan.facility_terms.is_empty() {
        for term in &plan.facility_terms {
            backend.add_match(term)?;
        }
        backend.add_conjunction()?;
    }

    for (idx, group) in plan.match_groups.iter().enumerate() {
        for term in group {
            match term {
                FilterMatchTerm::Field(value) => backend.add_match(value)?,
                FilterMatchTerm::AbsolutePath(_) => {
                    return Err(FilterApplyError::UnresolvedAbsolutePathTerm);
                }
            }
        }

        if idx + 1 < plan.match_groups.len() {
            backend.add_disjunction()?;
        }
    }

    Ok(())
}

pub(crate) fn replay_filter_plan(
    plan: &FilterPlan,
) -> Result<Vec<FilterBackendOp>, FilterApplyError> {
    let mut backend = RecordingFilterBackend::default();
    apply_filter_plan(plan, &mut backend)?;
    Ok(backend.into_ops())
}

pub(crate) fn map_filter_build_error(error: FilterBuildError) -> ParseArgvError {
    match error {
        FilterBuildError::InvalidFacility(_) => ParseArgvError::Invalid("invalid --facility value"),
        FilterBuildError::MisplacedPlusSeparator => {
            ParseArgvError::Invalid("\"+\" can only be used between terms")
        }
        FilterBuildError::AbsolutePathWithSourceConflict => ParseArgvError::Invalid(
            "an extra path in match filter is currently not supported with --root, --image, or -M/--machine",
        ),
        FilterBuildError::InvalidAbsolutePath(message) => ParseArgvError::Invalid(message),
    }
}

pub(crate) fn map_filter_apply_error(error: FilterApplyError) -> ParseArgvError {
    match error {
        FilterApplyError::UnresolvedAbsolutePathTerm => {
            ParseArgvError::Invalid("internal filter plan contains unresolved absolute path term")
        }
        FilterApplyError::BackendFailure(message) => ParseArgvError::Invalid(message),
    }
}

pub(crate) const BOOT_ID_NULL_MATCH: &str = "_BOOT_ID=00000000000000000000000000000000";
pub(crate) const TASK_COMM_LEN: usize = 16;

pub(crate) fn truncate_task_comm(name: &str) -> String {
    let max = TASK_COMM_LEN - 1;
    if name.len() <= max {
        return name.to_string();
    }

    let mut end = max;
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_string()
}

fn parse_shebang_interpreter(path: &Path) -> Option<String> {
    let content = std::fs::read(path).ok()?;
    if !content.starts_with(b"#!") {
        return None;
    }

    let newline = content
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(content.len());
    let line = std::str::from_utf8(&content[2..newline]).ok()?.trim();
    if line.is_empty() {
        return None;
    }

    line.split_whitespace().next().map(str::to_string)
}

pub(crate) fn current_boot_id_match_term() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let compact = raw
            .trim()
            .chars()
            .filter(|c| *c != '-')
            .collect::<String>()
            .to_ascii_lowercase();
        if compact.len() == 32 && compact.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(format!("_BOOT_ID={compact}"));
        }
    }

    None
}

fn kernel_device_parent_terms_from_syspath(mut syspath: PathBuf) -> Vec<String> {
    let mut terms = Vec::new();

    loop {
        let subsystem_link = syspath.join("subsystem");
        if let (Ok(target), Some(sysname)) = (
            std::fs::read_link(&subsystem_link),
            syspath.file_name().and_then(|s| s.to_str()),
        ) && let Some(subsystem) = target.file_name().and_then(|s| s.to_str())
        {
            terms.push(format!("_KERNEL_DEVICE=+{subsystem}:{sysname}"));

            if let Ok(raw_devnum) = std::fs::read_to_string(syspath.join("dev"))
                && let Some((major, minor)) = raw_devnum.trim().split_once(':')
                && major.chars().all(|c| c.is_ascii_digit())
                && minor.chars().all(|c| c.is_ascii_digit())
            {
                let prefix = if subsystem == "block" { 'b' } else { 'c' };
                terms.push(format!("_KERNEL_DEVICE={prefix}{major}:{minor}"));
            }
        }

        let Some(parent) = syspath.parent() else {
            break;
        };
        if parent == syspath {
            break;
        }
        syspath = parent.to_path_buf();
    }

    terms
}

fn expand_executable_path(path: &Path) -> Vec<FilterMatchTerm> {
    let mut terms = Vec::new();

    if let Some(interpreter) = parse_shebang_interpreter(path) {
        if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
            terms.push(FilterMatchTerm::Field(format!(
                "_COMM={}",
                truncate_task_comm(file_name)
            )));
        }

        let interpreter_path = Path::new(&interpreter);
        if std::fs::symlink_metadata(interpreter_path)
            .map(|m| !m.file_type().is_symlink())
            .unwrap_or(false)
        {
            terms.push(FilterMatchTerm::Field(format!("_EXE={interpreter}")));
        }

        return terms;
    }

    terms.push(FilterMatchTerm::Field(format!(
        "_EXE={}",
        path.to_string_lossy()
    )));
    terms
}

fn expand_device_path(path: &Path, st_rdev: u64, is_block: bool) -> Vec<FilterMatchTerm> {
    let mut terms = Vec::new();

    let major = libc::major(st_rdev as libc::dev_t);
    let minor = libc::minor(st_rdev as libc::dev_t);
    let prefix = if is_block { 'b' } else { 'c' };
    terms.push(FilterMatchTerm::Field(format!(
        "_KERNEL_DEVICE={prefix}{major}:{minor}"
    )));

    let sysfs_node = if is_block {
        Path::new("/sys/dev/block").join(format!("{major}:{minor}"))
    } else {
        Path::new("/sys/dev/char").join(format!("{major}:{minor}"))
    };
    if let Ok(canonical) = std::fs::canonicalize(sysfs_node) {
        terms.extend(
            kernel_device_parent_terms_from_syspath(canonical)
                .into_iter()
                .map(FilterMatchTerm::Field),
        );
    }

    terms.push(FilterMatchTerm::Field(
        current_boot_id_match_term().unwrap_or_else(|| BOOT_ID_NULL_MATCH.to_string()),
    ));

    let _ = path;
    terms
}

fn expand_absolute_path_match(path: &str) -> Result<Vec<FilterMatchTerm>, FilterBuildError> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|_| FilterBuildError::InvalidAbsolutePath("couldn't canonicalize path"))?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|_| FilterBuildError::InvalidAbsolutePath("couldn't canonicalize path"))?;
    let file_type = metadata.file_type();

    if file_type.is_file() && is_executable(&canonical) {
        return Ok(expand_executable_path(&canonical));
    }

    if file_type.is_char_device() {
        return Ok(expand_device_path(&canonical, metadata.rdev(), false));
    }

    if file_type.is_block_device() {
        return Ok(expand_device_path(&canonical, metadata.rdev(), true));
    }

    Err(FilterBuildError::InvalidAbsolutePath(
        "file is neither a device node nor executable",
    ))
}

// Mirrors the filter input assembly role of add_filters() in
// src/journal/journalctl-filter.c for parser-derived state.
pub fn build_filter_plan(parsed: &JournalctlArgs) -> Result<FilterPlan, FilterBuildError> {
    let priority_terms = priority_match_terms(parsed.priorities_mask);
    let facility_terms = facility_match_terms(&parsed.facilities)?;
    let identifier_terms = syslog_identifier_terms(&parsed.syslog_identifier);
    let exclude_identifiers = excluded_syslog_identifier_set(&parsed.exclude_identifier);
    let literal_groups = split_match_terms(&parsed.positional_matches)?;

    let has_external_source =
        parsed.root.is_some() || parsed.image.is_some() || parsed.machine.is_some();
    let match_groups = literal_groups
        .into_iter()
        .map(|group| {
            let mut expanded = Vec::new();
            for term in group {
                if term.starts_with('/') {
                    if has_external_source {
                        return Err(FilterBuildError::AbsolutePathWithSourceConflict);
                    } else {
                        expanded.extend(expand_absolute_path_match(&term)?);
                    }
                } else {
                    expanded.push(FilterMatchTerm::Field(term));
                }
            }
            Ok(expanded)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let scope = if parsed.invocation {
        Some(ScopePlan::Invocation {
            id: parsed.invocation_id,
            offset: parsed.invocation_offset,
        })
    } else if parsed.boot > 0 {
        Some(ScopePlan::Boot {
            id: parsed.boot_id,
            offset: parsed.boot_offset,
        })
    } else {
        None
    };

    let unit_matches = if parsed.invocation {
        None
    } else if !parsed.system_units.is_empty() || !parsed.user_units.is_empty() {
        let coredump_uid_relaxed = parsed.directory.is_some()
            || parsed.root.is_some()
            || parsed.file_stdin
            || !parsed.file.is_empty()
            || parsed.machine.is_some();

        Some(UnitMatchPlan {
            system_units: parsed.system_units.clone(),
            user_units: parsed.user_units.clone(),
            coredump_uid_relaxed,
            mangle_warn: !parsed.quiet,
        })
    } else {
        None
    };

    let transport = if parsed.dmesg {
        Some(TransportFilter::Kernel)
    } else {
        None
    };

    Ok(FilterPlan {
        scope,
        unit_matches,
        transport,
        priority_terms,
        facility_terms,
        identifier_terms,
        exclude_identifiers,
        match_groups,
    })
}
