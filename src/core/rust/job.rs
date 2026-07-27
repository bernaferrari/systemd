// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/job.c
//

use std::collections::BTreeSet;
use std::time::Instant;

use crate::ffi::Errno;
use crate::job_tables::{JobResult, JobState, JobType};

pub type Result<T> = std::result::Result<T, JobError>;
pub type JobId = u32;
pub type UnitId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobError {
    ConflictingJobType,
    AlreadyInstalled,
    InvalidDeserializedJobType,
    DuplicateId,
}

impl JobError {
    pub const fn errno(self) -> i32 {
        match self {
            Self::ConflictingJobType => Errno::EEXIST.to_neg_errno(),
            Self::AlreadyInstalled => Errno::EEXIST.to_neg_errno(),
            Self::InvalidDeserializedJobType => Errno::EINVAL.to_neg_errno(),
            Self::DuplicateId => Errno::EEXIST.to_neg_errno(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActiveState {
    Inactive,
    Active,
    Refreshing,
    Reloading,
    Activating,
    Deactivating,
    Failed,
    Maintenance,
}

impl UnitActiveState {
    pub const fn is_active_or_reloading(self) -> bool {
        matches!(self, Self::Active | Self::Refreshing | Self::Reloading)
    }

    pub const fn is_active_or_activating(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Refreshing | Self::Reloading | Self::Activating
        )
    }

    pub const fn is_inactive_or_failed(self) -> bool {
        matches!(self, Self::Inactive | Self::Failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: JobId,
    pub unit: UnitId,
    pub state: JobState,
    pub kind: JobType,
    pub installed: bool,
    pub refuse_late_merge: bool,
    pub irreversible: bool,
    pub ignore_order: bool,
    pub added_timestamp: Instant,
    pub begin_timestamp: Option<Instant>,
    pub activation_details: Option<String>,
    pub result: Option<JobResult>,
}

impl Job {
    pub fn new_raw(unit: impl Into<String>) -> Self {
        Self {
            id: 0,
            unit: unit.into(),
            state: JobState::Waiting,
            kind: JobType::Nop,
            installed: false,
            refuse_late_merge: false,
            irreversible: false,
            ignore_order: false,
            added_timestamp: Instant::now(),
            begin_timestamp: None,
            activation_details: None,
            result: None,
        }
    }

    pub fn new(unit: impl Into<String>, kind: JobType, id: JobId) -> Self {
        let mut job = Self::new_raw(unit);
        job.kind = kind;
        job.id = id;
        job
    }

    pub fn set_state(&mut self, state: JobState) {
        if state == JobState::Running && self.begin_timestamp.is_none() {
            self.begin_timestamp = Some(Instant::now());
        }
        self.state = state;
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct JobRegistry {
    current_job_id: JobId,
    allocated_ids: BTreeSet<JobId>,
}

impl JobRegistry {
    pub(crate) fn has_allocated_ids(&self) -> bool {
        !self.allocated_ids.is_empty()
    }

    pub fn alloc_id(&mut self) -> u32 {
        loop {
            self.current_job_id = self.current_job_id.wrapping_add(1);

            if self.current_job_id == 0 || self.allocated_ids.contains(&self.current_job_id) {
                continue;
            }

            self.allocated_ids.insert(self.current_job_id);
            return self.current_job_id;
        }
    }

    pub fn reserve_existing_id(&mut self, id: u32) -> Result<()> {
        if id == 0 {
            let _ = self.alloc_id();
            return Ok(());
        }

        if !self.allocated_ids.insert(id) {
            return Err(JobError::DuplicateId);
        }

        Ok(())
    }

    pub fn release_id(&mut self, id: JobId) {
        self.allocated_ids.remove(&id);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallDisposition {
    Installed,
    Merged,
    ReplacedConflicting { canceled: Job },
}

fn is_merging_type(kind: JobType) -> bool {
    matches!(
        kind,
        JobType::Start | JobType::VerifyActive | JobType::Stop | JobType::Reload | JobType::Restart
    )
}

pub fn job_type_lookup_merge(a: JobType, b: JobType) -> Result<JobType> {
    use JobType::*;

    if a == b {
        return Ok(a);
    }

    if a == Nop {
        return Ok(b);
    }
    if b == Nop {
        return Ok(a);
    }
    if !is_merging_type(a) || !is_merging_type(b) {
        return Err(JobError::ConflictingJobType);
    }

    let merged = match normalize_pair(a, b) {
        (VerifyActive, Start) => Start,
        (Reload, Start) => ReloadOrStart,
        (Reload, VerifyActive) => Reload,
        (Restart, Start) => Restart,
        (Restart, VerifyActive) => Restart,
        (Restart, Reload) => Restart,
        _ => return Err(JobError::ConflictingJobType),
    };

    Ok(merged)
}

fn normalize_pair(a: JobType, b: JobType) -> (JobType, JobType) {
    if (a as i32) >= (b as i32) {
        (a, b)
    } else {
        (b, a)
    }
}

pub fn job_type_is_mergeable(a: JobType, b: JobType) -> bool {
    job_type_lookup_merge(a, b).is_ok()
}

pub fn job_type_is_conflicting(a: JobType, b: JobType) -> bool {
    a != JobType::Nop && b != JobType::Nop && !job_type_is_mergeable(a, b)
}

pub fn job_type_is_redundant(kind: JobType, state: UnitActiveState) -> bool {
    match kind {
        JobType::Start | JobType::VerifyActive => state.is_active_or_reloading(),
        JobType::Stop => state.is_inactive_or_failed(),
        JobType::Reload | JobType::Restart => false,
        JobType::Nop => true,
        JobType::TryRestart => !state.is_active_or_activating(),
        JobType::TryReload => !state.is_active_or_reloading(),
        JobType::ReloadOrStart => false,
    }
}

pub fn job_type_collapse(kind: JobType, state: UnitActiveState) -> JobType {
    match kind {
        JobType::TryRestart => {
            if state.is_active_or_activating() {
                JobType::Restart
            } else {
                JobType::Nop
            }
        }
        JobType::TryReload => {
            if state.is_active_or_reloading() {
                JobType::Reload
            } else {
                JobType::Nop
            }
        }
        JobType::ReloadOrStart => {
            if state.is_active_or_reloading() {
                JobType::Reload
            } else {
                JobType::Start
            }
        }
        other => other,
    }
}

pub fn job_type_merge_and_collapse(
    current: &mut JobType,
    incoming: JobType,
    state: UnitActiveState,
) -> Result<()> {
    *current = job_type_collapse(job_type_lookup_merge(*current, incoming)?, state);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitDependencyAtom {
    After,
    Before,
}

fn ordering_kind(kind: JobType) -> JobType {
    match kind {
        JobType::TryRestart => JobType::Restart,
        JobType::TryReload => JobType::Reload,
        JobType::ReloadOrStart => JobType::Start,
        other => other,
    }
}

/// Port of `job_compare()` from `src/core/job.c`.
///
/// Returns:
/// - `0`: independent
/// - `>0`: `a` should run after `b`
/// - `<0`: `a` should run before `b`
pub fn job_compare(a: &Job, b: &Job, assume_dep: UnitDependencyAtom) -> i32 {
    let a_kind = ordering_kind(a.kind);
    let b_kind = ordering_kind(b.kind);

    if a_kind == JobType::Nop || b_kind == JobType::Nop {
        return 0;
    }
    if a.ignore_order || b.ignore_order {
        return 0;
    }

    if assume_dep == UnitDependencyAtom::After {
        return -job_compare(b, a, UnitDependencyAtom::Before);
    }

    if matches!(b_kind, JobType::Stop | JobType::Restart) {
        1
    } else {
        -1
    }
}

pub fn job_blocks(a: &Job, b: &Job, assume_dep: UnitDependencyAtom) -> bool {
    job_compare(a, b, assume_dep) > 0
}

pub fn jobs_conflict_on_unit(a: &Job, b: &Job) -> bool {
    a.unit == b.unit && job_type_is_conflicting(a.kind, b.kind)
}

pub fn jobs_may_late_merge(pending: &Job, installed: &Job) -> bool {
    if pending.refuse_late_merge {
        return false;
    }

    if pending.kind == JobType::Reload {
        return false;
    }

    matches!(job_type_lookup_merge(installed.kind, pending.kind), Ok(merged) if merged == installed.kind)
}

pub fn job_merge_into_installed(
    installed: &mut Job,
    incoming: Job,
    unit_state: UnitActiveState,
) -> Result<()> {
    if installed.kind != JobType::Nop {
        job_type_merge_and_collapse(&mut installed.kind, incoming.kind, unit_state)?;
        if installed.activation_details.is_none() {
            installed.activation_details = incoming.activation_details;
        }
    } else {
        installed.kind = incoming.kind;
        if installed.activation_details.is_none() {
            installed.activation_details = incoming.activation_details;
        }
    }

    installed.irreversible |= incoming.irreversible;
    installed.ignore_order |= incoming.ignore_order;
    Ok(())
}

pub fn job_install(
    incoming: Job,
    installed: Option<Job>,
    unit_state: UnitActiveState,
) -> Result<(Job, InstallDisposition)> {
    match installed {
        None => {
            let mut job = incoming;
            job.installed = true;
            Ok((job, InstallDisposition::Installed))
        }
        Some(mut current) => {
            if job_type_is_conflicting(current.kind, incoming.kind) {
                let mut replacement = incoming;
                replacement.installed = true;
                current.installed = false;
                current.result = Some(JobResult::Canceled);
                current.set_state(JobState::Failed);
                return Ok((
                    replacement,
                    InstallDisposition::ReplacedConflicting { canceled: current },
                ));
            }

            if current.state == JobState::Waiting || jobs_may_late_merge(&incoming, &current) {
                job_merge_into_installed(&mut current, incoming, unit_state)?;
                Ok((current, InstallDisposition::Merged))
            } else {
                job_merge_into_installed(&mut current, incoming, unit_state)?;
                current.set_state(JobState::Waiting);
                Ok((current, InstallDisposition::Merged))
            }
        }
    }
}

pub fn job_install_deserialized(job: &mut Job, registry: &mut JobRegistry) -> Result<()> {
    if matches!(job.kind, JobType::ReloadOrStart) {
        return Err(JobError::InvalidDeserializedJobType);
    }

    if job.installed {
        return Err(JobError::AlreadyInstalled);
    }

    if job.id == 0 {
        job.id = registry.alloc_id();
    } else {
        registry.reserve_existing_id(job.id)?;
    }

    job.installed = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_merge_is_commutative_for_supported_pairs() {
        assert_eq!(
            job_type_lookup_merge(JobType::Start, JobType::VerifyActive).unwrap(),
            JobType::Start
        );
        assert_eq!(
            job_type_lookup_merge(JobType::VerifyActive, JobType::Start).unwrap(),
            JobType::Start
        );
        assert_eq!(
            job_type_lookup_merge(JobType::Restart, JobType::Reload).unwrap(),
            JobType::Restart
        );
    }

    #[test]
    fn lookup_merge_rejects_conflicting_pairs() {
        assert_eq!(
            job_type_lookup_merge(JobType::Start, JobType::Stop),
            Err(JobError::ConflictingJobType)
        );
    }

    #[test]
    fn merge_with_nop_is_identity_and_not_conflicting() {
        assert_eq!(
            job_type_lookup_merge(JobType::Start, JobType::Nop).unwrap(),
            JobType::Start
        );
        assert_eq!(
            job_type_lookup_merge(JobType::Nop, JobType::Stop).unwrap(),
            JobType::Stop
        );
        assert!(!job_type_is_conflicting(JobType::Nop, JobType::Stop));
        assert!(!job_type_is_conflicting(JobType::Start, JobType::Nop));
    }

    #[test]
    fn redundancy_rules_match_c_semantics() {
        assert!(job_type_is_redundant(
            JobType::Start,
            UnitActiveState::Active
        ));
        assert!(job_type_is_redundant(
            JobType::Stop,
            UnitActiveState::Failed
        ));
        assert!(!job_type_is_redundant(
            JobType::Restart,
            UnitActiveState::Activating
        ));
        assert!(job_type_is_redundant(
            JobType::Nop,
            UnitActiveState::Inactive
        ));
    }

    #[test]
    fn collapse_turns_try_variants_into_effective_jobs() {
        assert_eq!(
            job_type_collapse(JobType::TryRestart, UnitActiveState::Inactive),
            JobType::Nop
        );
        assert_eq!(
            job_type_collapse(JobType::TryRestart, UnitActiveState::Activating),
            JobType::Restart
        );
        assert_eq!(
            job_type_collapse(JobType::TryReload, UnitActiveState::Active),
            JobType::Reload
        );
        assert_eq!(
            job_type_collapse(JobType::ReloadOrStart, UnitActiveState::Inactive),
            JobType::Start
        );
    }

    #[test]
    fn late_merge_refuses_reload_and_explicit_refusal() {
        let mut pending = Job::new("a.service", JobType::Start, 1);
        let mut running = Job::new("a.service", JobType::Start, 2);
        running.installed = true;
        running.state = JobState::Running;

        assert!(jobs_may_late_merge(&pending, &running));
        pending.refuse_late_merge = true;
        assert!(!jobs_may_late_merge(&pending, &running));

        let reload = Job::new("a.service", JobType::Reload, 3);
        assert!(!jobs_may_late_merge(&reload, &running));
    }

    #[test]
    fn install_merges_flags_and_keeps_oldest_activation_details() {
        let mut installed = Job::new("a.service", JobType::Start, 1);
        installed.installed = true;
        installed.activation_details = Some("older".into());

        let mut incoming = Job::new("a.service", JobType::VerifyActive, 2);
        incoming.irreversible = true;
        incoming.ignore_order = true;
        incoming.activation_details = Some("newer".into());

        let (merged, disposition) =
            job_install(incoming, Some(installed), UnitActiveState::Active).unwrap();
        assert_eq!(disposition, InstallDisposition::Merged);
        assert_eq!(merged.kind, JobType::Start);
        assert_eq!(merged.activation_details.as_deref(), Some("older"));
        assert!(merged.irreversible);
        assert!(merged.ignore_order);
    }

    #[test]
    fn install_can_promote_installed_nop_to_real_job_kind() {
        let mut installed = Job::new("a.service", JobType::Nop, 1);
        installed.installed = true;
        installed.state = JobState::Waiting;

        let incoming = Job::new("a.service", JobType::Start, 2);
        let (merged, disposition) =
            job_install(incoming, Some(installed), UnitActiveState::Inactive).unwrap();
        assert_eq!(disposition, InstallDisposition::Merged);
        assert_eq!(merged.kind, JobType::Start);
    }

    #[test]
    fn install_replaces_conflicting_job() {
        let mut current = Job::new("a.service", JobType::Stop, 1);
        current.installed = true;
        current.state = JobState::Running;

        let incoming = Job::new("a.service", JobType::Start, 2);
        let (replacement, disposition) =
            job_install(incoming, Some(current), UnitActiveState::Inactive).unwrap();
        let InstallDisposition::ReplacedConflicting { canceled } = disposition else {
            panic!("expected conflicting replacement");
        };
        assert!(replacement.installed);
        assert_eq!(replacement.result, None);
        assert_eq!(replacement.state, JobState::Waiting);
        assert!(!canceled.installed);
        assert_eq!(canceled.id, 1);
        assert_eq!(canceled.result, Some(JobResult::Canceled));
        assert_eq!(canceled.state, JobState::Failed);
    }

    #[test]
    fn set_state_running_sets_begin_timestamp_once() {
        let mut job = Job::new("a.service", JobType::Start, 1);
        assert!(job.begin_timestamp.is_none());
        job.set_state(JobState::Running);
        let first = job.begin_timestamp;
        assert!(first.is_some());
        job.set_state(JobState::Running);
        assert_eq!(job.begin_timestamp, first);
    }

    #[test]
    fn same_unit_conflict_detection_matches_c_intent() {
        let a = Job::new("a.service", JobType::Start, 1);
        let b = Job::new("a.service", JobType::Stop, 2);
        let c = Job::new("b.service", JobType::Stop, 3);
        assert!(jobs_conflict_on_unit(&a, &b));
        assert!(!jobs_conflict_on_unit(&a, &c));
    }

    #[test]
    fn job_compare_orders_stop_before_start_for_before_dependency() {
        let start_a = Job::new("a.service", JobType::Start, 1);
        let stop_b = Job::new("b.service", JobType::Stop, 2);

        assert!(job_compare(&start_a, &stop_b, UnitDependencyAtom::Before) > 0);
        assert!(job_compare(&stop_b, &start_a, UnitDependencyAtom::Before) < 0);
    }

    #[test]
    fn job_compare_respects_after_dependency_direction() {
        let start_a = Job::new("a.service", JobType::Start, 1);
        let start_b = Job::new("b.service", JobType::Start, 2);

        assert!(job_compare(&start_b, &start_a, UnitDependencyAtom::After) > 0);
        assert!(job_blocks(&start_b, &start_a, UnitDependencyAtom::After));
    }

    #[test]
    fn deserialized_install_allocates_and_reserves_ids() {
        let mut registry = JobRegistry::default();

        let mut first = Job::new("a.service", JobType::Start, 0);
        job_install_deserialized(&mut first, &mut registry).unwrap();
        assert!(first.installed);
        assert_ne!(first.id, 0);

        let mut duplicate = Job::new("b.service", JobType::Stop, first.id);
        assert_eq!(
            job_install_deserialized(&mut duplicate, &mut registry),
            Err(JobError::DuplicateId)
        );
    }

    #[test]
    fn job_registry_skips_zero_and_wraps() {
        let mut registry = JobRegistry {
            current_job_id: u32::MAX,
            allocated_ids: BTreeSet::from([1_u32]),
        };

        assert_eq!(registry.alloc_id(), 2);
    }
}
