// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/transaction.c
//
// Safe transaction graph planner inspired by systemd's job transaction engine.

use std::collections::{BTreeMap, BTreeSet};

use crate::ffi::Errno;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobType {
    Start,
    VerifyActive,
    Stop,
    Reload,
    Restart,
    TryRestart,
    Nop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobMode {
    Replace,
    ReplaceIrreversibly,
    Fail,
    Lenient,
    Isolate,
    Flush,
    IgnoreDependencies,
    IgnoreRequirements,
    Triggering,
    RestartDependencies,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitState {
    Inactive,
    Active,
    Activating,
    Failed,
    Maintenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSpec {
    pub id: String,
    pub state: UnitState,
    pub ignore_on_isolate: bool,
    pub installed_job: Option<JobType>,
    /// Requires= and BindsTo= pull in Start jobs that matter.
    pub deps_start: Vec<String>,
    /// Requisite= pulls in VerifyActive rather than starting the unit.
    pub deps_verify: Vec<String>,
    /// Wants= and Upholds= pull in best-effort Start jobs.
    pub deps_start_ignored: Vec<String>,
    /// Reverse Requires=/Requisite=/BindsTo=/PartOf= stop propagation.
    pub deps_stop: Vec<String>,
    /// Direct Conflicts= entries pulled in as Stop when this unit starts.
    pub conflicts: Vec<String>,
    /// Reverse Conflicts= entries pulled in as best-effort Stop jobs.
    pub conflicts_ignored: Vec<String>,
    pub deps_reload: Vec<String>,
    pub before: Vec<String>,
    pub after: Vec<String>,
    pub triggered_by: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: usize,
    pub unit: String,
    pub job_type: JobType,
    pub matters_to_anchor: bool,
    pub irreversible: bool,
    pub ignore_order: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Dependency {
    subject: usize,
    object: usize,
    matters: bool,
    conflicts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedTransaction {
    pub jobs: Vec<Job>,
    pub anchor_job: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionError {
    MissingUnit(String),
    UnsatisfiedDependency(String, String),
    InvalidMode(String),
    DuplicateAnchor,
    CyclicOrder,
    ConflictingJobs(String),
    Destructive(String),
}

impl TransactionError {
    pub const fn errno(&self) -> i32 {
        match self {
            Self::MissingUnit(_) | Self::UnsatisfiedDependency(_, _) => {
                Errno::ENOENT.to_neg_errno()
            }
            Self::InvalidMode(_) => Errno::EINVAL.to_neg_errno(),
            Self::DuplicateAnchor | Self::ConflictingJobs(_) | Self::Destructive(_) => {
                Errno::EEXIST.to_neg_errno()
            }
            Self::CyclicOrder => Errno::EDEADLK.to_neg_errno(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    units: BTreeMap<String, UnitSpec>,
    jobs: BTreeMap<usize, Job>,
    jobs_by_unit: BTreeMap<String, Vec<usize>>,
    deps: Vec<Dependency>,
    next_id: usize,
    anchor_job: Option<usize>,
    irreversible: bool,
    pub id: u64,
}

impl Transaction {
    pub fn new(
        units: impl IntoIterator<Item = UnitSpec>,
        irreversible: bool,
        id: u64,
    ) -> Result<Self, TransactionError> {
        let units = units
            .into_iter()
            .map(|unit| (unit.id.clone(), unit))
            .collect();
        Ok(Self {
            units,
            jobs: BTreeMap::new(),
            jobs_by_unit: BTreeMap::new(),
            deps: Vec::new(),
            next_id: 1,
            anchor_job: None,
            irreversible,
            id,
        })
    }

    fn unit(&self, unit: &str) -> Result<&UnitSpec, TransactionError> {
        self.units
            .get(unit)
            .ok_or_else(|| TransactionError::MissingUnit(unit.to_string()))
    }

    fn add_one_job(&mut self, job_type: JobType, unit: &str) -> usize {
        if let Some(existing) = self.jobs_by_unit.get(unit).and_then(|ids| {
            ids.iter().copied().find(|id| {
                self.jobs
                    .get(id)
                    .is_some_and(|job| job.job_type == job_type)
            })
        }) {
            return existing;
        }

        let id = self.next_id;
        self.next_id += 1;
        self.jobs.insert(
            id,
            Job {
                id,
                unit: unit.to_string(),
                job_type,
                matters_to_anchor: false,
                irreversible: self.irreversible,
                ignore_order: false,
            },
        );
        self.jobs_by_unit
            .entry(unit.to_string())
            .or_default()
            .push(id);
        id
    }

    fn add_dependency(&mut self, subject: usize, object: usize, matters: bool, conflicts: bool) {
        self.deps.push(Dependency {
            subject,
            object,
            matters,
            conflicts,
        });
    }

    pub fn add_job_and_dependencies(
        &mut self,
        job_type: JobType,
        unit: &str,
        by: Option<usize>,
        matters: bool,
        conflicts: bool,
        ignore_order: bool,
    ) -> Result<usize, TransactionError> {
        self.add_job_and_dependencies_with_flags(
            job_type,
            unit,
            by,
            matters,
            conflicts,
            ignore_order,
            false,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the explicit flags mirror transaction_add_job_and_dependencies() and keep call-site policy choices reviewable"
    )]
    pub fn add_job_and_dependencies_with_flags(
        &mut self,
        job_type: JobType,
        unit: &str,
        by: Option<usize>,
        matters: bool,
        conflicts: bool,
        ignore_order: bool,
        ignore_requirements: bool,
    ) -> Result<usize, TransactionError> {
        self.add_job_and_dependencies_with_policies(
            job_type,
            unit,
            by,
            matters,
            conflicts,
            ignore_order,
            ignore_requirements,
            false,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the explicit policies mirror systemd's transaction recursion and avoid obscuring propagation semantics in a catch-all options object"
    )]
    pub fn add_job_and_dependencies_with_policies(
        &mut self,
        job_type: JobType,
        unit: &str,
        by: Option<usize>,
        matters: bool,
        conflicts: bool,
        ignore_order: bool,
        ignore_requirements: bool,
        restart_reverse_dependencies: bool,
    ) -> Result<usize, TransactionError> {
        let unit_spec = self.unit(unit)?.clone();
        let already_exists = self.jobs_by_unit.get(unit).is_some_and(|ids| {
            ids.iter().any(|id| {
                self.jobs
                    .get(id)
                    .is_some_and(|job| job.job_type == job_type)
            })
        });
        let job_id = self.add_one_job(job_type, unit);

        if let Some(job) = self.jobs.get_mut(&job_id) {
            job.ignore_order |= ignore_order;
        }

        if let Some(parent) = by {
            self.add_dependency(parent, job_id, matters, conflicts);
        } else if self.anchor_job.replace(job_id).is_some() {
            return Err(TransactionError::DuplicateAnchor);
        }

        if already_exists || ignore_requirements || job_type == JobType::Nop {
            return Ok(job_id);
        }

        let (required_dependencies, best_effort_dependencies) = match job_type {
            JobType::Start | JobType::Restart => (
                unit_spec.deps_start.clone(),
                unit_spec.deps_start_ignored.clone(),
            ),
            JobType::Stop => (unit_spec.deps_stop.clone(), Vec::new()),
            JobType::Reload => (Vec::new(), Vec::new()),
            JobType::VerifyActive | JobType::TryRestart | JobType::Nop => (Vec::new(), Vec::new()),
        };

        for dependency in required_dependencies {
            let propagated_type = match job_type {
                JobType::Restart => JobType::Start,
                other => other,
            };
            let _ = self.add_job_and_dependencies_with_policies(
                propagated_type,
                &dependency,
                Some(job_id),
                true,
                false,
                ignore_order,
                false,
                false,
            )?;
        }

        for dependency in best_effort_dependencies {
            let propagated_type = match job_type {
                JobType::Restart => JobType::Start,
                other => other,
            };
            let _ = self.add_job_and_dependencies_with_policies(
                propagated_type,
                &dependency,
                Some(job_id),
                false,
                false,
                ignore_order,
                false,
                false,
            );
        }

        if matches!(job_type, JobType::Start | JobType::Restart) {
            for dependency in unit_spec.deps_verify {
                let _ = self.add_job_and_dependencies_with_policies(
                    JobType::VerifyActive,
                    &dependency,
                    Some(job_id),
                    true,
                    false,
                    ignore_order,
                    false,
                    false,
                )?;
            }
        }

        if job_type == JobType::Restart
            || (job_type == JobType::Start && restart_reverse_dependencies)
        {
            for dependency in &unit_spec.deps_stop {
                let dependency_state = self.unit(dependency)?.state;
                if !matches!(dependency_state, UnitState::Active | UnitState::Activating) {
                    continue;
                }
                let _ = self.add_job_and_dependencies_with_policies(
                    JobType::Restart,
                    dependency,
                    Some(job_id),
                    true,
                    false,
                    ignore_order,
                    false,
                    false,
                )?;
            }
        }

        if matches!(job_type, JobType::Start | JobType::Restart) {
            for conflict in unit_spec.conflicts {
                let _ = self.add_job_and_dependencies_with_flags(
                    JobType::Stop,
                    &conflict,
                    Some(job_id),
                    true,
                    true,
                    ignore_order,
                    false,
                )?;
            }

            for conflict in unit_spec.conflicts_ignored {
                let _ = self.add_job_and_dependencies_with_flags(
                    JobType::Stop,
                    &conflict,
                    Some(job_id),
                    false,
                    false,
                    ignore_order,
                    false,
                );
            }
        }

        if job_type == JobType::Reload {
            for dependency in unit_spec.deps_reload {
                if !self
                    .units
                    .get(&dependency)
                    .is_some_and(|unit| unit.state == UnitState::Active)
                {
                    continue;
                }
                let _ = self.add_job_and_dependencies_with_flags(
                    JobType::Reload,
                    &dependency,
                    Some(job_id),
                    false,
                    false,
                    ignore_order,
                    false,
                );
            }
        }

        Ok(job_id)
    }

    fn outgoing(&self, job_id: usize) -> impl Iterator<Item = &Dependency> {
        self.deps.iter().filter(move |dep| dep.subject == job_id)
    }

    fn incoming(&self, job_id: usize) -> impl Iterator<Item = &Dependency> {
        self.deps.iter().filter(move |dep| dep.object == job_id)
    }

    fn ordering_successors(&self, job_id: usize) -> Vec<usize> {
        let Some(job) = self.jobs.get(&job_id) else {
            return Vec::new();
        };
        if job.ignore_order {
            return Vec::new();
        }
        let Some(unit) = self.units.get(&job.unit) else {
            return Vec::new();
        };

        let mut next = BTreeSet::new();
        for other in self.jobs.values() {
            if other.id == job_id {
                continue;
            }
            let Some(other_unit) = self.units.get(&other.unit) else {
                continue;
            };

            let is_after =
                unit.after.contains(&other.unit) || other_unit.before.contains(&job.unit);
            if is_after && transaction_job_compare(job, other, OrderingRelation::After) < 0 {
                next.insert(other.id);
            }

            let is_before =
                unit.before.contains(&other.unit) || other_unit.after.contains(&job.unit);
            if is_before && transaction_job_compare(job, other, OrderingRelation::Before) < 0 {
                next.insert(other.id);
            }
        }

        next.into_iter().collect()
    }

    fn delete_job(&mut self, job_id: usize, delete_dependencies: bool) {
        let Some(job) = self.jobs.remove(&job_id) else {
            return;
        };

        if let Some(entries) = self.jobs_by_unit.get_mut(&job.unit) {
            entries.retain(|id| *id != job_id);
            if entries.is_empty() {
                self.jobs_by_unit.remove(&job.unit);
            }
        }

        let dependents: Vec<usize> = self
            .deps
            .iter()
            .filter(|dep| dep.subject == job_id || dep.object == job_id)
            .filter(|dep| delete_dependencies && dep.object == job_id && dep.matters)
            .map(|dep| dep.subject)
            .collect();

        self.deps
            .retain(|dep| dep.subject != job_id && dep.object != job_id);
        for dependent in dependents {
            self.delete_job(dependent, true);
        }
    }

    fn find_jobs_that_matter_to_anchor(&mut self) {
        let Some(anchor) = self.anchor_job else {
            return;
        };

        let mut stack = vec![anchor];
        let mut seen = BTreeSet::new();
        while let Some(job_id) = stack.pop() {
            if !seen.insert(job_id) {
                continue;
            }
            if let Some(job) = self.jobs.get_mut(&job_id) {
                job.matters_to_anchor = true;
            }
            let next: Vec<usize> = self
                .outgoing(job_id)
                .filter(|dep| dep.matters)
                .map(|dep| dep.object)
                .collect();
            stack.extend(next);
        }
    }

    fn minimize_impact(&mut self, mode: JobMode) -> Result<(), TransactionError> {
        if !matches!(mode, JobMode::Fail | JobMode::Lenient) {
            return Ok(());
        }

        loop {
            let candidate = self.jobs.values().find_map(|job| {
                let unit = self.units.get(&job.unit)?;
                let stops_running = job.job_type == JobType::Stop
                    && matches!(unit.state, UnitState::Active | UnitState::Activating);
                let changes_existing = unit
                    .installed_job
                    .is_some_and(|installed| job_types_conflict(job.job_type, installed));
                (stops_running || changes_existing).then_some((
                    job.id,
                    job.matters_to_anchor,
                    job.unit.clone(),
                    job.job_type,
                ))
            });

            let Some((job_id, matters, unit_id, job_type)) = candidate else {
                return Ok(());
            };
            if matters {
                return Err(TransactionError::Destructive(format!(
                    "{unit_id}/{job_type:?}"
                )));
            }
            self.delete_job(job_id, true);
        }
    }

    fn collect_garbage(&mut self) {
        loop {
            let removable = self.jobs.values().find_map(|job| {
                (Some(job.id) != self.anchor_job && self.incoming(job.id).next().is_none())
                    .then_some(job.id)
            });
            let Some(job_id) = removable else {
                break;
            };
            self.delete_job(job_id, true);
        }
    }

    fn verify_order(&mut self) -> Result<(), TransactionError> {
        loop {
            let mut visiting = BTreeSet::new();
            let mut visited = BTreeSet::new();
            let mut cycle = None;

            for job_id in self.jobs.keys().copied().collect::<Vec<_>>() {
                if dfs_cycle(self, job_id, &mut visiting, &mut visited, &mut cycle) {
                    break;
                }
            }

            let Some(cycle_jobs) = cycle else {
                return Ok(());
            };

            if let Some(drop_id) = cycle_jobs.iter().copied().find(|job_id| {
                self.jobs
                    .get(job_id)
                    .is_some_and(|job| !job.matters_to_anchor)
            }) {
                let unit = self.jobs.get(&drop_id).map(|job| job.unit.clone()).unwrap();
                if let Some(ids) = self.jobs_by_unit.get(&unit).cloned() {
                    for id in ids {
                        self.delete_job(id, true);
                    }
                }
                continue;
            }

            return Err(TransactionError::CyclicOrder);
        }
    }

    fn verify_conflicts(&mut self) -> Result<(), TransactionError> {
        loop {
            let mut action: Option<Result<usize, TransactionError>> = None;

            for job in self.jobs.values() {
                if !matches!(
                    job.job_type,
                    JobType::Start | JobType::Restart | JobType::TryRestart
                ) {
                    continue;
                }

                let Some(unit) = self.units.get(&job.unit) else {
                    continue;
                };

                for conflict_unit in &unit.conflicts {
                    let Some(conflict_ids) = self.jobs_by_unit.get(conflict_unit) else {
                        continue;
                    };

                    for conflict_id in conflict_ids {
                        let Some(conflict_job) = self.jobs.get(conflict_id) else {
                            continue;
                        };
                        if job.id == conflict_job.id {
                            continue;
                        }
                        if !matches!(
                            conflict_job.job_type,
                            JobType::Start | JobType::Restart | JobType::TryRestart
                        ) {
                            continue;
                        }

                        let drop_id = if !job.matters_to_anchor {
                            Some(job.id)
                        } else if !conflict_job.matters_to_anchor {
                            Some(conflict_job.id)
                        } else {
                            None
                        };

                        action = Some(match drop_id {
                            Some(id) => Ok(id),
                            None => Err(TransactionError::ConflictingJobs(format!(
                                "{} <-> {}",
                                job.unit, conflict_job.unit
                            ))),
                        });
                        break;
                    }

                    if action.is_some() {
                        break;
                    }
                }

                if action.is_some() {
                    break;
                }
            }

            let Some(result) = action else {
                return Ok(());
            };

            let drop_id = result?;
            let Some(unit) = self.jobs.get(&drop_id).map(|job| job.unit.clone()) else {
                continue;
            };
            if let Some(ids) = self.jobs_by_unit.get(&unit).cloned() {
                for id in ids {
                    self.delete_job(id, false);
                }
            }
            self.collect_garbage();
        }
    }

    fn verify_required_dependencies(&self) -> Result<(), TransactionError> {
        for job in self.jobs.values() {
            if !matches!(job.job_type, JobType::Start | JobType::Restart) {
                continue;
            }

            let Some(unit) = self.units.get(&job.unit) else {
                continue;
            };

            for dep in unit.deps_start.iter().chain(&unit.deps_verify) {
                let dep_has_start_job = self.jobs_by_unit.get(dep).is_some_and(|ids| {
                    ids.iter().any(|id| {
                        self.jobs.get(id).is_some_and(|candidate| {
                            matches!(
                                candidate.job_type,
                                JobType::Start
                                    | JobType::Restart
                                    | JobType::TryRestart
                                    | JobType::VerifyActive
                            )
                        })
                    })
                });
                let dep_already_active = self.units.get(dep).is_some_and(|spec| {
                    matches!(spec.state, UnitState::Active | UnitState::Activating)
                });

                if !dep_has_start_job && !dep_already_active {
                    return Err(TransactionError::UnsatisfiedDependency(
                        job.unit.clone(),
                        dep.clone(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn verify(&mut self, mode: JobMode) -> Result<(), TransactionError> {
        self.verify_conflicts()?;
        self.verify_order()?;
        if !matches!(
            mode,
            JobMode::IgnoreDependencies | JobMode::IgnoreRequirements
        ) {
            self.verify_required_dependencies()?;
        }
        Ok(())
    }

    fn merge_jobs(&mut self) -> Result<(), TransactionError> {
        for unit in self.jobs_by_unit.keys().cloned().collect::<Vec<_>>() {
            let ids = self.jobs_by_unit.get(&unit).cloned().unwrap_or_default();
            if ids.len() <= 1 {
                continue;
            }

            let mut merged = self
                .jobs
                .get(&ids[0])
                .map(|job| job.job_type)
                .unwrap_or(JobType::Nop);
            for &id in ids.iter().skip(1) {
                let other = self.jobs.get(&id).unwrap().job_type;
                merged = merge_job_types(merged, other)
                    .ok_or_else(|| TransactionError::ConflictingJobs(unit.clone()))?;
            }

            let keep_id = ids[0];
            if let Some(job) = self.jobs.get_mut(&keep_id) {
                job.job_type = merged;
            }
            for id in ids.into_iter().skip(1) {
                for dependency in &mut self.deps {
                    if dependency.subject == id {
                        dependency.subject = keep_id;
                    }
                    if dependency.object == id {
                        dependency.object = keep_id;
                    }
                }
                if self.anchor_job == Some(id) {
                    self.anchor_job = Some(keep_id);
                }
                self.delete_job(id, false);
            }
        }
        Ok(())
    }

    fn drop_redundant(&mut self) {
        loop {
            let redundant_ids = self.jobs_by_unit.iter().find_map(|(unit_name, ids)| {
                let unit = self.units.get(unit_name)?;
                let keep = ids.iter().any(|id| {
                    let Some(job) = self.jobs.get(id) else {
                        return false;
                    };
                    let redundant = match job.job_type {
                        JobType::Start | JobType::VerifyActive => unit.state == UnitState::Active,
                        JobType::Stop => {
                            matches!(unit.state, UnitState::Inactive | UnitState::Failed)
                        }
                        JobType::Nop => true,
                        JobType::Reload | JobType::Restart | JobType::TryRestart => false,
                    };
                    Some(*id) == self.anchor_job
                        || !redundant
                        || unit
                            .installed_job
                            .is_some_and(|installed| job_types_conflict(job.job_type, installed))
                });
                (!keep).then(|| ids.clone())
            });
            let Some(ids) = redundant_ids else {
                break;
            };
            for id in ids {
                self.delete_job(id, false);
            }
        }
    }

    fn is_destructive(&self, mode: JobMode) -> Result<(), TransactionError> {
        if !matches!(mode, JobMode::Fail | JobMode::Lenient) {
            return Ok(());
        }

        for job in self.jobs.values() {
            let unit = self.units.get(&job.unit).unwrap();
            if unit
                .installed_job
                .is_some_and(|installed| job_types_conflict(installed, job.job_type))
            {
                return Err(TransactionError::Destructive(job.unit.clone()));
            }
        }

        Ok(())
    }

    pub fn activate(&mut self, mode: JobMode) -> Result<AppliedTransaction, TransactionError> {
        self.find_jobs_that_matter_to_anchor();
        self.minimize_impact(mode)?;
        self.drop_redundant();
        if !matches!(mode, JobMode::Isolate) {
            self.collect_garbage();
        }
        self.verify(mode)?;
        self.merge_jobs()?;
        self.drop_redundant();
        self.is_destructive(mode)?;

        let anchor_job = self.anchor_job.ok_or(TransactionError::DuplicateAnchor)?;
        if !self.jobs.contains_key(&anchor_job) {
            return Err(TransactionError::DuplicateAnchor);
        }
        let jobs = self.jobs.values().cloned().collect();
        self.jobs.clear();
        self.jobs_by_unit.clear();
        self.deps.clear();
        self.anchor_job = None;
        Ok(AppliedTransaction { jobs, anchor_job })
    }

    pub fn add_isolate_jobs(&mut self) -> Result<(), TransactionError> {
        let keep = self.jobs_by_unit.keys().cloned().collect::<BTreeSet<_>>();
        for unit in self.units.values().cloned().collect::<Vec<_>>() {
            if unit.ignore_on_isolate
                || keep.contains(&unit.id)
                || matches!(unit.state, UnitState::Inactive | UnitState::Failed)
            {
                continue;
            }
            let anchor = self.anchor_job;
            let _ =
                self.add_job_and_dependencies(JobType::Stop, &unit.id, anchor, true, false, false)?;
        }
        Ok(())
    }

    pub fn add_triggering_jobs(&mut self, unit: &str) -> Result<(), TransactionError> {
        let triggered = self.unit(unit)?.triggered_by.clone();
        for trigger in triggered {
            if self.jobs_by_unit.contains_key(&trigger) {
                continue;
            }
            let anchor = self.anchor_job;
            let _ =
                self.add_job_and_dependencies(JobType::Stop, &trigger, anchor, true, false, false)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrderingRelation {
    After,
    Before,
}

fn transaction_ordering_kind(kind: JobType) -> JobType {
    match kind {
        JobType::TryRestart => JobType::Restart,
        other => other,
    }
}

fn transaction_job_compare(a: &Job, b: &Job, relation: OrderingRelation) -> i32 {
    let a_kind = transaction_ordering_kind(a.job_type);
    let b_kind = transaction_ordering_kind(b.job_type);

    if a_kind == JobType::Nop || b_kind == JobType::Nop {
        return 0;
    }
    if a.ignore_order || b.ignore_order {
        return 0;
    }
    if relation == OrderingRelation::After {
        return -transaction_job_compare(b, a, OrderingRelation::Before);
    }

    if matches!(b_kind, JobType::Stop | JobType::Restart) {
        1
    } else {
        -1
    }
}

fn dfs_cycle(
    transaction: &Transaction,
    job_id: usize,
    visiting: &mut BTreeSet<usize>,
    visited: &mut BTreeSet<usize>,
    cycle: &mut Option<Vec<usize>>,
) -> bool {
    if visited.contains(&job_id) {
        return false;
    }
    if !visiting.insert(job_id) {
        *cycle = Some(vec![job_id]);
        return true;
    }

    for next_id in transaction.ordering_successors(job_id) {
        if dfs_cycle(transaction, next_id, visiting, visited, cycle) {
            if let Some(path) = cycle.as_mut() {
                path.push(job_id);
            }
            return true;
        }
    }

    visiting.remove(&job_id);
    visited.insert(job_id);
    false
}

fn merge_job_types(left: JobType, right: JobType) -> Option<JobType> {
    use JobType::*;
    match (left, right) {
        (a, b) if a == b => Some(a),
        (Start, VerifyActive) | (VerifyActive, Start) => Some(Start),
        (Reload, VerifyActive) | (VerifyActive, Reload) => Some(Reload),
        (Restart, VerifyActive) | (VerifyActive, Restart) => Some(Restart),
        (Start, Reload) | (Reload, Start) => Some(Start),
        (Start, Restart) | (Restart, Start) => Some(Restart),
        (TryRestart, Start) | (Start, TryRestart) => Some(Start),
        (Reload, Restart) | (Restart, Reload) => Some(Restart),
        (Nop, other) | (other, Nop) => Some(other),
        _ => None,
    }
}

fn job_types_conflict(left: JobType, right: JobType) -> bool {
    use JobType::*;
    matches!(
        (left, right),
        (Stop, Start | VerifyActive | Restart | Reload | TryRestart)
            | (Start | VerifyActive | Restart | Reload | TryRestart, Stop)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units() -> Vec<UnitSpec> {
        vec![
            UnitSpec {
                id: "a.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec!["b.service".into()],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "b.service".into(),
                state: UnitState::Active,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec!["c.service".into()],
            },
            UnitSpec {
                id: "c.service".into(),
                state: UnitState::Active,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
        ]
    }

    #[test]
    fn add_job_pulls_in_dependencies() {
        let mut transaction = Transaction::new(units(), false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, false, false, false)
            .unwrap();
        assert_eq!(transaction.jobs.len(), 2);
    }

    #[test]
    fn requisite_pulls_in_verify_active_instead_of_start() {
        let mut requisite_units = units();
        requisite_units[0].deps_start.clear();
        requisite_units[0].deps_verify.push("b.service".to_string());
        let mut transaction = Transaction::new(requisite_units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap();

        assert!(
            transaction
                .jobs
                .values()
                .any(|job| job.unit == "b.service" && job.job_type == JobType::VerifyActive)
        );
        assert!(
            !transaction
                .jobs
                .values()
                .any(|job| job.unit == "b.service" && job.job_type == JobType::Start)
        );

        let applied = transaction.activate(JobMode::Replace).unwrap();
        assert!(!applied.jobs.iter().any(|job| job.unit == "b.service"));
    }

    #[test]
    fn duplicate_anchor_is_rejected() {
        let mut transaction = Transaction::new(units(), false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, false, false, false)
            .unwrap();
        let err = transaction
            .add_job_and_dependencies(JobType::Start, "b.service", None, false, false, false)
            .unwrap_err();
        assert_eq!(err, TransactionError::DuplicateAnchor);
    }

    #[test]
    fn activate_marks_anchor_chain_as_mattering() {
        let mut transaction = Transaction::new(units(), false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, false, false, false)
            .unwrap();
        transaction.find_jobs_that_matter_to_anchor();
        assert!(transaction.jobs.values().all(|job| job.matters_to_anchor));
    }

    #[test]
    fn isolate_adds_stop_jobs_for_other_active_units() {
        let mut transaction = Transaction::new(units(), false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, false, false, false)
            .unwrap();
        transaction.add_isolate_jobs().unwrap();
        assert!(
            transaction
                .jobs
                .values()
                .any(|job| job.unit == "c.service" && job.job_type == JobType::Stop)
        );
    }

    #[test]
    fn triggering_jobs_add_stops() {
        let mut transaction = Transaction::new(units(), false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, false, false, false)
            .unwrap();
        transaction.add_triggering_jobs("b.service").unwrap();
        assert!(
            transaction
                .jobs
                .values()
                .any(|job| job.unit == "c.service" && job.job_type == JobType::Stop)
        );
    }

    #[test]
    fn conflicting_jobs_fail_during_merge() {
        let mut transaction = Transaction::new(units(), false, 1).unwrap();
        let anchor = transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, false, false, false)
            .unwrap();
        let _ = transaction
            .add_job_and_dependencies(
                JobType::Stop,
                "a.service",
                Some(anchor),
                false,
                false,
                false,
            )
            .unwrap();
        let err = transaction.activate(JobMode::Replace).unwrap_err();
        assert_eq!(err, TransactionError::ConflictingJobs("a.service".into()));
    }

    #[test]
    fn cycle_without_drop_candidate_fails() {
        let mut cycle_units = units();
        // An already-active Start job is redundant and is dropped before C's
        // ordering pass. Keep both members non-redundant so this is truly an
        // unbreakable ordering cycle of jobs that matter to the anchor.
        cycle_units[1].state = UnitState::Inactive;
        cycle_units[0].before.push("b.service".into());
        cycle_units[1].before.push("a.service".into());
        let mut transaction = Transaction::new(cycle_units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, false, false, false)
            .unwrap();
        let err = transaction.activate(JobMode::Replace).unwrap_err();
        assert_eq!(err, TransactionError::CyclicOrder);
    }

    #[test]
    fn stop_jobs_reverse_a_declared_before_successor() {
        let mut stop_units = units();
        stop_units[0].state = UnitState::Active;
        stop_units[1].state = UnitState::Active;
        stop_units[0].deps_start.clear();
        stop_units[0].before.push("b.service".into());
        let mut transaction = Transaction::new(stop_units, false, 1).unwrap();
        let a = transaction
            .add_job_and_dependencies(JobType::Stop, "a.service", None, true, false, false)
            .unwrap();
        let b = transaction
            .add_job_and_dependencies(JobType::Stop, "b.service", Some(a), true, false, false)
            .unwrap();

        assert!(transaction.ordering_successors(b).contains(&a));
        assert!(!transaction.ordering_successors(a).contains(&b));
    }

    #[test]
    fn lenient_mode_rejects_destructive_anchor_jobs() {
        let mut destructive_units = units();
        destructive_units[0].installed_job = Some(JobType::Stop);
        let mut transaction = Transaction::new(destructive_units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, false, false, false)
            .unwrap();
        let err = transaction.activate(JobMode::Lenient).unwrap_err();
        assert!(matches!(err, TransactionError::Destructive(_)));
    }

    #[test]
    fn successful_activation_drops_redundant_active_dependency() {
        let mut transaction = Transaction::new(units(), false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, false, false, false)
            .unwrap();
        let applied = transaction.activate(JobMode::Replace).unwrap();
        assert_eq!(
            applied.jobs,
            vec![Job {
                id: applied.anchor_job,
                unit: "a.service".into(),
                job_type: JobType::Start,
                matters_to_anchor: true,
                irreversible: false,
                ignore_order: false,
            }]
        );
        assert!(transaction.jobs.is_empty());
    }

    #[test]
    fn linear_requirements_are_metadata_not_execution_order() {
        let linear = vec![
            UnitSpec {
                id: "a.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec!["b.service".into()],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "b.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec!["c.service".into()],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "c.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
        ];
        let mut transaction = Transaction::new(linear, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap();
        let applied = transaction.activate(JobMode::Replace).unwrap();
        let order: Vec<&str> = applied.jobs.iter().map(|job| job.unit.as_str()).collect();
        assert_eq!(order, vec!["a.service", "b.service", "c.service"]);
        assert_eq!(applied.jobs.len(), 3);
    }

    #[test]
    fn diamond_requirements_do_not_form_a_static_dispatch_list() {
        let diamond = vec![
            UnitSpec {
                id: "a.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec!["b.service".into(), "c.service".into()],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "b.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec!["d.service".into()],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "c.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec!["d.service".into()],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "d.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
        ];
        let mut transaction = Transaction::new(diamond, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap();
        let applied = transaction.activate(JobMode::Replace).unwrap();
        let order: Vec<&str> = applied.jobs.iter().map(|job| job.unit.as_str()).collect();
        assert_eq!(
            order,
            vec!["a.service", "b.service", "d.service", "c.service"]
        );
        assert_eq!(applied.jobs.len(), 4);
    }

    #[test]
    fn conflicts_pull_in_stop_without_becoming_ordering_edges() {
        let conflict_units = vec![
            UnitSpec {
                id: "a.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec!["b.service".into()],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "b.service".into(),
                state: UnitState::Active,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
        ];
        let mut transaction = Transaction::new(conflict_units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap();
        let applied = transaction.activate(JobMode::Replace).unwrap();
        let stop_b = applied
            .jobs
            .iter()
            .position(|job| job.unit == "b.service" && job.job_type == JobType::Stop)
            .unwrap();
        let start_a = applied
            .jobs
            .iter()
            .position(|job| job.unit == "a.service" && job.job_type == JobType::Start)
            .unwrap();
        assert!(start_a < stop_b);
    }

    #[test]
    fn inverse_conflicts_pull_in_best_effort_stop() {
        let mut conflict_units = units();
        conflict_units[0].deps_start.clear();
        conflict_units[0].conflicts_ignored = vec!["b.service".into()];
        conflict_units[1].state = UnitState::Active;
        let mut transaction = Transaction::new(conflict_units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap();
        let applied = transaction.activate(JobMode::Replace).unwrap();

        assert!(
            applied
                .jobs
                .iter()
                .any(|job| job.unit == "b.service" && job.job_type == JobType::Stop)
        );
    }

    #[test]
    fn stopping_bound_unit_stops_dependents() {
        let bound_units = vec![
            UnitSpec {
                id: "a.service".into(),
                state: UnitState::Active,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec!["b.service".into()],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "b.service".into(),
                state: UnitState::Active,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec!["a.service".into()],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
        ];
        let mut transaction = Transaction::new(bound_units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Stop, "b.service", None, true, false, false)
            .unwrap();
        let applied = transaction.activate(JobMode::Replace).unwrap();
        assert!(
            applied
                .jobs
                .iter()
                .any(|job| job.unit == "a.service" && job.job_type == JobType::Stop)
        );
    }

    #[test]
    fn restart_propagates_as_restart_only_to_active_dependents() {
        let mut restart_units = units();
        restart_units[0].state = UnitState::Active;
        restart_units[0].deps_start.clear();
        restart_units[1].state = UnitState::Active;
        restart_units[1].deps_stop = vec!["a.service".into()];
        let mut transaction = Transaction::new(restart_units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Restart, "b.service", None, true, false, false)
            .unwrap();
        let applied = transaction.activate(JobMode::Replace).unwrap();

        assert!(
            applied
                .jobs
                .iter()
                .any(|job| job.unit == "a.service" && job.job_type == JobType::Restart)
        );
    }

    #[test]
    fn reload_propagation_is_best_effort_and_skips_inactive_targets() {
        let mut reload_units = units();
        reload_units[0].state = UnitState::Active;
        reload_units[0].deps_start.clear();
        reload_units[0].deps_reload = vec![
            "b.service".into(),
            "c.service".into(),
            "missing.service".into(),
        ];
        reload_units[1].state = UnitState::Active;
        reload_units[2].state = UnitState::Inactive;
        let mut transaction = Transaction::new(reload_units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Reload, "a.service", None, true, false, false)
            .unwrap();
        let applied = transaction.activate(JobMode::Replace).unwrap();

        assert!(
            applied
                .jobs
                .iter()
                .any(|job| job.unit == "b.service" && job.job_type == JobType::Reload)
        );
        assert!(
            !applied
                .jobs
                .iter()
                .any(|job| job.unit == "c.service" || job.unit == "missing.service")
        );
    }

    #[test]
    fn start_on_active_unit_keeps_the_explicit_anchor_job() {
        let active = vec![UnitSpec {
            id: "a.service".into(),
            state: UnitState::Active,
            ignore_on_isolate: false,
            installed_job: None,
            deps_start: vec![],
            deps_verify: vec![],
            deps_start_ignored: vec![],
            deps_stop: vec![],
            conflicts: vec![],
            conflicts_ignored: vec![],
            deps_reload: vec![],
            before: vec![],
            after: vec![],
            triggered_by: vec![],
        }];
        let mut transaction = Transaction::new(active, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap();
        let applied = transaction.activate(JobMode::Replace).unwrap();
        assert_eq!(applied.jobs.len(), 1);
        assert_eq!(applied.jobs[0].unit, "a.service");
        assert_eq!(applied.jobs[0].job_type, JobType::Start);
    }

    #[test]
    fn missing_required_dependency_bubbles_up_failure() {
        let missing_dep = vec![UnitSpec {
            id: "a.service".into(),
            state: UnitState::Inactive,
            ignore_on_isolate: false,
            installed_job: None,
            deps_start: vec!["b.service".into()],
            deps_verify: vec![],
            deps_start_ignored: vec![],
            deps_stop: vec![],
            conflicts: vec![],
            conflicts_ignored: vec![],
            deps_reload: vec![],
            before: vec![],
            after: vec![],
            triggered_by: vec![],
        }];
        let mut transaction = Transaction::new(missing_dep, false, 1).unwrap();
        let err = transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap_err();
        assert_eq!(err, TransactionError::MissingUnit("b.service".into()));
    }

    #[test]
    fn verify_drops_non_mattering_conflicting_start_jobs() {
        let conflict_units = vec![
            UnitSpec {
                id: "a.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec!["b.service".into()],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "b.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec!["a.service".into()],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
        ];
        let mut transaction = Transaction::new(conflict_units, false, 1).unwrap();
        let anchor = transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap();
        transaction
            .add_job_and_dependencies(
                JobType::Start,
                "b.service",
                Some(anchor),
                false,
                false,
                false,
            )
            .unwrap();

        let applied = transaction.activate(JobMode::Replace).unwrap();
        assert!(
            applied
                .jobs
                .iter()
                .any(|job| job.unit == "a.service" && job.job_type == JobType::Start)
        );
        assert!(!applied.jobs.iter().any(|job| job.unit == "b.service"));
    }

    #[test]
    fn verify_rejects_essential_conflicting_start_jobs() {
        let conflict_units = vec![
            UnitSpec {
                id: "a.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec!["b.service".into()],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec!["b.service".into()],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "b.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec!["a.service".into()],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
        ];
        let mut transaction = Transaction::new(conflict_units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap();
        let err = transaction.activate(JobMode::Replace).unwrap_err();
        assert_eq!(
            err,
            TransactionError::ConflictingJobs("a.service <-> b.service".into())
        );
    }

    #[test]
    fn verify_detects_unsatisfied_required_dependency() {
        let dependency_units = vec![
            UnitSpec {
                id: "a.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec!["b.service".into()],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "b.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec![],
                triggered_by: vec![],
            },
        ];

        let mut transaction = Transaction::new(dependency_units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap();

        let b_id = transaction
            .jobs
            .values()
            .find(|job| job.unit == "b.service")
            .map(|job| job.id)
            .unwrap();
        transaction.delete_job(b_id, false);

        let err = transaction.verify_required_dependencies().unwrap_err();
        assert_eq!(
            err,
            TransactionError::UnsatisfiedDependency("a.service".into(), "b.service".into())
        );
    }

    #[test]
    fn best_effort_start_dependency_missing_is_ignored() {
        let units = vec![UnitSpec {
            id: "a.service".into(),
            state: UnitState::Inactive,
            ignore_on_isolate: false,
            installed_job: None,
            deps_start: vec![],
            deps_verify: vec![],
            deps_start_ignored: vec!["missing.service".into()],
            deps_stop: vec![],
            conflicts: vec![],
            conflicts_ignored: vec![],
            deps_reload: vec![],
            before: vec![],
            after: vec![],
            triggered_by: vec![],
        }];
        let mut transaction = Transaction::new(units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap();

        let applied = transaction.activate(JobMode::Replace).unwrap();
        assert_eq!(applied.jobs.len(), 1);
        assert_eq!(applied.jobs[0].unit, "a.service");
        assert_eq!(applied.jobs[0].job_type, JobType::Start);
    }

    #[test]
    fn ignore_requirements_mode_skips_required_dependency_checks() {
        let units = vec![UnitSpec {
            id: "a.service".into(),
            state: UnitState::Inactive,
            ignore_on_isolate: false,
            installed_job: None,
            deps_start: vec!["missing.service".into()],
            deps_verify: vec![],
            deps_start_ignored: vec![],
            deps_stop: vec![],
            conflicts: vec![],
            conflicts_ignored: vec![],
            deps_reload: vec![],
            before: vec![],
            after: vec![],
            triggered_by: vec![],
        }];
        let mut transaction = Transaction::new(units, false, 1).unwrap();
        transaction
            .add_job_and_dependencies_with_flags(
                JobType::Start,
                "a.service",
                None,
                true,
                false,
                false,
                true,
            )
            .unwrap();

        let applied = transaction.activate(JobMode::IgnoreRequirements).unwrap();
        assert_eq!(applied.jobs.len(), 1);
        assert_eq!(applied.jobs[0].unit, "a.service");
    }

    #[test]
    fn after_edges_participate_in_cycle_detection() {
        let units = vec![
            UnitSpec {
                id: "a.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec!["b.service".into()],
                triggered_by: vec![],
            },
            UnitSpec {
                id: "b.service".into(),
                state: UnitState::Inactive,
                ignore_on_isolate: false,
                installed_job: None,
                deps_start: vec![],
                deps_verify: vec![],
                deps_start_ignored: vec![],
                deps_stop: vec![],
                conflicts: vec![],
                conflicts_ignored: vec![],
                deps_reload: vec![],
                before: vec![],
                after: vec!["a.service".into()],
                triggered_by: vec![],
            },
        ];

        let mut transaction = Transaction::new(units, false, 1).unwrap();
        let anchor = transaction
            .add_job_and_dependencies(JobType::Start, "a.service", None, true, false, false)
            .unwrap();
        transaction
            .add_job_and_dependencies(
                JobType::Start,
                "b.service",
                Some(anchor),
                true,
                false,
                false,
            )
            .unwrap();

        let err = transaction.activate(JobMode::Replace).unwrap_err();
        assert_eq!(err, TransactionError::CyclicOrder);
    }
}
