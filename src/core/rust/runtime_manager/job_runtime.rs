// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Own the canonical installed-job lifecycle and the live ordering helpers.
 * RuntimeManager remains the sole owner of the jobs, units, and queue state.
 */
use std::collections::VecDeque;

use super::{
    JOB_REMOVED_RECORD_LIMIT, JobRemovedRecord, Result, RuntimeManager, active_state_to_job_state,
};
use crate::ffi::Errno;
use crate::job::{
    InstallDisposition, Job, JobId, UnitDependencyAtom, job_compare, job_install,
    job_type_is_conflicting,
};
use crate::job_tables::{
    JobResult as CanonicalJobResult, JobState as CanonicalJobState, JobType as CanonicalJobType,
};
use crate::unit::DependencyKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DependencyFailureAtom {
    Start,
    Stop,
    InactiveStart,
}

impl RuntimeManager {
    /// Remove every manager-side queue membership before releasing a terminal
    /// job ID. This mirrors `job_free()` in `src/core/job.c`: a terminal job
    /// must not remain runnable or eligible for redispatch after its unit
    /// property has been cleared. The set removals are intentionally
    /// idempotent so duplicate terminal notifications are harmless.
    fn detach_terminal_job_queues(&mut self, id: JobId) {
        self.job_run_queue.remove(&id);
        self.job_redispatch_queue.remove(&id);
    }

    /// Record the C `JobRemoved(uoss)` payload locally without publishing it.
    ///
    /// PORT-SYNC: `send_removed_signal()` in `src/core/dbus-job.c` obtains
    /// `p = job_dbus_path(j)` and appends `j->id`, `p`, `j->unit->id`, and
    /// `job_result_to_string(j->result)`. The Rust runtime has no live bus
    /// transport at this point, so this is deliberately an internal audit
    /// record—not a pending signal and not evidence of bus delivery.
    fn record_terminal_job_removed(&mut self, job: &Job, result: CanonicalJobResult) {
        if self.job_removed_records.len() == JOB_REMOVED_RECORD_LIMIT {
            // Explicit FIFO overflow policy: discard the oldest terminal
            // record, never grow history and never delay cleanup.
            self.job_removed_records.pop_front();
        }
        self.job_removed_records.push_back(JobRemovedRecord {
            id: job.id,
            job_path: format!("/org/freedesktop/systemd1/job/{}", job.id),
            unit_id: job.unit.clone(),
            result: result
                .to_string_val()
                .expect("canonical JobResult values have string names"),
        });
    }

    /// Record a terminal job and release its ID exactly once.
    ///
    /// PORT-SYNC: `job_unlink()` in `src/core/job.c` clears manager queues
    /// before `job_free()` releases the job. We retain that cleanup ordering;
    /// the record is local only and must not be mistaken for D-Bus emission.
    fn release_terminal_job(&mut self, job: &Job, result: CanonicalJobResult) {
        self.record_terminal_job_removed(job, result);
        self.detach_terminal_job_queues(job.id);
        self.job_registry.release_id(job.id);
    }

    pub(crate) fn job_removed_records(&self) -> &VecDeque<JobRemovedRecord> {
        &self.job_removed_records
    }

    pub fn installed_job(&self, id: JobId) -> Option<&Job> {
        let job = self.installed_jobs.get(&id)?;
        let unit = self.units.get(&job.unit)?;
        (job.installed
            && unit.current_job_id == Some(id)
            && matches!(
                job.state,
                CanonicalJobState::Waiting | CanonicalJobState::Running
            ))
        .then_some(job)
    }

    pub fn installed_jobs(&self) -> Vec<&Job> {
        self.installed_jobs
            .keys()
            .filter_map(|id| self.installed_job(*id))
            .collect()
    }

    pub fn installed_job_for_unit(&self, unit: &str) -> Option<&Job> {
        let id = self.units.get(unit)?.current_job_id?;
        self.installed_job(id).filter(|job| job.unit == unit)
    }

    pub(super) fn install_target_job(
        &mut self,
        unit: &str,
        kind: CanonicalJobType,
    ) -> Result<(JobId, bool)> {
        self.install_canonical_job(unit, kind, false, false)
    }

    pub(super) fn install_canonical_job(
        &mut self,
        unit: &str,
        kind: CanonicalJobType,
        irreversible: bool,
        ignore_order: bool,
    ) -> Result<(JobId, bool)> {
        let unit_state = self
            .units
            .get(unit)
            .map(|unit| active_state_to_job_state(unit.active_state))
            .ok_or(Errno::ENOENT)?;
        let existing_id = self.units.get(unit).and_then(|unit| unit.current_job_id);
        // transaction_is_destructive() guarantees this before C reaches
        // job_install(). Keep the same invariant for direct canonical installs.
        if existing_id
            .and_then(|id| self.installed_jobs.get(&id))
            .is_some_and(|existing| {
                existing.irreversible && job_type_is_conflicting(existing.kind, kind)
            })
        {
            return Err(Errno::EEXIST);
        }
        let existing = existing_id.and_then(|id| self.installed_jobs.remove(&id));

        if existing.as_ref().is_some_and(|job| {
            job.kind == CanonicalJobType::Reload
                && kind == CanonicalJobType::Reload
                && job.state == CanonicalJobState::Running
        }) {
            let mut job = existing.expect("checked above");
            job.irreversible |= irreversible;
            job.ignore_order |= ignore_order;
            let id = job.id;
            self.installed_jobs.insert(id, job);
            self.job_redispatch_queue.insert(id);
            return Ok((id, false));
        }

        let incoming_id = self.job_registry.alloc_id();
        let mut incoming = Job::new(unit, kind, incoming_id);
        incoming.irreversible = irreversible;
        incoming.ignore_order = ignore_order;
        let existing_backup = existing.clone();
        let (installed, disposition) = match job_install(incoming, existing, unit_state) {
            Ok(installed) => installed,
            Err(_) => {
                self.job_registry.release_id(incoming_id);
                if let Some(existing) = existing_backup {
                    self.installed_jobs.insert(existing.id, existing);
                }
                return Err(Errno::EEXIST);
            }
        };
        let id = installed.id;
        let (should_dispatch, terminal_job) = match disposition {
            InstallDisposition::Installed => (true, None),
            InstallDisposition::Merged => {
                self.job_registry.release_id(incoming_id);
                if existing_backup.as_ref().is_some_and(|existing| {
                    existing.state == CanonicalJobState::Running
                        && installed.state == CanonicalJobState::Waiting
                }) {
                    self.job_redispatch_queue.insert(id);
                }
                (false, None)
            }
            InstallDisposition::ReplacedConflicting { mut canceled } => {
                self.service_restart_after_stop.remove(&canceled.unit);
                canceled.installed = false;
                canceled.result = Some(CanonicalJobResult::Canceled);
                canceled.set_state(CanonicalJobState::Failed);
                (true, Some(canceled))
            }
        };

        self.installed_jobs.insert(id, installed);
        if let Some(unit) = self.units.get_mut(unit) {
            unit.current_job_id = Some(id);
        }
        if let Some(canceled) = terminal_job.as_ref() {
            self.release_terminal_job(canceled, CanonicalJobResult::Canceled);
        }
        Ok((id, should_dispatch))
    }

    pub(super) fn finish_installed_job(&mut self, id: JobId, result: CanonicalJobResult) {
        let mut pending = VecDeque::from([(id, result)]);

        while let Some((id, result)) = pending.pop_front() {
            let Some(mut job) = self.installed_jobs.remove(&id) else {
                continue;
            };
            let failure_atom = if result != CanonicalJobResult::Done {
                match job.kind {
                    CanonicalJobType::Start | CanonicalJobType::VerifyActive => {
                        Some(DependencyFailureAtom::Start)
                    }
                    CanonicalJobType::Stop => Some(DependencyFailureAtom::Stop),
                    _ => None,
                }
            } else if matches!(job.kind, CanonicalJobType::Start | CanonicalJobType::Reload)
                && !self
                    .units
                    .get(&job.unit)
                    .is_some_and(|unit| unit.active_state.is_active_or_reloading())
            {
                Some(DependencyFailureAtom::InactiveStart)
            } else {
                None
            };
            self.service_restart_after_stop.remove(&job.unit);
            job.installed = false;
            job.result = Some(result);
            job.set_state(if result == CanonicalJobResult::Done {
                CanonicalJobState::Done
            } else {
                CanonicalJobState::Failed
            });
            if let Some(unit) = self.units.get_mut(&job.unit)
                && unit.current_job_id == Some(id)
            {
                unit.current_job_id = None;
            }
            self.submit_bound_unit_for_recheck(&job.unit);

            // C frees transaction JobDependency links during activation.
            // Runtime propagation instead traverses persistent typed Unit
            // dependency atoms, independent of live ordering barriers. Queue
            // the snapshot iteratively so cycles and deep chains are safe.
            if let Some(atom) = failure_atom {
                pending.extend(
                    self.dependency_failure_targets(&job.unit, atom)
                        .into_iter()
                        .map(|dependent_id| (dependent_id, CanonicalJobResult::Dependency)),
                );
            }
            self.enqueue_ordering_neighbours(&job.unit);
            self.release_terminal_job(&job, result);
        }
    }

    fn dependency_failure_targets(
        &self,
        prerequisite: &str,
        atom: DependencyFailureAtom,
    ) -> Vec<JobId> {
        self.units
            .values()
            .filter_map(|unit| {
                let id = unit.current_job_id?;
                let job = self.installed_jobs.get(&id)?;
                if !matches!(
                    job.kind,
                    CanonicalJobType::Start | CanonicalJobType::VerifyActive
                ) {
                    return None;
                }

                let propagates = match atom {
                    DependencyFailureAtom::Start => [
                        DependencyKind::Requires,
                        DependencyKind::Requisite,
                        DependencyKind::BindsTo,
                    ]
                    .into_iter()
                    .any(|kind| {
                        unit.dependencies
                            .get(&kind)
                            .is_some_and(|dependencies| dependencies.contains(prerequisite))
                    }),
                    DependencyFailureAtom::Stop => unit
                        .dependencies
                        .get(&DependencyKind::Conflicts)
                        .is_some_and(|dependencies| dependencies.contains(prerequisite)),
                    DependencyFailureAtom::InactiveStart => unit
                        .dependencies
                        .get(&DependencyKind::Requisite)
                        .is_some_and(|dependencies| dependencies.contains(prerequisite)),
                };
                propagates.then_some(id)
            })
            .collect()
    }

    pub(super) fn change_restart_job_to_start(&mut self, id: JobId) -> bool {
        let Some(job) = self.installed_jobs.get_mut(&id) else {
            return false;
        };
        if job.kind != CanonicalJobType::Restart {
            return false;
        }
        job.kind = CanonicalJobType::Start;
        job.result = None;
        job.set_state(CanonicalJobState::Waiting);
        let job = job.clone();
        self.enqueue_ordering_neighbours(&job.unit);
        true
    }

    pub(super) fn mark_installed_job_running(&mut self, id: JobId) -> bool {
        let Some(job) = self.installed_jobs.get_mut(&id) else {
            return false;
        };
        job.set_state(CanonicalJobState::Running);
        true
    }

    fn units_have_ordering_relation(&self, unit_name: &str, other_name: &str) -> bool {
        let direct = self.units.get(unit_name).is_some_and(|unit| {
            unit.dependencies
                .get(&DependencyKind::After)
                .is_some_and(|dependencies| dependencies.contains(other_name))
                || unit
                    .dependencies
                    .get(&DependencyKind::Before)
                    .is_some_and(|dependencies| dependencies.contains(other_name))
        });
        direct
            || self.units.get(other_name).is_some_and(|unit| {
                unit.dependencies
                    .get(&DependencyKind::After)
                    .is_some_and(|dependencies| dependencies.contains(unit_name))
                    || unit
                        .dependencies
                        .get(&DependencyKind::Before)
                        .is_some_and(|dependencies| dependencies.contains(unit_name))
            })
    }

    pub(super) fn job_is_runnable(&self, id: JobId) -> bool {
        let Some(job) = self.installed_jobs.get(&id) else {
            return false;
        };
        if job.state != CanonicalJobState::Waiting {
            return false;
        }

        for other in self.installed_jobs.values() {
            if other.id == id {
                continue;
            }

            let direct_after = self.units.get(&job.unit).is_some_and(|unit| {
                unit.dependencies
                    .get(&DependencyKind::After)
                    .is_some_and(|dependencies| dependencies.contains(&other.unit))
            });
            let inverse_before = self.units.get(&other.unit).is_some_and(|unit| {
                unit.dependencies
                    .get(&DependencyKind::Before)
                    .is_some_and(|dependencies| dependencies.contains(&job.unit))
            });
            if (direct_after || inverse_before)
                && job_compare(job, other, UnitDependencyAtom::After) > 0
            {
                return false;
            }

            let direct_before = self.units.get(&job.unit).is_some_and(|unit| {
                unit.dependencies
                    .get(&DependencyKind::Before)
                    .is_some_and(|dependencies| dependencies.contains(&other.unit))
            });
            let inverse_after = self.units.get(&other.unit).is_some_and(|unit| {
                unit.dependencies
                    .get(&DependencyKind::After)
                    .is_some_and(|dependencies| dependencies.contains(&job.unit))
            });
            if (direct_before || inverse_after)
                && job_compare(job, other, UnitDependencyAtom::Before) > 0
            {
                return false;
            }
        }

        true
    }

    pub(super) fn enqueue_installed_job(&mut self, id: JobId) {
        if !self.job_redispatch_queue.contains(&id)
            && self
                .installed_jobs
                .get(&id)
                .is_some_and(|job| job.state == CanonicalJobState::Waiting)
        {
            self.job_run_queue.insert(id);
        }
    }

    fn enqueue_ordering_neighbours(&mut self, unit_name: &str) {
        let neighbours: Vec<JobId> = self
            .installed_jobs
            .values()
            .filter(|job| {
                job.state == CanonicalJobState::Waiting
                    && self.units_have_ordering_relation(unit_name, &job.unit)
            })
            .map(|job| job.id)
            .collect();
        for id in neighbours {
            self.enqueue_installed_job(id);
        }
    }
}
