// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Own canonical job installation, live ordering dispatch, and translation of
 * service state notifications into completion. RuntimeManager remains the
 * sole owner of jobs and units.
 */
use std::collections::{BTreeMap, BTreeSet};

use super::{Result, RuntimeManager};
use crate::ffi::Errno;
use crate::job::{Job, JobId, job_install, job_type_is_conflicting};
use crate::job_tables::{
    JobResult as CanonicalJobResult, JobState as CanonicalJobState, JobType as CanonicalJobType,
};
use crate::service::{
    ServiceState, UnitActiveState as ServiceUnitActiveState, service_state_translation,
};
use crate::service_tables::ServiceResult;
use crate::transaction::{AppliedTransaction, JobType as TxJobType};
use crate::unit::ActiveState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstalledJobStateAction {
    None,
    Finish(CanonicalJobResult),
    RestartAsStart,
}

impl RuntimeManager {
    pub(super) fn set_service_state(&mut self, name: &str, state: ServiceState) {
        let Some((translated, reload_success)) = self.services.get_mut(name).map(|service| {
            service.state = state;
            (
                service_state_translation(state, service.service_type),
                service.reload_result == ServiceResult::Success,
            )
        }) else {
            return;
        };
        let new_state: ActiveState = translated.into();
        let old_state = self
            .units
            .get(name)
            .map(|unit| unit.active_state)
            .unwrap_or(new_state);
        if let Some(unit) = self.units.get_mut(name) {
            unit.active_state = new_state;
        }
        // C's unit_notify() prunes an empty cgroup whenever a unit enters an
        // inactive or failed state. Keep that manager-owned capability cleanup
        // before job propagation so terminal/canceled jobs cannot retain a
        // cgroup FD, event watch, or compatibility index until a later kernel
        // event (or forever when no event arrives).
        if matches!(new_state, ActiveState::Inactive | ActiveState::Failed) {
            self.prune_unit_cgroup(name);
        }
        // Like unit_notify() in the C manager, process every low-level
        // transition, including transitions with an unchanged translated
        // state. The installed canonical job is the only lifecycle owner.
        let unexpected = self.process_installed_job_state(name, translated, reload_success);
        self.queue_bound_state_change(name, old_state, new_state, unexpected);
        self.dispatch_replacement_bound_stops();
        self.dispatch_job_run_queue();
    }

    fn process_installed_job_state(
        &mut self,
        name: &str,
        state: ServiceUnitActiveState,
        reload_success: bool,
    ) -> bool {
        let Some(id) = self.units.get(name).and_then(|unit| unit.current_job_id) else {
            return true;
        };
        let Some((kind, job_state)) = self
            .installed_jobs
            .get(&id)
            .map(|job| (job.kind, job.state))
        else {
            return true;
        };
        if job_state == CanonicalJobState::Waiting {
            self.enqueue_installed_job(id);
        }

        let active_or_reloading = matches!(
            state,
            ServiceUnitActiveState::Active
                | ServiceUnitActiveState::Reloading
                | ServiceUnitActiveState::Refreshing
        );
        let unexpected = match kind {
            CanonicalJobType::Start | CanonicalJobType::VerifyActive => {
                job_state == CanonicalJobState::Running
                    && !active_or_reloading
                    && state != ServiceUnitActiveState::Activating
            }
            CanonicalJobType::Reload => {
                job_state == CanonicalJobState::Running
                    && state != ServiceUnitActiveState::Active
                    && !matches!(
                        state,
                        ServiceUnitActiveState::Activating
                            | ServiceUnitActiveState::Reloading
                            | ServiceUnitActiveState::Refreshing
                    )
            }
            CanonicalJobType::Stop | CanonicalJobType::Restart => {
                job_state == CanonicalJobState::Running
                    && !matches!(
                        state,
                        ServiceUnitActiveState::Inactive | ServiceUnitActiveState::Failed
                    )
                    && state != ServiceUnitActiveState::Deactivating
            }
            CanonicalJobType::Nop
            | CanonicalJobType::TryRestart
            | CanonicalJobType::TryReload
            | CanonicalJobType::ReloadOrStart => false,
        };
        let action = match kind {
            CanonicalJobType::Start | CanonicalJobType::VerifyActive => {
                if active_or_reloading {
                    InstalledJobStateAction::Finish(CanonicalJobResult::Done)
                } else if job_state == CanonicalJobState::Running
                    && state != ServiceUnitActiveState::Activating
                {
                    match state {
                        ServiceUnitActiveState::Inactive => {
                            InstalledJobStateAction::Finish(CanonicalJobResult::Done)
                        }
                        ServiceUnitActiveState::Failed => {
                            InstalledJobStateAction::Finish(CanonicalJobResult::Failed)
                        }
                        _ => InstalledJobStateAction::None,
                    }
                } else {
                    InstalledJobStateAction::None
                }
            }
            CanonicalJobType::Reload => {
                if job_state != CanonicalJobState::Running {
                    InstalledJobStateAction::None
                } else if state == ServiceUnitActiveState::Active {
                    InstalledJobStateAction::Finish(if reload_success {
                        CanonicalJobResult::Done
                    } else {
                        CanonicalJobResult::Failed
                    })
                } else if !matches!(
                    state,
                    ServiceUnitActiveState::Activating
                        | ServiceUnitActiveState::Reloading
                        | ServiceUnitActiveState::Refreshing
                ) {
                    InstalledJobStateAction::Finish(if reload_success {
                        CanonicalJobResult::Canceled
                    } else {
                        CanonicalJobResult::Failed
                    })
                } else {
                    InstalledJobStateAction::None
                }
            }
            CanonicalJobType::Stop | CanonicalJobType::Restart => {
                if matches!(
                    state,
                    ServiceUnitActiveState::Inactive | ServiceUnitActiveState::Failed
                ) {
                    if kind == CanonicalJobType::Restart {
                        InstalledJobStateAction::RestartAsStart
                    } else {
                        InstalledJobStateAction::Finish(CanonicalJobResult::Done)
                    }
                } else if job_state == CanonicalJobState::Running
                    && state != ServiceUnitActiveState::Deactivating
                {
                    InstalledJobStateAction::Finish(CanonicalJobResult::Failed)
                } else {
                    InstalledJobStateAction::None
                }
            }
            CanonicalJobType::Nop
            | CanonicalJobType::TryRestart
            | CanonicalJobType::TryReload
            | CanonicalJobType::ReloadOrStart => InstalledJobStateAction::None,
        };

        match action {
            InstalledJobStateAction::None => {}
            InstalledJobStateAction::Finish(result) => self.finish_installed_job(id, result),
            InstalledJobStateAction::RestartAsStart => {
                if self.change_restart_job_to_start(id) {
                    self.service_restart_after_stop.insert(name.to_string());
                }
            }
        }
        unexpected
    }

    fn current_translated_unit_state(&self, name: &str) -> Option<(ServiceUnitActiveState, bool)> {
        let (state, reload_success) = if let Some(service) = self.services.get(name) {
            (
                service_state_translation(service.state, service.service_type),
                service.reload_result == ServiceResult::Success,
            )
        } else {
            let state = self.units.get(name)?.active_state;
            let state = match state {
                ActiveState::Inactive => ServiceUnitActiveState::Inactive,
                ActiveState::Activating => ServiceUnitActiveState::Activating,
                ActiveState::Active | ActiveState::Frozen => ServiceUnitActiveState::Active,
                ActiveState::Refreshing => ServiceUnitActiveState::Refreshing,
                ActiveState::Reloading => ServiceUnitActiveState::Reloading,
                ActiveState::Deactivating => ServiceUnitActiveState::Deactivating,
                ActiveState::Failed => ServiceUnitActiveState::Failed,
                ActiveState::Maintenance => ServiceUnitActiveState::Maintenance,
            };
            (state, true)
        };
        Some((state, reload_success))
    }

    pub(super) fn publish_nonservice_state(&mut self, name: &str, new_state: ActiveState) {
        let old_state = self
            .units
            .get(name)
            .map(|unit| unit.active_state)
            .unwrap_or(new_state);
        if let Some(unit) = self.units.get_mut(name) {
            unit.active_state = new_state;
        }
        let Some((state, reload_success)) = self.current_translated_unit_state(name) else {
            return;
        };
        let unexpected = self.process_installed_job_state(name, state, reload_success);
        self.queue_bound_state_change(name, old_state, new_state, unexpected);
        self.dispatch_replacement_bound_stops();
        self.dispatch_job_run_queue();
    }

    fn dispatch_verify_active_job(&mut self, id: JobId, name: &str) {
        let Some((state, _)) = self.current_translated_unit_state(name) else {
            self.finish_installed_job(id, CanonicalJobResult::Skipped);
            return;
        };
        if matches!(
            state,
            ServiceUnitActiveState::Active
                | ServiceUnitActiveState::Reloading
                | ServiceUnitActiveState::Refreshing
        ) {
            self.finish_installed_job(id, CanonicalJobResult::Done);
        } else if state == ServiceUnitActiveState::Activating {
            if let Some(job) = self.installed_jobs.get_mut(&id) {
                job.set_state(CanonicalJobState::Waiting);
            }
        } else {
            self.finish_installed_job(id, CanonicalJobResult::Skipped);
        }
    }

    pub(super) fn dispatch_pending_explicit_restart(&mut self, name: &str) {
        if !self.service_restart_after_stop.remove(name) {
            return;
        }

        let current_id = self.units.get(name).and_then(|unit| unit.current_job_id);
        if let Some(id) = current_id {
            let ready = self.installed_jobs.get(&id).is_some_and(|job| {
                job.kind == CanonicalJobType::Start && job.state == CanonicalJobState::Waiting
            });
            if !ready {
                return;
            }
            self.enqueue_installed_job(id);
        }
        self.dispatch_job_run_queue();
    }

    pub(super) fn prepare_repeated_reload_for_redispatch(&mut self, name: &str) {
        let Some(id) = self.units.get(name).and_then(|unit| unit.current_job_id) else {
            return;
        };
        let repeated_reload = self.job_redispatch_queue.contains(&id)
            && self.installed_jobs.get(&id).is_some_and(|job| {
                job.kind == CanonicalJobType::Reload && job.state == CanonicalJobState::Running
            });
        if !repeated_reload {
            return;
        }
        if let Some(job) = self.installed_jobs.get_mut(&id) {
            job.set_state(CanonicalJobState::Waiting);
        }
    }

    pub(super) fn dispatch_pending_installed_job(&mut self, name: &str) {
        let Some(id) = self.units.get(name).and_then(|unit| unit.current_job_id) else {
            return;
        };
        if !self.job_redispatch_queue.contains(&id) {
            return;
        }
        if !self
            .installed_jobs
            .get(&id)
            .is_some_and(|job| job.state == CanonicalJobState::Waiting)
        {
            return;
        }
        self.job_redispatch_queue.remove(&id);
        self.enqueue_installed_job(id);
        self.dispatch_job_run_queue();
    }

    fn install_applied_transaction(
        &mut self,
        applied: &AppliedTransaction,
    ) -> Result<BTreeMap<usize, JobId>> {
        self.preflight_applied_transaction(applied)?;
        let mut installed = BTreeMap::new();

        for planned in &applied.jobs {
            let (id, _) = self.install_canonical_job(
                &planned.unit,
                super::transaction_job_type_to_canonical(planned.job_type),
                planned.irreversible,
                planned.ignore_order,
            )?;
            installed.insert(planned.id, id);
        }

        for id in installed.values().copied().collect::<BTreeSet<_>>() {
            self.enqueue_installed_job(id);
        }
        Ok(installed)
    }

    fn preflight_applied_transaction(&self, applied: &AppliedTransaction) -> Result<()> {
        let mut staged: BTreeMap<String, Job> = BTreeMap::new();

        for planned in &applied.jobs {
            let unit = self.units.get(&planned.unit).ok_or(Errno::ENOENT)?;
            if !staged.contains_key(&planned.unit)
                && let Some(existing) = self.installed_job_for_unit(&planned.unit).cloned()
            {
                staged.insert(planned.unit.clone(), existing);
            }

            let kind = super::transaction_job_type_to_canonical(planned.job_type);
            // Match C's transaction_is_destructive() check before applying any
            // jobs, so a later irreversible conflict cannot leave a partial
            // transaction installed.
            if staged.get(&planned.unit).is_some_and(|existing| {
                existing.irreversible && job_type_is_conflicting(existing.kind, kind)
            }) {
                return Err(Errno::EEXIST);
            }
            let existing = staged.remove(&planned.unit);
            if existing.as_ref().is_some_and(|job| {
                job.kind == CanonicalJobType::Reload
                    && kind == CanonicalJobType::Reload
                    && job.state == CanonicalJobState::Running
            }) {
                staged.insert(planned.unit.clone(), existing.expect("checked above"));
                continue;
            }

            let mut incoming = Job::new(&planned.unit, kind, 0);
            incoming.irreversible = planned.irreversible;
            incoming.ignore_order = planned.ignore_order;
            let (installed, _) = job_install(
                incoming,
                existing,
                super::active_state_to_job_state(unit.active_state),
            )
            .map_err(|_| Errno::EEXIST)?;
            staged.insert(planned.unit.clone(), installed);
        }
        Ok(())
    }

    fn dispatch_installed_job(&mut self, id: JobId) {
        let Some((unit_name, kind)) = self
            .installed_jobs
            .get(&id)
            .map(|job| (job.unit.clone(), job.kind))
        else {
            return;
        };
        if !self.mark_installed_job_running(id) {
            return;
        }
        if kind == CanonicalJobType::Start && !self.bound_start_dependencies_satisfied(&unit_name) {
            self.finish_installed_job(id, CanonicalJobResult::Dependency);
            return;
        }

        if !self.services.contains_key(&unit_name) {
            if kind == CanonicalJobType::VerifyActive {
                self.dispatch_verify_active_job(id, &unit_name);
                return;
            }
            if kind == CanonicalJobType::Restart {
                if !self.execute_socket_job(&unit_name, TxJobType::Stop) {
                    self.publish_nonservice_state(&unit_name, ActiveState::Inactive);
                }
                self.dispatch_pending_explicit_restart(&unit_name);
                return;
            }

            if let Some(transaction_kind) = super::canonical_job_type_to_transaction(kind)
                && !self.execute_socket_job(&unit_name, transaction_kind)
            {
                match transaction_kind {
                    TxJobType::Start | TxJobType::Reload => {
                        self.publish_nonservice_state(&unit_name, ActiveState::Active)
                    }
                    TxJobType::Stop => {
                        self.publish_nonservice_state(&unit_name, ActiveState::Inactive)
                    }
                    _ => {}
                }
            }

            if kind == CanonicalJobType::Nop {
                self.finish_installed_job(id, CanonicalJobResult::Done);
            }
            return;
        }

        match kind {
            CanonicalJobType::Start => self.execute_service_start(&unit_name),
            CanonicalJobType::Restart => {
                self.service_restart_after_stop.insert(unit_name.clone());
                self.execute_service_stop(&unit_name);
            }
            CanonicalJobType::Stop => self.execute_service_stop(&unit_name),
            CanonicalJobType::Reload => self.execute_service_reload(&unit_name),
            CanonicalJobType::VerifyActive => {
                self.dispatch_verify_active_job(id, &unit_name);
            }
            CanonicalJobType::Nop => {
                self.finish_installed_job(id, CanonicalJobResult::Done);
            }
            CanonicalJobType::TryRestart
            | CanonicalJobType::TryReload
            | CanonicalJobType::ReloadOrStart => {
                self.finish_installed_job(id, CanonicalJobResult::Failed);
            }
        }
    }

    pub(super) fn dispatch_job_run_queue(&mut self) {
        if self.job_run_queue_dispatching {
            return;
        }

        self.job_run_queue_dispatching = true;
        while let Some(id) = self.job_run_queue.iter().next().copied() {
            self.job_run_queue.remove(&id);
            if !self.job_is_runnable(id) {
                continue;
            }
            self.dispatch_installed_job(id);
        }
        self.job_run_queue_dispatching = false;
        self.dispatch_bound_stop_queue();
    }

    pub fn execute_transaction(
        &mut self,
        applied: &AppliedTransaction,
    ) -> Result<BTreeMap<usize, JobId>> {
        let installed = self.install_applied_transaction(applied)?;
        self.dispatch_job_run_queue();
        Ok(installed)
    }
}
