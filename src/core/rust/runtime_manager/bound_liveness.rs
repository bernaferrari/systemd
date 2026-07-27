// SPDX-License-Identifier: LGPL-2.1-or-later

//! Runtime `BindsTo=` state coupling.
//!
//! Transaction pull-in/failure propagation remains in the transaction and job
//! runtimes. This module owns the two post-transaction C behaviours: immediate
//! replacement stops after unexpected provider loss, and the deferred
//! stop-when-bound race-repair queue.

use super::RuntimeManager;
use crate::transaction::JobMode;
use crate::unit::{ActiveState, DependencyKind};
use systemd_platform_rs::time::boottime_usec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum BoundStopMode {
    Continuous,
    Replace,
}

impl RuntimeManager {
    fn unit_binds_to(&self, subject: &str, provider: &str) -> bool {
        self.units
            .get(subject)
            .and_then(|unit| unit.dependencies.get(&DependencyKind::BindsTo))
            .is_some_and(|dependencies| {
                dependencies
                    .iter()
                    .any(|dependency| self.canonical_unit_name(dependency) == provider)
            })
    }

    fn submit_bound_stop(&mut self, unit: String, mode: BoundStopMode) {
        self.bound_stop_queue
            .entry(unit)
            .and_modify(|queued| *queued = (*queued).max(mode))
            .or_insert(mode);
    }

    #[cfg(target_os = "linux")]
    fn sync_bound_stop_retry_timer(&self) {
        let deadline = self.bound_stop_retry_deadlines.values().min().copied();
        if let Some(timer) = &self.bound_stop_retry_timer {
            if let Err(error) = timer.arm_absolute_usec(deadline) {
                eprintln!("systemd: cannot arm CLOCK_BOOTTIME BindsTo= retry timer: {error}");
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn sync_bound_stop_retry_timer(&self) {}

    fn defer_bound_stop_retry(&mut self, name: String, deadline_usec: u64) {
        self.bound_stop_retry_deadlines
            .entry(name)
            .and_modify(|deadline| *deadline = (*deadline).min(deadline_usec))
            .or_insert(deadline_usec);
        self.sync_bound_stop_retry_timer();
    }

    fn clear_bound_stop_retry(&mut self, name: &str) {
        self.bound_stop_retry_deadlines.remove(name);
        self.sync_bound_stop_retry_timer();
    }

    pub(super) fn queue_bound_state_change(
        &mut self,
        name: &str,
        old_state: ActiveState,
        new_state: ActiveState,
        unexpected: bool,
    ) {
        let name = self.canonical_unit_name(name);

        if inactive_or_failed(new_state) {
            let dependents: Vec<String> = self
                .units
                .iter()
                .filter(|(candidate_name, candidate)| {
                    candidate.active_state.is_active_or_reloading()
                        && self.unit_binds_to(candidate_name, &name)
                })
                .map(|(candidate_name, _)| candidate_name.clone())
                .collect();
            for dependent in dependents {
                self.submit_bound_stop(dependent, BoundStopMode::Continuous);
            }
        } else if new_state.is_active_or_reloading()
            && self
                .units
                .get(&name)
                .and_then(|unit| unit.dependencies.get(&DependencyKind::BindsTo))
                .is_some_and(|dependencies| !dependencies.is_empty())
        {
            self.submit_bound_stop(name.clone(), BoundStopMode::Continuous);
        }

        if unexpected
            && old_state.is_active_or_activating()
            && new_state.is_inactive_or_deactivating()
        {
            let dependents: Vec<String> = self
                .units
                .iter()
                .filter(|(candidate_name, candidate)| {
                    !candidate.active_state.is_inactive_or_deactivating()
                        && self.unit_binds_to(candidate_name, &name)
                })
                .map(|(candidate_name, _)| candidate_name.clone())
                .collect();
            for dependent in dependents {
                self.submit_bound_stop(dependent, BoundStopMode::Replace);
            }
        }
    }

    pub(super) fn submit_bound_unit_for_recheck(&mut self, name: &str) {
        let name = self.canonical_unit_name(name);
        let eligible = self.units.get(&name).is_some_and(|unit| {
            unit.active_state.is_active_or_reloading()
                && unit
                    .dependencies
                    .get(&DependencyKind::BindsTo)
                    .is_some_and(|dependencies| !dependencies.is_empty())
        });
        if eligible {
            self.submit_bound_stop(name, BoundStopMode::Continuous);
        }
    }

    fn continuous_bound_stop_needed(&self, name: &str) -> bool {
        let Some(unit) = self.units.get(name) else {
            return false;
        };
        if !unit.active_state.is_exact_active() || unit.current_job_id.is_some() {
            return false;
        }

        unit.dependencies
            .get(&DependencyKind::BindsTo)
            .into_iter()
            .flatten()
            .any(|provider| {
                let provider = self.canonical_unit_name(provider);
                self.units.get(&provider).map_or(true, |provider| {
                    provider.current_job_id.is_none()
                        && provider.active_state.is_inactive_or_failed()
                })
            })
    }

    fn replacement_bound_stop_needed(&self, name: &str) -> bool {
        self.units
            .get(name)
            .is_some_and(|unit| !unit.active_state.is_inactive_or_deactivating())
    }

    pub(super) fn dispatch_replacement_bound_stops(&mut self) {
        if self.bound_replace_dispatching {
            return;
        }

        self.bound_replace_dispatching = true;
        loop {
            let replacement = self
                .bound_stop_queue
                .iter()
                .find_map(|(name, mode)| (*mode == BoundStopMode::Replace).then_some(name.clone()));
            let Some(name) = replacement else {
                break;
            };
            self.bound_stop_queue.remove(&name);
            if !self.replacement_bound_stop_needed(&name) {
                continue;
            }
            self.clear_bound_stop_retry(&name);
            if let Err(error) = self.stop_unit_with_mode(&name, JobMode::Replace) {
                eprintln!(
                    "systemd: failed to enqueue immediate BindsTo= stop for {name}: {error:?}"
                );
            }
        }
        self.bound_replace_dispatching = false;
    }

    pub(super) fn dispatch_bound_stop_queue(&mut self) {
        if self.bound_stop_queue_dispatching {
            return;
        }

        self.bound_stop_queue_dispatching = true;
        while let Some((name, mode)) = self
            .bound_stop_queue
            .iter()
            .next()
            .map(|(name, mode)| (name.clone(), *mode))
        {
            self.bound_stop_queue.remove(&name);
            let needed = match mode {
                BoundStopMode::Continuous => self.continuous_bound_stop_needed(&name),
                BoundStopMode::Replace => self.replacement_bound_stop_needed(&name),
            };
            if !needed {
                self.clear_bound_stop_retry(&name);
                continue;
            }

            if mode == BoundStopMode::Continuous {
                let Ok(now_usec) = boottime_usec() else {
                    eprintln!("systemd: cannot read CLOCK_BOOTTIME for BindsTo= rate limiting");
                    continue;
                };
                let Some((below_limit, retry_at_usec)) = self.units.get_mut(&name).map(|unit| {
                    let below_limit = unit.auto_start_stop_ratelimit.check(now_usec).is_ok();
                    let retry_at_usec = unit
                        .auto_start_stop_ratelimit
                        .retry_at_usec()
                        .unwrap_or_else(|| {
                            now_usec
                                .saturating_add(unit.auto_start_stop_ratelimit.interval_usec)
                                .saturating_add(1)
                        });
                    (below_limit, retry_at_usec)
                }) else {
                    continue;
                };
                if !below_limit {
                    self.defer_bound_stop_retry(name.clone(), retry_at_usec);
                    eprintln!(
                        "systemd: delaying BindsTo= stop for {name}: automatic stop rate limit exceeded"
                    );
                    continue;
                }
                self.clear_bound_stop_retry(&name);
            }

            if let Err(error) = self.stop_unit_with_mode(&name, JobMode::Replace) {
                eprintln!("systemd: failed to enqueue BindsTo= stop for {name}: {error:?}");
            }
        }
        self.bound_stop_queue_dispatching = false;
    }

    pub(super) fn process_due_bound_stop_retries(&mut self) {
        let Ok(now_usec) = boottime_usec() else {
            return;
        };
        let due: Vec<String> = self
            .bound_stop_retry_deadlines
            .iter()
            .filter_map(|(name, deadline)| (now_usec >= *deadline).then_some(name.clone()))
            .collect();
        for name in due {
            self.clear_bound_stop_retry(&name);
            self.submit_bound_stop(name, BoundStopMode::Continuous);
        }
        self.dispatch_bound_stop_queue();
    }

    pub(super) fn bound_start_dependencies_satisfied(&self, name: &str) -> bool {
        let Some(unit) = self.units.get(name) else {
            return false;
        };
        let Some(bound) = unit.dependencies.get(&DependencyKind::BindsTo) else {
            return true;
        };

        bound.iter().all(|provider| {
            let provider = self.canonical_unit_name(provider);
            let ordered_after =
                unit.dependencies
                    .get(&DependencyKind::After)
                    .is_some_and(|dependencies| {
                        dependencies
                            .iter()
                            .any(|dependency| self.canonical_unit_name(dependency) == provider)
                    })
                    || self.units.get(&provider).is_some_and(|provider_unit| {
                        provider_unit
                            .dependencies
                            .get(&DependencyKind::Before)
                            .is_some_and(|dependencies| {
                                dependencies
                                    .iter()
                                    .any(|dependency| self.canonical_unit_name(dependency) == name)
                            })
                    });

            !ordered_after
                || self
                    .units
                    .get(&provider)
                    .is_some_and(|provider| provider.active_state.is_active_or_reloading())
        })
    }
}
