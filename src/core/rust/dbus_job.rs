// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-job.c

use std::collections::BTreeSet;
use std::fmt;

pub const SOURCE_PATH: &str = "src/core/dbus-job.c";

pub type Result<T> = std::result::Result<T, DbusJobError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbusJobError {
    UnknownPath(String),
    UnknownMember(String),
    MissingSender,
}

impl fmt::Display for DbusJobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPath(path) => write!(f, "unknown job path: {path}"),
            Self::UnknownMember(member) => write!(f, "unknown member: {member}"),
            Self::MissingSender => write!(f, "missing sender"),
        }
    }
}

impl std::error::Error for DbusJobError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobType {
    Start,
    Stop,
    Reload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Waiting,
    Running,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobResult {
    Done,
    Canceled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobUnit {
    pub id: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: u32,
    pub path: String,
    pub unit: JobUnit,
    pub job_type: JobType,
    pub state: JobState,
    pub result: JobResult,
    pub sent_dbus_new_signal: bool,
    pub in_dbus_queue: bool,
    pub deserialized_clients: Vec<String>,
    pub tracked_senders: BTreeSet<String>,
    pub ref_by_private_bus: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitingJob {
    pub id: u32,
    pub unit_id: String,
    pub job_type: JobType,
    pub state: JobState,
    pub job_path: String,
    pub unit_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobSignal {
    New {
        id: u32,
        path: String,
        unit_id: String,
    },
    Changed {
        path: String,
    },
    Removed {
        id: u32,
        path: String,
        unit_id: String,
        result: JobResult,
    },
}

pub fn property_get_unit(job: &Job) -> (String, String) {
    (job.unit.id.clone(), job.unit.path.clone())
}

pub fn bus_job_method_get_waiting_jobs(member: &str, jobs: &[Job]) -> Result<Vec<WaitingJob>> {
    if member != "GetAfter" && member != "GetBefore" {
        return Err(DbusJobError::UnknownMember(member.into()));
    }

    Ok(jobs
        .iter()
        .map(|job| WaitingJob {
            id: job.id,
            unit_id: job.unit.id.clone(),
            job_type: job.job_type,
            state: job.state,
            job_path: job.path.clone(),
            unit_path: job.unit.path.clone(),
        })
        .collect())
}

pub fn bus_job_find<'a>(jobs: &'a [Job], path: &str) -> Result<&'a Job> {
    jobs.iter()
        .find(|job| job.path == path)
        .ok_or_else(|| DbusJobError::UnknownPath(path.into()))
}

pub fn bus_job_enumerate(jobs: &[Job]) -> Vec<String> {
    jobs.iter().map(|job| job.path.clone()).collect()
}

pub fn send_new_signal(job: &Job) -> JobSignal {
    JobSignal::New {
        id: job.id,
        path: job.path.clone(),
        unit_id: job.unit.id.clone(),
    }
}

pub fn send_changed_signal(job: &Job) -> JobSignal {
    JobSignal::Changed {
        path: job.path.clone(),
    }
}

pub fn send_removed_signal(job: &Job) -> JobSignal {
    JobSignal::Removed {
        id: job.id,
        path: job.path.clone(),
        unit_id: job.unit.id.clone(),
        result: job.result,
    }
}

pub fn bus_job_send_change_signal(job: &mut Job) -> JobSignal {
    if job.in_dbus_queue {
        job.in_dbus_queue = false;
    }

    let signal = if job.sent_dbus_new_signal {
        send_changed_signal(job)
    } else {
        send_new_signal(job)
    };

    job.sent_dbus_new_signal = true;
    signal
}

pub fn bus_job_send_pending_change_signal(
    job: &mut Job,
    including_new: bool,
    manager_reloading: bool,
) -> Option<JobSignal> {
    if !job.in_dbus_queue {
        return None;
    }
    if !job.sent_dbus_new_signal && !including_new {
        return None;
    }
    if manager_reloading {
        return None;
    }

    Some(bus_job_send_change_signal(job))
}

pub fn bus_job_send_removed_signal(job: &mut Job) -> JobSignal {
    if !job.sent_dbus_new_signal {
        let _ = bus_job_send_change_signal(job);
    }
    send_removed_signal(job)
}

pub fn bus_job_coldplug_bus_track(job: &mut Job, api_bus_available: bool) -> usize {
    if !api_bus_available {
        return 0;
    }

    let clients = std::mem::take(&mut job.deserialized_clients);
    for client in clients {
        job.tracked_senders.insert(client);
    }
    job.tracked_senders.len()
}

pub fn bus_job_track_sender(
    job: &mut Job,
    message_bus_is_api_bus: bool,
    sender: &str,
) -> Result<()> {
    if sender.is_empty() {
        return Err(DbusJobError::MissingSender);
    }

    if !message_bus_is_api_bus {
        job.ref_by_private_bus = true;
        return Ok(());
    }

    job.tracked_senders.insert(sender.to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_job() -> Job {
        Job {
            id: 7,
            path: "/org/freedesktop/systemd1/job/7".into(),
            unit: JobUnit {
                id: "basic.target".into(),
                path: "/org/freedesktop/systemd1/unit/basic_2etarget".into(),
            },
            job_type: JobType::Start,
            state: JobState::Waiting,
            result: JobResult::Done,
            sent_dbus_new_signal: false,
            in_dbus_queue: true,
            deserialized_clients: vec![":1.10".into(), ":1.11".into()],
            tracked_senders: BTreeSet::new(),
            ref_by_private_bus: false,
        }
    }

    #[test]
    fn property_get_unit_returns_id_and_path() {
        let job = sample_job();
        assert_eq!(
            property_get_unit(&job),
            (
                "basic.target".to_string(),
                "/org/freedesktop/systemd1/unit/basic_2etarget".to_string()
            )
        );
    }

    #[test]
    fn waiting_jobs_returns_marshaled_shape() {
        let jobs = vec![sample_job()];
        let waiting = bus_job_method_get_waiting_jobs("GetAfter", &jobs).unwrap();
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].id, 7);
        assert_eq!(waiting[0].unit_id, "basic.target");
    }

    #[test]
    fn waiting_jobs_rejects_unknown_member() {
        let jobs = vec![sample_job()];
        assert!(matches!(
            bus_job_method_get_waiting_jobs("Nope", &jobs),
            Err(DbusJobError::UnknownMember(_))
        ));
    }

    #[test]
    fn find_and_enumerate_jobs_by_path() {
        let jobs = vec![sample_job()];
        assert_eq!(
            bus_job_find(&jobs, "/org/freedesktop/systemd1/job/7")
                .unwrap()
                .id,
            7
        );
        assert_eq!(
            bus_job_enumerate(&jobs),
            vec!["/org/freedesktop/systemd1/job/7"]
        );
    }

    #[test]
    fn first_change_signal_emits_new_then_marks_sent() {
        let mut job = sample_job();
        let signal = bus_job_send_change_signal(&mut job);
        assert!(matches!(signal, JobSignal::New { .. }));
        assert!(job.sent_dbus_new_signal);
        assert!(!job.in_dbus_queue);
    }

    #[test]
    fn pending_change_signal_respects_flags() {
        let mut job = sample_job();
        assert!(bus_job_send_pending_change_signal(&mut job, false, false).is_none());
        assert!(matches!(
            bus_job_send_pending_change_signal(&mut job, true, false),
            Some(JobSignal::New { .. })
        ));
    }

    #[test]
    fn removed_signal_forces_new_signal_first() {
        let mut job = sample_job();
        let signal = bus_job_send_removed_signal(&mut job);
        assert!(matches!(signal, JobSignal::Removed { .. }));
        assert!(job.sent_dbus_new_signal);
    }

    #[test]
    fn coldplug_moves_deserialized_clients_into_track_set() {
        let mut job = sample_job();
        let count = bus_job_coldplug_bus_track(&mut job, true);
        assert_eq!(count, 2);
        assert!(job.deserialized_clients.is_empty());
        assert!(job.tracked_senders.contains(":1.10"));
    }

    #[test]
    fn track_sender_handles_private_and_api_bus() {
        let mut job = sample_job();
        bus_job_track_sender(&mut job, false, "sender.private").unwrap();
        assert!(job.ref_by_private_bus);

        bus_job_track_sender(&mut job, true, ":1.99").unwrap();
        assert!(job.tracked_senders.contains(":1.99"));
    }
}
