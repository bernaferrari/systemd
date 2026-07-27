// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-varlink/varlink-util.c, src/libsystemd/sd-varlink/varlink-util.h

use crate::varlink_state::VarlinkState;

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const NEG_ENOMEM: i32 = -(libc::ENOMEM as i32);
pub const NEG_EBADR: i32 = -53;
pub const NEG_EPERM: i32 = -(libc::EPERM as i32);

pub const PROJECT_URL: &str = "https://systemd.io/";
pub const PROJECT_VENDOR: &str = "The systemd Project";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidRef {
    pub pid: Option<i32>,
    pub pidfd: Option<i32>,
    pub secure: bool,
}

impl PidRef {
    pub fn from_pid(pid: i32) -> Self {
        Self {
            pid: Some(pid),
            pidfd: None,
            secure: false,
        }
    }
    pub fn from_pidfd(pidfd: i32) -> Self {
        Self {
            pid: None,
            pidfd: Some(pidfd),
            secure: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastReport {
    pub total: usize,
    pub failures: usize,
    pub first_error: Option<i32>,
}

impl BroadcastReport {
    pub fn is_success(&self) -> bool {
        self.failures == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarlinkServerInfo {
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SentinelState {
    pub error_id: Option<String>,
    pub armed: bool,
}

pub fn varlink_get_peer_pidref(peer_pidfd: i32, peer_pid: Option<i32>) -> Result<PidRef> {
    if peer_pidfd >= 0 {
        return Ok(PidRef::from_pidfd(peer_pidfd));
    }
    match peer_pid {
        Some(pid) if pid >= 0 => Ok(PidRef::from_pid(pid)),
        _ => Err(NEG_EINVAL),
    }
}

pub fn varlink_call_and_log(
    method: &str,
    result: Result<Option<String>>,
) -> Result<Option<String>> {
    if method.is_empty() {
        return Err(NEG_EINVAL);
    }
    result.map_err(|e| if e == 0 { NEG_EBADR } else { e })
}

pub fn varlink_many_notify(results: &[Result<()>]) -> BroadcastReport {
    summarize(results)
}
pub fn varlink_many_reply(results: &[Result<()>]) -> BroadcastReport {
    summarize(results)
}
pub fn varlink_many_error(results: &[Result<()>], _error_id: &str) -> BroadcastReport {
    summarize(results)
}

pub fn varlink_set_info_systemd(product_suffix: &str, version: &str) -> Result<VarlinkServerInfo> {
    if version.is_empty() {
        return Err(NEG_EINVAL);
    }
    let product = if product_suffix.is_empty() {
        "systemd".to_string()
    } else {
        format!("systemd ({product_suffix})")
    };
    Ok(VarlinkServerInfo {
        vendor: PROJECT_VENDOR.to_string(),
        product,
        version: version.to_string(),
        url: PROJECT_URL.to_string(),
    })
}

pub fn varlink_check_privileged_peer(peer_uid: u32) -> Result<()> {
    if peer_uid == 0 {
        Ok(())
    } else {
        Err(NEG_EPERM)
    }
}

impl SentinelState {
    pub fn set_sentinel(&mut self, state: VarlinkState, error_id: Option<&str>) -> Result<()> {
        if state == VarlinkState::ProcessingMethodOneway {
            return Ok(());
        }
        if !matches!(
            state,
            VarlinkState::ProcessingMethod | VarlinkState::ProcessingMethodMore
        ) {
            return Err(NEG_EINVAL);
        }
        self.error_id = error_id.map(str::to_owned);
        self.armed = true;
        Ok(())
    }

    pub fn clear(&mut self) {
        self.error_id = None;
        self.armed = false;
    }
}

fn summarize(results: &[Result<()>]) -> BroadcastReport {
    let mut failures = 0;
    let mut first_error = None;
    for result in results {
        if let Err(error) = result {
            failures += 1;
            first_error.get_or_insert(*error);
        }
    }
    BroadcastReport {
        total: results.len(),
        failures,
        first_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prefers_pidfd_when_available() {
        let pidref = varlink_get_peer_pidref(5, Some(10)).unwrap();
        assert_eq!(pidref.pidfd, Some(5));
        assert!(pidref.secure);
    }
    #[test]
    fn falls_back_to_pid() {
        let pidref = varlink_get_peer_pidref(-1, Some(10)).unwrap();
        assert_eq!(pidref.pid, Some(10));
        assert!(!pidref.secure);
    }
    #[test]
    fn rejects_missing_peer_identity() {
        assert_eq!(varlink_get_peer_pidref(-1, None), Err(NEG_EINVAL));
    }
    #[test]
    fn passes_through_successful_call() {
        assert_eq!(
            varlink_call_and_log("io.test.Ping", Ok(Some("ok".into()))),
            Ok(Some("ok".into()))
        );
    }
    #[test]
    fn rejects_empty_method_name() {
        assert_eq!(varlink_call_and_log("", Ok(None)), Err(NEG_EINVAL));
    }
    #[test]
    fn summarizes_broadcast_results() {
        let report = varlink_many_notify(&[Ok(()), Err(NEG_EINVAL), Ok(())]);
        assert_eq!(report.total, 3);
        assert_eq!(report.failures, 1);
        assert_eq!(report.first_error, Some(NEG_EINVAL));
    }
    #[test]
    fn builds_systemd_server_info() {
        let info = varlink_set_info_systemd("homed", "1.0").unwrap();
        assert_eq!(info.vendor, PROJECT_VENDOR);
        assert_eq!(info.url, PROJECT_URL);
        assert!(info.product.contains("homed"));
    }
    #[test]
    fn checks_privileged_peer() {
        assert!(varlink_check_privileged_peer(0).is_ok());
        assert_eq!(varlink_check_privileged_peer(1000), Err(NEG_EPERM));
    }
    #[test]
    fn arms_sentinel_for_reply_states() {
        let mut sentinel = SentinelState::default();
        sentinel
            .set_sentinel(VarlinkState::ProcessingMethod, Some("io.test.Error"))
            .unwrap();
        assert!(sentinel.armed);
        assert_eq!(sentinel.error_id.as_deref(), Some("io.test.Error"));
    }
    #[test]
    fn ignores_oneway_sentinel() {
        let mut sentinel = SentinelState::default();
        sentinel
            .set_sentinel(VarlinkState::ProcessingMethodOneway, Some("ignored"))
            .unwrap();
        assert!(!sentinel.armed);
    }
    #[test]
    fn rejects_invalid_sentinel_state() {
        let mut sentinel = SentinelState::default();
        assert_eq!(
            sentinel.set_sentinel(VarlinkState::IdleClient, None),
            Err(NEG_EINVAL)
        );
    }
}
