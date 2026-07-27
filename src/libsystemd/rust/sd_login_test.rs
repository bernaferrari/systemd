// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-login/test-login.c
//

pub type Result<T> = std::result::Result<T, LoginTestError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginTestError {
    InvalidUid,
    EmptySet,
}

pub fn format_uids(uids: &[u32]) -> Result<String> {
    if uids.is_empty() {
        return Err(LoginTestError::EmptySet);
    }
    Ok(uids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(" "))
}

pub fn peer_sessions_match(left: Option<&str>, right: Option<&str>) -> bool {
    left == right
}

pub fn assert_units_distinct(unit: Option<&str>, user_unit: Option<&str>) -> bool {
    match (unit, user_unit) {
        (Some(a), Some(b)) => a != b,
        _ => true,
    }
}

pub fn validate_display_lookup(uid: Option<u32>) -> Result<()> {
    uid.filter(|value| *value != u32::MAX)
        .map(|_| ())
        .ok_or(LoginTestError::InvalidUid)
}

pub fn count_matches<T>(items: &[T]) -> usize {
    items.len()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub session: Option<String>,
    pub state: Option<String>,
    pub seat: Option<String>,
    pub uid: Option<u32>,
}

impl SessionSnapshot {
    pub fn is_logind_backed(&self) -> bool {
        self.session.is_some() && self.uid.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_uid_list() {
        assert_eq!(format_uids(&[1000, 1001]).unwrap(), "1000 1001");
    }

    #[test]
    fn rejects_empty_uid_list() {
        assert_eq!(format_uids(&[]), Err(LoginTestError::EmptySet));
    }

    #[test]
    fn peer_session_comparison_matches_c_expectation() {
        assert!(peer_sessions_match(Some("c2"), Some("c2")));
        assert!(!peer_sessions_match(Some("c2"), Some("c3")));
    }

    #[test]
    fn unit_and_user_unit_may_not_be_identical_when_both_present() {
        assert!(assert_units_distinct(
            Some("init.scope"),
            Some("user@1000.service")
        ));
        assert!(!assert_units_distinct(Some("same"), Some("same")));
    }

    #[test]
    fn invalid_uid_is_rejected() {
        assert_eq!(
            validate_display_lookup(Some(u32::MAX)),
            Err(LoginTestError::InvalidUid)
        );
    }

    #[test]
    fn valid_uid_is_accepted() {
        assert_eq!(validate_display_lookup(Some(1000)), Ok(()));
    }

    #[test]
    fn session_snapshot_reports_logind_backing() {
        let snapshot = SessionSnapshot {
            session: Some("c1".into()),
            state: Some("active".into()),
            seat: Some("seat0".into()),
            uid: Some(1000),
        };
        assert!(snapshot.is_logind_backed());
    }

    #[test]
    fn count_matches_is_len_passthrough() {
        assert_eq!(count_matches(&[1, 2, 3]), 3);
    }
}
