// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/test-homed-regression-31896.c
//
// Regression model for RefHomeUnrestricted → AuthenticateHome → ReleaseHome.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusAction {
    OpenSystem,
    RefHomeUnrestricted {
        username: String,
        unrestricted: bool,
    },
    AuthenticateHome {
        username: String,
        secret_json: String,
    },
    Flush,
    ReleaseHome {
        username: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegressionError {
    InvalidArgumentCount { got: usize },
    EmptyUserName,
    NoReply,
}

impl std::fmt::Display for RegressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgumentCount { got } => write!(f, "expected 2 argv items, got {got}"),
            Self::EmptyUserName => write!(f, "username must not be empty"),
            Self::NoReply => write!(f, "release unexpectedly timed out with NoReply"),
        }
    }
}

impl std::error::Error for RegressionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegressionTrace {
    pub username: String,
    pub actions: Vec<BusAction>,
}

pub fn run_regression(
    argv: &[&str],
    release_has_no_reply: bool,
) -> Result<RegressionTrace, RegressionError> {
    if argv.len() != 2 {
        return Err(RegressionError::InvalidArgumentCount { got: argv.len() });
    }

    let username = argv[1].trim();
    if username.is_empty() {
        return Err(RegressionError::EmptyUserName);
    }
    if release_has_no_reply {
        return Err(RegressionError::NoReply);
    }

    Ok(RegressionTrace {
        username: username.to_owned(),
        actions: vec![
            BusAction::OpenSystem,
            BusAction::RefHomeUnrestricted {
                username: username.to_owned(),
                unrestricted: true,
            },
            BusAction::AuthenticateHome {
                username: username.to_owned(),
                secret_json: "{}".to_string(),
            },
            BusAction::Flush,
            BusAction::ReleaseHome {
                username: username.to_owned(),
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regression_emits_five_steps() {
        let trace = run_regression(&["prog", "alice"], false).unwrap();
        assert_eq!(trace.actions.len(), 5);
    }

    #[test]
    fn first_step_opens_system_bus() {
        let trace = run_regression(&["prog", "alice"], false).unwrap();
        assert_eq!(trace.actions[0], BusAction::OpenSystem);
    }

    #[test]
    fn ref_step_is_unrestricted() {
        let trace = run_regression(&["prog", "alice"], false).unwrap();
        assert_eq!(
            trace.actions[1],
            BusAction::RefHomeUnrestricted {
                username: "alice".into(),
                unrestricted: true
            }
        );
    }

    #[test]
    fn authenticate_uses_empty_json_secret() {
        let trace = run_regression(&["prog", "alice"], false).unwrap();
        assert_eq!(
            trace.actions[2],
            BusAction::AuthenticateHome {
                username: "alice".into(),
                secret_json: "{}".into()
            }
        );
    }

    #[test]
    fn fourth_step_flushes_bus() {
        let trace = run_regression(&["prog", "alice"], false).unwrap();
        assert_eq!(trace.actions[3], BusAction::Flush);
    }

    #[test]
    fn last_step_releases_home() {
        let trace = run_regression(&["prog", "alice"], false).unwrap();
        assert_eq!(
            trace.actions[4],
            BusAction::ReleaseHome {
                username: "alice".into()
            }
        );
    }

    #[test]
    fn invalid_argv_count_fails() {
        assert_eq!(
            run_regression(&["prog"], false),
            Err(RegressionError::InvalidArgumentCount { got: 1 })
        );
    }

    #[test]
    fn empty_username_fails() {
        assert_eq!(
            run_regression(&["prog", "   "], false),
            Err(RegressionError::EmptyUserName)
        );
    }

    #[test]
    fn no_reply_is_detected() {
        assert_eq!(
            run_regression(&["prog", "alice"], true),
            Err(RegressionError::NoReply)
        );
    }
}
