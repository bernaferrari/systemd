// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/ac-power/ac-power.c
//
// Safe Rust model of the systemd-ac-power command line and result semantics.

pub const EINVAL: i32 = -22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    AcPower,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Positive,
    Negative,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub verbose: bool,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub i32);

pub type Result<T> = std::result::Result<T, Error>;

impl Default for Config {
    fn default() -> Self {
        Self {
            verbose: false,
            action: Action::AcPower,
        }
    }
}

pub fn parse_argv(args: &[&str]) -> Result<Config> {
    let mut cfg = Config::default();
    for arg in args {
        match *arg {
            "-v" | "--verbose" => cfg.verbose = true,
            "--low" => cfg.action = Action::Low,
            _ => return Err(Error(EINVAL)),
        }
    }
    Ok(cfg)
}

pub fn outcome_to_status(value: bool) -> Status {
    if value {
        Status::Positive
    } else {
        Status::Negative
    }
}

pub fn verbose_text(status: Status) -> &'static str {
    match status {
        Status::Positive => "yes",
        Status::Negative => "no",
    }
}

pub fn exit_code(status: Status) -> i32 {
    match status {
        Status::Positive => 0,
        Status::Negative => 1,
    }
}

pub fn error_message(action: Action) -> &'static str {
    match action {
        Action::AcPower => "Failed to read AC status",
        Action::Low => "Failed to read battery discharging + low status",
    }
}

pub fn run(cfg: &Config, probe_result: Result<bool>) -> Result<(Option<&'static str>, i32)> {
    let state = outcome_to_status(probe_result?);
    Ok((cfg.verbose.then(|| verbose_text(state)), exit_code(state)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_c() {
        assert_eq!(
            Config::default(),
            Config {
                verbose: false,
                action: Action::AcPower
            }
        );
    }
    #[test]
    fn parses_verbose() {
        assert!(parse_argv(&["--verbose"]).unwrap().verbose);
    }
    #[test]
    fn parses_low() {
        assert_eq!(parse_argv(&["--low"]).unwrap().action, Action::Low);
    }
    #[test]
    fn rejects_positional_arguments() {
        assert_eq!(parse_argv(&["x"]).unwrap_err(), Error(EINVAL));
    }
    #[test]
    fn positive_is_yes() {
        assert_eq!(verbose_text(outcome_to_status(true)), "yes");
    }
    #[test]
    fn negative_is_no() {
        assert_eq!(verbose_text(outcome_to_status(false)), "no");
    }
    #[test]
    fn exit_code_matches_c_contract() {
        assert_eq!(exit_code(Status::Positive), 0);
        assert_eq!(exit_code(Status::Negative), 1);
    }
    #[test]
    fn action_specific_error_message() {
        assert!(error_message(Action::Low).contains("battery"));
    }
    #[test]
    fn run_omits_output_when_not_verbose() {
        assert_eq!(run(&Config::default(), Ok(true)).unwrap(), (None, 0));
    }
    #[test]
    fn run_formats_verbose_output() {
        assert_eq!(
            run(
                &Config {
                    verbose: true,
                    action: Action::AcPower
                },
                Ok(false)
            )
            .unwrap(),
            (Some("no"), 1)
        );
    }
}
