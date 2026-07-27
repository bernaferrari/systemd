// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-login/test-sd-login.c
//

use std::fmt;

pub type Result<T> = std::result::Result<T, LoginCliError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginCliError {
    InvalidSyntax,
    InvalidPid(String),
    UnknownVerb(String),
    Provider(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verb {
    Session,
    Unit,
    UserUnit,
    MachineName,
    Slice,
    UserSlice,
    OwnerUid,
    Cgroup,
}

impl Verb {
    pub const ALL: [Self; 8] = [
        Self::Session,
        Self::Unit,
        Self::UserUnit,
        Self::MachineName,
        Self::Slice,
        Self::UserSlice,
        Self::OwnerUid,
        Self::Cgroup,
    ];

    pub fn parse(raw: &str) -> Result<Option<Self>> {
        Ok(match raw {
            "all" => None,
            "session" => Some(Self::Session),
            "unit" => Some(Self::Unit),
            "user_unit" => Some(Self::UserUnit),
            "machine_name" => Some(Self::MachineName),
            "slice" => Some(Self::Slice),
            "user_slice" => Some(Self::UserSlice),
            "owner_uid" => Some(Self::OwnerUid),
            "cgroup" => Some(Self::Cgroup),
            other => return Err(LoginCliError::UnknownVerb(other.to_string())),
        })
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Session => "session",
            Self::Unit => "unit",
            Self::UserUnit => "user_unit",
            Self::MachineName => "machine_name",
            Self::Slice => "slice",
            Self::UserSlice => "user_slice",
            Self::OwnerUid => "owner_uid",
            Self::Cgroup => "cgroup",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginCli {
    pub verb: Option<Verb>,
    pub pid: u32,
}

impl LoginCli {
    pub fn verbs(&self) -> Vec<Verb> {
        self.verb.map_or_else(|| Verb::ALL.to_vec(), |v| vec![v])
    }
}

pub fn parse_argv(argv: &[&str]) -> Result<LoginCli> {
    if argv.len() > 3 {
        return Err(LoginCliError::InvalidSyntax);
    }

    let verb = argv.get(1).map_or(Ok(None), |v| Verb::parse(v))?;
    let pid = argv.get(2).map_or(Ok(0), |raw| {
        raw.parse::<u32>()
            .map_err(|_| LoginCliError::InvalidPid((*raw).to_string()))
    })?;

    Ok(LoginCli { verb, pid })
}

pub trait LoginInfoProvider {
    fn string_value(&self, pid: u32, verb: Verb) -> Result<Option<String>>;
    fn owner_uid(&self, pid: u32) -> Result<u32>;
}

pub fn print_info(provider: &impl LoginInfoProvider, cli: &LoginCli) -> Result<Vec<String>> {
    cli.verbs()
        .into_iter()
        .map(|verb| match verb {
            Verb::OwnerUid => provider
                .owner_uid(cli.pid)
                .map(|uid| format!("sd_pid_get_{verb}({}) → {uid}", cli.pid)),
            _ => provider.string_value(cli.pid, verb).map(|value| {
                format!(
                    "sd_pid_get_{verb}({}) → {}",
                    cli.pid,
                    value.unwrap_or_else(|| "<none>".to_string())
                )
            }),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct StubProvider {
        strings: BTreeMap<Verb, &'static str>,
        uid: u32,
    }

    impl LoginInfoProvider for StubProvider {
        fn string_value(&self, _pid: u32, verb: Verb) -> Result<Option<String>> {
            Ok(self.strings.get(&verb).map(|s| (*s).to_string()))
        }

        fn owner_uid(&self, _pid: u32) -> Result<u32> {
            Ok(self.uid)
        }
    }

    #[test]
    fn parses_default_arguments() {
        assert_eq!(
            parse_argv(&["test-sd-login"]).unwrap(),
            LoginCli { verb: None, pid: 0 }
        );
    }

    #[test]
    fn parses_named_verb_and_pid() {
        assert_eq!(
            parse_argv(&["test-sd-login", "session", "42"]).unwrap(),
            LoginCli {
                verb: Some(Verb::Session),
                pid: 42
            }
        );
    }

    #[test]
    fn rejects_unknown_verb() {
        assert!(matches!(
            parse_argv(&["test-sd-login", "wat"]),
            Err(LoginCliError::UnknownVerb(_))
        ));
    }

    #[test]
    fn rejects_invalid_pid() {
        assert!(matches!(
            parse_argv(&["test-sd-login", "all", "abc"]),
            Err(LoginCliError::InvalidPid(_))
        ));
    }

    #[test]
    fn expands_all_verbs() {
        assert_eq!(LoginCli { verb: None, pid: 0 }.verbs(), Verb::ALL.to_vec());
    }

    #[test]
    fn prints_string_and_uid_entries() {
        let provider = StubProvider {
            strings: BTreeMap::from([(Verb::Session, "c1"), (Verb::Unit, "user@1000.service")]),
            uid: 1000,
        };
        let out = print_info(
            &provider,
            &LoginCli {
                verb: Some(Verb::OwnerUid),
                pid: 99,
            },
        )
        .unwrap();
        assert_eq!(out, vec!["sd_pid_get_owner_uid(99) → 1000"]);
    }

    #[test]
    fn prints_none_for_missing_optional_value() {
        let provider = StubProvider {
            strings: BTreeMap::new(),
            uid: 0,
        };
        let out = print_info(
            &provider,
            &LoginCli {
                verb: Some(Verb::Cgroup),
                pid: 1,
            },
        )
        .unwrap();
        assert_eq!(out, vec!["sd_pid_get_cgroup(1) → <none>"]);
    }

    #[test]
    fn renders_all_default_lines() {
        let provider = StubProvider {
            strings: BTreeMap::from([(Verb::Session, "seat0"), (Verb::Slice, "system.slice")]),
            uid: 7,
        };
        let out = print_info(&provider, &LoginCli { verb: None, pid: 5 }).unwrap();
        assert_eq!(out.len(), 8);
        assert!(out.iter().any(|line| line.contains("owner_uid(5) → 7")));
    }
}
