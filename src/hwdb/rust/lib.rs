// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
// PORT-SYNC: src/hwdb/hwdb.c

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidVerb(String),
    MissingModalias,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVerb(v) => write!(f, "invalid verb: {v}"),
            Self::MissingModalias => f.write_str("query requires a modalias"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Update,
    Query,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub hwdb_bin_dir: Option<String>,
    pub root: Option<String>,
    pub strict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Update(Config),
    Query { config: Config, modalias: String },
}

pub fn parse_verb(value: &str) -> Result<Verb> {
    match value {
        "update" => Ok(Verb::Update),
        "query" => Ok(Verb::Query),
        _ => Err(Error::InvalidVerb(value.into())),
    }
}

pub fn parse_cli(args: &[&str]) -> Result<Command> {
    let mut config = Config::default();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--usr" => config.hwdb_bin_dir = Some("/usr/lib/udev".into()),
            "--strict" | "-s" => config.strict = true,
            arg if arg.starts_with("--root=") => config.root = Some(arg[7..].into()),
            "--root" | "-r" => {
                i += 1;
                config.root = args.get(i).map(|v| (*v).into());
            }
            other => rest.push(other),
        }
        i += 1;
    }
    let verb = parse_verb(rest.first().copied().unwrap_or("update"))?;
    match verb {
        Verb::Update => Ok(Command::Update(config)),
        Verb::Query => Ok(Command::Query {
            config,
            modalias: rest.get(1).ok_or(Error::MissingModalias)?.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_update_verb() {
        assert_eq!(parse_verb("update").unwrap(), Verb::Update);
    }
    #[test]
    fn parses_query_verb() {
        assert_eq!(parse_verb("query").unwrap(), Verb::Query);
    }
    #[test]
    fn rejects_invalid_verb() {
        assert!(matches!(parse_verb("show"), Err(Error::InvalidVerb(_))));
    }
    #[test]
    fn update_is_default_without_command() {
        let args: &[&str] = &[];
        assert!(matches!(parse_cli(args).unwrap(), Command::Update(_)));
    }
    #[test]
    fn parses_usr_flag() {
        let command = parse_cli(["--usr", "update"].as_slice()).unwrap();
        assert!(matches!(
            command,
            Command::Update(Config {
                hwdb_bin_dir: Some(_),
                ..
            })
        ));
    }
    #[test]
    fn parses_strict_flag() {
        let command = parse_cli(["--strict", "update"].as_slice()).unwrap();
        assert!(matches!(
            command,
            Command::Update(Config { strict: true, .. })
        ));
    }
    #[test]
    fn parses_query_modalias() {
        let command = parse_cli(["query", "usb:v1p2"].as_slice()).unwrap();
        assert!(matches!(command, Command::Query { modalias, .. } if modalias == "usb:v1p2"));
    }
    #[test]
    fn query_requires_modalias() {
        assert_eq!(
            parse_cli(["query"].as_slice()).unwrap_err(),
            Error::MissingModalias
        );
    }
}
