// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/hwdb/hwdb.c
//
// Safe Rust model of systemd-hwdb command parsing and helpers.

pub const EINVAL: i32 = -22;
pub const UDEVLIBEXECDIR: &str = "/usr/lib/udev";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Update,
    Query,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub hwdb_bin_dir: Option<String>,
    pub root: Option<String>,
    pub strict: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub i32);
pub type Result<T> = std::result::Result<T, Error>;

pub fn parse_options(args: &[&str]) -> Result<Config> {
    let mut cfg = Config::default();
    for arg in args {
        match *arg {
            "-s" | "--strict" => cfg.strict = true,
            "--usr" => cfg.hwdb_bin_dir = Some(UDEVLIBEXECDIR.into()),
            _ if arg.starts_with("--root=") => cfg.root = Some(arg[7..].into()),
            _ => return Err(Error(EINVAL)),
        }
    }
    Ok(cfg)
}

pub fn parse_command(argv: &[&str]) -> Result<(Command, Option<String>)> {
    match argv {
        ["update"] => Ok((Command::Update, None)),
        ["query", modalias] => Ok((Command::Query, Some((*modalias).into()))),
        _ => Err(Error(EINVAL)),
    }
}

pub fn build_update_request(cfg: &Config) -> (Option<&str>, Option<&str>, bool, bool) {
    (
        cfg.root.as_deref(),
        cfg.hwdb_bin_dir.as_deref(),
        cfg.strict,
        false,
    )
}

pub fn query_argument(argv: &[&str]) -> Result<&str> {
    match parse_command(argv)? {
        (Command::Query, Some(m)) => Ok(Box::leak(m.into_boxed_str())),
        _ => Err(Error(EINVAL)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_config() {
        assert!(!Config::default().strict);
    }
    #[test]
    fn parse_strict() {
        assert!(parse_options(&["--strict"]).unwrap().strict);
    }
    #[test]
    fn parse_usr() {
        assert_eq!(
            parse_options(&["--usr"]).unwrap().hwdb_bin_dir.as_deref(),
            Some(UDEVLIBEXECDIR)
        );
    }
    #[test]
    fn parse_root() {
        assert_eq!(
            parse_options(&["--root=/x"]).unwrap().root.as_deref(),
            Some("/x")
        );
    }
    #[test]
    fn invalid_option_fails() {
        assert!(parse_options(&["--wat"]).is_err());
    }
    #[test]
    fn parse_update_command() {
        assert_eq!(parse_command(&["update"]).unwrap().0, Command::Update);
    }
    #[test]
    fn parse_query_command() {
        assert_eq!(
            parse_command(&["query", "usb:v1234"]).unwrap().1.as_deref(),
            Some("usb:v1234")
        );
    }
    #[test]
    fn query_requires_modalias() {
        assert!(parse_command(&["query"]).is_err());
    }
    #[test]
    fn build_update_request_preserves_settings() {
        assert!(
            build_update_request(&Config {
                strict: true,
                ..Config::default()
            })
            .2
        );
    }
    #[test]
    fn unknown_command_fails() {
        assert!(parse_command(&["other"]).is_err());
    }
}
