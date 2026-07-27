// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/getty-generator/getty-generator.c
//
// Safe Rust model of getty source parsing and unit name generation.

pub const GETTY_SOURCE_NONE: u32 = 0;
pub const GETTY_SOURCE_CREDENTIAL: u32 = 1 << 0;
pub const GETTY_SOURCE_CONTAINER: u32 = 1 << 1;
pub const GETTY_SOURCE_CONSOLE: u32 = 1 << 2;
pub const GETTY_SOURCE_BUILTIN: u32 = 1 << 3;
pub const GETTY_SOURCE_ALL: u32 =
    GETTY_SOURCE_CREDENTIAL | GETTY_SOURCE_CONTAINER | GETTY_SOURCE_CONSOLE | GETTY_SOURCE_BUILTIN;

pub const EINVAL: i32 = -22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GettyKind {
    Serial,
    Container,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub i32);
pub type Result<T> = std::result::Result<T, Error>;

pub fn parse_getty_sources(s: &str) -> Result<u32> {
    if s.is_empty() {
        return Ok(GETTY_SOURCE_ALL);
    }
    if s == "1" || s.eq_ignore_ascii_case("yes") || s.eq_ignore_ascii_case("true") {
        return Ok(GETTY_SOURCE_ALL);
    }
    if s == "0" || s.eq_ignore_ascii_case("no") || s.eq_ignore_ascii_case("false") {
        return Ok(GETTY_SOURCE_NONE);
    }
    let mut flags = 0;
    for word in s.split(',').filter(|w| !w.is_empty()) {
        flags |= match word {
            "credential" => GETTY_SOURCE_CREDENTIAL,
            "container" => GETTY_SOURCE_CONTAINER,
            "console" => GETTY_SOURCE_CONSOLE,
            "builtin" => GETTY_SOURCE_BUILTIN,
            _ => return Err(Error(EINVAL)),
        };
    }
    Ok(flags)
}

pub fn skip_dev_prefix(path: &str) -> &str {
    path.strip_prefix("/dev/").unwrap_or(path)
}

pub fn valid_tty_name(tty: &str) -> bool {
    !tty.is_empty() && !tty.contains('/') && !tty.contains(' ') && !tty.contains('\0')
}

pub fn escaped_instance(tty: &str) -> Result<String> {
    let tty = skip_dev_prefix(tty);
    if !valid_tty_name(tty) && !tty.starts_with("pts/") {
        return Err(Error(EINVAL));
    }
    Ok(tty.replace('/', "-"))
}

pub fn build_unit_name(kind: GettyKind, tty: &str) -> Result<String> {
    let instance = escaped_instance(tty)?;
    Ok(match kind {
        GettyKind::Serial => format!("serial-getty@{instance}.service"),
        GettyKind::Container => format!("container-getty@{instance}.service"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_sources_mean_all() {
        assert_eq!(parse_getty_sources("").unwrap(), GETTY_SOURCE_ALL);
    }
    #[test]
    fn boolean_yes_means_all() {
        assert_eq!(parse_getty_sources("yes").unwrap(), GETTY_SOURCE_ALL);
    }
    #[test]
    fn boolean_no_means_none() {
        assert_eq!(parse_getty_sources("no").unwrap(), GETTY_SOURCE_NONE);
    }
    #[test]
    fn csv_is_accumulated() {
        assert_eq!(
            parse_getty_sources("console,builtin").unwrap(),
            GETTY_SOURCE_CONSOLE | GETTY_SOURCE_BUILTIN
        );
    }
    #[test]
    fn invalid_source_fails() {
        assert!(parse_getty_sources("bogus").is_err());
    }
    #[test]
    fn dev_prefix_is_removed() {
        assert_eq!(skip_dev_prefix("/dev/ttyS0"), "ttyS0");
    }
    #[test]
    fn tty_validation_rejects_slash() {
        assert!(!valid_tty_name("tty/S0"));
    }
    #[test]
    fn serial_unit_name_is_generated() {
        assert_eq!(
            build_unit_name(GettyKind::Serial, "/dev/ttyS0").unwrap(),
            "serial-getty@ttyS0.service"
        );
    }
    #[test]
    fn container_pts_path_is_supported() {
        assert_eq!(
            build_unit_name(GettyKind::Container, "/dev/pts/0").unwrap(),
            "container-getty@pts-0.service"
        );
    }
    #[test]
    fn invalid_instance_is_rejected() {
        assert!(build_unit_name(GettyKind::Serial, "bad tty").is_err());
    }
}
