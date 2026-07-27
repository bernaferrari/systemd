// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-utmp.c

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtmpType {
    UserProcess,
    DeadProcess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtmpEntry {
    pub ut_type: UtmpType,
    pub line: String,
    pub pid: i32,
}

pub fn normalize_utmp_line(line: &str) -> String {
    line.strip_prefix("/dev/").unwrap_or(line).to_string()
}

pub fn should_update_session_tty(existing_tty: Option<&str>, new_tty: &str) -> bool {
    match existing_tty {
        None => !new_tty.is_empty(),
        Some(current) => current == new_tty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utmp_lines_drop_dev_prefix() {
        assert_eq!(normalize_utmp_line("/dev/tty2"), "tty2");
    }
}
