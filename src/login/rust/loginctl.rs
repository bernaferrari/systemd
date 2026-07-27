// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/loginctl.c

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginctlAction {
    ListSessions,
    ListUsers,
    ListSeats,
    SessionStatus(String),
    UserStatus(String),
    SeatStatus(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginctlOptions {
    pub full: bool,
    pub legend: bool,
    pub properties: Vec<String>,
    pub json: bool,
    pub no_pager: bool,
}

impl Default for LoginctlOptions {
    fn default() -> Self {
        Self {
            full: false,
            legend: true,
            properties: Vec::new(),
            json: false,
            no_pager: false,
        }
    }
}

pub fn parse_verb(verb: &str, arg: Option<&str>) -> Result<LoginctlAction, String> {
    match (verb, arg) {
        ("list-sessions", None) => Ok(LoginctlAction::ListSessions),
        ("list-users", None) => Ok(LoginctlAction::ListUsers),
        ("list-seats", None) => Ok(LoginctlAction::ListSeats),
        ("session-status", Some(id)) => Ok(LoginctlAction::SessionStatus(id.to_string())),
        ("user-status", Some(id)) => Ok(LoginctlAction::UserStatus(id.to_string())),
        ("seat-status", Some(id)) => Ok(LoginctlAction::SeatStatus(id.to_string())),
        _ => Err(format!("unsupported loginctl verb: {verb}")),
    }
}

pub fn render_table(headers: &[&str], rows: &[Vec<String>]) -> Result<String, String> {
    let mut lines = vec![headers.join("\t")];
    lines.extend(rows.iter().map(|row| row.join("\t")));
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbs_parse() {
        assert_eq!(
            parse_verb("list-sessions", None),
            Ok(LoginctlAction::ListSessions)
        );
        assert_eq!(
            parse_verb("seat-status", Some("seat0")),
            Ok(LoginctlAction::SeatStatus("seat0".into()))
        );
    }
}
