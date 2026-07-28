// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/sysusers/sysusers.c
//
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemType {
    AddUser,
    AddGroup,
    AddMember,
    AddRange,
}

impl ItemType {
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'u' => Some(Self::AddUser),
            'g' => Some(Self::AddGroup),
            'm' => Some(Self::AddMember),
            'r' => Some(Self::AddRange),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AddUser => "user",
            Self::AddGroup => "group",
            Self::AddMember => "member",
            Self::AddRange => "range",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub item_type: ItemType,
    pub name: String,
    pub id: Option<u32>,
    pub description: Option<String>,
    pub home: Option<String>,
    pub shell: Option<String>,
    pub locked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysusersError {
    InvalidType,
    InvalidLine,
}

impl std::fmt::Display for SysusersError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SysusersError {}

pub fn pick_shell(is_root: bool, configured: Option<&str>) -> &'static str {
    if configured.is_some() {
        return "configured";
    }
    if is_root { "/bin/sh" } else { "/sbin/nologin" }
}

pub fn password_field(locked: bool, is_root: bool) -> &'static str {
    if locked {
        "!*"
    } else if is_root {
        "!"
    } else {
        "x"
    }
}

pub fn merge_members(existing: &[&str], additions: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = existing.iter().map(|s| (*s).to_string()).collect();
    for item in additions {
        if !out.iter().any(|e| e == item) {
            out.push((*item).to_string());
        }
    }
    out.sort();
    out
}

pub fn parse_item_line(line: &str) -> Result<Item, SysusersError> {
    let parts: Vec<_> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(SysusersError::InvalidLine);
    }
    let t = parts[0]
        .chars()
        .next()
        .and_then(ItemType::from_char)
        .ok_or(SysusersError::InvalidType)?;
    Ok(Item {
        item_type: t,
        name: parts[1].to_string(),
        id: parts.get(2).and_then(|s| s.parse().ok()),
        description: None,
        home: None,
        shell: None,
        locked: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_type() {
        assert_eq!(ItemType::from_char('u'), Some(ItemType::AddUser));
    }

    #[test]
    fn exposes_human_name() {
        assert_eq!(ItemType::AddGroup.as_str(), "group");
    }

    #[test]
    fn rejects_invalid_type() {
        assert_eq!(
            parse_item_line("x demo").unwrap_err(),
            SysusersError::InvalidType
        );
    }

    #[test]
    fn parses_simple_item() {
        assert_eq!(parse_item_line("u demo 100").unwrap().id, Some(100));
    }

    #[test]
    fn root_shell_defaults_to_sh() {
        assert_eq!(pick_shell(true, None), "/bin/sh");
    }

    #[test]
    fn non_root_shell_defaults_to_nologin() {
        assert_eq!(pick_shell(false, None), "/sbin/nologin");
    }

    #[test]
    fn locked_accounts_get_invalid_password_marker() {
        assert_eq!(password_field(true, false), "!*");
    }

    #[test]
    fn members_are_merged_uniquely() {
        assert_eq!(merge_members(&["b", "a"], &["a", "c"]), vec!["a", "b", "c"]);
    }
}
