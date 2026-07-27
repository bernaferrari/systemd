// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
// PORT-SYNC: src/kernel-install/kernel-install.c

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidAction(String),
    InvalidLayout(String),
    InvalidEntryTokenType(String),
    InvalidVersion,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAction(v) => write!(f, "invalid action: {v}"),
            Self::InvalidLayout(v) => write!(f, "invalid layout: {v}"),
            Self::InvalidEntryTokenType(v) => write!(f, "invalid entry token type: {v}"),
            Self::InvalidVersion => f.write_str("invalid kernel version"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Add,
    Remove,
    Inspect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layout {
    Auto,
    Uki,
    Bls,
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BootEntryTokenType {
    #[default]
    Auto,
    MachineId,
    OsImage,
    Filesystem,
    GptAuto,
    Temporary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootEntryType {
    Regular,
    Loader,
    Unified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelImageType {
    Unknown,
    Uki,
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub action: Action,
    pub layout: Layout,
    pub entry_token_type: BootEntryTokenType,
    pub version: Option<String>,
    pub kernel: Option<String>,
}

pub fn parse_action(value: &str) -> Result<Action> {
    match value {
        "add" => Ok(Action::Add),
        "remove" => Ok(Action::Remove),
        "inspect" => Ok(Action::Inspect),
        _ => Err(Error::InvalidAction(value.into())),
    }
}

pub fn parse_layout(value: &str) -> Result<Layout> {
    Ok(match value {
        "" | "auto" => Layout::Auto,
        "uki" => Layout::Uki,
        "bls" | "type1" => Layout::Bls,
        other
            if other
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') =>
        {
            Layout::Other(other.into())
        }
        _ => return Err(Error::InvalidLayout(value.into())),
    })
}

pub fn parse_entry_token_type(value: &str) -> Result<BootEntryTokenType> {
    match value {
        "auto" => Ok(BootEntryTokenType::Auto),
        "machine-id" => Ok(BootEntryTokenType::MachineId),
        "os-image" => Ok(BootEntryTokenType::OsImage),
        "filesystem" => Ok(BootEntryTokenType::Filesystem),
        "gpt-auto" => Ok(BootEntryTokenType::GptAuto),
        "temporary" => Ok(BootEntryTokenType::Temporary),
        _ => Err(Error::InvalidEntryTokenType(value.into())),
    }
}

pub fn set_version(context: &mut Context, version: &str) -> Result<()> {
    if version.is_empty() || version.contains('/') {
        return Err(Error::InvalidVersion);
    }
    context.version = Some(version.into());
    Ok(())
}

pub fn new_context(action: Action) -> Context {
    Context {
        action,
        layout: Layout::Auto,
        entry_token_type: BootEntryTokenType::Auto,
        version: None,
        kernel: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_add_action() {
        assert_eq!(parse_action("add").unwrap(), Action::Add);
    }
    #[test]
    fn rejects_invalid_action() {
        assert!(matches!(parse_action("list"), Err(Error::InvalidAction(_))));
    }
    #[test]
    fn parses_bls_layout_alias() {
        assert_eq!(parse_layout("type1").unwrap(), Layout::Bls);
    }
    #[test]
    fn parses_custom_layout() {
        assert_eq!(
            parse_layout("custom-x").unwrap(),
            Layout::Other("custom-x".into())
        );
    }
    #[test]
    fn rejects_invalid_layout() {
        assert!(matches!(
            parse_layout("bad/value"),
            Err(Error::InvalidLayout(_))
        ));
    }
    #[test]
    fn parses_entry_token_type() {
        assert_eq!(
            parse_entry_token_type("filesystem").unwrap(),
            BootEntryTokenType::Filesystem
        );
    }
    #[test]
    fn sets_valid_version() {
        let mut context = new_context(Action::Add);
        set_version(&mut context, "6.9.0").unwrap();
        assert_eq!(context.version.as_deref(), Some("6.9.0"));
    }
    #[test]
    fn rejects_invalid_version() {
        let mut context = new_context(Action::Add);
        assert_eq!(
            set_version(&mut context, "bad/ver").unwrap_err(),
            Error::InvalidVersion
        );
    }
}
