// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/kernel-install/kernel-install.c
//
// Safe Rust model of core kernel-install parsing and path construction rules.

pub const EINVAL: i32 = -22;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BootEntryTokenType {
    #[default]
    Auto,
    MachineId,
    Literal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Add,
    Remove,
    Inspect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    Auto,
    Uki,
    Bls,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub action: Action,
    pub layout: Layout,
    pub entry_token_type: BootEntryTokenType,
    pub entry_token: Option<String>,
    pub version: Option<String>,
    pub kernel: Option<String>,
    pub initrds: Vec<String>,
    pub plugins: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub i32);
pub type Result<T> = std::result::Result<T, Error>;

impl Default for Context {
    fn default() -> Self {
        Self {
            action: Action::Inspect,
            layout: Layout::Auto,
            entry_token_type: BootEntryTokenType::Auto,
            entry_token: None,
            version: None,
            kernel: None,
            initrds: Vec::new(),
            plugins: Vec::new(),
        }
    }
}

pub fn parse_layout(s: &str) -> Result<Layout> {
    Ok(match s {
        "auto" => Layout::Auto,
        "uki" => Layout::Uki,
        "bls" => Layout::Bls,
        _ if !s.is_empty() => Layout::Other,
        _ => return Err(Error(EINVAL)),
    })
}

pub fn layout_to_string(layout: Layout) -> &'static str {
    match layout {
        Layout::Auto => "auto",
        Layout::Uki => "uki",
        Layout::Bls => "bls",
        Layout::Other => "other",
    }
}

pub fn parse_action(s: &str) -> Result<Action> {
    match s {
        "add" => Ok(Action::Add),
        "remove" => Ok(Action::Remove),
        "inspect" => Ok(Action::Inspect),
        _ => Err(Error(EINVAL)),
    }
}

pub fn validate_version_filename(version: &str) -> Result<()> {
    if version.is_empty()
        || version == "."
        || version == ".."
        || version.contains('/')
        || version.contains('\0')
    {
        return Err(Error(EINVAL));
    }
    Ok(())
}

pub fn build_entry_dir(boot_root: &str, token: &str, version: &str) -> Result<String> {
    validate_version_filename(version)?;
    Ok(format!("{boot_root}/{token}/{version}"))
}

pub fn build_plugin_argv(
    action: Action,
    version: &str,
    entry_dir: &str,
    kernel: Option<&str>,
) -> Vec<String> {
    let mut v = vec![
        match action {
            Action::Add => "add",
            Action::Remove => "remove",
            Action::Inspect => "inspect",
        }
        .into(),
        version.into(),
        entry_dir.into(),
    ];
    if let Some(k) = kernel {
        v.push(k.into());
    }
    v
}

pub fn context_should_make_entry_dir(layout: Layout, explicit: Option<bool>) -> bool {
    explicit.unwrap_or(layout == Layout::Bls)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_context() {
        assert_eq!(Context::default().layout, Layout::Auto);
    }
    #[test]
    fn parse_layout_known() {
        assert_eq!(parse_layout("bls").unwrap(), Layout::Bls);
    }
    #[test]
    fn parse_layout_other() {
        assert_eq!(parse_layout("custom").unwrap(), Layout::Other);
    }
    #[test]
    fn parse_layout_empty_fails() {
        assert!(parse_layout("").is_err());
    }
    #[test]
    fn parse_action_add() {
        assert_eq!(parse_action("add").unwrap(), Action::Add);
    }
    #[test]
    fn version_validation_rejects_slash() {
        assert!(validate_version_filename("1/2").is_err());
    }
    #[test]
    fn entry_dir_is_constructed() {
        assert_eq!(build_entry_dir("/boot", "abc", "1").unwrap(), "/boot/abc/1");
    }
    #[test]
    fn plugin_argv_includes_kernel_when_present() {
        assert_eq!(
            build_plugin_argv(Action::Add, "1", "/e", Some("/vmlinuz")).len(),
            4
        );
    }
    #[test]
    fn default_make_entry_dir_depends_on_layout() {
        assert!(context_should_make_entry_dir(Layout::Bls, None));
    }
    #[test]
    fn explicit_make_entry_dir_overrides_default() {
        assert!(!context_should_make_entry_dir(Layout::Bls, Some(false)));
    }
}
