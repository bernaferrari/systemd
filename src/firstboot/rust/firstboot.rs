// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/firstboot/firstboot.c

pub const EINVAL: i32 = -22;
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub locale: Option<String>,
    pub locale_messages: Option<String>,
    pub keymap: Option<String>,
    pub timezone: Option<String>,
    pub hostname: Option<String>,
    pub root_password: Option<String>,
    pub prompt_locale: bool,
    pub prompt_keymap: bool,
    pub prompt_timezone: bool,
    pub prompt_hostname: bool,
    pub prompt_root_password: bool,
    pub force: bool,
    pub delete_root_password: bool,
    pub welcome: bool,
    pub reset: bool,
}
pub fn should_configure(exists: bool, force: bool) -> bool {
    force || !exists
}
pub fn read_credential(current: Option<String>, value: Option<&str>) -> Option<String> {
    current.or_else(|| value.map(str::to_string))
}
pub fn validate_hostname(s: &str) -> Result<(), i32> {
    if s.is_empty() || s.len() > 64 || s.contains(' ') {
        Err(EINVAL)
    } else {
        Ok(())
    }
}
pub fn welcome_text(pretty_name: &str) -> String {
    format!("Welcome to {pretty_name}!\n\nPlease configure the system!")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_flags() {
        assert!(!Config::default().force);
    }
    #[test]
    fn should_configure_when_missing() {
        assert!(should_configure(false, false));
    }
    #[test]
    fn should_not_configure_when_present() {
        assert!(!should_configure(true, false));
    }
    #[test]
    fn force_always_configures() {
        assert!(should_configure(true, true));
    }
    #[test]
    fn credential_uses_current_first() {
        assert_eq!(
            read_credential(Some("x".into()), Some("y")),
            Some("x".into())
        );
    }
    #[test]
    fn credential_uses_new_value() {
        assert_eq!(read_credential(None, Some("y")), Some("y".into()));
    }
    #[test]
    fn hostname_validation_accepts_simple_name() {
        assert!(validate_hostname("host").is_ok());
    }
    #[test]
    fn hostname_validation_rejects_space() {
        assert!(validate_hostname("bad host").is_err());
    }
    #[test]
    fn hostname_validation_rejects_empty() {
        assert!(validate_hostname("").is_err());
    }
    #[test]
    fn welcome_mentions_configuration() {
        assert!(welcome_text("TestOS").contains("configure"));
    }
}
