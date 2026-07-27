// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/escape/escape-tool.c

pub const EINVAL: i32 = -22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Escape,
    Unescape,
    Mangle,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub action: Action,
    pub suffix: Option<String>,
    pub template: Option<String>,
    pub path: bool,
    pub instance: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub i32);
pub type Result<T> = std::result::Result<T, Error>;

impl Default for Action {
    fn default() -> Self {
        Self::Escape
    }
}

pub fn validate(cfg: &Config) -> Result<()> {
    if cfg.template.is_some() && cfg.suffix.is_some() {
        return Err(Error(EINVAL));
    }
    if matches!(cfg.action, Action::Mangle) && (cfg.template.is_some() || cfg.suffix.is_some()) {
        return Err(Error(EINVAL));
    }
    if cfg.path && matches!(cfg.action, Action::Mangle) {
        return Err(Error(EINVAL));
    }
    if cfg.instance && !matches!(cfg.action, Action::Unescape) {
        return Err(Error(EINVAL));
    }
    if cfg.instance && cfg.template.is_some() {
        return Err(Error(EINVAL));
    }
    if cfg.suffix.is_some() && matches!(cfg.action, Action::Unescape) {
        return Err(Error(EINVAL));
    }
    Ok(())
}

pub fn escape_name(s: &str, path: bool) -> String {
    if path {
        s.trim_start_matches('/').replace('/', "-")
    } else {
        s.replace('/', "-")
    }
}
pub fn unescape_name(s: &str, path: bool) -> String {
    if path {
        format!("/{}", s.replace('-', "/"))
    } else {
        s.replace('-', "/")
    }
}
pub fn mangle_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '-' | '@') {
                c
            } else {
                '-'
            }
        })
        .collect()
}
pub fn apply(cfg: &Config, s: &str) -> Result<String> {
    validate(cfg)?;
    let mut out = match cfg.action {
        Action::Escape => escape_name(s, cfg.path),
        Action::Unescape => unescape_name(s, cfg.path),
        Action::Mangle => mangle_name(s),
    };
    if let Some(t) = &cfg.template {
        out = t.replace('@', &format!("@{out}"));
    }
    if let Some(suf) = &cfg.suffix {
        out.push('.');
        out.push_str(suf);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_action_is_escape() {
        assert!(matches!(Config::default().action, Action::Escape));
    }
    #[test]
    fn suffix_and_template_conflict() {
        assert!(
            validate(&Config {
                suffix: Some("service".into()),
                template: Some("x@.service".into()),
                ..Config::default()
            })
            .is_err()
        );
    }
    #[test]
    fn instance_requires_unescape() {
        assert!(
            validate(&Config {
                instance: true,
                ..Config::default()
            })
            .is_err()
        );
    }
    #[test]
    fn path_not_allowed_with_mangle() {
        assert!(
            validate(&Config {
                action: Action::Mangle,
                path: true,
                ..Config::default()
            })
            .is_err()
        );
    }
    #[test]
    fn escape_path_trims_leading_slash() {
        assert_eq!(escape_name("/var/lib", true), "var-lib");
    }
    #[test]
    fn unescape_path_restores_absolute_shape() {
        assert_eq!(unescape_name("var-lib", true), "/var/lib");
    }
    #[test]
    fn mangle_replaces_spaces() {
        assert_eq!(mangle_name("a b"), "a-b");
    }
    #[test]
    fn apply_suffix() {
        assert_eq!(
            apply(
                &Config {
                    suffix: Some("service".into()),
                    ..Config::default()
                },
                "tty1"
            )
            .unwrap(),
            "tty1.service"
        );
    }
    #[test]
    fn apply_template() {
        assert_eq!(
            apply(
                &Config {
                    template: Some("getty@.service".into()),
                    ..Config::default()
                },
                "tty1"
            )
            .unwrap(),
            "getty@tty1.service"
        );
    }
    #[test]
    fn suffix_disallowed_for_unescape() {
        assert!(
            validate(&Config {
                action: Action::Unescape,
                suffix: Some("service".into()),
                ..Config::default()
            })
            .is_err()
        );
    }
}
