// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/install-printf.c, src/shared/install-printf.h
//
// Specifier-based printf formatting for systemd unit install names.
//
// Expands %n, %p, %i, %j, %N, and %% specifiers in format strings
// using [`InstallNameContext`] to resolve unit name components.

// ── Error type ──────────────────────────────────────────────────────────────

/// Error type for install name printf operations.
use crate::ffi::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallPrintfError {
    /// Encountered an unknown specifier character after `%`.
    UnknownSpecifier(char),
}

impl std::fmt::Display for InstallPrintfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSpecifier(ch) => write!(f, "unknown specifier '%{}'", ch),
        }
    }
}

impl std::error::Error for InstallPrintfError {}

// ── Context ─────────────────────────────────────────────────────────────────

/// Context providing unit name information for specifier expansion.
///
/// Provides the full unit name and an optional default instance used
/// when the name is a template (e.g. `"foo@.service"`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallNameContext<'a> {
    /// The full unit name (e.g. `"foo@bar.service"`).
    pub name: &'a str,
    /// Optional default instance for template unit names.
    pub default_instance: Option<&'a str>,
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Extract the prefix from a unit name (everything before `@` or the first `.`).
///
/// Mirrors C's `unit_name_to_prefix`:
/// - `"foo@bar.service"` → `"foo"`
/// - `"foo.service"`     → `"foo"`
/// - `"foo-bar-baz@inst.service"` → `"foo-bar-baz"`
fn unit_prefix(name: &str) -> &str {
    if let Some((prefix, _)) = name.split_once('@') {
        return prefix;
    }
    name.split('.').next().unwrap_or(name)
}

/// Extract the instance from a unit name (the part between `@` and `.`).
///
/// Mirrors C's `unit_name_to_instance`:
/// - `"foo@bar.service"` → `Some("bar")`
/// - `"foo@.service"`    → `None` (empty instance = template)
/// - `"foo.service"`     → `None` (no `@`)
fn unit_instance(name: &str) -> Option<&str> {
    let (_, rest) = name.split_once('@')?;
    let (instance, _) = rest.split_once('.').unwrap_or((rest, ""));
    (!instance.is_empty()).then_some(instance)
}

/// Check whether a unit name is a template (has `@` with an empty instance part).
///
/// Mirrors C's `unit_name_is_valid(name, UNIT_NAME_TEMPLATE)`:
/// - `"foo@.service"`    → `true`
/// - `"foo@bar.service"` → `false`
/// - `"foo.service"`     → `false`
fn is_template(name: &str) -> bool {
    match name.split_once('@') {
        Some((_, rest)) => rest.split('.').next().map_or(false, |s| s.is_empty()),
        None => false,
    }
}

/// Replace the instance portion of a unit name, preserving prefix and suffix.
///
/// Mirrors C's `unit_name_replace_instance`:
/// - `("foo@.service", "inst")`  → `"foo@inst.service"`
/// - `("foo@bar.service", "baz")` → `"foo@baz.service"`
/// - `("foo.service", "inst")`   → `"foo.service"` (no `@`, unchanged)
fn replace_instance(name: &str, instance: &str) -> String {
    let Some(at_pos) = name.find('@') else {
        return name.to_string();
    };
    let suffix_start = name[at_pos..]
        .find('.')
        .map(|p| at_pos + p)
        .unwrap_or(name.len());
    format!("{}@{}{}", &name[..at_pos], instance, &name[suffix_start..])
}

/// Extract the prefix with trailing `@` for template/instance names,
/// or just the prefix for plain names.
///
/// Mirrors C's `unit_name_to_prefix_and_instance`:
/// - `"foo@bar.service"` → `"foo@"`
/// - `"foo@.service"`    → `"foo@"`
/// - `"foo.service"`     → `"foo"`
fn unit_prefix_and_instance(name: &str) -> &str {
    if let Some(at_pos) = name.find('@') {
        return &name[..=at_pos];
    }
    name.split('.').next().unwrap_or(name)
}

/// Expand a single specifier character using the given context.
fn expand_specifier(ch: char, ctx: &InstallNameContext<'_>, out: &mut String) -> bool {
    match ch {
        '%' => {
            out.push('%');
            true
        }
        'n' => {
            if is_template(ctx.name) && ctx.default_instance.is_some() {
                out.push_str(&replace_instance(ctx.name, ctx.default_instance.unwrap()));
            } else {
                out.push_str(ctx.name);
            }
            true
        }
        'p' => {
            out.push_str(unit_prefix(ctx.name));
            true
        }
        'i' => {
            let instance = unit_instance(ctx.name)
                .map(|s| s.to_string())
                .or_else(|| ctx.default_instance.map(|s| s.to_string()))
                .unwrap_or_default();
            out.push_str(&instance);
            true
        }
        'j' => {
            let prefix = unit_prefix(ctx.name);
            let last = prefix.rsplit('-').next().unwrap_or(prefix);
            out.push_str(last);
            true
        }
        'N' => {
            let pai = unit_prefix_and_instance(ctx.name);
            out.push_str(pai);
            if pai.ends_with('@') {
                if let Some(di) = ctx.default_instance {
                    out.push_str(di);
                }
            }
            true
        }
        _ => false,
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Expand `%`-specifiers in a format string using the given install name context.
///
/// Mirrors C's `install_name_printf`. Supported specifiers:
///
/// | Specifier | Expansion |
/// |-----------|-----------|
/// | `%%`      | Literal `%` |
/// | `%n`      | Full unit name (instance replaced for templates with default) |
/// | `%p`      | Unit prefix (before `@` or first `.`) |
/// | `%i`      | Instance, falling back to `default_instance` if absent |
/// | `%j`      | Last component of prefix (after final `-`) |
/// | `%N`      | Prefix and instance combined |
pub fn expand_install_name(
    format: &str,
    ctx: &InstallNameContext<'_>,
) -> Result<String, InstallPrintfError> {
    let mut out = String::new();
    let mut percent = false;

    for ch in format.chars() {
        if !percent {
            percent = ch == '%';
            if !percent {
                out.push(ch);
            }
            continue;
        }

        percent = false;
        if !expand_specifier(ch, ctx, &mut out) {
            return Err(InstallPrintfError::UnknownSpecifier(ch));
        }
    }

    // Trailing `%` with no specifier character: preserve it.
    if percent {
        out.push('%');
    }

    Ok(out)
}

/// Check whether a format string contains any known install-printf specifier.
///
/// Detects `%i`, `%j`, `%n`, `%N`, `%p`, and `%%` patterns.
pub fn has_specifier(format: &str) -> bool {
    let bytes = format.as_bytes();
    bytes
        .windows(2)
        .any(|w| w[0] == b'%' && b"ijnNp%".contains(&w[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper unit tests ───────────────────────────────────────────────

    #[test]
    fn test_unit_prefix_with_instance() {
        assert_eq!(unit_prefix("foo@bar.service"), "foo");
        assert_eq!(unit_prefix("foo-bar-baz@inst.service"), "foo-bar-baz");
    }

    #[test]
    fn test_unit_prefix_without_at() {
        assert_eq!(unit_prefix("foo.service"), "foo");
        assert_eq!(unit_prefix("multi-word.service"), "multi-word");
    }

    #[test]
    fn test_unit_prefix_template() {
        assert_eq!(unit_prefix("foo@.service"), "foo");
    }

    #[test]
    fn test_unit_instance_present() {
        assert_eq!(unit_instance("foo@bar.service"), Some("bar"));
        assert_eq!(unit_instance("a@b.c"), Some("b"));
    }

    #[test]
    fn test_unit_instance_template_empty() {
        assert_eq!(unit_instance("foo@.service"), None);
    }

    #[test]
    fn test_unit_instance_no_at() {
        assert_eq!(unit_instance("foo.service"), None);
    }

    #[test]
    fn test_is_template_various() {
        assert!(is_template("foo@.service"));
        assert!(is_template("foo-bar@.socket"));
        assert!(!is_template("foo@bar.service"));
        assert!(!is_template("foo.service"));
    }

    #[test]
    fn test_replace_instance_template() {
        assert_eq!(replace_instance("foo@.service", "inst"), "foo@inst.service");
        assert_eq!(
            replace_instance("foo@bar.service", "baz"),
            "foo@baz.service"
        );
    }

    #[test]
    fn test_replace_instance_no_at() {
        assert_eq!(replace_instance("foo.service", "inst"), "foo.service");
    }

    #[test]
    fn test_unit_prefix_and_instance() {
        assert_eq!(unit_prefix_and_instance("foo@bar.service"), "foo@");
        assert_eq!(unit_prefix_and_instance("foo@.service"), "foo@");
        assert_eq!(unit_prefix_and_instance("foo.service"), "foo");
    }

    // ── Specifier expansion tests ───────────────────────────────────────

    #[test]
    fn test_expand_name_regular() {
        let ctx = InstallNameContext {
            name: "foo.service",
            default_instance: None,
        };
        assert_eq!(expand_install_name("%n", &ctx).unwrap(), "foo.service");
    }

    #[test]
    fn test_expand_name_template_with_default() {
        let ctx = InstallNameContext {
            name: "foo@.service",
            default_instance: Some("inst"),
        };
        assert_eq!(expand_install_name("%n", &ctx).unwrap(), "foo@inst.service");
    }

    #[test]
    fn test_expand_name_template_without_default() {
        let ctx = InstallNameContext {
            name: "foo@.service",
            default_instance: None,
        };
        assert_eq!(expand_install_name("%n", &ctx).unwrap(), "foo@.service");
    }

    #[test]
    fn test_expand_name_instance_name_ignores_default() {
        let ctx = InstallNameContext {
            name: "foo@bar.service",
            default_instance: Some("baz"),
        };
        assert_eq!(expand_install_name("%n", &ctx).unwrap(), "foo@bar.service");
    }

    #[test]
    fn test_expand_prefix() {
        let ctx = InstallNameContext {
            name: "foo@bar.service",
            default_instance: None,
        };
        assert_eq!(expand_install_name("%p", &ctx).unwrap(), "foo");
    }

    #[test]
    fn test_expand_instance_present() {
        let ctx = InstallNameContext {
            name: "foo@bar.service",
            default_instance: Some("baz"),
        };
        assert_eq!(expand_install_name("%i", &ctx).unwrap(), "bar");
    }

    #[test]
    fn test_expand_instance_fallback_to_default() {
        let ctx = InstallNameContext {
            name: "foo@.service",
            default_instance: Some("inst"),
        };
        assert_eq!(expand_install_name("%i", &ctx).unwrap(), "inst");
    }

    #[test]
    fn test_expand_instance_empty_when_nothing() {
        let ctx = InstallNameContext {
            name: "foo@.service",
            default_instance: None,
        };
        assert_eq!(expand_install_name("%i", &ctx).unwrap(), "");
    }

    #[test]
    fn test_expand_instance_no_at_uses_default() {
        let ctx = InstallNameContext {
            name: "foo.service",
            default_instance: Some("fallback"),
        };
        assert_eq!(expand_install_name("%i", &ctx).unwrap(), "fallback");
    }

    #[test]
    fn test_expand_last_component_with_dash() {
        let ctx = InstallNameContext {
            name: "foo-bar-baz.service",
            default_instance: None,
        };
        assert_eq!(expand_install_name("%j", &ctx).unwrap(), "baz");
    }

    #[test]
    fn test_expand_last_component_with_instance_and_dash() {
        let ctx = InstallNameContext {
            name: "foo-bar-baz@inst.service",
            default_instance: None,
        };
        assert_eq!(expand_install_name("%j", &ctx).unwrap(), "baz");
    }

    #[test]
    fn test_expand_last_component_no_dash() {
        let ctx = InstallNameContext {
            name: "foo.service",
            default_instance: None,
        };
        assert_eq!(expand_install_name("%j", &ctx).unwrap(), "foo");
    }

    #[test]
    fn test_expand_prefix_and_instance_template_with_default() {
        let ctx = InstallNameContext {
            name: "foo@.service",
            default_instance: Some("inst"),
        };
        assert_eq!(expand_install_name("%N", &ctx).unwrap(), "foo@inst");
    }

    #[test]
    fn test_expand_prefix_and_instance_template_without_default() {
        let ctx = InstallNameContext {
            name: "foo@.service",
            default_instance: None,
        };
        assert_eq!(expand_install_name("%N", &ctx).unwrap(), "foo@");
    }

    #[test]
    fn test_expand_prefix_and_instance_non_template() {
        let ctx = InstallNameContext {
            name: "foo.service",
            default_instance: Some("inst"),
        };
        assert_eq!(expand_install_name("%N", &ctx).unwrap(), "foo");
    }

    #[test]
    fn test_expand_prefix_and_instance_instantiated_with_default() {
        let ctx = InstallNameContext {
            name: "foo@bar.service",
            default_instance: Some("baz"),
        };
        assert_eq!(expand_install_name("%N", &ctx).unwrap(), "foo@baz");
    }

    #[test]
    fn test_expand_percent_literal() {
        let ctx = InstallNameContext {
            name: "foo.service",
            default_instance: None,
        };
        assert_eq!(expand_install_name("100%%", &ctx).unwrap(), "100%");
    }

    #[test]
    fn test_trailing_percent() {
        let ctx = InstallNameContext {
            name: "foo.service",
            default_instance: None,
        };
        assert_eq!(expand_install_name("foo%", &ctx).unwrap(), "foo%");
    }

    #[test]
    fn test_unknown_specifier_returns_error() {
        let ctx = InstallNameContext {
            name: "foo.service",
            default_instance: None,
        };
        let err = expand_install_name("%z", &ctx).unwrap_err();
        assert_eq!(err, InstallPrintfError::UnknownSpecifier('z'));
    }

    #[test]
    fn test_empty_format() {
        let ctx = InstallNameContext {
            name: "foo.service",
            default_instance: None,
        };
        assert_eq!(expand_install_name("", &ctx).unwrap(), "");
    }

    #[test]
    fn test_no_specifiers_passthrough() {
        let ctx = InstallNameContext {
            name: "foo.service",
            default_instance: None,
        };
        assert_eq!(
            expand_install_name("hello world", &ctx).unwrap(),
            "hello world"
        );
    }

    #[test]
    fn test_mixed_specifiers() {
        let ctx = InstallNameContext {
            name: "foo-bar@baz.service",
            default_instance: Some("qux"),
        };
        assert_eq!(
            expand_install_name("%n %p %i %j %N %%", &ctx).unwrap(),
            "foo-bar@baz.service foo-bar baz bar foo-bar@qux %"
        );
    }

    // ── has_specifier tests ─────────────────────────────────────────────

    #[test]
    fn test_has_specifier_true() {
        assert!(has_specifier("%n"));
        assert!(has_specifier("%p"));
        assert!(has_specifier("%i"));
        assert!(has_specifier("%j"));
        assert!(has_specifier("%N"));
        assert!(has_specifier("%%"));
        assert!(has_specifier("prefix-%n-suffix"));
    }

    #[test]
    fn test_has_specifier_false() {
        assert!(!has_specifier(""));
        assert!(!has_specifier("no specifiers"));
        assert!(!has_specifier("100 percent"));
        assert!(!has_specifier("%z"));
        assert!(!has_specifier("%x"));
    }

    #[test]
    fn test_has_specifier_edge_cases() {
        assert!(!has_specifier("%"));
        assert!(has_specifier("%%"));
        assert!(!has_specifier("% "));
    }
}
