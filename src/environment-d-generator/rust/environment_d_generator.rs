// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/environment-d-generator/environment-d-generator.c
//
// Load additional environment variables from /etc/environment.d/.
// Merges .conf files and prints VAR=value assignments.

// ── Constants ─────────────────────────────────────────────────────────────

/// Standard environment.d search paths.
pub const ENVIRONMENT_D_PATHS: &[&str] = &[
    "/etc/environment.d",
    "/run/environment.d",
    "/usr/local/lib/environment.d",
    "/usr/lib/environment.d",
    "/lib/environment.d",
];

/// User environment.d relative path.
pub const USER_ENVIRONMENT_D: &str = "environment.d";

/// Config file extension.
pub const CONF_EXTENSION: &str = ".conf";

// ── Types ─────────────────────────────────────────────────────────────────

/// Parsed command-line arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentDGeneratorArgs;

/// Environment variable assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvAssignment {
    pub key: String,
    pub value: String,
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parse arguments — the generator takes no arguments.
pub fn parse_args(args: &[&str]) -> Result<EnvironmentDGeneratorArgs, i32> {
    if args.len() > 1 {
        return Err(-libc::EINVAL);
    }
    Ok(EnvironmentDGeneratorArgs)
}

// ── Core logic ────────────────────────────────────────────────────────────

/// Parse a VAR=value line into key and value.
pub fn parse_env_line(line: &str) -> Option<EnvAssignment> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
        return None;
    }
    let eq_pos = trimmed.find('=')?;
    let key = trimmed[..eq_pos].to_string();
    let value = trimmed[eq_pos + 1..].to_string();
    Some(EnvAssignment { key, value })
}

/// Merge a new assignment into an existing environment list.
/// If the key already exists, its value is replaced.
pub fn merge_env(env: &mut Vec<EnvAssignment>, assignment: EnvAssignment) {
    if let Some(existing) = env.iter_mut().find(|e| e.key == assignment.key) {
        existing.value = assignment.value;
    } else {
        env.push(assignment);
    }
}

/// Merge multiple assignments from lines of a config file.
pub fn merge_env_lines(env: &mut Vec<EnvAssignment>, lines: &[&str]) {
    for line in lines {
        if let Some(assignment) = parse_env_line(line) {
            merge_env(env, assignment);
        }
    }
}

/// Shell-quote a value if it contains special characters.
/// Mirrors the C `shell_maybe_quote()` function.
pub fn shell_maybe_quote(value: &str) -> String {
    let needs_quoting = value.is_empty()
        || value.chars().any(|c| {
            !c.is_ascii_alphanumeric()
                && c != '@'
                && c != '_'
                && c != '.'
                && c != '/'
                && c != ':'
                && c != '-'
                && c != '+'
                && c != ','
        });

    if !needs_quoting {
        return value.to_string();
    }

    let mut quoted = String::with_capacity(value.len() + 4);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

/// Format an environment assignment for output: KEY=quoted_value
pub fn format_env_assignment(assignment: &EnvAssignment) -> String {
    let quoted = shell_maybe_quote(&assignment.value);
    format!("{}={}", assignment.key, quoted)
}

/// Format all assignments for output, one per line.
pub fn format_env_output(env: &[EnvAssignment]) -> String {
    env.iter()
        .map(|a| format!("{}={}", a.key, shell_maybe_quote(&a.value)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Get the list of config file search directories.
pub fn environment_dirs(user_config_dir: Option<&str>) -> Vec<String> {
    let mut dirs: Vec<String> = ENVIRONMENT_D_PATHS.iter().map(|s| s.to_string()).collect();
    if let Some(user) = user_config_dir {
        dirs.insert(0, format!("{}/{}", user, USER_ENVIRONMENT_D));
    }
    dirs
}

/// Check if a filename has the expected .conf extension.
pub fn is_conf_file(name: &str) -> bool {
    name.ends_with(CONF_EXTENSION)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args_empty() {
        assert!(parse_args(&[]).is_ok());
    }

    #[test]
    fn test_parse_args_no_args() {
        assert!(parse_args(&["prog"]).is_ok());
    }

    #[test]
    fn test_parse_args_rejects_extra() {
        assert!(parse_args(&["prog", "extra"]).is_err());
    }

    #[test]
    fn test_parse_env_line_simple() {
        let a = parse_env_line("FOO=bar").unwrap();
        assert_eq!(a.key, "FOO");
        assert_eq!(a.value, "bar");
    }

    #[test]
    fn test_parse_env_line_with_equals() {
        let a = parse_env_line("PATH=/usr/bin:/bin").unwrap();
        assert_eq!(a.key, "PATH");
        assert_eq!(a.value, "/usr/bin:/bin");
    }

    #[test]
    fn test_parse_env_line_empty_value() {
        let a = parse_env_line("EMPTY=").unwrap();
        assert_eq!(a.key, "EMPTY");
        assert_eq!(a.value, "");
    }

    #[test]
    fn test_parse_env_line_comment() {
        assert!(parse_env_line("# comment").is_none());
    }

    #[test]
    fn test_parse_env_line_empty() {
        assert!(parse_env_line("").is_none());
        assert!(parse_env_line("   ").is_none());
    }

    #[test]
    fn test_parse_env_line_no_equals() {
        assert!(parse_env_line("NOEQUALSSIGN").is_none());
    }

    #[test]
    fn test_merge_env_new() {
        let mut env = Vec::new();
        merge_env(
            &mut env,
            EnvAssignment {
                key: "A".into(),
                value: "1".into(),
            },
        );
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].key, "A");
    }

    #[test]
    fn test_merge_env_replace() {
        let mut env = vec![EnvAssignment {
            key: "A".into(),
            value: "1".into(),
        }];
        merge_env(
            &mut env,
            EnvAssignment {
                key: "A".into(),
                value: "2".into(),
            },
        );
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].value, "2");
    }

    #[test]
    fn test_merge_env_lines() {
        let mut env = Vec::new();
        merge_env_lines(&mut env, &["A=1", "B=2", "# skip", "A=3"]);
        assert_eq!(env.len(), 2);
        assert_eq!(env[0].value, "3");
        assert_eq!(env[1].value, "2");
    }

    #[test]
    fn test_shell_maybe_quote_simple() {
        assert_eq!(shell_maybe_quote("hello"), "hello");
    }

    #[test]
    fn test_shell_maybe_quote_empty() {
        assert_eq!(shell_maybe_quote(""), "''");
    }

    #[test]
    fn test_shell_maybe_quote_with_space() {
        assert_eq!(shell_maybe_quote("hello world"), "'hello world'");
    }

    #[test]
    fn test_shell_maybe_quote_with_quote() {
        assert_eq!(shell_maybe_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_maybe_quote_path() {
        assert_eq!(shell_maybe_quote("/usr/bin:/bin"), "/usr/bin:/bin");
    }

    #[test]
    fn test_format_env_assignment() {
        let a = EnvAssignment {
            key: "FOO".into(),
            value: "bar baz".into(),
        };
        assert_eq!(format_env_assignment(&a), "FOO='bar baz'");
    }

    #[test]
    fn test_format_env_output() {
        let env = vec![
            EnvAssignment {
                key: "A".into(),
                value: "1".into(),
            },
            EnvAssignment {
                key: "B".into(),
                value: "hello world".into(),
            },
        ];
        let out = format_env_output(&env);
        assert!(out.contains("A=1"));
        assert!(out.contains("B='hello world'"));
    }

    #[test]
    fn test_environment_dirs_no_user() {
        let dirs = environment_dirs(None);
        assert_eq!(dirs.len(), ENVIRONMENT_D_PATHS.len());
    }

    #[test]
    fn test_environment_dirs_with_user() {
        let dirs = environment_dirs(Some("/home/user/.config/systemd"));
        assert_eq!(dirs.len(), ENVIRONMENT_D_PATHS.len() + 1);
        assert!(dirs[0].contains("user"));
    }

    #[test]
    fn test_is_conf_file() {
        assert!(is_conf_file("test.conf"));
        assert!(!is_conf_file("test.txt"));
        assert!(!is_conf_file("conf"));
    }
}
