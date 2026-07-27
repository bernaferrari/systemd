// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolvconf-compat.c
//
// resolvconf compatibility layer: parses CLI arguments and stdin input
// to register/unregister per-interface DNS configuration with systemd-resolved.
// Provides command-line compatibility with the resolvconf(8) tool.

use std::fmt;
use std::io::{self, BufRead};

// ── Constants ─────────────────────────────────────────────────────────────

pub const LONG_LINE_MAX: usize = 1024 * 1024;

// ── Enums ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupType {
    Regular,
    Private,
    Exclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecutionMode {
    #[default]
    Invalid,
    ResolveHost,
    SetLink,
    RevertLink,
}

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvconfError {
    InvalidArgument(String),
    NoDnsServers,
    StdinReadFailed(String),
    ParseFailed(String),
    UnsupportedOption(String),
    MissingMode,
    MissingInterface,
    InterfaceResolveFailed(String),
}

impl fmt::Display for ResolvconfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolvconfError::InvalidArgument(s) => write!(f, "Invalid argument: {}", s),
            ResolvconfError::NoDnsServers => {
                write!(f, "No DNS servers specified, refusing operation")
            }
            ResolvconfError::StdinReadFailed(s) => write!(f, "Failed to read from stdin: {}", s),
            ResolvconfError::ParseFailed(s) => write!(f, "Parse error: {}", s),
            ResolvconfError::UnsupportedOption(s) => write!(f, "Switch not supported: {}", s),
            ResolvconfError::MissingMode => {
                write!(f, "Expected either -a or -d on the command line")
            }
            ResolvconfError::MissingInterface => write!(f, "Expected interface name as argument"),
            ResolvconfError::InterfaceResolveFailed(s) => {
                write!(f, "Failed to resolve interface: {}", s)
            }
        }
    }
}

impl std::error::Error for ResolvconfError {}

// ── Parsed state ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvconfState {
    pub mode: ExecutionMode,
    pub dns_servers: Vec<String>,
    pub search_domains: Vec<String>,
    pub disable_default_route: bool,
    pub ifindex_permissive: bool,
    pub interface: Option<String>,
}

impl ResolvconfState {
    pub fn new() -> Self {
        Self {
            mode: ExecutionMode::Invalid,
            ..Default::default()
        }
    }
}

// ── Word extraction ────────────────────────────────────────────────────────

fn extract_words(input: &str, unquote: bool) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(&ch) = chars.peek() {
        match ch {
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
                chars.next();
            }
            '"' | '\'' if unquote => {
                in_quotes = !in_quotes;
                chars.next();
            }
            '\\' if unquote => {
                chars.next();
                if let Some(&next) = chars.peek() {
                    current.push(next);
                    chars.next();
                }
            }
            _ => {
                current.push(ch);
                chars.next();
            }
        }
    }

    if !current.is_empty() {
        words.push(current);
    }

    words
}

// ── Nameserver parsing ─────────────────────────────────────────────────────

fn parse_nameserver(string: &str, state: &mut ResolvconfState) {
    for word in extract_words(string, false) {
        state.dns_servers.push(word);
    }
}

// ── Search domain parsing ──────────────────────────────────────────────────

fn parse_search_domain(string: &str, state: &mut ResolvconfState) {
    for word in extract_words(string, true) {
        state.search_domains.push(word);
    }
}

// ── First word check ───────────────────────────────────────────────────────

fn first_word<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix(keyword) {
        if rest.is_empty() || rest.starts_with(char::is_whitespace) {
            return Some(rest.trim_start());
        }
    }
    None
}

// ── Stdin parsing ──────────────────────────────────────────────────────────

fn parse_stdin_content(
    content: &str,
    lookup_type: LookupType,
    state: &mut ResolvconfState,
) -> Result<(), ResolvconfError> {
    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if let Some(rest) = first_word(line, "nameserver") {
            parse_nameserver(rest, state);
            continue;
        }

        let domain_rest = first_word(line, "domain");
        let search_rest = first_word(line, "search");
        if let Some(rest) = domain_rest.or(search_rest) {
            parse_search_domain(rest, state);
            continue;
        }
    }

    match lookup_type {
        LookupType::Regular => {}
        LookupType::Private => {
            state.disable_default_route = true;
        }
        LookupType::Exclusive => {
            state.search_domains.push("~.".to_string());
        }
    }

    if state.dns_servers.is_empty() {
        return Err(ResolvconfError::NoDnsServers);
    }

    if state.search_domains.is_empty() {
        state.search_domains.push(String::new());
    }

    Ok(())
}

// ── Argument parsing ───────────────────────────────────────────────────────

pub fn resolvconf_parse_argv(
    args: &[&str],
    stdin_content: Option<&str>,
) -> Result<ResolvconfState, ResolvconfError> {
    let mut state = ResolvconfState::new();
    let mut lookup_type = LookupType::Regular;
    let mut args_iter = args.iter().peekable();

    // Check environment-variable equivalents
    // (In the real system these would be env vars; here they're just defaults)

    while let Some(&arg) = args_iter.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(state);
        }
        if arg == "--version" {
            return Ok(state);
        }
        if arg == "-a" {
            state.mode = ExecutionMode::SetLink;
            continue;
        }
        if arg == "-d" {
            state.mode = ExecutionMode::RevertLink;
            continue;
        }
        if arg == "-x" {
            lookup_type = LookupType::Exclusive;
            continue;
        }
        if arg == "-p" {
            lookup_type = LookupType::Private;
            continue;
        }
        if arg == "-f" {
            state.ifindex_permissive = true;
            continue;
        }
        if arg == "-m" {
            continue;
        }
        if arg == "-u" {
            return Ok(state);
        }
        if arg == "-I"
            || arg == "-i"
            || arg == "-l"
            || arg == "-R"
            || arg == "-r"
            || arg == "-v"
            || arg == "-V"
        {
            return Err(ResolvconfError::UnsupportedOption(arg.to_string()));
        }
        if arg == "--enable-updates" || arg == "--disable-updates" || arg == "--updates-are-enabled"
        {
            return Err(ResolvconfError::UnsupportedOption(arg.to_string()));
        }
        if arg.starts_with('-') {
            return Err(ResolvconfError::InvalidArgument(arg.to_string()));
        }

        // Positional argument: interface name
        state.interface = Some(arg.to_string());
    }

    if state.mode == ExecutionMode::Invalid {
        return Err(ResolvconfError::MissingMode);
    }

    if state.interface.is_none() {
        return Err(ResolvconfError::MissingInterface);
    }

    if state.mode == ExecutionMode::SetLink {
        if let Some(content) = stdin_content {
            parse_stdin_content(content, lookup_type, &mut state)?;
        }
    }

    Ok(state)
}

// ── High-level run ─────────────────────────────────────────────────────────

pub fn resolvconf_run(
    args: &[&str],
    stdin_content: Option<&str>,
) -> Result<ResolvconfState, ResolvconfError> {
    resolvconf_parse_argv(args, stdin_content)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_words_simple() {
        assert_eq!(
            extract_words("ns1 ns2 ns3", false),
            vec!["ns1", "ns2", "ns3"]
        );
    }

    #[test]
    fn test_extract_words_unquote() {
        assert_eq!(
            extract_words("\"my domain\" other", true),
            vec!["my domain", "other"]
        );
    }

    #[test]
    fn test_extract_words_empty() {
        assert!(extract_words("", false).is_empty());
    }

    #[test]
    fn test_extract_words_whitespace_only() {
        assert!(extract_words("   \t  ", false).is_empty());
    }

    #[test]
    fn test_first_word_match() {
        assert_eq!(
            first_word("nameserver 8.8.8.8", "nameserver"),
            Some("8.8.8.8")
        );
    }

    #[test]
    fn test_first_word_no_match() {
        assert_eq!(first_word("search example.com", "nameserver"), None);
    }

    #[test]
    fn test_first_word_partial_no_match() {
        assert_eq!(first_word("nameserverX foo", "nameserver"), None);
    }

    #[test]
    fn test_parse_nameserver() {
        let mut state = ResolvconfState::new();
        parse_nameserver("8.8.8.8 8.8.4.4", &mut state);
        assert_eq!(state.dns_servers, vec!["8.8.8.8", "8.8.4.4"]);
    }

    #[test]
    fn test_parse_search_domain() {
        let mut state = ResolvconfState::new();
        parse_search_domain("example.com \"my domain\"", &mut state);
        assert_eq!(state.search_domains, vec!["example.com", "my domain"]);
    }

    #[test]
    fn test_parse_stdin_regular() {
        let mut state = ResolvconfState::new();
        state.dns_servers.clear();
        parse_stdin_content(
            "nameserver 8.8.8.8\nsearch example.com\n",
            LookupType::Regular,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.dns_servers, vec!["8.8.8.8"]);
        assert_eq!(state.search_domains, vec!["example.com"]);
        assert!(!state.disable_default_route);
    }

    #[test]
    fn test_parse_stdin_private() {
        let mut state = ResolvconfState::new();
        parse_stdin_content("nameserver 1.1.1.1\n", LookupType::Private, &mut state).unwrap();
        assert!(state.disable_default_route);
    }

    #[test]
    fn test_parse_stdin_exclusive() {
        let mut state = ResolvconfState::new();
        parse_stdin_content("nameserver 1.1.1.1\n", LookupType::Exclusive, &mut state).unwrap();
        assert!(state.search_domains.contains(&"~.".to_string()));
    }

    #[test]
    fn test_parse_stdin_no_dns_servers() {
        let mut state = ResolvconfState::new();
        let result = parse_stdin_content("# empty\n", LookupType::Regular, &mut state);
        assert_eq!(result, Err(ResolvconfError::NoDnsServers));
    }

    #[test]
    fn test_parse_stdin_comments_and_empty() {
        let mut state = ResolvconfState::new();
        parse_stdin_content(
            "# comment\n; also comment\nnameserver 8.8.8.8\n\n",
            LookupType::Regular,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.dns_servers, vec!["8.8.8.8"]);
    }

    #[test]
    fn test_resolvconf_parse_argv_register() {
        let state = resolvconf_parse_argv(&["-a", "eth0"], Some("nameserver 8.8.8.8\n")).unwrap();
        assert_eq!(state.mode, ExecutionMode::SetLink);
        assert_eq!(state.interface, Some("eth0".to_string()));
        assert_eq!(state.dns_servers, vec!["8.8.8.8"]);
    }

    #[test]
    fn test_resolvconf_parse_argv_unregister() {
        let state = resolvconf_parse_argv(&["-d", "eth0"], None).unwrap();
        assert_eq!(state.mode, ExecutionMode::RevertLink);
        assert_eq!(state.interface, Some("eth0".to_string()));
    }

    #[test]
    fn test_resolvconf_parse_argv_missing_mode() {
        let result = resolvconf_parse_argv(&["eth0"], None);
        assert_eq!(result, Err(ResolvconfError::MissingMode));
    }

    #[test]
    fn test_resolvconf_parse_argv_missing_interface() {
        let result = resolvconf_parse_argv(&["-a"], None);
        assert_eq!(result, Err(ResolvconfError::MissingInterface));
    }

    #[test]
    fn test_resolvconf_parse_argv_flag_f() {
        let state =
            resolvconf_parse_argv(&["-a", "-f", "eth0"], Some("nameserver 1.1.1.1\n")).unwrap();
        assert!(state.ifindex_permissive);
    }

    #[test]
    fn test_resolvconf_parse_argv_unsupported() {
        let result = resolvconf_parse_argv(&["-I", "eth0"], None);
        assert!(matches!(result, Err(ResolvconfError::UnsupportedOption(_))));
    }

    #[test]
    fn test_resolvconf_parse_argv_update_flag() {
        let state = resolvconf_parse_argv(&["-u"], None).unwrap();
        assert_eq!(state.mode, ExecutionMode::Invalid);
    }

    #[test]
    fn test_resolvconf_parse_argv_full_stdin() {
        let stdin = "nameserver 8.8.8.8\nnameserver 8.8.4.4\ndomain example.com test.com\n";
        let state = resolvconf_parse_argv(&["-a", "eth0"], Some(stdin)).unwrap();
        assert_eq!(state.dns_servers, vec!["8.8.8.8", "8.8.4.4"]);
        assert!(state.search_domains.contains(&"example.com".to_string()));
        assert!(state.search_domains.contains(&"test.com".to_string()));
    }
}
