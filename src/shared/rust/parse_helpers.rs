// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/parse-helpers.c, src/shared/parse-helpers.h
//
// Path validation/simplification and socket-bind item parsing utilities.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum path length (matches Linux PATH_MAX).
const PATH_MAX: usize = 4096;

/// Known API VFS mount prefixes used by `path_below_api_vfs`.
const API_VFS_PREFIXES: &[&str] = &["/proc", "/sys", "/dev"];

// ── Enums ─────────────────────────────────────────────────────────────────

/// Address family for socket bind items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 (AF_INET).
    Inet,
    /// IPv6 (AF_INET6).
    Inet6,
}

/// IP protocol for socket bind items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// Errors returned by parse-helper functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Invalid argument supplied.
    InvalidArgument,
    /// Path exceeds maximum allowed length.
    PathTooLong,
    /// Path is not normalized (contains `//`, `./`, or `../` after simplification).
    NotNormalized,
    /// Path is below an API VFS mount point.
    BelowApiVfs,
    /// Token did not match any expected pattern.
    UnknownToken,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::PathTooLong => write!(f, "path exceeds maximum length"),
            Self::NotNormalized => write!(f, "path is not normalized"),
            Self::BelowApiVfs => write!(f, "path is below API VFS"),
            Self::UnknownToken => write!(f, "unrecognised token"),
        }
    }
}

impl std::error::Error for ParseError {}

// ── Bitflags ──────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling `path_simplify_and_warn` validation behaviour.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PathSimplifyWarnFlags: u32 {
        /// Treat validation failures as fatal (log level distinction).
        const FATAL = 1 << 0;
        /// Require the path to be absolute.
        const ABSOLUTE = 1 << 1;
        /// Require the path to be relative.
        const RELATIVE = 1 << 2;
        /// Preserve trailing slashes during simplification.
        const KEEP_TRAILING_SLASH = 1 << 3;
        /// Reject paths below API VFS mounts (`/proc`, `/sys`, `/dev`).
        const NON_API_VFS = 1 << 4;
        /// Like `NON_API_VFS` but allow paths under `/dev`.
        const NON_API_VFS_DEV_OK = 1 << 5;
    }
}

// ── Socket bind item ──────────────────────────────────────────────────────

/// Parsed result of a socket bind item string such as `"ipv4:tcp:80-81"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SocketBindItem {
    /// Parsed address family, if specified.
    pub address_family: Option<AddressFamily>,
    /// Parsed IP protocol, if specified.
    pub ip_protocol: Option<IpProtocol>,
    /// Number of ports in the range (0 means "any").
    pub nr_ports: u16,
    /// First port in the range (0 means "any").
    pub port_min: u16,
}

// ── Path helpers ──────────────────────────────────────────────────────────

/// Check whether `path` is below a known API VFS mount point.
///
/// Returns `true` when `path` is exactly `/proc`, `/sys`, or `/dev`,
/// or any subdirectory thereof.
pub fn path_below_api_vfs(path: &str) -> bool {
    API_VFS_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

/// Validate that `path` does not violate API VFS restrictions imposed by `flags`.
///
/// Returns `true` when the path passes, `false` when it should be rejected.
fn validate_api_vfs(path: &str, flags: PathSimplifyWarnFlags) -> bool {
    if !flags
        .intersects(PathSimplifyWarnFlags::NON_API_VFS | PathSimplifyWarnFlags::NON_API_VFS_DEV_OK)
    {
        return true;
    }
    if !path_below_api_vfs(path) {
        return true;
    }
    if flags.contains(PathSimplifyWarnFlags::NON_API_VFS_DEV_OK) && path.starts_with("/dev") {
        return true;
    }
    false
}

/// Simplify a path string by collapsing `//`, resolving `.` and `..`
/// components, and optionally preserving a trailing slash.
pub fn simplify_path(path: &str, keep_trailing_slash: bool) -> String {
    let is_absolute = path.starts_with('/');
    let had_trailing_slash = path.len() > 1 && path.ends_with('/');

    let mut components: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            c => components.push(c),
        }
    }

    let mut result = if is_absolute {
        if components.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", components.join("/"))
        }
    } else if components.is_empty() {
        ".".to_string()
    } else {
        components.join("/")
    };

    if keep_trailing_slash && had_trailing_slash && !result.ends_with('/') && result != "/" {
        result.push('/');
    }

    result
}

/// Check whether a simplified path still contains non-normalized components.
fn is_path_normalized(path: &str) -> bool {
    !path.contains("//") && !path.contains("/./") && !path.contains("/../")
}

/// Validate and simplify a path according to the given flags.
///
/// Mirrors the C `path_simplify_and_warn` but returns the simplified path
/// on success rather than modifying in place.
pub fn path_simplify_and_warn(
    path: &str,
    flags: PathSimplifyWarnFlags,
) -> Result<String, ParseError> {
    if path.is_empty() {
        return Err(ParseError::InvalidArgument);
    }

    // Absolute / relative checks
    let is_absolute = path.starts_with('/');
    if flags.contains(PathSimplifyWarnFlags::ABSOLUTE) && !is_absolute {
        return Err(ParseError::InvalidArgument);
    }
    if flags.contains(PathSimplifyWarnFlags::RELATIVE) && is_absolute {
        return Err(ParseError::InvalidArgument);
    }

    // Simplify
    let simplified = simplify_path(
        path,
        flags.contains(PathSimplifyWarnFlags::KEEP_TRAILING_SLASH),
    );

    // Length check
    if simplified.len() > PATH_MAX {
        return Err(ParseError::PathTooLong);
    }

    // Normalisation sanity check (defence in depth after simplify)
    if !is_path_normalized(&simplified) {
        return Err(ParseError::NotNormalized);
    }

    // API VFS check
    if !validate_api_vfs(&simplified, flags) {
        return Err(ParseError::BelowApiVfs);
    }

    Ok(simplified)
}

// ── Socket bind parsing ───────────────────────────────────────────────────

/// Parse a socket bind item string such as `"ipv4:tcp:80-81"`.
///
/// Tokens are tried against three ordered parsers (address family, protocol,
/// ports), matching the C `parse_socket_bind_item` fallback semantics so that
/// optional fields can be omitted.
pub fn parse_socket_bind_item(s: &str) -> Result<SocketBindItem, ParseError> {
    if s.is_empty() {
        return Err(ParseError::InvalidArgument);
    }

    let mut result = SocketBindItem::default();
    let mut parser_index: usize = 0;
    let mut last_result: Result<(), ParseError> = Ok(());
    let mut tokens = s.split(':').peekable();

    for token in tokens.by_ref() {
        if token.is_empty() {
            return Err(ParseError::InvalidArgument);
        }

        while parser_index < 3 {
            last_result = match parser_index {
                0 => parse_af_token(token, &mut result),
                1 => parse_ip_protocol_token(token, &mut result),
                _ => parse_ip_ports_token(token, &mut result),
            };
            parser_index += 1;
            if last_result.is_ok() {
                break;
            }
        }

        if parser_index >= 3 {
            if matches!(last_result, Err(ParseError::InvalidArgument)) {
                last_result = Err(ParseError::UnknownToken);
            }
            break;
        }
    }

    last_result?;

    // Unconsumed input remains → invalid
    if tokens.peek().is_some() {
        return Err(ParseError::InvalidArgument);
    }

    Ok(result)
}

fn parse_af_token(token: &str, result: &mut SocketBindItem) -> Result<(), ParseError> {
    match token {
        "ipv4" => {
            result.address_family = Some(AddressFamily::Inet);
            Ok(())
        }
        "ipv6" => {
            result.address_family = Some(AddressFamily::Inet6);
            Ok(())
        }
        _ => Err(ParseError::UnknownToken),
    }
}

fn parse_ip_protocol_token(token: &str, result: &mut SocketBindItem) -> Result<(), ParseError> {
    match token {
        "tcp" => {
            result.ip_protocol = Some(IpProtocol::Tcp);
            Ok(())
        }
        "udp" => {
            result.ip_protocol = Some(IpProtocol::Udp);
            Ok(())
        }
        _ => Err(ParseError::UnknownToken),
    }
}

fn parse_ip_ports_token(token: &str, result: &mut SocketBindItem) -> Result<(), ParseError> {
    if token == "any" {
        result.nr_ports = 0;
        result.port_min = 0;
        return Ok(());
    }

    let (min, max) = if let Some((a, b)) = token.split_once('-') {
        let mn = a.parse::<u16>().map_err(|_| ParseError::InvalidArgument)?;
        let mx = b.parse::<u16>().map_err(|_| ParseError::InvalidArgument)?;
        (mn, mx)
    } else {
        let port = token
            .parse::<u16>()
            .map_err(|_| ParseError::InvalidArgument)?;
        (port, port)
    };

    if max < min {
        return Err(ParseError::InvalidArgument);
    }

    result.nr_ports = max - min + 1;
    result.port_min = min;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── path_below_api_vfs ─────────────────────────────────────────────

    #[test]
    fn test_path_below_api_vfs_exact() {
        assert!(path_below_api_vfs("/proc"));
        assert!(path_below_api_vfs("/sys"));
        assert!(path_below_api_vfs("/dev"));
    }

    #[test]
    fn test_path_below_api_vfs_subpath() {
        assert!(path_below_api_vfs("/proc/self/status"));
        assert!(path_below_api_vfs("/sys/kernel"));
        assert!(path_below_api_vfs("/dev/null"));
    }

    #[test]
    fn test_path_below_api_vfs_negative() {
        assert!(!path_below_api_vfs("/home"));
        assert!(!path_below_api_vfs("/etc/fstab"));
        assert!(!path_below_api_vfs("/tmp"));
        assert!(!path_below_api_vfs("/procx"));
    }

    // ── simplify_path ──────────────────────────────────────────────────

    #[test]
    fn test_simplify_path_dots() {
        assert_eq!(simplify_path("/a/./b/../c", false), "/a/c");
        assert_eq!(simplify_path("a/b/../../c", false), "c");
        assert_eq!(simplify_path("/../..", false), "/");
        assert_eq!(simplify_path("/./", false), "/");
    }

    #[test]
    fn test_simplify_path_trailing_slash() {
        assert_eq!(simplify_path("/a/b/", true), "/a/b/");
        assert_eq!(simplify_path("/a/b/", false), "/a/b");
        assert_eq!(simplify_path("/", true), "/");
    }

    #[test]
    fn test_simplify_path_relative() {
        assert_eq!(simplify_path("a/b/c", false), "a/b/c");
        assert_eq!(simplify_path("./a", false), "a");
        assert_eq!(simplify_path("a/..", false), ".");
    }

    // ── validate_api_vfs ───────────────────────────────────────────────

    #[test]
    fn test_validate_api_vfs_no_flags() {
        assert!(validate_api_vfs(
            "/proc/self",
            PathSimplifyWarnFlags::empty()
        ));
        assert!(validate_api_vfs(
            "/dev/null",
            PathSimplifyWarnFlags::empty()
        ));
    }

    #[test]
    fn test_validate_api_vfs_with_flags() {
        assert!(!validate_api_vfs(
            "/proc/self",
            PathSimplifyWarnFlags::NON_API_VFS
        ));
        assert!(validate_api_vfs(
            "/home/user",
            PathSimplifyWarnFlags::NON_API_VFS
        ));
        assert!(validate_api_vfs(
            "/dev/sda1",
            PathSimplifyWarnFlags::NON_API_VFS_DEV_OK
        ));
        assert!(!validate_api_vfs(
            "/proc/self",
            PathSimplifyWarnFlags::NON_API_VFS_DEV_OK
        ));
    }

    // ── path_simplify_and_warn ─────────────────────────────────────────

    #[test]
    fn test_path_simplify_and_warn_basic() {
        assert_eq!(
            path_simplify_and_warn("/a/./b/../c", PathSimplifyWarnFlags::ABSOLUTE).unwrap(),
            "/a/c"
        );
    }

    #[test]
    fn test_path_simplify_and_warn_absolute_required() {
        assert!(path_simplify_and_warn("relative/path", PathSimplifyWarnFlags::ABSOLUTE).is_err());
        assert!(path_simplify_and_warn("/absolute/path", PathSimplifyWarnFlags::ABSOLUTE).is_ok());
    }

    #[test]
    fn test_path_simplify_and_warn_relative_required() {
        assert!(path_simplify_and_warn("/absolute/path", PathSimplifyWarnFlags::RELATIVE).is_err());
        assert!(path_simplify_and_warn("relative/path", PathSimplifyWarnFlags::RELATIVE).is_ok());
    }

    #[test]
    fn test_path_simplify_and_warn_api_vfs_rejection() {
        assert_eq!(
            path_simplify_and_warn(
                "/proc/self",
                PathSimplifyWarnFlags::ABSOLUTE | PathSimplifyWarnFlags::NON_API_VFS
            ),
            Err(ParseError::BelowApiVfs)
        );
        assert!(
            path_simplify_and_warn(
                "/home/user",
                PathSimplifyWarnFlags::ABSOLUTE | PathSimplifyWarnFlags::NON_API_VFS
            )
            .is_ok()
        );
    }

    #[test]
    fn test_path_simplify_and_warn_empty() {
        assert_eq!(
            path_simplify_and_warn("", PathSimplifyWarnFlags::empty()),
            Err(ParseError::InvalidArgument)
        );
    }

    // ── parse_socket_bind_item ─────────────────────────────────────────

    #[test]
    fn test_parse_socket_bind_item_full() {
        let item = parse_socket_bind_item("ipv4:tcp:80").unwrap();
        assert_eq!(item.address_family, Some(AddressFamily::Inet));
        assert_eq!(item.ip_protocol, Some(IpProtocol::Tcp));
        assert_eq!(item.nr_ports, 1);
        assert_eq!(item.port_min, 80);
    }

    #[test]
    fn test_parse_socket_bind_item_port_range() {
        let item = parse_socket_bind_item("ipv6:udp:80-85").unwrap();
        assert_eq!(item.address_family, Some(AddressFamily::Inet6));
        assert_eq!(item.ip_protocol, Some(IpProtocol::Udp));
        assert_eq!(item.nr_ports, 6);
        assert_eq!(item.port_min, 80);
    }

    #[test]
    fn test_parse_socket_bind_item_any() {
        let item = parse_socket_bind_item("any").unwrap();
        assert_eq!(item.address_family, None);
        assert_eq!(item.ip_protocol, None);
        assert_eq!(item.nr_ports, 0);
        assert_eq!(item.port_min, 0);
    }

    #[test]
    fn test_parse_socket_bind_item_af_and_ports() {
        let item = parse_socket_bind_item("ipv4:80-81").unwrap();
        assert_eq!(item.address_family, Some(AddressFamily::Inet));
        assert_eq!(item.ip_protocol, None);
        assert_eq!(item.nr_ports, 2);
        assert_eq!(item.port_min, 80);
    }

    #[test]
    fn test_parse_socket_bind_item_protocol_and_ports() {
        let item = parse_socket_bind_item("tcp:443").unwrap();
        assert_eq!(item.address_family, None);
        assert_eq!(item.ip_protocol, Some(IpProtocol::Tcp));
        assert_eq!(item.nr_ports, 1);
        assert_eq!(item.port_min, 443);
    }

    #[test]
    fn test_parse_socket_bind_item_errors() {
        assert_eq!(parse_socket_bind_item(""), Err(ParseError::InvalidArgument));
        assert_eq!(
            parse_socket_bind_item("ipv4:tcp:80:extra"),
            Err(ParseError::InvalidArgument)
        );
        assert_eq!(
            parse_socket_bind_item("bogus"),
            Err(ParseError::UnknownToken)
        );
    }

    #[test]
    fn test_parse_socket_bind_item_port_zero() {
        let item = parse_socket_bind_item("0").unwrap();
        assert_eq!(item.nr_ports, 1);
        assert_eq!(item.port_min, 0);
    }

    #[test]
    fn test_parse_socket_bind_item_empty_token() {
        assert_eq!(
            parse_socket_bind_item("ipv4::80"),
            Err(ParseError::InvalidArgument)
        );
    }
}
