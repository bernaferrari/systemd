// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-polkit.c, src/shared/bus-polkit.h
//
// PolicyKit (polkit) D-Bus integration helpers.
//
// Provides authorization checking for privileged operations over D-Bus and
// Varlink.  The async variant (`bus_verify_polkit_async_full`) supports
// interrupting message processing while a polkit check is in flight and
// re-dispatching once the result arrives.

// ── Constants ─────────────────────────────────────────────────────────────

/// Sentinel for "no valid UID" (mirrors `UID_INVALID` in C).
pub const UID_INVALID: u32 = u32::MAX;

/// Allow interactive authentication.
pub const POLKIT_ALLOW_INTERACTIVE: u32 = 1 << 0;
/// Query polkit even if the client is already privileged.
pub const POLKIT_ALWAYS_QUERY: u32 = 1 << 1;
/// When polkit is absent, assume "allow" instead of "deny".
pub const POLKIT_DEFAULT_ALLOW: u32 = 1 << 2;
/// Varlink: do not immediately propagate the polkit error to the client.
pub const POLKIT_DONT_REPLY: u32 = 1 << 3;
/// Bitmask of flags forwarded verbatim to the polkit daemon.
pub const POLKIT_MASK_PUBLIC: u32 = POLKIT_ALLOW_INTERACTIVE | POLKIT_ALWAYS_QUERY;

/// D-Bus service / object path / interface used by PolicyKit1.
pub const POLKIT_BUS_NAME: &str = "org.freedesktop.PolicyKit1";
pub const POLKIT_OBJECT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
pub const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
pub const POLKIT_METHOD_CHECK_AUTH: &str = "CheckAuthorization";

/// Well-known polkit error names that map to denial.
pub const POLKIT_ERROR_FAILED: &str = "org.freedesktop.PolicyKit1.Error.Failed";
pub const POLKIT_ERROR_CANCELLED: &str = "org.freedesktop.PolicyKit1.Error.Cancelled";
pub const POLKIT_ERROR_NOT_AUTHORIZED: &str = "org.freedesktop.PolicyKit1.Error.NotAuthorized";

/// Error name for "interactive auth required" (used in bus-error.c).
pub const SD_BUS_ERROR_INTERACTIVE_AUTHORIZATION_REQUIRED: &str =
    "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired";

/// Varlink error names for polkit results.
pub const SD_VARLINK_ERROR_INTERACTIVE_AUTHENTICATION_REQUIRED: &str =
    "systemd.varlink.InteractiveAuthenticationRequired";
pub const SD_VARLINK_ERROR_PERMISSION_DENIED: &str = "systemd.varlink.PermissionDenied";

/// Field name for the optional polkit interactive-auth flag in Varlink messages.
pub const VARLINK_ALLOW_INTERACTIVE_AUTH_FIELD: &str = "allowInteractiveAuthentication";

// ── Error types ───────────────────────────────────────────────────────────

/// Errors that can arise during polkit authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolkitError {
    /// The caller was denied access.
    AccessDenied,
    /// Polkit service is not available.
    ServiceUnavailable,
    /// A previous polkit check is still in flight for a different action.
    Busy,
    /// Interactive authentication was required but not enabled by the caller.
    InteractiveAuthorizationRequired(String),
    /// An unexpected error from polkit (name + message).
    PolkitError { name: String, message: String },
    /// Invalid arguments (null pointers, missing fields, etc.).
    InvalidArgument(String),
    /// Out of memory.
    OutOfMemory,
    /// I/O or D-Bus communication error.
    BusError(String),
}

impl std::fmt::Display for PolkitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolkitError::AccessDenied => write!(f, "Access denied"),
            PolkitError::ServiceUnavailable => write!(f, "PolicyKit service unavailable"),
            PolkitError::Busy => write!(f, "A previous polkit check is still pending"),
            PolkitError::InteractiveAuthorizationRequired(msg) => {
                write!(f, "Interactive authorization required: {msg}")
            }
            PolkitError::PolkitError { name, message } => {
                write!(f, "PolicyKit error {name}: {message}")
            }
            PolkitError::InvalidArgument(s) => write!(f, "invalid argument: {s}"),
            PolkitError::OutOfMemory => write!(f, "out of memory"),
            PolkitError::BusError(s) => write!(f, "bus error: {s}"),
        }
    }
}

impl std::error::Error for PolkitError {}

// ── Polkit flags ──────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Bitflag wrapper for polkit flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PolkitFlags: u32 {
        const ALLOW_INTERACTIVE = POLKIT_ALLOW_INTERACTIVE;
        const ALWAYS_QUERY      = POLKIT_ALWAYS_QUERY;
        const DEFAULT_ALLOW     = POLKIT_DEFAULT_ALLOW;
        const DONT_REPLY        = POLKIT_DONT_REPLY;
    }
}

impl Default for PolkitFlags {
    fn default() -> Self {
        PolkitFlags::empty()
    }
}

// ── Result of a polkit check ──────────────────────────────────────────────

/// Outcome of a (synchronous) polkit authorization test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolkitResult {
    /// The action is authorized.
    Authorized,
    /// The action is not authorized.
    Denied,
    /// Polkit challenges for interactive auth (the caller can decide).
    Challenge,
}

// ── Async polkit query types ──────────────────────────────────────────────

/// Status stored for a single action within an async query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsyncActionStatus {
    /// Still waiting for a reply.
    Pending,
    /// Polkit authorized this action.
    Authorized,
    /// Polkit denied this action.
    Denied,
    /// Polkit service was absent.
    Absent,
    /// Polkit returned an error.
    Error(PolkitError),
}

/// A single action being verified asynchronously.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncPolkitQueryAction {
    /// The polkit action identifier (e.g. "org.freedesktop.systemd1.manage-units").
    pub action: String,
    /// Key-value detail pairs forwarded to polkit.
    pub details: Vec<(String, String)>,
    /// Current status of this action.
    pub status: AsyncActionStatus,
}

impl AsyncPolkitQueryAction {
    /// Create a new pending action query.
    pub fn new(action: impl Into<String>, details: Vec<(String, String)>) -> Self {
        Self {
            action: action.into(),
            details,
            status: AsyncActionStatus::Pending,
        }
    }

    /// Check whether this action matches the given action name and details.
    pub fn matches(&self, action: &str, details: &[(String, String)]) -> bool {
        self.action == action && self.details == details
    }
}

/// Return value from `bus_verify_polkit_async_full`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsyncPolkitReturn {
    /// A new polkit query has been dispatched; processing should be
    /// interrupted (return 1 to sd-bus to pause the message).
    QueryDispatched,
    /// The action has been allowed.
    Authorized,
    /// The action has been denied.
    Denied,
}

// ── Good-user checking ────────────────────────────────────────────────────

/// Check whether the caller matches the designated "good user" (a superuser
/// that is always trusted, bypassing polkit).
///
/// Mirrors `bus_message_check_good_user` / `varlink_check_good_user`.
///
/// - Returns `Ok(true)` if `sender_uid == good_user`.
/// - Returns `Ok(false)` if they differ or `good_user` is `UID_INVALID`.
/// - Returns `Err` if the sender UID could not be determined.
pub fn check_good_user(good_user: u32, sender_uid: u32) -> bool {
    if good_user == UID_INVALID {
        return false;
    }
    sender_uid == good_user
}

// ── Synchronous polkit test ───────────────────────────────────────────────

/// Result of `bus_test_polkit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusTestPolkitResult {
    /// Whether the action is authorized.
    pub authorized: bool,
    /// Whether polkit would like interactive authentication.
    pub challenge: bool,
}

/// Test polkit authorization non-interactively.
///
/// This performs the same logic as the C `bus_test_polkit()`:
/// 1. Check good_user.
/// 2. Check if sender is privileged.
/// 3. If neither, the action is denied (in a real implementation,
///    a synchronous polkit call would be made here).
///
/// Returns `Ok(result)` on success or `Err` if a preliminary check fails.
pub fn bus_test_polkit(
    good_user: u32,
    sender_uid: u32,
    sender_privileged: bool,
) -> Result<BusTestPolkitResult, PolkitError> {
    // Step 1: good-user bypass
    if check_good_user(good_user, sender_uid) {
        return Ok(BusTestPolkitResult {
            authorized: true,
            challenge: false,
        });
    }

    // Step 2: check privilege
    if sender_privileged {
        return Ok(BusTestPolkitResult {
            authorized: true,
            challenge: false,
        });
    }

    // Not privileged → denied
    Ok(BusTestPolkitResult {
        authorized: false,
        challenge: false,
    })
}

// ── Peer privilege checking (Varlink) ─────────────────────────────────────

/// Check whether a Varlink peer is considered privileged.
///
/// A peer is privileged if:
/// - Its UID matches our own UID, OR
/// - Our UID is non-zero (not root) and the peer UID is zero (root).
///
/// Mirrors `varlink_check_peer_privilege`.
pub fn varlink_check_peer_privilege(peer_uid: u32, our_uid: u32) -> bool {
    peer_uid == our_uid || (our_uid != 0 && peer_uid == 0)
}

// ── Polkit reply parsing ──────────────────────────────────────────────────

/// Parsed result from a PolicyKit CheckAuthorization reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolkitAuthReply {
    /// Whether the action is authorized.
    pub authorized: bool,
    /// Whether interactive authentication is required.
    pub challenge: bool,
}

/// Classify a polkit error name into a well-known category.
pub fn classify_polkit_error(error_name: &str) -> PolkitError {
    if error_name == POLKIT_ERROR_FAILED
        || error_name == POLKIT_ERROR_CANCELLED
        || error_name == POLKIT_ERROR_NOT_AUTHORIZED
    {
        return PolkitError::AccessDenied;
    }
    PolkitError::PolkitError {
        name: error_name.to_owned(),
        message: String::new(),
    }
}

/// Process a polkit authorization reply and update the action status.
///
/// This mirrors `async_polkit_read_reply` from the C code.
pub fn process_polkit_reply(
    error_name: Option<&str>,
    auth_reply: Option<PolkitAuthReply>,
) -> AsyncActionStatus {
    // If there is an error, classify it
    if let Some(name) = error_name {
        return match name {
            // Polkit absent
            n if is_unknown_service_error(n) => AsyncActionStatus::Absent,
            // Well-known denial errors
            n if n == POLKIT_ERROR_FAILED
                || n == POLKIT_ERROR_CANCELLED
                || n == POLKIT_ERROR_NOT_AUTHORIZED =>
            {
                AsyncActionStatus::Denied
            }
            // Unexpected error
            n => AsyncActionStatus::Error(PolkitError::PolkitError {
                name: n.to_owned(),
                message: String::new(),
            }),
        };
    }

    // Parse the structured reply
    if let Some(reply) = auth_reply {
        if reply.authorized {
            return AsyncActionStatus::Authorized;
        }
        if reply.challenge {
            return AsyncActionStatus::Error(PolkitError::InteractiveAuthorizationRequired(
                "Interactive authentication required but was not enabled by the calling program."
                    .into(),
            ));
        }
        return AsyncActionStatus::Denied;
    }

    AsyncActionStatus::Denied
}

/// Check whether a D-Bus error indicates that the service is unknown
/// (i.e. polkit is not installed / not running).
///
/// Mirrors `bus_error_is_unknown_service`.
pub fn is_unknown_service_error(error_name: &str) -> bool {
    error_name == "org.freedesktop.DBus.Error.ServiceUnknown"
        || error_name == "org.freedesktop.DBus.Error.NameHasNoOwner"
}

// ── Async query action checking ───────────────────────────────────────────

/// Check an action against the list of already-resolved async actions.
///
/// Mirrors `async_polkit_query_check_action`.
///
/// Returns:
/// - `Some(AsyncPolkitReturn::Authorized)` if the action was previously authorized.
/// - `Some(AsyncPolkitReturn::Denied)` if the action was denied.
/// - `Some(AsyncPolkitReturn::Denied)` if a previous action failed and polkit is absent
///   (unless `POLKIT_DEFAULT_ALLOW` is set).
/// - `None` if the action has not been seen yet (new query needed).
pub fn async_polkit_query_check_action(
    actions: &[AsyncPolkitQueryAction],
    action: &str,
    details: &[(String, String)],
    flags: PolkitFlags,
) -> Option<AsyncPolkitReturn> {
    // Check if already authorized
    for a in actions {
        if a.matches(action, details) && a.status == AsyncActionStatus::Authorized {
            return Some(AsyncPolkitReturn::Authorized);
        }
    }

    // Check for matching error/denied/absent actions
    for a in actions {
        if a.action == action {
            return Some(match &a.status {
                AsyncActionStatus::Denied => AsyncPolkitReturn::Denied,
                AsyncActionStatus::Error(_) => AsyncPolkitReturn::Denied,
                AsyncActionStatus::Absent => {
                    if flags.contains(PolkitFlags::DEFAULT_ALLOW) {
                        AsyncPolkitReturn::Authorized
                    } else {
                        AsyncPolkitReturn::Denied
                    }
                }
                _ => return None, // still pending → no result yet
            });
        }
    }

    // If *any* previous action was denied or errored, we're busy
    for a in actions {
        if matches!(
            a.status,
            AsyncActionStatus::Denied | AsyncActionStatus::Error(_)
        ) {
            // There is an auth failure for a different action; we can't proceed
            // with a new one.
            return Some(AsyncPolkitReturn::Denied);
        }
    }

    // If polkit was absent for a previous action, apply the default
    for a in actions {
        if a.status == AsyncActionStatus::Absent {
            return Some(if flags.contains(PolkitFlags::DEFAULT_ALLOW) {
                AsyncPolkitReturn::Authorized
            } else {
                AsyncPolkitReturn::Denied
            });
        }
    }

    // No reply yet — caller should issue a new query
    None
}

/// Check whether a previously authorized action exists in the list.
///
/// Mirrors `async_polkit_query_have_action`.
pub fn async_polkit_query_has_action(
    actions: &[AsyncPolkitQueryAction],
    action: &str,
    details: &[(String, String)],
) -> bool {
    actions
        .iter()
        .any(|a| a.matches(action, details) && a.status == AsyncActionStatus::Authorized)
}

// ── Public flags for action serialization ─────────────────────────────────

/// Compute the public flags bitmask to send to polkit.
///
/// Only `POLKIT_ALLOW_INTERACTIVE` and `POLKIT_ALWAYS_QUERY` are forwarded
/// to the polkit daemon.  All other flags are internal to systemd.
pub fn polkit_public_flags(flags: PolkitFlags) -> u32 {
    (flags.bits() & POLKIT_MASK_PUBLIC) as u32
}

// ── Varlink interactive auth detection ────────────────────────────────────

/// Determine whether a Varlink message's parameters indicate that
/// interactive authentication should be allowed.
///
/// The caller extracts the `allowInteractiveAuthentication` field from the
/// Varlink parameters and passes it here as `Option<bool>`.  Returns `false`
/// if the field is absent, not a boolean, or the parameters cannot be read.
pub fn varlink_allows_interactive_auth(value: Option<bool>) -> bool {
    value.unwrap_or(false)
}

// ── Simplified wrappers (mirror the C inline helpers) ─────────────────────

/// Convenience wrapper: verify polkit with default parameters.
///
/// Equivalent to `bus_verify_polkit_async_full` with `good_user = UID_INVALID`
/// and `flags = 0`.
pub fn bus_verify_polkit_async(
    action: &str,
    sender_uid: u32,
    sender_privileged: bool,
    existing_actions: &[AsyncPolkitQueryAction],
    details: &[(String, String)],
) -> Result<AsyncPolkitReturn, PolkitError> {
    bus_verify_polkit_async_full(
        action,
        UID_INVALID,
        PolkitFlags::empty(),
        sender_uid,
        sender_privileged,
        existing_actions,
        details,
    )
}

/// Full async polkit verification.
///
/// This is the main entry point for D-Bus method handlers that need polkit
/// authorization.  The logic mirrors `bus_verify_polkit_async_full`:
///
/// 1. Check good-user bypass.
/// 2. Check if the action was already resolved in a previous round.
/// 3. If not `POLKIT_ALWAYS_QUERY`, check sender privilege.
/// 4. Otherwise, return `QueryDispatched` (the caller should interrupt
///    processing and wait for the async reply).
pub fn bus_verify_polkit_async_full(
    action: &str,
    good_user: u32,
    flags: PolkitFlags,
    sender_uid: u32,
    sender_privileged: bool,
    existing_actions: &[AsyncPolkitQueryAction],
    details: &[(String, String)],
) -> Result<AsyncPolkitReturn, PolkitError> {
    if action.is_empty() {
        return Err(PolkitError::InvalidArgument("action is empty".into()));
    }

    // Step 1: good-user bypass
    if check_good_user(good_user, sender_uid) {
        return Ok(AsyncPolkitReturn::Authorized);
    }

    // Step 2: check for an existing result
    if let Some(result) = async_polkit_query_check_action(existing_actions, action, details, flags)
    {
        return Ok(result);
    }

    // Step 3: skip polkit if sender is privileged (unless ALWAYS_QUERY)
    if !flags.contains(PolkitFlags::ALWAYS_QUERY) && sender_privileged {
        return Ok(AsyncPolkitReturn::Authorized);
    }

    // Step 4: need to dispatch a new async query
    Ok(AsyncPolkitReturn::QueryDispatched)
}

/// Varlink async polkit verification (full variant).
///
/// Mirrors `varlink_verify_polkit_async_full`.
pub fn varlink_verify_polkit_async_full(
    action: &str,
    good_user: u32,
    flags: PolkitFlags,
    peer_uid: u32,
    our_uid: u32,
    existing_actions: &[AsyncPolkitQueryAction],
    details: &[(String, String)],
) -> Result<AsyncPolkitReturn, PolkitError> {
    if action.is_empty() {
        return Err(PolkitError::InvalidArgument("action is empty".into()));
    }

    // Good-user bypass
    if check_good_user(good_user, peer_uid) {
        return Ok(AsyncPolkitReturn::Authorized);
    }

    // Check existing results
    if let Some(result) = async_polkit_query_check_action(existing_actions, action, details, flags)
    {
        return Ok(result);
    }

    // Skip polkit if peer is privileged (unless ALWAYS_QUERY)
    if !flags.contains(PolkitFlags::ALWAYS_QUERY) && varlink_check_peer_privilege(peer_uid, our_uid)
    {
        return Ok(AsyncPolkitReturn::Authorized);
    }

    Ok(AsyncPolkitReturn::QueryDispatched)
}

/// Convenience wrapper: varlink polkit verification with defaults.
pub fn varlink_verify_polkit_async(
    action: &str,
    peer_uid: u32,
    our_uid: u32,
    existing_actions: &[AsyncPolkitQueryAction],
    details: &[(String, String)],
) -> Result<AsyncPolkitReturn, PolkitError> {
    varlink_verify_polkit_async_full(
        action,
        UID_INVALID,
        PolkitFlags::empty(),
        peer_uid,
        our_uid,
        existing_actions,
        details,
    )
}

/// Check whether a polkit action has already been authorized for a Varlink
/// connection.
///
/// Mirrors `varlink_has_polkit_action`.
pub fn varlink_has_polkit_action(
    existing_actions: &[AsyncPolkitQueryAction],
    action: &str,
    details: &[(String, String)],
) -> bool {
    async_polkit_query_has_action(existing_actions, action, details)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- Constants --

    #[test]
    fn test_polkit_flag_values() {
        assert_eq!(POLKIT_ALLOW_INTERACTIVE, 1);
        assert_eq!(POLKIT_ALWAYS_QUERY, 2);
        assert_eq!(POLKIT_DEFAULT_ALLOW, 4);
        assert_eq!(POLKIT_DONT_REPLY, 8);
        assert_eq!(POLKIT_MASK_PUBLIC, 3);
    }

    #[test]
    fn test_uid_invalid() {
        assert_eq!(UID_INVALID, u32::MAX);
    }

    // -- PolkitFlags bitflags --

    #[test]
    fn test_polkit_flags_empty() {
        let f = PolkitFlags::empty();
        assert!(!f.contains(PolkitFlags::ALLOW_INTERACTIVE));
        assert!(!f.contains(PolkitFlags::ALWAYS_QUERY));
        assert_eq!(f.bits(), 0);
    }

    #[test]
    fn test_polkit_flags_combined() {
        let f = PolkitFlags::ALLOW_INTERACTIVE | PolkitFlags::ALWAYS_QUERY;
        assert!(f.contains(PolkitFlags::ALLOW_INTERACTIVE));
        assert!(f.contains(PolkitFlags::ALWAYS_QUERY));
        assert!(!f.contains(PolkitFlags::DEFAULT_ALLOW));
        assert_eq!(f.bits(), 3);
    }

    #[test]
    fn test_polkit_flags_default() {
        let f = PolkitFlags::default();
        assert!(f.is_empty());
    }

    // -- check_good_user --

    #[test]
    fn test_check_good_user_match() {
        assert!(check_good_user(0, 0));
        assert!(check_good_user(1000, 1000));
    }

    #[test]
    fn test_check_good_user_mismatch() {
        assert!(!check_good_user(0, 1000));
        assert!(!check_good_user(1000, 0));
    }

    #[test]
    fn test_check_good_user_invalid() {
        assert!(!check_good_user(UID_INVALID, 0));
        assert!(!check_good_user(UID_INVALID, 1000));
    }

    // -- bus_test_polkit --

    #[test]
    fn test_bus_test_polkit_good_user() {
        let r = bus_test_polkit(0, 0, false).unwrap();
        assert!(r.authorized);
        assert!(!r.challenge);
    }

    #[test]
    fn test_bus_test_polkit_privileged() {
        let r = bus_test_polkit(UID_INVALID, 1000, true).unwrap();
        assert!(r.authorized);
        assert!(!r.challenge);
    }

    #[test]
    fn test_bus_test_polkit_denied() {
        let r = bus_test_polkit(UID_INVALID, 1000, false).unwrap();
        assert!(!r.authorized);
        assert!(!r.challenge);
    }

    #[test]
    fn test_bus_test_polkit_good_user_overrides_unprivileged() {
        // Good user should be authorized even if not privileged
        let r = bus_test_polkit(42, 42, false).unwrap();
        assert!(r.authorized);
    }

    // -- varlink_check_peer_privilege --

    #[test]
    fn test_varlink_peer_privilege_same_uid() {
        assert!(varlink_check_peer_privilege(1000, 1000));
    }

    #[test]
    fn test_varlink_peer_privilege_root_to_nonroot() {
        // Non-root (our_uid != 0) trusts root (peer_uid == 0)
        assert!(varlink_check_peer_privilege(0, 1000));
    }

    #[test]
    fn test_varlink_peer_privilege_nonroot_to_root() {
        // Root does NOT automatically trust non-root
        assert!(!varlink_check_peer_privilege(1000, 0));
    }

    #[test]
    fn test_varlink_peer_privilege_different_nonroot() {
        assert!(!varlink_check_peer_privilege(1000, 2000));
    }

    // -- is_unknown_service_error --

    #[test]
    fn test_is_unknown_service_error_known() {
        assert!(is_unknown_service_error(
            "org.freedesktop.DBus.Error.ServiceUnknown"
        ));
        assert!(is_unknown_service_error(
            "org.freedesktop.DBus.Error.NameHasNoOwner"
        ));
    }

    #[test]
    fn test_is_unknown_service_error_other() {
        assert!(!is_unknown_service_error(
            "org.freedesktop.DBus.Error.UnknownMethod"
        ));
        assert!(!is_unknown_service_error(POLKIT_ERROR_FAILED));
    }

    // -- classify_polkit_error --

    #[test]
    fn test_classify_polkit_error_denial() {
        assert_eq!(
            classify_polkit_error(POLKIT_ERROR_FAILED),
            PolkitError::AccessDenied
        );
        assert_eq!(
            classify_polkit_error(POLKIT_ERROR_CANCELLED),
            PolkitError::AccessDenied
        );
        assert_eq!(
            classify_polkit_error(POLKIT_ERROR_NOT_AUTHORIZED),
            PolkitError::AccessDenied
        );
    }

    #[test]
    fn test_classify_polkit_error_unknown() {
        let err = classify_polkit_error("org.freedesktop.DBus.Error.TimedOut");
        assert!(matches!(err, PolkitError::PolkitError { .. }));
    }

    // -- process_polkit_reply --

    #[test]
    fn test_process_polkit_reply_authorized() {
        let status = process_polkit_reply(
            None,
            Some(PolkitAuthReply {
                authorized: true,
                challenge: false,
            }),
        );
        assert_eq!(status, AsyncActionStatus::Authorized);
    }

    #[test]
    fn test_process_polkit_reply_denied() {
        let status = process_polkit_reply(
            None,
            Some(PolkitAuthReply {
                authorized: false,
                challenge: false,
            }),
        );
        assert_eq!(status, AsyncActionStatus::Denied);
    }

    #[test]
    fn test_process_polkit_reply_challenge() {
        let status = process_polkit_reply(
            None,
            Some(PolkitAuthReply {
                authorized: false,
                challenge: true,
            }),
        );
        assert!(matches!(
            status,
            AsyncActionStatus::Error(PolkitError::InteractiveAuthorizationRequired(_))
        ));
    }

    #[test]
    fn test_process_polkit_reply_service_unavailable() {
        let status = process_polkit_reply(Some("org.freedesktop.DBus.Error.ServiceUnknown"), None);
        assert_eq!(status, AsyncActionStatus::Absent);
    }

    #[test]
    fn test_process_polkit_reply_failed_error() {
        let status = process_polkit_reply(Some(POLKIT_ERROR_FAILED), None);
        assert_eq!(status, AsyncActionStatus::Denied);
    }

    #[test]
    fn test_process_polkit_reply_unexpected_error() {
        let status = process_polkit_reply(Some("org.freedesktop.DBus.Error.TimedOut"), None);
        assert!(matches!(
            status,
            AsyncActionStatus::Error(PolkitError::PolkitError { .. })
        ));
    }

    // -- polkit_public_flags --

    #[test]
    fn test_polkit_public_flags() {
        assert_eq!(
            polkit_public_flags(PolkitFlags::ALLOW_INTERACTIVE | PolkitFlags::ALWAYS_QUERY),
            3
        );
        assert_eq!(
            polkit_public_flags(
                PolkitFlags::ALLOW_INTERACTIVE
                    | PolkitFlags::ALWAYS_QUERY
                    | PolkitFlags::DEFAULT_ALLOW
                    | PolkitFlags::DONT_REPLY
            ),
            3
        );
        assert_eq!(polkit_public_flags(PolkitFlags::DEFAULT_ALLOW), 0);
    }

    // -- async_polkit_query_check_action --

    #[test]
    fn test_async_check_already_authorized() {
        let actions = vec![AsyncPolkitQueryAction {
            action: "org.freedesktop.test.action".into(),
            details: vec![("key".into(), "value".into())],
            status: AsyncActionStatus::Authorized,
        }];
        assert_eq!(
            async_polkit_query_check_action(
                &actions,
                "org.freedesktop.test.action",
                &[("key".into(), "value".into())],
                PolkitFlags::empty()
            ),
            Some(AsyncPolkitReturn::Authorized)
        );
    }

    #[test]
    fn test_async_check_already_denied() {
        let actions = vec![AsyncPolkitQueryAction {
            action: "org.freedesktop.test.action".into(),
            details: vec![],
            status: AsyncActionStatus::Denied,
        }];
        assert_eq!(
            async_polkit_query_check_action(
                &actions,
                "org.freedesktop.test.action",
                &[],
                PolkitFlags::empty()
            ),
            Some(AsyncPolkitReturn::Denied)
        );
    }

    #[test]
    fn test_async_check_absent_default_allow() {
        let actions = vec![AsyncPolkitQueryAction {
            action: "org.freedesktop.test.action".into(),
            details: vec![],
            status: AsyncActionStatus::Absent,
        }];
        // DEFAULT_ALLOW → Authorized
        assert_eq!(
            async_polkit_query_check_action(
                &actions,
                "org.freedesktop.test.action",
                &[],
                PolkitFlags::DEFAULT_ALLOW
            ),
            Some(AsyncPolkitReturn::Authorized)
        );
        // No flag → Denied
        assert_eq!(
            async_polkit_query_check_action(
                &actions,
                "org.freedesktop.test.action",
                &[],
                PolkitFlags::empty()
            ),
            Some(AsyncPolkitReturn::Denied)
        );
    }

    #[test]
    fn test_async_check_no_result_yet() {
        let actions = vec![AsyncPolkitQueryAction {
            action: "org.freedesktop.test.action".into(),
            details: vec![],
            status: AsyncActionStatus::Pending,
        }];
        assert_eq!(
            async_polkit_query_check_action(
                &actions,
                "org.freedesktop.test.action",
                &[],
                PolkitFlags::empty()
            ),
            None
        );
    }

    #[test]
    fn test_async_check_previous_denial_blocks_new() {
        // A denied action for "action_a" should block a new action "action_b"
        let actions = vec![AsyncPolkitQueryAction {
            action: "org.freedesktop.test.actionA".into(),
            details: vec![],
            status: AsyncActionStatus::Denied,
        }];
        assert_eq!(
            async_polkit_query_check_action(
                &actions,
                "org.freedesktop.test.actionB",
                &[],
                PolkitFlags::empty()
            ),
            Some(AsyncPolkitReturn::Denied)
        );
    }

    // -- async_polkit_query_has_action --

    #[test]
    fn test_has_action_found() {
        let actions = vec![AsyncPolkitQueryAction {
            action: "org.freedesktop.test.action".into(),
            details: vec![("k".into(), "v".into())],
            status: AsyncActionStatus::Authorized,
        }];
        assert!(async_polkit_query_has_action(
            &actions,
            "org.freedesktop.test.action",
            &[("k".into(), "v".into())]
        ));
    }

    #[test]
    fn test_has_action_not_found() {
        let actions = vec![AsyncPolkitQueryAction {
            action: "org.freedesktop.test.action".into(),
            details: vec![],
            status: AsyncActionStatus::Authorized,
        }];
        assert!(!async_polkit_query_has_action(
            &actions,
            "org.freedesktop.test.other",
            &[]
        ));
    }

    #[test]
    fn test_has_action_denied_does_not_count() {
        let actions = vec![AsyncPolkitQueryAction {
            action: "org.freedesktop.test.action".into(),
            details: vec![],
            status: AsyncActionStatus::Denied,
        }];
        assert!(!async_polkit_query_has_action(
            &actions,
            "org.freedesktop.test.action",
            &[]
        ));
    }

    // -- bus_verify_polkit_async_full --

    #[test]
    fn test_verify_async_good_user() {
        assert_eq!(
            bus_verify_polkit_async_full(
                "org.freedesktop.test",
                0,
                PolkitFlags::empty(),
                0,
                false,
                &[],
                &[]
            )
            .unwrap(),
            AsyncPolkitReturn::Authorized
        );
    }

    #[test]
    fn test_verify_async_privileged() {
        assert_eq!(
            bus_verify_polkit_async_full(
                "org.freedesktop.test",
                UID_INVALID,
                PolkitFlags::empty(),
                1000,
                true,
                &[],
                &[]
            )
            .unwrap(),
            AsyncPolkitReturn::Authorized
        );
    }

    #[test]
    fn test_verify_async_dispatch_needed() {
        assert_eq!(
            bus_verify_polkit_async_full(
                "org.freedesktop.test",
                UID_INVALID,
                PolkitFlags::empty(),
                1000,
                false,
                &[],
                &[]
            )
            .unwrap(),
            AsyncPolkitReturn::QueryDispatched
        );
    }

    #[test]
    fn test_verify_async_always_query_dispatches() {
        // Even if privileged, ALWAYS_QUERY should dispatch
        assert_eq!(
            bus_verify_polkit_async_full(
                "org.freedesktop.test",
                UID_INVALID,
                PolkitFlags::ALWAYS_QUERY,
                0,
                true,
                &[],
                &[]
            )
            .unwrap(),
            AsyncPolkitReturn::QueryDispatched
        );
    }

    #[test]
    fn test_verify_async_empty_action_rejected() {
        let err = bus_verify_polkit_async_full(
            "",
            UID_INVALID,
            PolkitFlags::empty(),
            1000,
            false,
            &[],
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, PolkitError::InvalidArgument(_)));
    }

    #[test]
    fn test_verify_async_reuses_existing_result() {
        let actions = vec![AsyncPolkitQueryAction {
            action: "org.freedesktop.test".into(),
            details: vec![],
            status: AsyncActionStatus::Authorized,
        }];
        assert_eq!(
            bus_verify_polkit_async_full(
                "org.freedesktop.test",
                UID_INVALID,
                PolkitFlags::empty(),
                1000,
                false,
                &actions,
                &[]
            )
            .unwrap(),
            AsyncPolkitReturn::Authorized
        );
    }

    // -- varlink_verify_polkit_async_full --

    #[test]
    fn test_varlink_verify_good_user() {
        assert_eq!(
            varlink_verify_polkit_async_full(
                "org.freedesktop.test",
                0,
                PolkitFlags::empty(),
                0,
                1000,
                &[],
                &[]
            )
            .unwrap(),
            AsyncPolkitReturn::Authorized
        );
    }

    #[test]
    fn test_varlink_verify_privileged_peer() {
        assert_eq!(
            varlink_verify_polkit_async_full(
                "org.freedesktop.test",
                UID_INVALID,
                PolkitFlags::empty(),
                1000,
                1000,
                &[],
                &[]
            )
            .unwrap(),
            AsyncPolkitReturn::Authorized
        );
    }

    #[test]
    fn test_varlink_verify_dispatch() {
        assert_eq!(
            varlink_verify_polkit_async_full(
                "org.freedesktop.test",
                UID_INVALID,
                PolkitFlags::empty(),
                1000,
                0,
                &[],
                &[]
            )
            .unwrap(),
            AsyncPolkitReturn::QueryDispatched
        );
    }

    // -- varlink_allows_interactive_auth --

    #[test]
    fn test_varlink_interactive_true() {
        assert!(varlink_allows_interactive_auth(Some(true)));
    }

    #[test]
    fn test_varlink_interactive_false() {
        assert!(!varlink_allows_interactive_auth(Some(false)));
    }

    #[test]
    fn test_varlink_interactive_missing() {
        assert!(!varlink_allows_interactive_auth(None));
    }

    // -- varlink_has_polkit_action --

    #[test]
    fn test_varlink_has_action_yes() {
        let actions = vec![AsyncPolkitQueryAction {
            action: "org.freedesktop.test".into(),
            details: vec![],
            status: AsyncActionStatus::Authorized,
        }];
        assert!(varlink_has_polkit_action(
            &actions,
            "org.freedesktop.test",
            &[]
        ));
    }

    #[test]
    fn test_varlink_has_action_no() {
        assert!(!varlink_has_polkit_action(&[], "org.freedesktop.test", &[]));
    }

    // -- PolkitError Display --

    #[test]
    fn test_polkit_error_display() {
        assert_eq!(format!("{}", PolkitError::AccessDenied), "Access denied");
        assert_eq!(
            format!("{}", PolkitError::ServiceUnavailable),
            "PolicyKit service unavailable"
        );
        assert_eq!(
            format!("{}", PolkitError::Busy),
            "A previous polkit check is still pending"
        );
        assert_eq!(
            format!("{}", PolkitError::InvalidArgument("bad".into())),
            "invalid argument: bad"
        );
        assert_eq!(format!("{}", PolkitError::OutOfMemory), "out of memory");
    }

    // -- AsyncPolkitQueryAction --

    #[test]
    fn test_action_matches() {
        let a = AsyncPolkitQueryAction::new("test.action", vec![("k".into(), "v".into())]);
        assert!(a.matches("test.action", &[("k".into(), "v".into())]));
        assert!(!a.matches("test.action", &[]));
        assert!(!a.matches("other.action", &[("k".into(), "v".into())]));
    }
}
