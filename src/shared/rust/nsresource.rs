// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/nsresource.c, src/shared/nsresource.h
//
// Namespace resource management — user namespace allocation, registration,
// and resource pinning via the systemd NamespaceResource varlink service.
//
// Provides types and logic for communicating with systemd-nsresourced to
// allocate and manage dynamic user namespaces, register them, and attach
// resources (mounts, cgroups, network interfaces).

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum namespace name length.
///
/// Names must fit within usernames (effective 31-char limit), since the
/// nsresourced service prefixes/suffixes additional bits. The kernel's
/// `TASK_COMM_LEN` (16) is chosen so names fit even after decoration.
pub const NAMESPACE_NAME_MAX: usize = 16;

/// Kernel task comm name length (`TASK_COMM_LEN`), asserted equal to
/// [`NAMESPACE_NAME_MAX`] in the C source.
pub const TASK_COMM_LEN: usize = 16;

/// Path to the NamespaceResource varlink socket.
pub const NSRESOURCE_SOCKET_PATH: &str = "/run/systemd/io.systemd.NamespaceResource";

/// Maximum allowed allocation size for user namespace UID ranges.
/// Upper bound is 4 GiB (`0x1_0000_0000`); the server currently only
/// permits 1 or 65536 (0x10000).
pub const MAX_ALLOCATION_SIZE: u64 = 0x1_0000_0000;

// ── Error types ───────────────────────────────────────────────────────────

/// Errors produced by namespace resource operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NsResourceError {
    /// An argument is invalid (e.g. allocation size out of range).
    InvalidArgument(String),
    /// Could not establish a varlink connection to nsresourced.
    ConnectionFailed(String),
    /// A varlink method call failed at the transport level.
    CallFailed(String),
    /// The kernel does not support unprivileged user namespace delegation.
    UnsupportedInterface,
    /// The target user namespace has not been registered.
    NamespaceNotRegistered,
    /// A generated namespace name exceeds [`NAMESPACE_NAME_MAX`].
    NameTooLong(String),
    /// Failed to push a file descriptor into the varlink connection.
    FdPushFailed(String),
    /// Failed to retrieve a file descriptor from a varlink reply.
    FdTakeFailed(String),
    /// The varlink reply could not be parsed.
    ResponseParseFailed(String),
    /// Catch-all for unexpected internal failures.
    InternalError(String),
}

impl std::fmt::Display for NsResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(s) => write!(f, "invalid argument: {}", s),
            Self::ConnectionFailed(s) => write!(f, "connection failed: {}", s),
            Self::CallFailed(s) => write!(f, "varlink call failed: {}", s),
            Self::UnsupportedInterface => {
                write!(
                    f,
                    "unprivileged user namespace delegation not supported on this system"
                )
            }
            Self::NamespaceNotRegistered => {
                write!(
                    f,
                    "user namespace is not registered with the resource manager"
                )
            }
            Self::NameTooLong(s) => write!(f, "namespace name too long: {}", s),
            Self::FdPushFailed(s) => write!(f, "failed to push fd: {}", s),
            Self::FdTakeFailed(s) => write!(f, "failed to take fd: {}", s),
            Self::ResponseParseFailed(s) => write!(f, "response parse failed: {}", s),
            Self::InternalError(s) => write!(f, "internal error: {}", s),
        }
    }
}

impl std::error::Error for NsResourceError {}

/// Convenience alias for `Result<T, NsResourceError>`.
pub type NsResourceResult<T> = Result<T, NsResourceError>;

// ── Operation result types ────────────────────────────────────────────────

/// Outcome of [`NsResourceClient::add_mount`] or
/// [`NsResourceClient::add_cgroup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddResourceResult {
    /// The user namespace was not previously registered; nothing was added.
    NotRegistered,
    /// The resource was successfully attached to the namespace registration.
    Added,
}

/// Outcome of [`NsResourceClient::add_netif_veth`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VethResult {
    /// Name assigned to the host-side end of the veth pair.
    pub host_interface_name: String,
    /// Name assigned to the namespace-side end of the veth pair.
    pub namespace_interface_name: String,
}

/// Outcome of [`NsResourceClient::add_netif_tap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapResult {
    /// Name assigned to the host-side tap interface.
    pub host_interface_name: String,
    /// File descriptor for the tap device (passed back via varlink).
    pub tap_fd: i32,
}

// ── Varlink protocol types ────────────────────────────────────────────────

/// Trait abstracting the varlink transport layer.
///
/// Implementations encapsulate the actual socket communication with
/// `io.systemd.NamespaceResource`. A mock implementation enables
/// unit-testing without a running nsresourced daemon.
pub trait VarlinkBackend {
    /// Enable or disable fd passing for the output (write) direction.
    fn set_fd_passing_output(&mut self, allow: bool) -> NsResourceResult<()>;
    /// Enable or disable fd passing for the input (read) direction.
    fn set_fd_passing_input(&mut self, allow: bool) -> NsResourceResult<()>;

    /// Duplicate `fd` into the connection and return its index.
    fn push_fd(&mut self, fd: i32) -> NsResourceResult<u32>;

    /// Take ownership of the fd at `index` from a previous reply.
    fn take_fd(&mut self, index: u32) -> NsResourceResult<i32>;

    /// Invoke a varlink method and return the reply.
    fn call_method(
        &mut self,
        method: &str,
        params: &VarlinkParams,
    ) -> NsResourceResult<VarlinkReply>;
}

/// Ordered collection of `(key, value)` pairs representing varlink method
/// parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VarlinkParams {
    entries: Vec<(String, VarlinkValue)>,
}

impl VarlinkParams {
    /// Create an empty parameter set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a parameter, returning `self` for chaining.
    pub fn with(mut self, key: &str, value: VarlinkValue) -> Self {
        self.entries.push((key.to_string(), value));
        self
    }

    /// Insert a parameter only when `condition` is true.
    pub fn with_when(mut self, key: &str, value: VarlinkValue, condition: bool) -> Self {
        if condition {
            self.entries.push((key.to_string(), value));
        }
        self
    }

    /// Look up a parameter value by key.
    pub fn get(&self, key: &str) -> Option<&VarlinkValue> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Number of parameters.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the parameter set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Values transmittable over varlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarlinkValue {
    String(String),
    Unsigned(u64),
    Boolean(bool),
    /// Reference to a file descriptor previously pushed via
    /// [`VarlinkBackend::push_fd`].
    FdIndex(u32),
}

/// Structured reply from a varlink method call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VarlinkReply {
    /// `Some(error_id)` if the server returned an error; `None` on success.
    pub error_id: Option<String>,
    /// Named reply fields.
    pub fields: Vec<(String, VarlinkValue)>,
}

impl VarlinkReply {
    /// Construct a successful reply with no fields.
    pub fn ok() -> Self {
        Self {
            error_id: None,
            fields: Vec::new(),
        }
    }

    /// Construct an error reply with no fields.
    pub fn error(id: &str) -> Self {
        Self {
            error_id: Some(id.to_string()),
            fields: Vec::new(),
        }
    }

    /// Construct an error reply with additional fields.
    pub fn error_with_fields(id: &str, fields: Vec<(String, VarlinkValue)>) -> Self {
        Self {
            error_id: Some(id.to_string()),
            fields,
        }
    }

    /// Retrieve a string field by key.
    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| match v {
                VarlinkValue::String(s) => Some(s.as_str()),
                _ => None,
            })
    }

    /// Retrieve an unsigned integer field by key.
    pub fn get_unsigned(&self, key: &str) -> Option<u64> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| match v {
                VarlinkValue::Unsigned(u) => Some(*u),
                _ => None,
            })
    }
}

// ── Well-known protocol identifiers ───────────────────────────────────────

/// Error ID: user namespace interface not supported by the kernel.
pub const ERR_USERNS_INTERFACE_NOT_SUPPORTED: &str =
    "io.systemd.NamespaceResource.UserNamespaceInterfaceNotSupported";

/// Error ID: target user namespace was never registered.
pub const ERR_USERNS_NOT_REGISTERED: &str =
    "io.systemd.NamespaceResource.UserNamespaceNotRegistered";

/// Method: allocate a new UID range in a user namespace.
pub const METHOD_ALLOCATE_USER_RANGE: &str = "io.systemd.NamespaceResource.AllocateUserRange";

/// Method: register an existing user namespace.
pub const METHOD_REGISTER_USER_NAMESPACE: &str =
    "io.systemd.NamespaceResource.RegisterUserNamespace";

/// Method: attach a mount to a registered user namespace.
pub const METHOD_ADD_MOUNT_TO_USER_NAMESPACE: &str =
    "io.systemd.NamespaceResource.AddMountToUserNamespace";

/// Method: attach a cgroup to a registered user namespace.
pub const METHOD_ADD_CONTROL_GROUP_TO_USER_NAMESPACE: &str =
    "io.systemd.NamespaceResource.AddControlGroupToUserNamespace";

/// Method: attach a network interface to a registered user namespace.
pub const METHOD_ADD_NETWORK_TO_USER_NAMESPACE: &str =
    "io.systemd.NamespaceResource.AddNetworkToUserNamespace";

// ── Name generation ───────────────────────────────────────────────────────

/// Stateful generator of unique namespace names.
///
/// Each call to [`NameGenerator::generate`] appends the process PID and an
/// optional hex counter to a base "comm" name. The counter ensures
/// uniqueness when a single process allocates multiple namespaces. The
/// first call suppresses the counter suffix entirely (matching the C
/// behaviour in `make_pid_name`).
///
/// # Example
///
/// ```
/// let mut gen = NameGenerator::new();
/// assert_eq!(gen.generate("myapp", 1234), "myapp1234");
/// assert_eq!(gen.generate("myapp", 1234), "myapp1231");
/// ```
#[derive(Debug)]
pub struct NameGenerator {
    counter: u64,
}

impl NameGenerator {
    /// Create a new generator with the counter starting at 0.
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    /// Create a generator with a specific initial counter value.
    pub fn with_counter(start: u64) -> Self {
        Self { counter: start }
    }

    /// Generate the next unique namespace name.
    ///
    /// Constructs `{comm}{pid}` on the first call, or
    /// `{comm}{pid}{counter:x}` on subsequent calls, truncating `comm`
    /// so the total length never exceeds [`NAMESPACE_NAME_MAX`].
    pub fn generate(&mut self, comm: &str, pid: u32) -> String {
        let pid_str = pid.to_string();
        let counter_str = if self.counter == 0 {
            String::new()
        } else {
            format!("{:x}", self.counter)
        };
        self.counter += 1;

        let (suffix, effective_counter) = if !counter_str.is_empty()
            && counter_str.len() == 1
            && comm.len() + pid_str.len() <= NAMESPACE_NAME_MAX
        {
            let mut pid_bytes = pid_str.into_bytes();
            let counter_byte = counter_str.as_bytes()[0];
            if let Some(last) = pid_bytes.last_mut() {
                *last = counter_byte;
            }
            (String::from_utf8(pid_bytes).unwrap(), String::new())
        } else {
            (pid_str.clone(), counter_str)
        };

        let suffix_len = suffix.len() + effective_counter.len();
        let max_comm = NAMESPACE_NAME_MAX.saturating_sub(suffix_len);
        let comm_slice = &comm[..comm.len().min(max_comm)];

        let mut name = format!("{}{}{}", comm_slice, suffix, effective_counter);
        name.truncate(NAMESPACE_NAME_MAX);
        name
    }

    /// Return the current counter value.
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

impl Default for NameGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Check that `size` is a valid user namespace allocation size.
///
/// Returns `Ok(())` when `1 <= size <= MAX_ALLOCATION_SIZE`.
pub fn validate_allocation_size(size: u64) -> NsResourceResult<()> {
    if size == 0 || size > MAX_ALLOCATION_SIZE {
        Err(NsResourceError::InvalidArgument(format!(
            "allocation size {} out of valid range 1..={}",
            size, MAX_ALLOCATION_SIZE
        )))
    } else {
        Ok(())
    }
}

/// Check that `name` does not exceed [`NAMESPACE_NAME_MAX`].
pub fn validate_namespace_name(name: &str) -> NsResourceResult<()> {
    if name.len() > NAMESPACE_NAME_MAX {
        Err(NsResourceError::NameTooLong(name.to_string()))
    } else {
        Ok(())
    }
}

// ── Client ────────────────────────────────────────────────────────────────

/// High-level client for the systemd NamespaceResource varlink service.
///
/// Wraps a [`VarlinkBackend`] and exposes safe, idiomatic methods for user
/// namespace allocation, registration, and resource attachment. Each method
/// performs argument validation before contacting the daemon and maps
/// daemon error IDs to Rust [`NsResourceError`] values.
pub struct NsResourceClient<B: VarlinkBackend> {
    backend: B,
    name_gen: NameGenerator,
}

impl<B: VarlinkBackend> NsResourceClient<B> {
    /// Create a new client backed by the given varlink transport.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            name_gen: NameGenerator::new(),
        }
    }

    /// Borrow the underlying backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Borrow the underlying backend mutably.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Borrow the name generator.
    pub fn name_generator(&self) -> &NameGenerator {
        &self.name_gen
    }

    /// Borrow the name generator mutably.
    pub fn name_generator_mut(&mut self) -> &mut NameGenerator {
        &mut self.name_gen
    }

    // ── Internal helpers ──────────────────────────────────────────────

    /// Resolve the namespace name: use the provided name or generate one.
    fn resolve_name(
        &mut self,
        name: Option<&str>,
        comm: &str,
        pid: u32,
    ) -> NsResourceResult<String> {
        let resolved = match name {
            Some(n) => n.to_string(),
            None => self.name_gen.generate(comm, pid),
        };
        validate_namespace_name(&resolved)?;
        Ok(resolved)
    }

    /// Push a userns fd and return its varlink index.
    fn push_userns_fd(&mut self, userns_fd: i32) -> NsResourceResult<u32> {
        self.backend.push_fd(userns_fd).map_err(|e| {
            NsResourceError::FdPushFailed(format!("failed to push userns fd {}: {}", userns_fd, e))
        })
    }

    /// Handle a reply, checking for well-known error IDs.
    fn check_reply(&self, reply: &VarlinkReply) -> NsResourceResult<()> {
        if reply.error_id.as_deref() == Some(ERR_USERNS_INTERFACE_NOT_SUPPORTED) {
            return Err(NsResourceError::UnsupportedInterface);
        }
        if reply.error_id.as_deref() == Some(ERR_USERNS_NOT_REGISTERED) {
            return Err(NsResourceError::NamespaceNotRegistered);
        }
        if let Some(ref id) = reply.error_id {
            return Err(NsResourceError::CallFailed(id.clone()));
        }
        Ok(())
    }

    /// Check a reply where `NamespaceNotRegistered` is a soft (non-)error.
    fn check_reply_soft(reply: &VarlinkReply) -> NsResourceResult<AddResourceResult> {
        if reply.error_id.as_deref() == Some(ERR_USERNS_NOT_REGISTERED) {
            return Ok(AddResourceResult::NotRegistered);
        }
        if let Some(ref id) = reply.error_id {
            return Err(NsResourceError::CallFailed(id.clone()));
        }
        Ok(AddResourceResult::Added)
    }

    // ── Public API ───────────────────────────────────────────────────

    /// Allocate a new dynamic user namespace.
    ///
    /// * `name` — optional name; auto-generated if `None`.
    /// * `size` — number of UIDs to allocate (1 or 65536 in practice).
    /// * `delegate_container_ranges` — nonzero to delegate ranges for
    ///   containers.
    /// * `empty_userns_fd` — fd of an empty user namespace (obtained from
    ///   `userns_acquire_empty()` or equivalent).
    /// * `comm` / `pid` — used when auto-generating a name.
    ///
    /// Returns the userns fd on success.
    pub fn allocate_userns(
        &mut self,
        name: Option<&str>,
        size: u64,
        delegate_container_ranges: u64,
        empty_userns_fd: i32,
        comm: &str,
        pid: u32,
    ) -> NsResourceResult<i32> {
        validate_allocation_size(size)?;
        let resolved_name = self.resolve_name(name, comm, pid)?;

        self.backend.set_fd_passing_output(true)?;
        let userns_idx = self.push_userns_fd(empty_userns_fd)?;

        let params = VarlinkParams::new()
            .with("name", VarlinkValue::String(resolved_name))
            .with("mangleName", VarlinkValue::Boolean(true))
            .with("size", VarlinkValue::Unsigned(size))
            .with(
                "userNamespaceFileDescriptor",
                VarlinkValue::FdIndex(userns_idx),
            )
            .with_when(
                "delegateContainerRanges",
                VarlinkValue::Unsigned(delegate_container_ranges),
                delegate_container_ranges != 0,
            );

        let reply = self
            .backend
            .call_method(METHOD_ALLOCATE_USER_RANGE, &params)?;

        self.check_reply(&reply)?;
        Ok(empty_userns_fd)
    }

    /// Register an existing user namespace with the resource manager.
    ///
    /// * `name` — optional name; auto-generated if `None`.
    /// * `userns_fd` — fd of the user namespace to register.
    /// * `comm` / `pid` — used when auto-generating a name.
    pub fn register_userns(
        &mut self,
        name: Option<&str>,
        userns_fd: i32,
        comm: &str,
        pid: u32,
    ) -> NsResourceResult<()> {
        let resolved_name = self.resolve_name(name, comm, pid)?;
        let userns_idx = self.push_userns_fd(userns_fd)?;

        let params = VarlinkParams::new()
            .with("name", VarlinkValue::String(resolved_name))
            .with("mangleName", VarlinkValue::Boolean(true))
            .with(
                "userNamespaceFileDescriptor",
                VarlinkValue::FdIndex(userns_idx),
            );

        let reply = self
            .backend
            .call_method(METHOD_REGISTER_USER_NAMESPACE, &params)?;

        self.check_reply(&reply)?;
        Ok(())
    }

    /// Attach a mount to a registered user namespace.
    ///
    /// Returns [`AddResourceResult::NotRegistered`] if the user namespace
    /// was not previously registered (a soft condition, not an error).
    pub fn add_mount(
        &mut self,
        userns_fd: i32,
        mount_fd: i32,
    ) -> NsResourceResult<AddResourceResult> {
        if mount_fd < 0 {
            return Err(NsResourceError::InvalidArgument(format!(
                "mount fd must be non-negative, got {}",
                mount_fd
            )));
        }

        let userns_idx = self.push_userns_fd(userns_fd)?;
        let mount_idx = self.backend.push_fd(mount_fd).map_err(|e| {
            NsResourceError::FdPushFailed(format!("failed to push mount fd {}: {}", mount_fd, e))
        })?;

        let params = VarlinkParams::new()
            .with(
                "userNamespaceFileDescriptor",
                VarlinkValue::FdIndex(userns_idx),
            )
            .with("mountFileDescriptor", VarlinkValue::FdIndex(mount_idx));

        let reply = self
            .backend
            .call_method(METHOD_ADD_MOUNT_TO_USER_NAMESPACE, &params)?;

        Self::check_reply_soft(&reply)
    }

    /// Attach a cgroup to a registered user namespace.
    ///
    /// Returns [`AddResourceResult::NotRegistered`] if the user namespace
    /// was not previously registered (a soft condition, not an error).
    pub fn add_cgroup(
        &mut self,
        userns_fd: i32,
        cgroup_fd: i32,
    ) -> NsResourceResult<AddResourceResult> {
        if cgroup_fd < 0 {
            return Err(NsResourceError::InvalidArgument(format!(
                "cgroup fd must be non-negative, got {}",
                cgroup_fd
            )));
        }

        let userns_idx = self.push_userns_fd(userns_fd)?;
        let cgroup_idx = self.backend.push_fd(cgroup_fd).map_err(|e| {
            NsResourceError::FdPushFailed(format!("failed to push cgroup fd {}: {}", cgroup_fd, e))
        })?;

        let params = VarlinkParams::new()
            .with(
                "userNamespaceFileDescriptor",
                VarlinkValue::FdIndex(userns_idx),
            )
            .with(
                "controlGroupFileDescriptor",
                VarlinkValue::FdIndex(cgroup_idx),
            );

        let reply = self
            .backend
            .call_method(METHOD_ADD_CONTROL_GROUP_TO_USER_NAMESPACE, &params)?;

        Self::check_reply_soft(&reply)
    }

    /// Attach a veth network interface pair to a registered user namespace.
    ///
    /// * `userns_fd` — fd of the user namespace.
    /// * `netns_fd` — fd of the network namespace.
    /// * `namespace_ifname` — optional desired name for the namespace-side
    ///   interface.
    ///
    /// Returns [`VethResult`] on success, or
    /// [`NsResourceError::NamespaceNotRegistered`] if the namespace is
    /// not registered.
    pub fn add_netif_veth(
        &mut self,
        userns_fd: i32,
        netns_fd: i32,
        namespace_ifname: Option<&str>,
    ) -> NsResourceResult<VethResult> {
        let userns_idx = self.push_userns_fd(userns_fd)?;
        let netns_idx = self.backend.push_fd(netns_fd).map_err(|e| {
            NsResourceError::FdPushFailed(format!("failed to push netns fd {}: {}", netns_fd, e))
        })?;

        let mut params = VarlinkParams::new()
            .with(
                "userNamespaceFileDescriptor",
                VarlinkValue::FdIndex(userns_idx),
            )
            .with(
                "networkNamespaceFileDescriptor",
                VarlinkValue::FdIndex(netns_idx),
            )
            .with("mode", VarlinkValue::String("veth".to_string()));

        if let Some(ifname) = namespace_ifname {
            params = params.with(
                "namespaceInterfaceName",
                VarlinkValue::String(ifname.to_string()),
            );
        }

        let reply = self
            .backend
            .call_method(METHOD_ADD_NETWORK_TO_USER_NAMESPACE, &params)?;

        self.check_reply(&reply)?;

        let host = reply
            .get_string("hostInterfaceName")
            .ok_or_else(|| {
                NsResourceError::ResponseParseFailed(
                    "missing hostInterfaceName in reply".to_string(),
                )
            })?
            .to_string();

        let ns = reply
            .get_string("namespaceInterfaceName")
            .ok_or_else(|| {
                NsResourceError::ResponseParseFailed(
                    "missing namespaceInterfaceName in reply".to_string(),
                )
            })?
            .to_string();

        Ok(VethResult {
            host_interface_name: host,
            namespace_interface_name: ns,
        })
    }

    /// Attach a tap network interface to a registered user namespace.
    ///
    /// * `userns_fd` — fd of the user namespace.
    ///
    /// Returns [`TapResult`] containing the host interface name and the
    /// tap device fd (passed back via varlink).
    pub fn add_netif_tap(&mut self, userns_fd: i32) -> NsResourceResult<TapResult> {
        self.backend.set_fd_passing_input(true)?;
        let userns_idx = self.push_userns_fd(userns_fd)?;

        let params = VarlinkParams::new()
            .with(
                "userNamespaceFileDescriptor",
                VarlinkValue::FdIndex(userns_idx),
            )
            .with("mode", VarlinkValue::String("tap".to_string()));

        let reply = self
            .backend
            .call_method(METHOD_ADD_NETWORK_TO_USER_NAMESPACE, &params)?;

        self.check_reply(&reply)?;

        let host = reply
            .get_string("hostInterfaceName")
            .ok_or_else(|| {
                NsResourceError::ResponseParseFailed(
                    "missing hostInterfaceName in reply".to_string(),
                )
            })?
            .to_string();

        let fd_index = reply
            .get_unsigned("interfaceFileDescriptor")
            .ok_or_else(|| {
                NsResourceError::ResponseParseFailed(
                    "missing interfaceFileDescriptor in reply".to_string(),
                )
            })? as u32;

        let tap_fd = self.backend.take_fd(fd_index)?;

        Ok(TapResult {
            host_interface_name: host,
            tap_fd,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock backend ──────────────────────────────────────────────────

    /// A mock varlink backend that records calls and returns preconfigured
    /// replies. Used for testing client logic without a live daemon.
    #[derive(Debug, Default)]
    struct MockBackend {
        fd_passing_output: bool,
        fd_passing_input: bool,
        pushed_fds: Vec<i32>,
        taken_fds: Vec<(u32, i32)>,
        /// Replies queued per method name.
        replies: std::collections::HashMap<String, VarlinkReply>,
    }

    impl MockBackend {
        /// Create a mock that always returns the given reply for a single
        /// method. Any other method will return a `CallFailed` error.
        fn with_reply(method: &str, reply: VarlinkReply) -> Self {
            let mut replies = std::collections::HashMap::new();
            replies.insert(method.to_string(), reply);
            Self {
                replies,
                ..Self::default()
            }
        }
    }

    impl VarlinkBackend for MockBackend {
        fn set_fd_passing_output(&mut self, allow: bool) -> NsResourceResult<()> {
            self.fd_passing_output = allow;
            Ok(())
        }

        fn set_fd_passing_input(&mut self, allow: bool) -> NsResourceResult<()> {
            self.fd_passing_input = allow;
            Ok(())
        }

        fn push_fd(&mut self, fd: i32) -> NsResourceResult<u32> {
            let idx = self.pushed_fds.len() as u32;
            self.pushed_fds.push(fd);
            Ok(idx)
        }

        fn take_fd(&mut self, index: u32) -> NsResourceResult<i32> {
            let fake_fd = -(index as i32) - 1;
            self.taken_fds.push((index, fake_fd));
            Ok(fake_fd)
        }

        fn call_method(
            &mut self,
            method: &str,
            _params: &VarlinkParams,
        ) -> NsResourceResult<VarlinkReply> {
            self.replies.get(method).cloned().ok_or_else(|| {
                NsResourceError::CallFailed(format!("unexpected method: {}", method))
            })
        }
    }

    // ── Validation tests ──────────────────────────────────────────────

    #[test]
    fn test_validate_allocation_size_valid() {
        assert!(validate_allocation_size(1).is_ok());
        assert!(validate_allocation_size(65536).is_ok());
        assert!(validate_allocation_size(MAX_ALLOCATION_SIZE).is_ok());
    }

    #[test]
    fn test_validate_allocation_size_zero() {
        let err = validate_allocation_size(0).unwrap_err();
        assert_eq!(
            err,
            NsResourceError::InvalidArgument(
                "allocation size 0 out of valid range 1..=4294967296".to_string()
            )
        );
    }

    #[test]
    fn test_validate_allocation_size_too_large() {
        let err = validate_allocation_size(MAX_ALLOCATION_SIZE + 1).unwrap_err();
        assert!(matches!(err, NsResourceError::InvalidArgument(_)));
    }

    #[test]
    fn test_validate_namespace_name_valid() {
        assert!(validate_namespace_name("short").is_ok());
        assert!(validate_namespace_name(&"x".repeat(NAMESPACE_NAME_MAX)).is_ok());
    }

    #[test]
    fn test_validate_namespace_name_too_long() {
        let long = "x".repeat(NAMESPACE_NAME_MAX + 1);
        let err = validate_namespace_name(&long).unwrap_err();
        assert!(matches!(err, NsResourceError::NameTooLong(_)));
    }

    // ── Name generator tests ──────────────────────────────────────────

    #[test]
    fn test_name_generator_first_call_no_counter() {
        let mut gen = NameGenerator::new();
        let name = gen.generate("myapp", 1234);
        assert_eq!(name, "myapp1234");
        assert_eq!(gen.counter(), 1);
    }

    #[test]
    fn test_name_generator_subsequent_calls_have_counter() {
        let mut gen = NameGenerator::new();
        assert_eq!(gen.generate("myapp", 1234), "myapp1234");
        assert_eq!(gen.generate("myapp", 1234), "myapp1231");
        assert_eq!(gen.generate("myapp", 1234), "myapp1232");
    }

    #[test]
    fn test_name_generator_truncation() {
        let mut gen = NameGenerator::new();
        // comm = 16 chars, pid = 5 chars → 11 chars of comm fit
        let name = gen.generate("abcdefghijklmnop", 99999);
        assert_eq!(name, "abcdefghijk99999");
        assert_eq!(name.len(), NAMESPACE_NAME_MAX);
    }

    #[test]
    fn test_name_generator_with_counter_truncation() {
        let mut gen = NameGenerator::with_counter(1);
        // comm = 16 chars, pid = 5 chars, counter "1" = 1 char → 10 chars of comm
        let name = gen.generate("abcdefghijklmnop", 99999);
        assert_eq!(name, "abcdefghij999991");
        assert_eq!(name.len(), NAMESPACE_NAME_MAX);
    }

    #[test]
    fn test_name_generator_default() {
        let mut gen = NameGenerator::default();
        assert_eq!(gen.generate("test", 1), "test1");
    }

    #[test]
    fn test_name_generator_empty_comm() {
        let mut gen = NameGenerator::new();
        assert_eq!(gen.generate("", 42), "42");
    }

    #[test]
    fn test_name_generator_exact_fit() {
        let mut gen = NameGenerator::new();
        // "ab" (2) + "1234" (4) = 6 chars — well under limit
        let name = gen.generate("ab", 1234);
        assert_eq!(name, "ab1234");
    }

    #[test]
    fn test_name_generator_large_counter_hex() {
        let mut gen = NameGenerator::with_counter(255);
        // counter = 255 → "ff" (2 chars)
        let name = gen.generate("svc", 1);
        assert_eq!(name, "svc1ff");
    }

    // ── VarlinkParams tests ───────────────────────────────────────────

    #[test]
    fn test_varlink_params_builder() {
        let params = VarlinkParams::new()
            .with("name", VarlinkValue::String("test".into()))
            .with("size", VarlinkValue::Unsigned(65536))
            .with_when("flag", VarlinkValue::Boolean(true), false);

        assert_eq!(params.len(), 2);
        assert_eq!(
            params.get("name"),
            Some(&VarlinkValue::String("test".into()))
        );
        assert!(params.get("flag").is_none());
    }

    #[test]
    fn test_varlink_params_with_when_includes() {
        let params = VarlinkParams::new().with_when("key", VarlinkValue::Boolean(true), true);

        assert_eq!(params.len(), 1);
    }

    // ── VarlinkReply tests ────────────────────────────────────────────

    #[test]
    fn test_varlink_reply_ok() {
        let reply = VarlinkReply::ok();
        assert!(reply.error_id.is_none());
        assert!(reply.get_string("anything").is_none());
    }

    #[test]
    fn test_varlink_reply_error() {
        let reply = VarlinkReply::error("some.error");
        assert_eq!(reply.error_id.as_deref(), Some("some.error"));
    }

    #[test]
    fn test_varlink_reply_error_with_fields() {
        let reply = VarlinkReply::error_with_fields(
            "err.id",
            vec![("msg".into(), VarlinkValue::String("details".into()))],
        );
        assert_eq!(reply.error_id.as_deref(), Some("err.id"));
        assert_eq!(reply.get_string("msg"), Some("details"));
    }

    #[test]
    fn test_varlink_reply_get_fields() {
        let reply = VarlinkReply {
            error_id: None,
            fields: vec![
                ("host".into(), VarlinkValue::String("veth0".into())),
                ("fd".into(), VarlinkValue::Unsigned(42)),
            ],
        };
        assert_eq!(reply.get_string("host"), Some("veth0"));
        assert_eq!(reply.get_unsigned("fd"), Some(42));
        assert!(reply.get_string("fd").is_none());
    }

    // ── Error display tests ───────────────────────────────────────────

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", NsResourceError::InvalidArgument("bad".into())),
            "invalid argument: bad"
        );
        assert!(format!("{}", NsResourceError::UnsupportedInterface).contains("not supported"));
        assert!(format!("{}", NsResourceError::NamespaceNotRegistered).contains("not registered"));
        assert!(format!("{}", NsResourceError::NameTooLong("x".into())).contains("too long"));
        assert!(format!("{}", NsResourceError::ConnectionFailed("e".into())).contains("connection"));
        assert!(format!("{}", NsResourceError::FdPushFailed("e".into())).contains("push"));
        assert!(format!("{}", NsResourceError::FdTakeFailed("e".into())).contains("take"));
        assert!(format!("{}", NsResourceError::ResponseParseFailed("e".into())).contains("parse"));
        assert!(format!("{}", NsResourceError::InternalError("e".into())).contains("internal"));
    }

    // ── Client: allocate_userns ───────────────────────────────────────

    #[test]
    fn test_allocate_userns_success() {
        let mock = MockBackend::with_reply(METHOD_ALLOCATE_USER_RANGE, VarlinkReply::ok());
        let mut client = NsResourceClient::new(mock);
        let result = client.allocate_userns(Some("testns"), 65536, 0, 10, "comm", 42);
        assert_eq!(result.unwrap(), 10);
    }

    #[test]
    fn test_allocate_userns_unsupported() {
        let mock = MockBackend::with_reply(
            METHOD_ALLOCATE_USER_RANGE,
            VarlinkReply::error(ERR_USERNS_INTERFACE_NOT_SUPPORTED),
        );
        let mut client = NsResourceClient::new(mock);
        let err = client
            .allocate_userns(Some("testns"), 65536, 0, 10, "comm", 42)
            .unwrap_err();
        assert_eq!(err, NsResourceError::UnsupportedInterface);
    }

    #[test]
    fn test_allocate_userns_invalid_size() {
        let mock = MockBackend::with_reply(METHOD_ALLOCATE_USER_RANGE, VarlinkReply::ok());
        let mut client = NsResourceClient::new(mock);
        let err = client
            .allocate_userns(Some("testns"), 0, 0, 10, "comm", 42)
            .unwrap_err();
        assert!(matches!(err, NsResourceError::InvalidArgument(_)));
    }

    #[test]
    fn test_allocate_userns_auto_name() {
        let mock = MockBackend::with_reply(METHOD_ALLOCATE_USER_RANGE, VarlinkReply::ok());
        let mut client = NsResourceClient::new(mock);
        let result = client.allocate_userns(None, 1, 0, 7, "myapp", 100);
        assert_eq!(result.unwrap(), 7);
        // Name generator counter should have advanced
        assert_eq!(client.name_generator().counter(), 1);
    }

    #[test]
    fn test_allocate_userns_delegate_container_ranges() {
        let mock = MockBackend::with_reply(METHOD_ALLOCATE_USER_RANGE, VarlinkReply::ok());
        let mut client = NsResourceClient::new(mock);
        let result = client.allocate_userns(Some("ns"), 65536, 1, 5, "comm", 1);
        assert!(result.is_ok());
    }

    // ── Client: register_userns ───────────────────────────────────────

    #[test]
    fn test_register_userns_success() {
        let mock = MockBackend::with_reply(METHOD_REGISTER_USER_NAMESPACE, VarlinkReply::ok());
        let mut client = NsResourceClient::new(mock);
        assert!(client
            .register_userns(Some("testns"), 10, "comm", 42)
            .is_ok());
    }

    #[test]
    fn test_register_userns_unsupported() {
        let mock = MockBackend::with_reply(
            METHOD_REGISTER_USER_NAMESPACE,
            VarlinkReply::error(ERR_USERNS_INTERFACE_NOT_SUPPORTED),
        );
        let mut client = NsResourceClient::new(mock);
        let err = client
            .register_userns(Some("testns"), 10, "comm", 42)
            .unwrap_err();
        assert_eq!(err, NsResourceError::UnsupportedInterface);
    }

    // ── Client: add_mount ─────────────────────────────────────────────

    #[test]
    fn test_add_mount_success() {
        let mock = MockBackend::with_reply(METHOD_ADD_MOUNT_TO_USER_NAMESPACE, VarlinkReply::ok());
        let mut client = NsResourceClient::new(mock);
        let result = client.add_mount(10, 20).unwrap();
        assert_eq!(result, AddResourceResult::Added);
    }

    #[test]
    fn test_add_mount_not_registered() {
        let mock = MockBackend::with_reply(
            METHOD_ADD_MOUNT_TO_USER_NAMESPACE,
            VarlinkReply::error(ERR_USERNS_NOT_REGISTERED),
        );
        let mut client = NsResourceClient::new(mock);
        let result = client.add_mount(10, 20).unwrap();
        assert_eq!(result, AddResourceResult::NotRegistered);
    }

    #[test]
    fn test_add_mount_invalid_fd() {
        let mock = MockBackend::default();
        let mut client = NsResourceClient::new(mock);
        let err = client.add_mount(10, -1).unwrap_err();
        assert!(matches!(err, NsResourceError::InvalidArgument(_)));
    }

    // ── Client: add_cgroup ───────────────────────────────────────────

    #[test]
    fn test_add_cgroup_success() {
        let mock = MockBackend::with_reply(
            METHOD_ADD_CONTROL_GROUP_TO_USER_NAMESPACE,
            VarlinkReply::ok(),
        );
        let mut client = NsResourceClient::new(mock);
        let result = client.add_cgroup(10, 20).unwrap();
        assert_eq!(result, AddResourceResult::Added);
    }

    #[test]
    fn test_add_cgroup_not_registered() {
        let mock = MockBackend::with_reply(
            METHOD_ADD_CONTROL_GROUP_TO_USER_NAMESPACE,
            VarlinkReply::error(ERR_USERNS_NOT_REGISTERED),
        );
        let mut client = NsResourceClient::new(mock);
        let result = client.add_cgroup(10, 20).unwrap();
        assert_eq!(result, AddResourceResult::NotRegistered);
    }

    #[test]
    fn test_add_cgroup_invalid_fd() {
        let mock = MockBackend::default();
        let mut client = NsResourceClient::new(mock);
        let err = client.add_cgroup(10, -1).unwrap_err();
        assert!(matches!(err, NsResourceError::InvalidArgument(_)));
    }

    // ── Client: add_netif_veth ────────────────────────────────────────

    #[test]
    fn test_add_netif_veth_success() {
        let reply = VarlinkReply {
            error_id: None,
            fields: vec![
                (
                    "hostInterfaceName".into(),
                    VarlinkValue::String("host0".into()),
                ),
                (
                    "namespaceInterfaceName".into(),
                    VarlinkValue::String("ns0".into()),
                ),
            ],
        };
        let mock = MockBackend::with_reply(METHOD_ADD_NETWORK_TO_USER_NAMESPACE, reply);
        let mut client = NsResourceClient::new(mock);
        let result = client.add_netif_veth(10, 20, Some("nsif")).unwrap();
        assert_eq!(result.host_interface_name, "host0");
        assert_eq!(result.namespace_interface_name, "ns0");
    }

    #[test]
    fn test_add_netif_veth_not_registered() {
        let mock = MockBackend::with_reply(
            METHOD_ADD_NETWORK_TO_USER_NAMESPACE,
            VarlinkReply::error(ERR_USERNS_NOT_REGISTERED),
        );
        let mut client = NsResourceClient::new(mock);
        let err = client.add_netif_veth(10, 20, None).unwrap_err();
        assert_eq!(err, NsResourceError::NamespaceNotRegistered);
    }

    #[test]
    fn test_add_netif_veth_missing_fields() {
        let mock =
            MockBackend::with_reply(METHOD_ADD_NETWORK_TO_USER_NAMESPACE, VarlinkReply::ok());
        let mut client = NsResourceClient::new(mock);
        let err = client.add_netif_veth(10, 20, None).unwrap_err();
        assert!(matches!(err, NsResourceError::ResponseParseFailed(_)));
    }

    // ── Client: add_netif_tap ─────────────────────────────────────────

    #[test]
    fn test_add_netif_tap_success() {
        let reply = VarlinkReply {
            error_id: None,
            fields: vec![
                (
                    "hostInterfaceName".into(),
                    VarlinkValue::String("tap0".into()),
                ),
                ("interfaceFileDescriptor".into(), VarlinkValue::Unsigned(5)),
            ],
        };
        let mock = MockBackend::with_reply(METHOD_ADD_NETWORK_TO_USER_NAMESPACE, reply);
        let mut client = NsResourceClient::new(mock);
        let result = client.add_netif_tap(10).unwrap();
        assert_eq!(result.host_interface_name, "tap0");
        assert_eq!(result.tap_fd, -6); // mock returns -(index+1) = -6
    }

    #[test]
    fn test_add_netif_tap_missing_fields() {
        let mock =
            MockBackend::with_reply(METHOD_ADD_NETWORK_TO_USER_NAMESPACE, VarlinkReply::ok());
        let mut client = NsResourceClient::new(mock);
        let err = client.add_netif_tap(10).unwrap_err();
        assert!(matches!(err, NsResourceError::ResponseParseFailed(_)));
    }

    // ── Constant tests ────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(NAMESPACE_NAME_MAX, 16);
        assert_eq!(TASK_COMM_LEN, 16);
        assert_eq!(NAMESPACE_NAME_MAX, TASK_COMM_LEN);
        assert_eq!(MAX_ALLOCATION_SIZE, 0x1_0000_0000);
        assert!(NSRESOURCE_SOCKET_PATH.starts_with("/run/systemd/"));
    }

    #[test]
    fn test_method_names() {
        assert!(METHOD_ALLOCATE_USER_RANGE.starts_with("io.systemd.NamespaceResource."));
        assert!(METHOD_REGISTER_USER_NAMESPACE.starts_with("io.systemd.NamespaceResource."));
        assert!(METHOD_ADD_MOUNT_TO_USER_NAMESPACE.starts_with("io.systemd.NamespaceResource."));
        assert!(
            METHOD_ADD_CONTROL_GROUP_TO_USER_NAMESPACE.starts_with("io.systemd.NamespaceResource.")
        );
        assert!(METHOD_ADD_NETWORK_TO_USER_NAMESPACE.starts_with("io.systemd.NamespaceResource."));
    }

    #[test]
    fn test_error_ids() {
        assert!(ERR_USERNS_INTERFACE_NOT_SUPPORTED.starts_with("io.systemd.NamespaceResource."));
        assert!(ERR_USERNS_NOT_REGISTERED.starts_with("io.systemd.NamespaceResource."));
    }

    // ── Result type tests ─────────────────────────────────────────────

    #[test]
    fn test_add_resource_result_variants() {
        assert_ne!(AddResourceResult::Added, AddResourceResult::NotRegistered);
    }

    #[test]
    fn test_veth_result_construction() {
        let r = VethResult {
            host_interface_name: "host0".into(),
            namespace_interface_name: "ns0".into(),
        };
        assert_eq!(r.host_interface_name, "host0");
        assert_eq!(r.namespace_interface_name, "ns0");
    }

    #[test]
    fn test_tap_result_construction() {
        let r = TapResult {
            host_interface_name: "tap0".into(),
            tap_fd: 42,
        };
        assert_eq!(r.host_interface_name, "tap0");
        assert_eq!(r.tap_fd, 42);
    }
}
