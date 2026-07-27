// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/stdio-bridge/stdio-bridge.c

//! An interim RAII boundary around two in-tree `sd_bus` connections.
//!
//! The D-Bus authentication and message format are deliberately not reimplemented
//! here. `stdio-bridge.c` is a forwarding *server*, not a byte proxy: each side
//! must complete a distinct sd-bus handshake before messages can be forwarded.
//! This removes the former false-success byte proxy, but it is not the final
//! C-implementation-free port: replacing the behavioral `sd_bus` dependency
//! remains a release gate. The raw ABI is confined to this module in the
//! meantime.

use std::ffi::{c_char, c_int, CString};
use std::fmt;
use std::os::fd::RawFd;
use std::ptr::NonNull;

use systemd_basic_rs::hostname_util::{hostname_is_valid, ValidHostnameFlags};

pub const DEFAULT_SYSTEM_BUS_ADDRESS: &str = "unix:path=/run/dbus/system_bus_socket";
pub const SD_LISTEN_FDS_START: RawFd = 3;

const DBUS_LOCAL_INTERFACE: &[u8] = b"org.freedesktop.DBus.Local\0";
const DBUS_DISCONNECTED_SIGNAL: &[u8] = b"Disconnected\0";

#[repr(C)]
struct SdBus {
    _private: [u8; 0],
}

#[repr(C)]
struct SdBusMessage {
    _private: [u8; 0],
}

// Keep the union representation rather than a byte array so its by-value ABI
// matches `sd_id128_t` in src/systemd/sd-id128.h too.
#[repr(C)]
union SdId128 {
    bytes: [u8; 16],
    qwords: [u64; 2],
}

// These symbols are supplied by the same in-tree C objects that build
// stdio-bridge.c. The build integration must link this Rust target against
// libsystemd and the internal bus-address helpers just like the C target.
// SAFETY: every declaration below mirrors the corresponding systemd C
// prototype; callers validate pointer lifetimes, ownership, and return codes.
unsafe extern "C" {
    fn version() -> c_int;
    fn sd_bus_new(ret: *mut *mut SdBus) -> c_int;
    fn sd_bus_set_address(bus: *mut SdBus, address: *const c_char) -> c_int;
    fn bus_set_address_system(bus: *mut SdBus) -> c_int;
    fn bus_set_address_user(bus: *mut SdBus) -> c_int;
    fn bus_set_address_machine(bus: *mut SdBus, scope: c_int, machine: *const c_char) -> c_int;
    fn sd_bus_negotiate_fds(bus: *mut SdBus, enabled: c_int) -> c_int;
    fn sd_bus_start(bus: *mut SdBus) -> c_int;
    fn sd_bus_get_bus_id(bus: *mut SdBus, ret: *mut SdId128) -> c_int;
    fn sd_bus_set_fd(bus: *mut SdBus, input_fd: c_int, output_fd: c_int) -> c_int;
    fn sd_bus_set_server(bus: *mut SdBus, enabled: c_int, server_id: SdId128) -> c_int;
    fn sd_bus_set_anonymous(bus: *mut SdBus, enabled: c_int) -> c_int;
    fn sd_bus_process(bus: *mut SdBus, ret: *mut *mut SdBusMessage) -> c_int;
    fn sd_bus_send(bus: *mut SdBus, message: *mut SdBusMessage, cookie: *mut u64) -> c_int;
    fn sd_bus_get_fd(bus: *mut SdBus) -> c_int;
    fn sd_bus_get_events(bus: *mut SdBus) -> c_int;
    fn sd_bus_get_timeout(bus: *mut SdBus, ret: *mut u64) -> c_int;
    fn sd_bus_message_is_signal(
        message: *mut SdBusMessage,
        interface: *const c_char,
        member: *const c_char,
    ) -> c_int;
    fn sd_bus_message_unref(message: *mut SdBusMessage) -> *mut SdBusMessage;
    fn sd_bus_flush_close_unref(bus: *mut SdBus) -> *mut SdBus;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusTransport {
    Local,
    Machine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeScope {
    System,
    User,
}

impl RuntimeScope {
    // Keep this tied to src/basic/runtime-scope.h.
    const fn c_value(self) -> c_int {
        match self {
            Self::System => 0,
            Self::User => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeConfig {
    pub bus_path: Option<String>,
    pub transport: BusTransport,
    pub runtime_scope: RuntimeScope,
    pub quiet: bool,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            bus_path: None,
            transport: BusTransport::Local,
            runtime_scope: RuntimeScope::System,
            quiet: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseAction {
    Run,
    Help,
    Version,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedArgs {
    pub action: ParseAction,
    pub config: BridgeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFailure {
    pub error: BridgeError,
    pub quiet: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    InvalidArgument(String),
    TooManyFds,
    Activation { message: String, errno: i32 },
    NulInAddress,
    BusCall { operation: &'static str, errno: i32 },
    Poll(i32),
    Clock(i32),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(argument) => write!(f, "invalid argument: {argument}"),
            Self::TooManyFds => write!(f, "More than one file descriptor was passed."),
            Self::Activation { message, .. } => {
                write!(f, "failed to inspect passed file descriptors: {message}")
            }
            Self::NulInAddress => write!(f, "bus address contains an interior NUL byte"),
            Self::BusCall { operation, errno } => write!(f, "{operation}: {}", errno_name(*errno)),
            Self::Poll(errno) => write!(f, "ppoll() failed: {}", errno_name(*errno)),
            Self::Clock(errno) => write!(f, "clock_gettime() failed: {}", errno_name(*errno)),
        }
    }
}

impl std::error::Error for BridgeError {}

impl BridgeError {
    pub fn errno(&self) -> i32 {
        match self {
            Self::InvalidArgument(_) | Self::TooManyFds | Self::NulInAddress => libc::EINVAL,
            Self::Activation { errno, .. }
            | Self::BusCall { errno, .. }
            | Self::Poll(errno)
            | Self::Clock(errno) => *errno,
        }
    }
}

fn errno_name(errno: i32) -> String {
    std::io::Error::from_raw_os_error(errno.saturating_abs()).to_string()
}

fn invalid_machine(machine: &str) -> BridgeError {
    BridgeError::InvalidArgument(format!("Invalid --machine= specified: {machine}"))
}

fn valid_relaxed_user_name(user: &str) -> bool {
    if user.is_empty() {
        return false;
    }

    // Mirrors parse_uid() followed by VALID_USER_ALLOW_NUMERIC.
    let numeric_uid = user.bytes().all(|byte| byte.is_ascii_digit())
        && (user == "0" || !user.starts_with('0'))
        && user
            .parse::<u32>()
            .is_ok_and(|uid| !matches!(uid, 0xffff | u32::MAX));
    if numeric_uid {
        return true;
    }

    // Mirrors valid_user_group_name(..., VALID_USER_RELAX |
    // VALID_USER_ALLOW_NUMERIC). Rust strings are already valid UTF-8.
    !user.starts_with(' ')
        && !user.ends_with(' ')
        && !user
            .bytes()
            .any(|byte| byte < b' ' || byte == 0x7f || matches!(byte, b':' | b'/'))
        && !user.bytes().all(|byte| byte.is_ascii_digit())
        && !(user.starts_with('-')
            && user.as_bytes()[1..]
                .iter()
                .all(|byte| byte.is_ascii_digit()))
        && !matches!(user, "." | "..")
}

fn machine_spec_valid_for_bridge(machine: &str) -> bool {
    let (user, host) = match machine.split_once('@') {
        Some((user, host)) => (
            (!user.is_empty()).then_some(user),
            (!host.is_empty()).then_some(host),
        ),
        None if machine.is_empty() => return false,
        None => (None, Some(machine)),
    };

    user.map_or(true, valid_relaxed_user_name)
        && host.map_or(true, |host| {
            hostname_is_valid(host, ValidHostnameFlags::DOT_HOST)
        })
}

fn set_machine(config: &mut BridgeConfig, machine: &str) -> Result<(), BridgeError> {
    if !machine_spec_valid_for_bridge(machine) {
        return Err(invalid_machine(machine));
    }

    config.bus_path = Some(machine.to_owned());
    config.transport = BusTransport::Machine;
    Ok(())
}

/// Parse the options accepted by `stdio-bridge.c`.
///
/// `getopt_long()` returns immediately for help and version, so this function
/// intentionally does the same instead of trying to validate later options.
pub fn parse_args(args: &[String]) -> Result<ParsedArgs, BridgeError> {
    parse_args_detailed(args).map_err(|failure| failure.error)
}

/// Parse arguments while retaining whether `--quiet` was seen before a failure.
pub fn parse_args_detailed(args: &[String]) -> Result<ParsedArgs, ParseFailure> {
    let mut config = BridgeConfig::default();
    let mut index = 0;
    let mut options_ended = false;
    let mut first_positional = None;

    while index < args.len() {
        let arg = &args[index];
        if options_ended || !arg.starts_with('-') || arg == "-" {
            first_positional.get_or_insert_with(|| arg.clone());
            index += 1;
            continue;
        }
        if arg == "--" {
            options_ended = true;
            index += 1;
            continue;
        }

        match arg.as_str() {
            "--help" => {
                return Ok(ParsedArgs {
                    action: ParseAction::Help,
                    config,
                })
            }
            "--version" => {
                return Ok(ParsedArgs {
                    action: ParseAction::Version,
                    config,
                })
            }
            "--user" => config.runtime_scope = RuntimeScope::User,
            "--system" => config.runtime_scope = RuntimeScope::System,
            "--quiet" => config.quiet = true,
            "--bus-path" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| ParseFailure {
                    error: BridgeError::InvalidArgument("--bus-path requires an argument".into()),
                    quiet: config.quiet,
                })?;
                config.bus_path = Some(value.clone());
            }
            "--machine" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| ParseFailure {
                    error: BridgeError::InvalidArgument("--machine requires an argument".into()),
                    quiet: config.quiet,
                })?;
                set_machine(&mut config, value).map_err(|error| ParseFailure {
                    error,
                    quiet: config.quiet,
                })?;
            }
            _ if arg.starts_with("--bus-path=") => config.bus_path = Some(arg[11..].to_owned()),
            _ if arg.starts_with("--machine=") => {
                set_machine(&mut config, &arg[10..]).map_err(|error| ParseFailure {
                    error,
                    quiet: config.quiet,
                })?
            }
            _ if arg.starts_with("--") => {
                return Err(ParseFailure {
                    error: BridgeError::InvalidArgument(arg.clone()),
                    quiet: config.quiet,
                })
            }
            "-p" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| ParseFailure {
                    error: BridgeError::InvalidArgument("-p requires an argument".into()),
                    quiet: config.quiet,
                })?;
                config.bus_path = Some(value.clone());
            }
            "-M" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| ParseFailure {
                    error: BridgeError::InvalidArgument("-M requires an argument".into()),
                    quiet: config.quiet,
                })?;
                set_machine(&mut config, value).map_err(|error| ParseFailure {
                    error,
                    quiet: config.quiet,
                })?;
            }
            _ => match parse_short_options(arg, &mut config).map_err(|error| ParseFailure {
                error,
                quiet: config.quiet,
            })? {
                Some(ParseAction::Help) => {
                    return Ok(ParsedArgs {
                        action: ParseAction::Help,
                        config,
                    })
                }
                Some(ParseAction::Version) | Some(ParseAction::Run) => unreachable!(),
                None => {}
            },
        }
        index += 1;
    }

    if let Some(argument) = first_positional {
        return Err(ParseFailure {
            error: BridgeError::InvalidArgument(format!(
                "systemd-stdio-bridge takes no arguments: {argument}"
            )),
            quiet: config.quiet,
        });
    }

    Ok(ParsedArgs {
        action: ParseAction::Run,
        config,
    })
}

/// Print the canonical build version and feature list through the same helper
/// used by `stdio-bridge.c` instead of substituting Cargo package metadata.
pub fn print_version() -> Result<(), BridgeError> {
    // SAFETY: `version()` has no arguments or memory preconditions and writes
    // only to the process standard output, as it does for the C entry point.
    let result = unsafe { version() };
    check_bus_call(result, "Failed to print version")
}

fn parse_short_options(
    argument: &str,
    config: &mut BridgeConfig,
) -> Result<Option<ParseAction>, BridgeError> {
    let bytes = argument.as_bytes();
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'h' => return Ok(Some(ParseAction::Help)),
            b'q' => {
                config.quiet = true;
                index += 1;
            }
            b'p' | b'M' => {
                // getopt accepts -pVALUE / -MVALUE, but a following argv item
                // is handled by the outer parser where its ownership is clear.
                let value = std::str::from_utf8(&bytes[index + 1..])
                    .map_err(|_| BridgeError::InvalidArgument(argument.to_owned()))?;
                if value.is_empty() {
                    return Err(BridgeError::InvalidArgument(format!(
                        "-{} requires an argument",
                        bytes[index] as char
                    )));
                }
                if bytes[index] == b'p' {
                    config.bus_path = Some(value.to_owned());
                } else {
                    set_machine(config, value)?;
                }
                return Ok(None);
            }
            _ => return Err(BridgeError::InvalidArgument(argument.to_owned())),
        }
    }
    Ok(None)
}

/// Select the same descriptors as `sd_listen_fds(0)` plus the C bridge.
///
/// Before `Bus::take_fds()` succeeds, the process owns these descriptors. Once
/// it does, this value is only a non-owning view used for the poll set; the
/// `sd_bus` object closes the descriptors during teardown.
#[derive(Debug, PartialEq, Eq)]
pub struct BridgeFds {
    input: RawFd,
    output: RawFd,
    transferred: bool,
}

impl BridgeFds {
    pub fn from_listen_fd_count(count: i32) -> Result<Self, BridgeError> {
        match count {
            0 => Ok(Self {
                input: libc::STDIN_FILENO,
                output: libc::STDOUT_FILENO,
                transferred: false,
            }),
            1 => Ok(Self {
                input: SD_LISTEN_FDS_START,
                output: SD_LISTEN_FDS_START,
                transferred: false,
            }),
            _ => Err(BridgeError::TooManyFds),
        }
    }

    pub const fn input(&self) -> RawFd {
        self.input
    }

    pub const fn output(&self) -> RawFd {
        self.output
    }
}

/// An owned sd-bus connection. It is intentionally !Send/!Sync because sd-bus
/// itself is event-loop-affine.
struct Bus {
    ptr: NonNull<SdBus>,
}

impl Bus {
    fn new() -> Result<Self, BridgeError> {
        let mut ptr = std::ptr::null_mut();
        // SAFETY: `ptr` points to writable storage for one opaque bus pointer.
        let result = unsafe { sd_bus_new(&mut ptr) };
        check_bus_call(result, "Failed to allocate bus")?;
        let ptr = NonNull::new(ptr).ok_or(BridgeError::BusCall {
            operation: "sd_bus_new returned a null bus",
            errno: libc::EIO,
        })?;
        Ok(Self { ptr })
    }

    fn set_address(&mut self, config: &BridgeConfig) -> Result<(), BridgeError> {
        let result = match config.transport {
            BusTransport::Local => match config.bus_path.as_deref() {
                Some(address) => {
                    let address = CString::new(address).map_err(|_| BridgeError::NulInAddress)?;
                    // SAFETY: `self.ptr` is a live bus and `address` is NUL-terminated for this call.
                    unsafe { sd_bus_set_address(self.ptr.as_ptr(), address.as_ptr()) }
                }
                // SAFETY: `self.ptr` is a live, unset bus.
                None if config.runtime_scope == RuntimeScope::System => unsafe {
                    bus_set_address_system(self.ptr.as_ptr())
                },
                // SAFETY: `self.ptr` is a live, unset bus.
                None => unsafe { bus_set_address_user(self.ptr.as_ptr()) },
            },
            BusTransport::Machine => {
                let machine = config.bus_path.as_deref().ok_or_else(|| {
                    BridgeError::InvalidArgument("--machine requires an argument".into())
                })?;
                let machine = CString::new(machine).map_err(|_| BridgeError::NulInAddress)?;
                // SAFETY: `self.ptr` is a live bus and the C enum values are pinned above to runtime-scope.h.
                unsafe {
                    bus_set_address_machine(
                        self.ptr.as_ptr(),
                        config.runtime_scope.c_value(),
                        machine.as_ptr(),
                    )
                }
            }
        };
        check_bus_call(result, "Failed to set address to connect to")
    }

    fn negotiate_fds(&mut self, enabled: bool) -> Result<(), BridgeError> {
        // SAFETY: `self.ptr` is a live bus in configuration state.
        let result = unsafe { sd_bus_negotiate_fds(self.ptr.as_ptr(), enabled.into()) };
        check_bus_call(result, "Failed to set FD negotiation")
    }

    fn start(&mut self) -> Result<(), BridgeError> {
        // SAFETY: `self.ptr` is a fully configured live bus.
        let result = unsafe { sd_bus_start(self.ptr.as_ptr()) };
        check_bus_call(result, "Failed to start bus")
    }

    fn bus_id(&mut self) -> Result<SdId128, BridgeError> {
        let mut id = SdId128 { bytes: [0; 16] };
        // SAFETY: `self.ptr` is live and `id` is aligned writable storage for sd_id128_t.
        let result = unsafe { sd_bus_get_bus_id(self.ptr.as_ptr(), &mut id) };
        check_bus_call(result, "Failed to get server ID")?;
        Ok(id)
    }

    /// On success `sd_bus_set_fd()` takes sole ownership of these descriptors.
    fn take_fds(&mut self, fds: &mut BridgeFds) -> Result<(), BridgeError> {
        if fds.transferred {
            return Err(BridgeError::InvalidArgument(
                "file descriptors were already transferred to sd-bus".into(),
            ));
        }
        // SAFETY: `self.ptr` is an unset bus. sd-bus documents that ownership
        // transfers only on a non-negative result, which is reflected below.
        let result = unsafe { sd_bus_set_fd(self.ptr.as_ptr(), fds.input, fds.output) };
        check_bus_call(result, "Failed to set fds")?;
        fds.transferred = true;
        Ok(())
    }

    fn set_server(&mut self, server_id: SdId128) -> Result<(), BridgeError> {
        // SAFETY: `self.ptr` is a live bus and `server_id` is ABI-compatible sd_id128_t.
        let result = unsafe { sd_bus_set_server(self.ptr.as_ptr(), 1, server_id) };
        check_bus_call(result, "Failed to set server mode")
    }

    fn set_anonymous(&mut self) -> Result<(), BridgeError> {
        // SAFETY: `self.ptr` is a live bus in configuration state.
        let result = unsafe { sd_bus_set_anonymous(self.ptr.as_ptr(), 1) };
        check_bus_call(result, "Failed to set anonymous authentication")
    }

    fn process(&mut self) -> Result<ProcessResult, BridgeError> {
        let mut message = std::ptr::null_mut();
        // SAFETY: `self.ptr` is live and `message` is writable storage for an optional message reference.
        let result = unsafe { sd_bus_process(self.ptr.as_ptr(), &mut message) };
        if result < 0 {
            return Err(BridgeError::BusCall {
                operation: "Failed to process bus",
                errno: -result,
            });
        }
        match NonNull::new(message) {
            Some(message) => Ok(ProcessResult::Message(Message { ptr: message })),
            None if result > 0 => Ok(ProcessResult::Processed),
            None => Ok(ProcessResult::Idle),
        }
    }

    fn send(&mut self, message: &Message) -> Result<(), BridgeError> {
        // SAFETY: both objects are live and sd_bus_send only borrows the message for the call.
        let result = unsafe {
            sd_bus_send(
                self.ptr.as_ptr(),
                message.ptr.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        check_bus_call(result, "Failed to send message")
    }

    fn fd(&self) -> Result<RawFd, BridgeError> {
        // SAFETY: `self.ptr` is live.
        let result = unsafe { sd_bus_get_fd(self.ptr.as_ptr()) };
        if result < 0 {
            return Err(BridgeError::BusCall {
                operation: "Failed to get fd",
                errno: -result,
            });
        }
        Ok(result)
    }

    fn events(&self) -> Result<c_int, BridgeError> {
        // SAFETY: `self.ptr` is live.
        let result = unsafe { sd_bus_get_events(self.ptr.as_ptr()) };
        if result < 0 {
            return Err(BridgeError::BusCall {
                operation: "Failed to get events mask",
                errno: -result,
            });
        }
        Ok(result)
    }

    fn timeout(&self) -> Result<u64, BridgeError> {
        let mut timeout = u64::MAX;
        // SAFETY: `self.ptr` is live and `timeout` is writable storage.
        let result = unsafe { sd_bus_get_timeout(self.ptr.as_ptr(), &mut timeout) };
        check_bus_call(result, "Failed to get timeout")?;
        Ok(timeout)
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        // SAFETY: `ptr` was created by sd_bus_new and is released exactly once here.
        unsafe { sd_bus_flush_close_unref(self.ptr.as_ptr()) };
    }
}

enum ProcessResult {
    Idle,
    Processed,
    Message(Message),
}

struct Message {
    ptr: NonNull<SdBusMessage>,
}

impl Message {
    fn is_disconnected_signal(&self) -> bool {
        // SAFETY: `ptr` is a live message and both constants are NUL-terminated C strings.
        unsafe {
            sd_bus_message_is_signal(
                self.ptr.as_ptr(),
                DBUS_LOCAL_INTERFACE.as_ptr().cast::<c_char>(),
                DBUS_DISCONNECTED_SIGNAL.as_ptr().cast::<c_char>(),
            ) > 0
        }
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        // SAFETY: `ptr` is an owned reference returned by sd_bus_process.
        unsafe { sd_bus_message_unref(self.ptr.as_ptr()) };
    }
}

fn check_bus_call(result: c_int, operation: &'static str) -> Result<(), BridgeError> {
    if result < 0 {
        Err(BridgeError::BusCall {
            operation,
            errno: -result,
        })
    } else {
        Ok(())
    }
}

fn is_disconnect_errno(errno: i32) -> bool {
    matches!(
        errno,
        libc::ECONNABORTED
            | libc::ECONNREFUSED
            | libc::ECONNRESET
            | libc::EHOSTDOWN
            | libc::EHOSTUNREACH
            | libc::ENETDOWN
            | libc::ENETRESET
            | libc::ENETUNREACH
            | libc::ENONET
            | libc::ENOPROTOOPT
            | libc::ENOTCONN
            | libc::EPIPE
            | libc::EPROTO
            | libc::ESHUTDOWN
            | libc::ETIMEDOUT
    )
}

fn monotonic_now_usec() -> Result<u64, BridgeError> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` points to valid writable storage.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } < 0 {
        return Err(BridgeError::Clock(last_errno()));
    }
    let seconds = u64::try_from(now.tv_sec).map_err(|_| BridgeError::Clock(libc::EOVERFLOW))?;
    let nanos = u64::try_from(now.tv_nsec).map_err(|_| BridgeError::Clock(libc::EOVERFLOW))?;
    seconds
        .checked_mul(1_000_000)
        .and_then(|usec| usec.checked_add(nanos / 1_000))
        .ok_or(BridgeError::Clock(libc::EOVERFLOW))
}

fn timeout_until(deadline: u64) -> Result<Option<libc::timespec>, BridgeError> {
    if deadline == u64::MAX {
        return Ok(None);
    }
    let remaining = deadline.saturating_sub(monotonic_now_usec()?);
    Ok(Some(libc::timespec {
        tv_sec: (remaining / 1_000_000) as libc::time_t,
        tv_nsec: ((remaining % 1_000_000) * 1_000) as libc::c_long,
    }))
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Run the canonical two-way message forwarder until either peer disconnects.
pub fn run_bridge(
    config: &BridgeConfig,
    mut fds: BridgeFds,
    fds_are_unix: bool,
) -> Result<(), BridgeError> {
    let mut remote = Bus::new()?;
    remote.set_address(config)?;
    remote.negotiate_fds(fds_are_unix)?;
    remote.start()?;
    let server_id = remote.bus_id()?;

    let mut peer = Bus::new()?;
    peer.take_fds(&mut fds)?;
    peer.set_server(server_id)?;
    peer.negotiate_fds(fds_are_unix)?;
    peer.set_anonymous()?;
    peer.start()?;

    loop {
        match remote.process() {
            Ok(ProcessResult::Message(message)) => {
                if message.is_disconnected_signal() {
                    return Ok(());
                }
                peer.send(&message)?;
                continue;
            }
            Ok(ProcessResult::Processed) => continue,
            Ok(ProcessResult::Idle) => {}
            Err(BridgeError::BusCall { errno, .. }) if is_disconnect_errno(errno) => return Ok(()),
            Err(error) => return Err(error),
        }

        match peer.process() {
            Ok(ProcessResult::Message(message)) => {
                if message.is_disconnected_signal() {
                    return Ok(());
                }
                remote.send(&message)?;
                continue;
            }
            Ok(ProcessResult::Processed) => continue,
            Ok(ProcessResult::Idle) => {}
            Err(BridgeError::BusCall { errno, .. }) if is_disconnect_errno(errno) => return Ok(()),
            Err(error) => return Err(error),
        }

        let remote_events = remote.events()?;
        let peer_events = peer.events()?;
        let timeout = remote.timeout()?.min(peer.timeout()?);
        let mut poll_fds = [
            libc::pollfd {
                fd: remote.fd()?,
                events: remote_events as i16,
                revents: 0,
            },
            libc::pollfd {
                fd: fds.input(),
                events: (peer_events & libc::POLLIN) as i16,
                revents: 0,
            },
            libc::pollfd {
                fd: fds.output(),
                events: (peer_events & libc::POLLOUT) as i16,
                revents: 0,
            },
        ];
        let timeout = timeout_until(timeout)?;
        let timeout_ptr = timeout
            .as_ref()
            .map_or(std::ptr::null(), |value| value as *const libc::timespec);
        // SAFETY: `poll_fds` is a valid mutable array and `timeout_ptr` is either null or points to `timeout`.
        let result = unsafe {
            libc::ppoll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as _,
                timeout_ptr,
                std::ptr::null(),
            )
        };
        if result < 0 {
            let errno = last_errno();
            if !matches!(errno, libc::EAGAIN | libc::EINTR) {
                return Err(BridgeError::Poll(errno));
            }
        } else if poll_fds
            .iter()
            .any(|poll_fd| poll_fd.revents & libc::POLLNVAL != 0)
        {
            return Err(BridgeError::Poll(libc::EBADF));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_canonical_options() {
        let parsed = parse_args(&strings(&["-q", "-p", "unix:path=/bus", "--user"])).unwrap();
        assert_eq!(parsed.action, ParseAction::Run);
        assert!(parsed.config.quiet);
        assert_eq!(parsed.config.bus_path.as_deref(), Some("unix:path=/bus"));
        assert_eq!(parsed.config.runtime_scope, RuntimeScope::User);
    }

    #[test]
    fn machine_transport_survives_scope_selection() {
        let parsed = parse_args(&strings(&["--machine=demo", "--user"])).unwrap();
        assert_eq!(parsed.config.transport, BusTransport::Machine);
        assert_eq!(parsed.config.runtime_scope, RuntimeScope::User);
    }

    #[test]
    fn help_stops_option_parsing_like_getopt() {
        let parsed = parse_args(&strings(&["--help", "--not-an-option"])).unwrap();
        assert_eq!(parsed.action, ParseAction::Help);
    }

    #[test]
    fn help_after_positional_matches_getopt_permutation() {
        let parsed = parse_args(&strings(&["unexpected", "--help"])).unwrap();
        assert_eq!(parsed.action, ParseAction::Help);
    }

    #[test]
    fn rejects_positional_arguments() {
        assert!(matches!(
            parse_args(&strings(&["unexpected"])),
            Err(BridgeError::InvalidArgument(_))
        ));
    }

    #[test]
    fn parse_failure_retains_quiet_state() {
        let failure = parse_args_detailed(&strings(&["unexpected", "--quiet"])).unwrap_err();
        assert!(failure.quiet);
        assert!(matches!(failure.error, BridgeError::InvalidArgument(_)));
    }

    #[test]
    fn chooses_stdio_or_exactly_one_activation_fd() {
        assert_eq!(BridgeFds::from_listen_fd_count(0).unwrap().input(), 0);
        assert_eq!(BridgeFds::from_listen_fd_count(1).unwrap().input(), 3);
        assert_eq!(
            BridgeFds::from_listen_fd_count(2).unwrap_err(),
            BridgeError::TooManyFds
        );
    }

    #[test]
    fn recognizes_all_c_disconnect_errors() {
        assert!(is_disconnect_errno(libc::ECONNRESET));
        assert!(is_disconnect_errno(libc::ETIMEDOUT));
        assert!(!is_disconnect_errno(libc::EINVAL));
    }
}
