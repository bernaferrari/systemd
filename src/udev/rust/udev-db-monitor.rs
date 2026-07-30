// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-event.c, src/udev/udev-ctrl.c, src/udev/udev-watch.c
//
// Device database + monitor/control socket + rules inotify helpers for udevd.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::mem::size_of;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use systemd_shared_rs::ffi::{AF_NETLINK, SOCK_CLOEXEC, SOCK_NONBLOCK, sockaddr_nl};
use systemd_shared_rs::socket_netlink::NETLINK_KOBJECT_UEVENT;

pub const UDEV_RUN_DIR: &str = "/run/udev";
pub const UDEV_DATA_DIR: &str = "/run/udev/data";
pub const UDEV_CONTROL_SOCKET: &str = "/run/udev/control";
pub const UDEV_MONITOR_SOCKET: &str = "/run/udev/monitor";

const IN_CLOSE_WRITE: u32 = 0x0000_0008;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE: u32 = 0x0000_0200;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_DELETE_SELF: u32 = 0x0000_0400;
const IN_MOVE_SELF: u32 = 0x0000_0800;

pub const UDEV_RULES_INOTIFY_MASK: u32 =
    IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceDatabaseKey {
    Block { major: u32, minor: u32 },
    Char { major: u32, minor: u32 },
    Net { ifindex: u32 },
}

impl DeviceDatabaseKey {
    pub fn file_name(self) -> String {
        match self {
            Self::Block { major, minor } => format!("b{major}:{minor}"),
            Self::Char { major, minor } => format!("c{major}:{minor}"),
            Self::Net { ifindex } => format!("n{ifindex}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceDatabaseError {
    InvalidKey(String),
    InvalidValue(String),
    Io(i32),
}

impl From<io::Error> for DeviceDatabaseError {
    fn from(value: io::Error) -> Self {
        Self::Io(-value.raw_os_error().unwrap_or(libc::EIO))
    }
}

fn validate_property(key: &str, value: &str) -> Result<(), DeviceDatabaseError> {
    if key.is_empty() || key.contains('\n') || key.contains('\0') || key.contains('=') {
        return Err(DeviceDatabaseError::InvalidKey(key.to_string()));
    }
    if value.contains('\n') || value.contains('\0') {
        return Err(DeviceDatabaseError::InvalidValue(value.to_string()));
    }
    Ok(())
}

pub fn serialize_properties(
    properties: &[(String, String)],
) -> Result<Vec<u8>, DeviceDatabaseError> {
    let mut out = Vec::new();
    for (key, value) in properties {
        validate_property(key, value)?;
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

pub fn device_database_path(base: &Path, key: DeviceDatabaseKey) -> PathBuf {
    base.join(key.file_name())
}

pub fn write_device_database_entry(
    base: &Path,
    key: DeviceDatabaseKey,
    properties: &[(String, String)],
) -> Result<PathBuf, DeviceDatabaseError> {
    fs::create_dir_all(base)?;
    let destination = device_database_path(base, key);
    let payload = serialize_properties(properties)?;
    let tmp = destination.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&tmp, payload)?;
    fs::rename(&tmp, &destination)?;
    Ok(destination)
}

pub fn read_device_database_entry(
    path: &Path,
) -> Result<Vec<(String, String)>, DeviceDatabaseError> {
    let text = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut split = line.splitn(2, '=');
        let key = split
            .next()
            .ok_or_else(|| DeviceDatabaseError::InvalidKey(line.to_string()))?;
        let value = split
            .next()
            .ok_or_else(|| DeviceDatabaseError::InvalidValue(line.to_string()))?;
        validate_property(key, value)?;
        out.push((key.to_string(), value.to_string()));
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCommand {
    Subscribe(PathBuf),
    Unsubscribe(PathBuf),
    ReloadRules,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlParseError {
    InvalidCommand,
    MissingPath,
}

pub fn parse_control_command(line: &str) -> Result<ControlCommand, ControlParseError> {
    let line = line.trim();
    if line == "RELOAD" {
        return Ok(ControlCommand::ReloadRules);
    }

    let (cmd, path) = line
        .split_once(' ')
        .ok_or(ControlParseError::InvalidCommand)?;
    if path.is_empty() {
        return Err(ControlParseError::MissingPath);
    }

    match cmd {
        "SUBSCRIBE" => Ok(ControlCommand::Subscribe(PathBuf::from(path))),
        "UNSUBSCRIBE" => Ok(ControlCommand::Unsubscribe(PathBuf::from(path))),
        _ => Err(ControlParseError::InvalidCommand),
    }
}

pub struct UdevControlListener {
    listener: UnixListener,
}

impl UdevControlListener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        let _ = fs::remove_file(path);
        Ok(Self {
            listener: UnixListener::bind(path)?,
        })
    }

    pub fn local_path(&self) -> io::Result<PathBuf> {
        self.listener
            .local_addr()?
            .as_pathname()
            .map(Path::to_path_buf)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))
    }

    pub fn from_owned_fd(fd: OwnedFd) -> Self {
        Self {
            listener: UnixListener::from(fd),
        }
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.listener.set_nonblocking(nonblocking)
    }

    pub fn try_receive_command(&self) -> io::Result<Option<ControlCommand>> {
        match self.listener.accept() {
            Ok((mut stream, _)) => Self::receive_command(&mut stream).map(Some),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub fn receive_command(stream: &mut UnixStream) -> io::Result<ControlCommand> {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes)?;
        let text = String::from_utf8_lossy(&bytes);
        parse_control_command(&text).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }
}

pub struct UdevMonitorHub {
    socket: UnixDatagram,
    subscribers: BTreeSet<PathBuf>,
}

impl UdevMonitorHub {
    pub fn bind(path: &Path) -> io::Result<Self> {
        let _ = fs::remove_file(path);
        Ok(Self {
            socket: UnixDatagram::bind(path)?,
            subscribers: BTreeSet::new(),
        })
    }

    pub fn from_owned_fd(fd: OwnedFd) -> Self {
        Self {
            socket: UnixDatagram::from(fd),
            subscribers: BTreeSet::new(),
        }
    }

    pub fn register_subscriber(&mut self, path: PathBuf) {
        self.subscribers.insert(path);
    }

    pub fn unregister_subscriber(&mut self, path: &Path) {
        self.subscribers.remove(path);
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    pub fn local_path(&self) -> io::Result<PathBuf> {
        self.socket
            .local_addr()?
            .as_pathname()
            .map(Path::to_path_buf)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))
    }

    pub fn broadcast(&mut self, payload: &[u8]) -> io::Result<usize> {
        let mut delivered = 0usize;
        let mut failed = Vec::new();

        for target in &self.subscribers {
            match self.socket.send_to(payload, target) {
                Ok(_) => delivered += 1,
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => failed.push(target.clone()),
                Err(err) => return Err(err),
            }
        }

        for target in failed {
            self.subscribers.remove(&target);
        }

        Ok(delivered)
    }
}

pub fn default_rules_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/udev/rules.d"),
        PathBuf::from("/run/udev/rules.d"),
        PathBuf::from("/usr/lib/udev/rules.d"),
    ]
}

pub struct UdevRuntimeResources {
    pub control: UdevControlListener,
    pub monitor: UdevMonitorHub,
    pub rules_watcher: Option<RulesInotifyWatcher>,
}

pub fn initialize_udev_runtime(
    run_dir: &Path,
    rules_dirs: &[PathBuf],
) -> io::Result<UdevRuntimeResources> {
    initialize_udev_runtime_with_fds(run_dir, rules_dirs, None, None)
}

pub fn initialize_udev_runtime_with_fds(
    run_dir: &Path,
    rules_dirs: &[PathBuf],
    control_fd: Option<OwnedFd>,
    monitor_fd: Option<OwnedFd>,
) -> io::Result<UdevRuntimeResources> {
    fs::create_dir_all(run_dir)?;
    fs::create_dir_all(run_dir.join("data"))?;

    let control = match control_fd {
        Some(fd) => UdevControlListener::from_owned_fd(fd),
        None => UdevControlListener::bind(&run_dir.join("control"))?,
    };
    let monitor = match monitor_fd {
        Some(fd) => UdevMonitorHub::from_owned_fd(fd),
        None => UdevMonitorHub::bind(&run_dir.join("monitor"))?,
    };

    let mut rules_watcher = match RulesInotifyWatcher::new() {
        Ok(watcher) => Some(watcher),
        Err(err) if err.raw_os_error() == Some(libc::ENOSYS) => None,
        Err(err) => return Err(err),
    };

    if let Some(watcher) = rules_watcher.as_mut() {
        for dir in rules_dirs {
            if dir.is_dir() {
                watcher.add_watch(dir)?;
            }
        }
    }

    Ok(UdevRuntimeResources {
        control,
        monitor,
        rules_watcher,
    })
}

pub fn create_kobject_uevent_multicast_socket(groups: u32) -> io::Result<OwnedFd> {
    // SAFETY: libc socket call with validated constants and no aliasing.
    let fd = unsafe {
        libc::socket(
            AF_NETLINK,
            libc::SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
            NETLINK_KOBJECT_UEVENT,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: zeroed sockaddr_nl is valid initialization.
    let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = AF_NETLINK as _;
    addr.nl_pid = 0;
    addr.nl_groups = groups;

    // SAFETY: fd is valid and addr points to a properly initialized sockaddr_nl.
    let bind_result = unsafe {
        libc::bind(
            fd,
            (&addr as *const sockaddr_nl).cast::<libc::sockaddr>(),
            size_of::<sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bind_result < 0 {
        let err = io::Error::last_os_error();
        // SAFETY: fd is owned locally and valid.
        let _ = unsafe { libc::close(fd) };
        return Err(err);
    }

    // SAFETY: fd is uniquely owned here after successful socket/bind.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn encode_uevent_properties(
    properties: &[(String, String)],
) -> Result<Vec<u8>, DeviceDatabaseError> {
    let mut out = Vec::new();
    for (key, value) in properties {
        validate_property(key, value)?;
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value.as_bytes());
        out.push(0);
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesReloadEvent {
    pub wd: i32,
    pub mask: u32,
    pub watched_dir: Option<PathBuf>,
    pub name: Option<String>,
}

impl RulesReloadEvent {
    pub fn should_reload_rules(&self) -> bool {
        (self.mask & UDEV_RULES_INOTIFY_MASK) != 0
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LinuxInotifyEvent {
    wd: i32,
    mask: u32,
    _cookie: u32,
    len: u32,
}

pub struct RulesInotifyWatcher {
    fd: OwnedFd,
    watched_dirs: BTreeMap<i32, PathBuf>,
}

impl RulesInotifyWatcher {
    pub fn new() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: libc call with constant flags.
            let fd = unsafe { libc::inotify_init1(libc::O_NONBLOCK | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd is newly created and uniquely owned.
            Ok(Self {
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
                watched_dirs: BTreeMap::new(),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::from_raw_os_error(libc::ENOSYS))
        }
    }

    pub fn add_watch(&mut self, path: &Path) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let path_bytes = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
                .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
            // SAFETY: inotify fd is valid and path is a valid C string.
            let wd = unsafe {
                libc::inotify_add_watch(
                    self.fd.as_raw_fd(),
                    path_bytes.as_ptr(),
                    UDEV_RULES_INOTIFY_MASK,
                )
            };
            if wd < 0 {
                return Err(io::Error::last_os_error());
            }
            self.watched_dirs.insert(wd, path.to_path_buf());
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Err(io::Error::from_raw_os_error(libc::ENOSYS))
        }
    }

    pub fn read_events(&self) -> io::Result<Vec<RulesReloadEvent>> {
        #[cfg(target_os = "linux")]
        {
            let mut buf = [0u8; 8192];
            // SAFETY: buffer pointer and length are valid for read().
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return Ok(Vec::new());
                }
                return Err(err);
            }
            Ok(parse_inotify_events(&buf[..n as usize], &self.watched_dirs))
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::from_raw_os_error(libc::ENOSYS))
        }
    }
}

fn parse_inotify_events(
    bytes: &[u8],
    watched_dirs: &BTreeMap<i32, PathBuf>,
) -> Vec<RulesReloadEvent> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + size_of::<LinuxInotifyEvent>() <= bytes.len() {
        // SAFETY: bounds checked above; read_unaligned handles alignment.
        let event = unsafe {
            std::ptr::read_unaligned(bytes[offset..].as_ptr().cast::<LinuxInotifyEvent>())
        };
        offset += size_of::<LinuxInotifyEvent>();

        let name_len = event.len as usize;
        if offset + name_len > bytes.len() {
            break;
        }

        let name = if name_len > 0 {
            let raw = &bytes[offset..offset + name_len];
            let trimmed = raw.split(|b| *b == 0).next().unwrap_or(&[]);
            if trimmed.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(trimmed).into_owned())
            }
        } else {
            None
        };
        offset += name_len;

        out.push(RulesReloadEvent {
            wd: event.wd,
            mask: event.mask,
            watched_dir: watched_dirs.get(&event.wd).cloned(),
            name,
        });
    }
    out
}

pub fn monitor_socket_exists(path: &Path) -> bool {
    fs::metadata(path)
        .map(|meta| meta.file_type().is_socket())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn database_key_formats_match_udev_convention() {
        assert_eq!(
            DeviceDatabaseKey::Block { major: 8, minor: 0 }.file_name(),
            "b8:0"
        );
        assert_eq!(
            DeviceDatabaseKey::Char { major: 1, minor: 3 }.file_name(),
            "c1:3"
        );
        assert_eq!(DeviceDatabaseKey::Net { ifindex: 2 }.file_name(), "n2");
    }

    #[test]
    fn write_and_read_device_database_entry_roundtrip() {
        let base = std::env::temp_dir().join(format!("udev-data-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let props = vec![
            ("ID_VENDOR".to_string(), "Acme".to_string()),
            ("ID_MODEL".to_string(), "Disk".to_string()),
        ];

        let path = write_device_database_entry(
            &base,
            DeviceDatabaseKey::Block { major: 8, minor: 0 },
            &props,
        )
        .unwrap();
        let read_back = read_device_database_entry(&path).unwrap();
        assert_eq!(read_back, props);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn rejects_invalid_property_keys_and_values() {
        let bad_key = vec![("BAD=KEY".to_string(), "x".to_string())];
        assert!(serialize_properties(&bad_key).is_err());

        let bad_value = vec![("OK".to_string(), "line1\nline2".to_string())];
        assert!(serialize_properties(&bad_value).is_err());
    }

    #[test]
    fn parses_control_commands() {
        assert_eq!(
            parse_control_command("SUBSCRIBE /tmp/udev-client").unwrap(),
            ControlCommand::Subscribe(PathBuf::from("/tmp/udev-client"))
        );
        assert_eq!(
            parse_control_command("UNSUBSCRIBE /tmp/udev-client").unwrap(),
            ControlCommand::Unsubscribe(PathBuf::from("/tmp/udev-client"))
        );
        assert_eq!(
            parse_control_command("RELOAD").unwrap(),
            ControlCommand::ReloadRules
        );
    }

    #[test]
    fn monitor_hub_broadcasts_to_subscribers() {
        let base = std::env::temp_dir().join(format!("udev-monitor-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let monitor_path = base.join("monitor.sock");
        let subscriber_path = base.join("subscriber.sock");
        let subscriber = UnixDatagram::bind(&subscriber_path).unwrap();
        subscriber
            .set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .unwrap();

        let mut hub = UdevMonitorHub::bind(&monitor_path).unwrap();
        hub.register_subscriber(subscriber_path.clone());
        assert_eq!(hub.broadcast(b"ACTION=add\0").unwrap(), 1);

        let mut buf = [0u8; 256];
        let n = subscriber.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ACTION=add\0");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn encode_uevent_payload_is_nul_separated() {
        let payload = encode_uevent_properties(&[
            ("ACTION".to_string(), "add".to_string()),
            ("DEVPATH".to_string(), "/devices/mock".to_string()),
        ])
        .unwrap();
        assert_eq!(payload, b"ACTION=add\0DEVPATH=/devices/mock\0".to_vec());
    }

    #[test]
    fn rules_reload_event_mask_detection() {
        let event = RulesReloadEvent {
            wd: 1,
            mask: IN_CREATE,
            watched_dir: None,
            name: Some("99-test.rules".to_string()),
        };
        assert!(event.should_reload_rules());
    }

    #[test]
    fn runtime_initialization_creates_paths_and_sockets() {
        let run_dir = std::env::temp_dir().join(format!("udev-runtime-{}", std::process::id()));
        let _ = fs::remove_dir_all(&run_dir);
        fs::create_dir_all(&run_dir).unwrap();

        let rules_dir = run_dir.join("rules.d");
        fs::create_dir_all(&rules_dir).unwrap();
        let runtime = initialize_udev_runtime(&run_dir, &[rules_dir]).unwrap();

        assert!(run_dir.join("data").is_dir());
        assert!(monitor_socket_exists(
            &runtime.control.local_path().unwrap()
        ));
        assert!(monitor_socket_exists(
            &runtime.monitor.local_path().unwrap()
        ));

        let _ = fs::remove_dir_all(&run_dir);
    }

    #[test]
    fn control_listener_try_receive_command_is_nonblocking() {
        let base = std::env::temp_dir().join(format!("udev-control-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let control_path = base.join("control.sock");
        let listener = UdevControlListener::bind(&control_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert_eq!(listener.try_receive_command().unwrap(), None);

        let mut stream = UnixStream::connect(&control_path).unwrap();
        stream.write_all(b"RELOAD").unwrap();
        drop(stream);

        let command = listener.try_receive_command().unwrap();
        assert_eq!(command, Some(ControlCommand::ReloadRules));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn runtime_initialization_accepts_preopened_sockets() {
        let run_dir = std::env::temp_dir().join(format!("udev-runtime-fd-{}", std::process::id()));
        let _ = fs::remove_dir_all(&run_dir);
        fs::create_dir_all(&run_dir).unwrap();

        let control_path = run_dir.join("control");
        let monitor_path = run_dir.join("monitor");

        let control_listener = UnixListener::bind(&control_path).unwrap();
        let monitor_socket = UnixDatagram::bind(&monitor_path).unwrap();
        let control_fd: OwnedFd = control_listener.into();
        let monitor_fd: OwnedFd = monitor_socket.into();

        let rules_dir = run_dir.join("rules.d");
        fs::create_dir_all(&rules_dir).unwrap();
        let runtime = initialize_udev_runtime_with_fds(
            &run_dir,
            &[rules_dir],
            Some(control_fd),
            Some(monitor_fd),
        )
        .unwrap();

        assert_eq!(runtime.control.local_path().unwrap(), control_path);
        assert_eq!(runtime.monitor.local_path().unwrap(), monitor_path);
        assert!(run_dir.join("data").is_dir());

        let _ = fs::remove_dir_all(&run_dir);
    }
}
