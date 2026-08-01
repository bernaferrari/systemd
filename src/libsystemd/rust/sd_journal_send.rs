// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-send.c
//

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::mem::{offset_of, size_of};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;
pub const NEG_ENOBUFS: i32 = -libc::ENOBUFS;
pub const NEG_EREMOTE: i32 = -libc::EREMOTE;
const NEG_EAGAIN: i32 = -libc::EAGAIN;
const NEG_ECONNREFUSED: i32 = -libc::ECONNREFUSED;
const NEG_EMSGSIZE: i32 = -libc::EMSGSIZE;
const NEG_ENOENT: i32 = -libc::ENOENT;
const NEG_ENOTDIR: i32 = -libc::ENOTDIR;
pub const LONG_LINE_MAX: usize = 48 * 1024;
pub const LINE_MAX: usize = 2048;
pub const SNDBUF_SIZE: usize = 8 * 1024 * 1024;
pub const JOURNAL_SOCKET_PATH: &str = "/run/systemd/journal/socket";
pub const ENTRY_SIZE_MAX: usize = 13 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalField {
    pub name: String,
    pub value: Vec<u8>,
}

impl JournalField {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let eq = bytes.iter().position(|b| *b == b'=').ok_or(NEG_EINVAL)?;
        if eq == 0 || bytes.len() <= 1 {
            return Err(NEG_EINVAL);
        }
        Ok(Self {
            name: String::from_utf8(bytes[..eq].to_vec()).map_err(|_| NEG_EINVAL)?,
            value: bytes[eq + 1..].to_vec(),
        })
    }

    pub fn as_bytes_with_equals(&self) -> Vec<u8> {
        let mut out = self.name.as_bytes().to_vec();
        out.push(b'=');
        out.extend_from_slice(&self.value);
        out
    }
}

pub fn journal_print(priority: i32, message: &str) -> Result<Vec<JournalField>> {
    if !(0..=7).contains(&priority) {
        return Err(NEG_EINVAL);
    }
    let stripped = message.trim_end();
    if stripped.is_empty() {
        return Ok(Vec::new());
    }
    let payload_len = b"MESSAGE=".len() + stripped.len();
    if payload_len >= LONG_LINE_MAX {
        return Err(NEG_ENOBUFS);
    }
    Ok(vec![
        JournalField {
            name: "MESSAGE".into(),
            value: stripped.as_bytes().to_vec(),
        },
        JournalField {
            name: "PRIORITY".into(),
            value: priority.to_string().into_bytes(),
        },
    ])
}

pub fn journal_send(fields: &[JournalField], identifier: Option<&str>) -> Result<Vec<u8>> {
    let mut owned = fields.to_vec();
    if let Some(identifier) =
        identifier.filter(|_| !owned.iter().any(|f| f.name == "SYSLOG_IDENTIFIER"))
    {
        owned.push(JournalField {
            name: "SYSLOG_IDENTIFIER".into(),
            value: identifier.as_bytes().to_vec(),
        });
    }
    encode_fields(&owned)
}

pub fn journal_perror(message: &str, saved_errno: i32) -> Result<Vec<JournalField>> {
    let rendered = if message.is_empty() {
        std::io::Error::from_raw_os_error(saved_errno).to_string()
    } else {
        format!(
            "{}: {}",
            message,
            std::io::Error::from_raw_os_error(saved_errno)
        )
    };
    Ok(vec![
        JournalField {
            name: "PRIORITY".into(),
            value: b"3".to_vec(),
        },
        JournalField {
            name: "MESSAGE".into(),
            value: rendered.into_bytes(),
        },
        JournalField {
            name: "ERRNO".into(),
            value: saved_errno.to_string().into_bytes(),
        },
    ])
}

pub fn journal_stream_path(
    name_space: Option<&str>,
    env_namespace: Option<&str>,
) -> Result<String> {
    match (name_space, env_namespace) {
        (Some(wanted), Some(env)) if wanted != env => Err(NEG_EREMOTE),
        (Some(_), Some(_)) => Ok("/run/systemd/journal/stdout".into()),
        (Some(ns), None) => Ok(format!("/run/systemd/journal.{ns}/stdout")),
        (None, _) => Ok("/run/systemd/journal/stdout".into()),
    }
}

pub fn journal_stream_header(
    identifier: Option<&str>,
    priority: i32,
    level_prefix: i32,
) -> Result<Vec<u8>> {
    if !(0..=7).contains(&priority) {
        return Err(NEG_EINVAL);
    }

    let identifier = identifier.unwrap_or("");
    let mut header = Vec::with_capacity(identifier.len() + 16);
    header.extend_from_slice(identifier.as_bytes());
    header.push(b'\n');
    header.push(b'\n'); // unit id
    header.push(b'0' + priority as u8);
    header.push(b'\n');
    header.push(b'0' + (level_prefix != 0) as u8);
    header.push(b'\n');
    header.extend_from_slice(b"0\n0\n0\n");
    Ok(header)
}

pub fn sd_journal_stream_fd_with_namespace(
    name_space: Option<&str>,
    identifier: Option<&str>,
    priority: i32,
    level_prefix: i32,
) -> Result<RawFd> {
    let mut name_space = name_space;
    if let Some(ns) = name_space
        && let Ok(env_ns) = env::var("LOG_NAMESPACE")
    {
        if ns != env_ns {
            return Err(NEG_EREMOTE);
        }
        name_space = None;
    }

    let path = journal_stream_path(name_space, env::var("LOG_NAMESPACE").ok().as_deref())?;
    sd_journal_stream_fd_at_path(&path, identifier, priority, level_prefix)
}

pub fn sd_journal_stream_fd(
    identifier: Option<&str>,
    priority: i32,
    level_prefix: i32,
) -> Result<RawFd> {
    sd_journal_stream_fd_with_namespace(None, identifier, priority, level_prefix)
}

pub fn sd_journal_print(priority: i32, message: &str) -> Result<i32> {
    sd_journal_print_to_path(priority, message, JOURNAL_SOCKET_PATH)
}

pub fn sd_journal_send(entries: &[&str]) -> Result<i32> {
    sd_journal_send_to_path(entries, JOURNAL_SOCKET_PATH)
}

pub fn sd_journal_sendv(fields: &[JournalField]) -> Result<i32> {
    sd_journal_sendv_to_path(fields, JOURNAL_SOCKET_PATH)
}

fn sd_journal_print_to_path(priority: i32, message: &str, path: &str) -> Result<i32> {
    let fields = journal_print(priority, message)?;
    sd_journal_sendv_to_path(&fields, path)
}

fn sd_journal_send_to_path(entries: &[&str], path: &str) -> Result<i32> {
    if entries.is_empty() {
        return Err(NEG_EINVAL);
    }

    let mut fields = Vec::with_capacity(entries.len());
    for entry in entries {
        fields.push(JournalField::from_bytes(entry.as_bytes())?);
    }
    sd_journal_sendv_to_path(&fields, path)
}

fn sd_journal_sendv_to_path(fields: &[JournalField], path: &str) -> Result<i32> {
    if fields.is_empty() {
        return Err(NEG_EINVAL);
    }

    let identifier = default_syslog_identifier();
    let payload = journal_send(fields, identifier.as_deref())?;
    match journal_send_internal(path, &payload) {
        Ok(()) => Ok(0),
        Err(NEG_ENOENT | NEG_ECONNREFUSED | NEG_ENOTDIR) => {
            let _ = std::io::stderr().write_all(&payload);
            Ok(0)
        }
        Err(errno) => Err(errno),
    }
}

fn journal_send_internal(path: &str, payload: &[u8]) -> Result<()> {
    if payload.len() > ENTRY_SIZE_MAX {
        return send_payload_via_fd(path, payload);
    }

    match send_journal_payload(path, payload) {
        Ok(()) => Ok(()),
        Err(NEG_EMSGSIZE | NEG_ENOBUFS | NEG_EAGAIN) => send_payload_via_fd(path, payload),
        Err(errno) => Err(errno),
    }
}

fn sd_journal_stream_fd_at_path(
    path: &str,
    identifier: Option<&str>,
    priority: i32,
    level_prefix: i32,
) -> Result<RawFd> {
    validate_unix_socket_path(path)?;
    let mut stream = UnixStream::connect(path).map_err(neg_io_error)?;
    stream.shutdown(Shutdown::Read).map_err(neg_io_error)?;
    set_stream_send_buffer(&stream);

    let header = journal_stream_header(identifier, priority, level_prefix)?;
    stream.write_all(&header).map_err(neg_io_error)?;
    Ok(stream.into_raw_fd())
}

fn send_journal_payload(path: &str, payload: &[u8]) -> Result<()> {
    validate_unix_socket_path(path)?;
    let socket = UnixDatagram::unbound().map_err(neg_io_error)?;
    let sent = socket.send_to(payload, path).map_err(neg_io_error)?;
    if sent == payload.len() {
        Ok(())
    } else {
        Err(-libc::EIO)
    }
}

fn send_payload_via_fd(path: &str, payload: &[u8]) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Ok(file) = create_memfd_with_payload(payload) {
        return send_fd_over_unix_datagram(path, file.as_raw_fd());
    }

    let mut temp_path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| -libc::EIO)?
        .as_nanos();
    temp_path.push(format!(
        "systemd-journal-data-{}-{nanos}.tmp",
        std::process::id()
    ));

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|e| -e.raw_os_error().unwrap_or(libc::EIO))?;
    file.write_all(payload)
        .map_err(|e| -e.raw_os_error().unwrap_or(libc::EIO))?;
    file.sync_all()
        .map_err(|e| -e.raw_os_error().unwrap_or(libc::EIO))?;

    let r = send_fd_over_unix_datagram(path, file.as_raw_fd());
    let _ = fs::remove_file(temp_path);
    r
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn create_memfd_with_payload(payload: &[u8]) -> Result<File> {
    let name = b"journal-data\0";
    // SAFETY: name is NUL-terminated and remains live for the call; the
    // returned descriptor is checked before ownership transfer.
    let fd = unsafe_ffi!(libc::memfd_create(
        name.as_ptr() as *const libc::c_char,
        libc::MFD_CLOEXEC
    ));
    if fd < 0 {
        return Err(neg_errno());
    }
    // SAFETY: memfd_create returned a uniquely owned descriptor, transferred
    // once to OwnedFd so errors close it automatically.
    let fd = unsafe_ffi!(OwnedFd::from_raw_fd(fd));
    let mut file = File::from(fd);
    file.write_all(payload).map_err(neg_io_error)?;
    Ok(file)
}

fn send_fd_over_unix_datagram(path: &str, fd_to_send: RawFd) -> Result<()> {
    validate_unix_socket_path(path)?;
    let socket = UnixDatagram::unbound().map_err(neg_io_error)?;
    socket.connect(path).map_err(neg_io_error)?;
    send_fd_message(&socket, fd_to_send)
}

fn send_fd_message(socket: &UnixDatagram, fd_to_send: RawFd) -> Result<()> {
    let mut byte = 0_u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    // SAFETY: CMSG_SPACE is a pure layout calculation for the one RawFd we
    // store in the live control buffer below.
    let control_len = unsafe_ffi!(libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize);
    let mut control = vec![0_u8; control_len];
    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: control.len(),
        msg_flags: 0,
    };

    // SAFETY: msg refers only to the live iov/control buffers. The CMSG
    // allocation has space for exactly one RawFd, and socket is connected for
    // the full sendmsg call.
    let sent = unsafe_ffi!({
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(-libc::EIO);
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        libc::CMSG_DATA(cmsg).cast::<RawFd>().write(fd_to_send);
        msg.msg_controllen = (*cmsg).cmsg_len as _;
        libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_NOSIGNAL)
    });
    if sent < 0 {
        return Err(neg_errno());
    }
    Ok(())
}

fn validate_unix_socket_path(path: &str) -> Result<()> {
    let max_path_len = size_of::<libc::sockaddr_un>() - offset_of!(libc::sockaddr_un, sun_path);
    if path.is_empty() || path.len() + 1 > max_path_len {
        return Err(NEG_EINVAL);
    }
    Ok(())
}

fn set_stream_send_buffer(stream: &UnixStream) {
    let sndbuf = SNDBUF_SIZE as libc::c_int;
    // SAFETY: stream owns a live socket descriptor and sndbuf is a valid
    // c_int option value for the duration of this best-effort call.
    let _ = unsafe_ffi!({
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&sndbuf as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    });
}

fn neg_io_error(error: io::Error) -> i32 {
    -error.raw_os_error().unwrap_or(libc::EIO)
}

fn neg_errno() -> i32 {
    -std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn default_syslog_identifier() -> Option<String> {
    let argv0 = env::args().next()?;
    Path::new(&argv0)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
}

pub fn encode_fields(fields: &[JournalField]) -> Result<Vec<u8>> {
    if fields.is_empty() {
        return Err(NEG_EINVAL);
    }

    let mut out = Vec::new();
    for field in fields {
        if field.name.is_empty() {
            return Err(NEG_EINVAL);
        }
        if field.value.contains(&b'\n') {
            out.extend_from_slice(field.name.as_bytes());
            out.push(b'\n');
            out.extend_from_slice(&(field.value.len() as u64).to_le_bytes());
            out.extend_from_slice(&field.value);
            out.push(b'\n');
        } else {
            out.extend_from_slice(&field.as_bytes_with_equals());
            out.push(b'\n');
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rejects_invalid_priority() {
        assert_eq!(journal_print(9, "x"), Err(NEG_EINVAL));
    }

    #[test]
    fn strips_trailing_whitespace() {
        let fields = journal_print(6, "hello  \n").unwrap();
        assert_eq!(fields[0].value, b"hello".to_vec());
    }

    #[test]
    fn rejects_oversize_payload() {
        let msg = "x".repeat(LONG_LINE_MAX);
        assert_eq!(journal_print(6, &msg), Err(NEG_ENOBUFS));
    }

    #[test]
    fn encodes_simple_fields() {
        let encoded = encode_fields(&[JournalField {
            name: "MESSAGE".into(),
            value: b"hello".to_vec(),
        }])
        .unwrap();
        assert_eq!(encoded, b"MESSAGE=hello\n".to_vec());
    }

    #[test]
    fn encodes_binary_fields() {
        let encoded = encode_fields(&[JournalField {
            name: "MESSAGE".into(),
            value: b"hello\nworld".to_vec(),
        }])
        .unwrap();
        assert!(encoded.starts_with(b"MESSAGE\n"));
    }

    #[test]
    fn injects_syslog_identifier() {
        let encoded = journal_send(
            &[JournalField {
                name: "MESSAGE".into(),
                value: b"x".to_vec(),
            }],
            Some("testbin"),
        )
        .unwrap();
        let text = String::from_utf8_lossy(&encoded);
        assert!(text.contains("SYSLOG_IDENTIFIER=testbin"));
    }

    #[test]
    fn builds_perror_fields() {
        let fields = journal_perror("Foobar", libc::ENOENT).unwrap();
        assert_eq!(fields[0].value, b"3".to_vec());
        assert_eq!(fields[2].value, libc::ENOENT.to_string().into_bytes());
    }

    #[test]
    fn computes_stream_namespace_path() {
        assert_eq!(
            journal_stream_path(Some("ns"), None).unwrap(),
            "/run/systemd/journal.ns/stdout"
        );
    }

    #[test]
    fn rejects_remote_namespace_conflict() {
        assert_eq!(journal_stream_path(Some("a"), Some("b")), Err(NEG_EREMOTE));
    }

    #[test]
    fn builds_stream_header() {
        let header = journal_stream_header(Some("svc"), 5, 1).unwrap();
        assert_eq!(header, b"svc\n\n5\n1\n0\n0\n0\n");
    }

    #[test]
    fn stream_fd_connects_and_sends_header_then_payload() {
        let mut socket_path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        socket_path.push(format!("systemd-journal-stream-{nanos}.sock"));

        let listener = UnixListener::bind(&socket_path).unwrap();
        let expected_header = b"svc\n\n6\n1\n0\n0\n0\n".to_vec();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            bytes
        });

        let fd = sd_journal_stream_fd_at_path(
            socket_path.as_os_str().to_string_lossy().as_ref(),
            Some("svc"),
            6,
            1,
        )
        .unwrap();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let mut file = unsafe_ffi!(std::fs::File::from_raw_fd(fd));
        file.write_all(b"hello\n").unwrap();
        drop(file);

        let received = handle.join().unwrap();
        assert!(received.starts_with(&expected_header));
        assert!(received.ends_with(b"hello\n"));

        let _ = fs::remove_file(socket_path);
    }

    #[test]
    fn sendv_to_mock_socket_writes_payload() {
        let mut socket_path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        socket_path.push(format!("systemd-journal-sendv-{nanos}.sock"));

        let socket = std::os::unix::net::UnixDatagram::bind(&socket_path).unwrap();
        let fields = vec![
            JournalField {
                name: "MESSAGE".into(),
                value: b"hello".to_vec(),
            },
            JournalField {
                name: "PRIORITY".into(),
                value: b"6".to_vec(),
            },
        ];

        let r =
            sd_journal_sendv_to_path(&fields, socket_path.as_os_str().to_string_lossy().as_ref())
                .unwrap();
        assert_eq!(r, 0);

        let mut buf = [0u8; 512];
        let n = socket.recv(&mut buf).unwrap();
        let payload = &buf[..n];
        assert!(
            payload
                .windows("MESSAGE=hello\n".len())
                .any(|w| w == b"MESSAGE=hello\n")
        );
        assert!(
            payload
                .windows("PRIORITY=6\n".len())
                .any(|w| w == b"PRIORITY=6\n")
        );
        assert!(
            payload
                .windows("SYSLOG_IDENTIFIER=".len())
                .any(|w| w == b"SYSLOG_IDENTIFIER=")
        );

        let _ = fs::remove_file(socket_path);
    }

    #[test]
    fn print_to_mock_socket_formats_and_sends() {
        let mut socket_path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        socket_path.push(format!("systemd-journal-print-{nanos}.sock"));

        let socket = std::os::unix::net::UnixDatagram::bind(&socket_path).unwrap();
        let r = sd_journal_print_to_path(
            5,
            "hello world",
            socket_path.as_os_str().to_string_lossy().as_ref(),
        )
        .unwrap();
        assert_eq!(r, 0);

        let mut buf = [0u8; 512];
        let n = socket.recv(&mut buf).unwrap();
        let payload = &buf[..n];
        assert!(
            payload
                .windows("MESSAGE=hello world\n".len())
                .any(|w| w == b"MESSAGE=hello world\n")
        );
        assert!(
            payload
                .windows("PRIORITY=5\n".len())
                .any(|w| w == b"PRIORITY=5\n")
        );

        let _ = fs::remove_file(socket_path);
    }

    #[test]
    fn send_to_missing_socket_falls_back_to_stderr_and_returns_zero() {
        let mut socket_path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        socket_path.push(format!("systemd-journal-missing-{nanos}.sock"));

        let r = sd_journal_send_to_path(
            &["MESSAGE=hello", "PRIORITY=6"],
            socket_path.as_os_str().to_string_lossy().as_ref(),
        )
        .unwrap();
        assert_eq!(r, 0);
    }
}
