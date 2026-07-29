// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/fido2-util.c, src/shared/fido2-util.h

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{Shutdown, UnixStream};
use std::path::Path;

use crate::ffi::Errno;

pub const FIDO2_CREDENTIAL_ID_SIZE_MAX: usize = 256;
pub const FIDO2_SALT_SIZE: usize = 32;
pub const FIDO2_HMAC_SALT_SIZE: usize = 32;

pub type Result<T> = std::result::Result<T, Fido2UtilError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fido2UtilError {
    Io(i32),
    InvalidSaltSize(usize),
    SaltTooLarge(usize),
    OffsetTooLarge(u64),
    ShortRandomRead,
    InvalidSocketAddress,
}

impl Fido2UtilError {
    pub const fn to_neg_errno(&self) -> i32 {
        match *self {
            Self::Io(errno) => -errno,
            Self::InvalidSaltSize(_) => Errno::EINVAL.to_neg_errno(),
            Self::SaltTooLarge(_) => Errno::E2BIG.to_neg_errno(),
            Self::OffsetTooLarge(_) => Errno::ERANGE.to_neg_errno(),
            Self::ShortRandomRead => Errno::EIO.to_neg_errno(),
            Self::InvalidSocketAddress => Errno::EINVAL.to_neg_errno(),
        }
    }
}

impl fmt::Display for Fido2UtilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(errno) => write!(f, "I/O error ({errno})"),
            Self::InvalidSaltSize(size) => {
                write!(
                    f,
                    "FIDO2 salt file must contain exactly {FIDO2_SALT_SIZE} bytes, got {size}"
                )
            }
            Self::SaltTooLarge(size) => {
                write!(
                    f,
                    "FIDO2 salt file exceeds {FIDO2_SALT_SIZE} bytes (got at least {size})"
                )
            }
            Self::OffsetTooLarge(offset) => write!(f, "Offset {offset} exceeds fseek() range"),
            Self::ShortRandomRead => write!(f, "Short read from kernel random source"),
            Self::InvalidSocketAddress => write!(f, "Invalid Unix socket address"),
        }
    }
}

impl std::error::Error for Fido2UtilError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Fido2DeviceType {
    Usb = 0,
    Hid = 1,
    Nfc = 2,
    Ble = 3,
}

pub fn fido2_device_type_to_string(t: Fido2DeviceType) -> &'static str {
    match t {
        Fido2DeviceType::Usb => "usb",
        Fido2DeviceType::Hid => "hid",
        Fido2DeviceType::Nfc => "nfc",
        Fido2DeviceType::Ble => "ble",
    }
}

pub fn fido2_device_type_from_string(s: &str) -> Option<Fido2DeviceType> {
    match s {
        _ if s.eq_ignore_ascii_case("usb") => Some(Fido2DeviceType::Usb),
        _ if s.eq_ignore_ascii_case("hid") => Some(Fido2DeviceType::Hid),
        _ if s.eq_ignore_ascii_case("nfc") => Some(Fido2DeviceType::Nfc),
        _ if s.eq_ignore_ascii_case("ble") => Some(Fido2DeviceType::Ble),
        _ => None,
    }
}

pub fn fido2_generate_salt() -> Result<[u8; FIDO2_SALT_SIZE]> {
    let mut salt = [0u8; FIDO2_SALT_SIZE];
    fill_random_bytes(&mut salt)?;
    Ok(salt)
}

pub fn fido2_read_salt_file<P: AsRef<Path>>(
    filename: P,
    offset: u64,
    client: &str,
    node: &str,
) -> Result<[u8; FIDO2_SALT_SIZE]> {
    let filename = filename.as_ref();
    let effective_offset = if offset == 0 { None } else { Some(offset) };

    let mut file = match File::open(filename) {
        Ok(file) => file,
        // Match read_full_file_full(): only retry as an AF_UNIX socket when a
        // non-seeking open reports ENXIO for the socket inode.
        Err(error)
            if effective_offset.is_none() && error.raw_os_error() == Some(Errno::ENXIO as i32) =>
        {
            let mut stream = connect_salt_socket(filename, client, node)?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(Fido2UtilError::from_io)?;
            return read_salt_from_reader(&mut stream);
        }
        Err(error) => return Err(Fido2UtilError::from_io(error)),
    };

    if let Some(offset) = effective_offset {
        ensure_offset_in_range(offset)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(Fido2UtilError::from_io)?;
    }

    read_salt_from_reader(&mut file)
}

/// Connect to the salt service with the recognizable abstract client name used
/// by C's `fido2_read_salt_file()` implementation. This lets a salt server
/// distinguish FIDO2 callers from anonymous local clients.
fn connect_salt_socket(filename: &Path, client: &str, node: &str) -> Result<UnixStream> {
    let mut random = [0u8; std::mem::size_of::<u64>()];
    fill_random_bytes(&mut random)?;
    let bind_name = format!(
        "@{:x}/{client}-fido2-salt/{node}",
        u64::from_ne_bytes(random)
    );

    // SAFETY: socket takes only scalar arguments and returns a newly-owned
    // descriptor on success. `SOCK_CLOEXEC` prevents descriptor inheritance.
    let raw_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw_fd < 0 {
        return Err(Fido2UtilError::from_io(io::Error::last_os_error()));
    }
    // SAFETY: `raw_fd` is a fresh descriptor owned by this function after the
    // successful socket call above; `OwnedFd` closes it on every error path.
    let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let (bind_address, bind_length) = abstract_socket_address(&bind_name)?;
    // SAFETY: `bind_address` is initialized and its advertised length covers
    // exactly the AF_UNIX family plus the constructed abstract-name bytes.
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&bind_address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            bind_length,
        )
    } < 0
    {
        return Err(Fido2UtilError::from_io(io::Error::last_os_error()));
    }

    connect_unix_path(socket.as_raw_fd(), filename)?;
    Ok(UnixStream::from(socket))
}

fn abstract_socket_address(name: &str) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
    let name = name
        .strip_prefix('@')
        .filter(|name| !name.is_empty())
        .ok_or(Fido2UtilError::InvalidSocketAddress)?;
    let bytes = name.as_bytes();
    let mut address = empty_unix_socket_address();

    if bytes.contains(&0) || bytes.len() + 1 >= address.sun_path.len() {
        return Err(Fido2UtilError::InvalidSocketAddress);
    }

    for (index, byte) in bytes.iter().enumerate() {
        address.sun_path[index + 1] = *byte as libc::c_char;
    }

    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + bytes.len();
    Ok((address, length as libc::socklen_t))
}

fn connect_unix_path(socket: libc::c_int, path: &Path) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(Fido2UtilError::InvalidSocketAddress);
    }

    // C's connect_unix_path() uses an O_PATH descriptor and /proc/self/fd for
    // long socket paths. Keep that descriptor alive until connect(2) has
    // resolved the indirection.
    let opened_socket = (bytes.len() + 1 > unix_socket_path_capacity())
        .then(|| {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                .open(path)
        })
        .transpose()
        .map_err(Fido2UtilError::from_io)?;
    let target: Vec<u8> = opened_socket
        .as_ref()
        .map(|file| format!("/proc/self/fd/{}", file.as_raw_fd()).into_bytes())
        .unwrap_or_else(|| bytes.to_vec());
    let (address, length) = filesystem_socket_address(&target)?;

    // SAFETY: `address` is initialized and its advertised length covers the
    // AF_UNIX family plus a NUL-terminated filesystem socket path. The file
    // backing a long path remains open until this synchronous call returns.
    if unsafe {
        libc::connect(
            socket,
            (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            length,
        )
    } < 0
    {
        return Err(Fido2UtilError::from_io(io::Error::last_os_error()));
    }

    Ok(())
}

fn empty_unix_socket_address() -> libc::sockaddr_un {
    libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    }
}

fn unix_socket_path_capacity() -> usize {
    empty_unix_socket_address().sun_path.len()
}

fn filesystem_socket_address(bytes: &[u8]) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
    let mut address = empty_unix_socket_address();
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() + 1 > address.sun_path.len() {
        return Err(Fido2UtilError::InvalidSocketAddress);
    }

    for (index, byte) in bytes.iter().enumerate() {
        address.sun_path[index] = *byte as libc::c_char;
    }

    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    Ok((address, length as libc::socklen_t))
}

impl Fido2UtilError {
    fn from_io(error: io::Error) -> Self {
        Self::Io(error.raw_os_error().unwrap_or(Errno::EIO as i32))
    }
}

fn fill_random_bytes(buffer: &mut [u8]) -> Result<()> {
    let mut filled = 0;

    while filled < buffer.len() {
        let chunk = &mut buffer[filled..];
        // SAFETY: `chunk` is an exclusive, live output slice and remains
        // writable for exactly `chunk.len()` bytes for this synchronous call.
        let read = unsafe { crate::ffi::getrandom(chunk.as_mut_ptr(), chunk.len(), 0) };

        if read < 0 {
            return Err(Fido2UtilError::from_io(io::Error::last_os_error()));
        }

        let read = read as usize;
        if read == 0 || read > chunk.len() {
            return Err(Fido2UtilError::ShortRandomRead);
        }

        filled += read;
    }

    Ok(())
}

fn ensure_offset_in_range(offset: u64) -> Result<()> {
    if offset > libc::c_long::MAX as u64 {
        return Err(Fido2UtilError::OffsetTooLarge(offset));
    }

    Ok(())
}

fn read_salt_from_reader<R: Read>(reader: &mut R) -> Result<[u8; FIDO2_SALT_SIZE]> {
    let mut bytes = Vec::with_capacity(FIDO2_SALT_SIZE + 1);
    reader
        .take((FIDO2_SALT_SIZE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(Fido2UtilError::from_io)?;

    bytes_to_salt(bytes)
}

fn bytes_to_salt(mut bytes: Vec<u8>) -> Result<[u8; FIDO2_SALT_SIZE]> {
    if bytes.len() > FIDO2_SALT_SIZE {
        let size = bytes.len();
        zero_bytes(&mut bytes);
        return Err(Fido2UtilError::SaltTooLarge(size));
    }

    if bytes.len() != FIDO2_SALT_SIZE {
        let size = bytes.len();
        zero_bytes(&mut bytes);
        return Err(Fido2UtilError::InvalidSaltSize(size));
    }

    let mut salt = [0u8; FIDO2_SALT_SIZE];
    salt.copy_from_slice(&bytes);
    zero_bytes(&mut bytes);
    Ok(salt)
}

fn zero_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is an exclusive reference to initialized storage in
        // the temporary salt buffer. A volatile write prevents its erasure
        // from being optimized away before the buffer is released.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sequential_salt() -> [u8; FIDO2_SALT_SIZE] {
        std::array::from_fn(|index| index as u8)
    }

    fn temp_path(name: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        std::env::temp_dir().join(format!(
            "systemd-fido2-util-{name}-{}-{nanos}-{unique}",
            std::process::id()
        ))
    }

    fn write_temp_file(contents: &[u8]) -> PathBuf {
        let path = temp_path("file");
        fs::write(&path, contents).unwrap();
        path
    }

    fn read_socket_payload(payload: Vec<u8>) -> [u8; FIDO2_SALT_SIZE] {
        let path = temp_path("socket");
        let listener = UnixListener::bind(&path).unwrap();

        let sender = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let mut byte = [0u8; 1];
            assert_eq!(connection.read(&mut byte).unwrap(), 0);
            connection.write_all(&payload).unwrap();
            !connection.peer_addr().unwrap().is_unnamed()
        });

        let result = fido2_read_salt_file(&path, 0, "client", "node").unwrap();
        assert!(sender.join().unwrap(), "FIDO2 client must bind an identity");
        fs::remove_file(&path).unwrap();
        result
    }

    fn read_socket_error(payload: Vec<u8>) -> Fido2UtilError {
        let path = temp_path("socket-error");
        let listener = UnixListener::bind(&path).unwrap();

        let sender = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection.write_all(&payload).unwrap();
        });

        let error = fido2_read_salt_file(&path, 0, "client", "node").unwrap_err();
        sender.join().unwrap();
        fs::remove_file(&path).unwrap();
        error
    }

    #[test]
    fn constants_match_header() {
        assert_eq!(FIDO2_CREDENTIAL_ID_SIZE_MAX, 256);
        assert_eq!(FIDO2_SALT_SIZE, 32);
        assert_eq!(FIDO2_HMAC_SALT_SIZE, 32);
    }

    #[test]
    fn device_type_to_string_roundtrip() {
        let cases = [
            (Fido2DeviceType::Usb, "usb"),
            (Fido2DeviceType::Hid, "hid"),
            (Fido2DeviceType::Nfc, "nfc"),
            (Fido2DeviceType::Ble, "ble"),
        ];

        for (value, name) in cases {
            assert_eq!(fido2_device_type_to_string(value), name);
            assert_eq!(fido2_device_type_from_string(name), Some(value));
        }
    }

    #[test]
    fn device_type_from_string_is_case_insensitive() {
        assert_eq!(
            fido2_device_type_from_string("USB"),
            Some(Fido2DeviceType::Usb)
        );
        assert_eq!(
            fido2_device_type_from_string("HiD"),
            Some(Fido2DeviceType::Hid)
        );
        assert_eq!(
            fido2_device_type_from_string("nFc"),
            Some(Fido2DeviceType::Nfc)
        );
        assert_eq!(
            fido2_device_type_from_string("bLe"),
            Some(Fido2DeviceType::Ble)
        );
    }

    #[test]
    fn device_type_from_string_rejects_unknown_values() {
        assert_eq!(fido2_device_type_from_string(""), None);
        assert_eq!(fido2_device_type_from_string("uart"), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn generate_salt_returns_full_buffer() {
        let salt = fido2_generate_salt().unwrap();
        assert_eq!(salt.len(), FIDO2_SALT_SIZE);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn generate_salt_is_not_all_zeroes() {
        let salt = fido2_generate_salt().unwrap();
        assert!(salt.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn bytes_to_salt_accepts_exact_length() {
        let expected = sequential_salt();
        assert_eq!(bytes_to_salt(expected.to_vec()).unwrap(), expected);
    }

    #[test]
    fn bytes_to_salt_rejects_short_input() {
        let error = bytes_to_salt(vec![0x55; FIDO2_SALT_SIZE - 1]).unwrap_err();
        assert_eq!(error, Fido2UtilError::InvalidSaltSize(FIDO2_SALT_SIZE - 1));
        assert_eq!(error.to_neg_errno(), Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn bytes_to_salt_rejects_long_input() {
        let error = bytes_to_salt(vec![0x55; FIDO2_SALT_SIZE + 1]).unwrap_err();
        assert_eq!(error, Fido2UtilError::SaltTooLarge(FIDO2_SALT_SIZE + 1));
        assert_eq!(error.to_neg_errno(), Errno::E2BIG.to_neg_errno());
    }

    #[test]
    fn read_salt_file_reads_exact_file() {
        let expected = sequential_salt();
        let path = write_temp_file(&expected);

        let actual = fido2_read_salt_file(&path, 0, "client", "node").unwrap();

        fs::remove_file(path).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn read_salt_file_applies_non_zero_offset() {
        let mut bytes = vec![0xaa; 7];
        bytes.extend_from_slice(&sequential_salt());
        let path = write_temp_file(&bytes);

        let actual = fido2_read_salt_file(&path, 7, "client", "node").unwrap();

        fs::remove_file(path).unwrap();
        assert_eq!(actual, sequential_salt());
    }

    #[test]
    fn read_salt_file_rejects_short_file() {
        let path = write_temp_file(&[0x11; FIDO2_SALT_SIZE - 1]);

        let error = fido2_read_salt_file(&path, 0, "client", "node").unwrap_err();

        fs::remove_file(path).unwrap();
        assert_eq!(error, Fido2UtilError::InvalidSaltSize(FIDO2_SALT_SIZE - 1));
        assert_eq!(error.to_neg_errno(), Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn read_salt_file_rejects_large_file() {
        let path = write_temp_file(&[0x22; FIDO2_SALT_SIZE + 1]);

        let error = fido2_read_salt_file(&path, 0, "client", "node").unwrap_err();

        fs::remove_file(path).unwrap();
        assert_eq!(error, Fido2UtilError::SaltTooLarge(FIDO2_SALT_SIZE + 1));
        assert_eq!(error.to_neg_errno(), Errno::E2BIG.to_neg_errno());
    }

    #[test]
    fn read_salt_file_rejects_short_tail_after_offset() {
        let path = write_temp_file(&[0x33; 12]);

        let error = fido2_read_salt_file(&path, 5, "client", "node").unwrap_err();

        fs::remove_file(path).unwrap();
        assert_eq!(error, Fido2UtilError::InvalidSaltSize(7));
    }

    #[test]
    fn read_salt_file_rejects_offset_past_end() {
        let path = write_temp_file(&sequential_salt());

        let error = fido2_read_salt_file(&path, 64, "client", "node").unwrap_err();

        fs::remove_file(path).unwrap();
        assert_eq!(error, Fido2UtilError::InvalidSaltSize(0));
    }

    #[test]
    fn read_salt_file_rejects_out_of_range_offset() {
        let path = write_temp_file(&sequential_salt());

        let error = fido2_read_salt_file(&path, (libc::c_long::MAX as u64) + 1, "client", "node")
            .unwrap_err();

        fs::remove_file(path).unwrap();
        assert!(matches!(error, Fido2UtilError::OffsetTooLarge(_)));
        assert_eq!(error.to_neg_errno(), Errno::ERANGE.to_neg_errno());
    }

    #[test]
    fn read_salt_file_reads_unix_socket_when_offset_is_zero() {
        assert_eq!(
            read_socket_payload(sequential_salt().to_vec()),
            sequential_salt()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn read_salt_file_rejects_short_unix_socket_payload() {
        let error = read_socket_error(vec![0x44; FIDO2_SALT_SIZE - 2]);
        assert_eq!(error, Fido2UtilError::InvalidSaltSize(FIDO2_SALT_SIZE - 2));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn read_salt_file_rejects_large_unix_socket_payload() {
        let error = read_socket_error(vec![0x55; FIDO2_SALT_SIZE + 1]);
        assert_eq!(error, Fido2UtilError::SaltTooLarge(FIDO2_SALT_SIZE + 1));
    }
}
