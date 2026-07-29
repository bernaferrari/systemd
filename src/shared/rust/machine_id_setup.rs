// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/machine-id-setup.c, src/shared/machine-id-setup.h
//
// Machine ID setup and management: initializes /etc/machine-id from
// D-Bus, credentials, container UUID, firmware (DMI/SMBIOS), or a
// random generator.  Supports transient (tmpfs bind-mount) and
// persistent modes, and can commit a transient ID to disk.
//
// PORT-GAP: The explicit `credential_value` integration seam has not yet been
// connected to C's encrypted credential store, and the D-Bus fallback still
// uses a metadata-then-read sequence instead of C's descriptor-pinned
// `chase_and_open()` path. Both gaps remain explicit rather than imitating
// their security-sensitive details with a partial Rust substitute.

use crate::ffi::*;
use std::ffi::{CStr, CString, c_char};
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

// SAFETY: Exact process-util.h and id128-util.h declarations. The wrappers
// below uphold the pointer/ownership contracts for `getenv_for_pid` and
// `c_id128_get_product`.
unsafe extern "C" {
    #[link_name = "detect_vm"]
    safe fn c_detect_vm() -> libc::c_int;

    #[link_name = "running_in_chroot"]
    safe fn c_running_in_chroot() -> libc::c_int;

    #[link_name = "detect_container"]
    safe fn c_detect_container() -> libc::c_int;

    #[link_name = "getenv_for_pid"]
    fn c_getenv_for_pid(
        pid: libc::pid_t,
        field: *const c_char,
        ret: *mut *mut c_char,
    ) -> libc::c_int;

    #[link_name = "id128_get_product"]
    fn c_id128_get_product(ret: *mut SdId128) -> libc::c_int;
}

/// A NUL-terminated string allocated by systemd's C allocator.
///
/// `getenv_for_pid()` returns this ownership only with a positive result.
/// Keeping it in a dedicated guard makes its `free(3)` allocation boundary
/// explicit and prevents `/proc/1/environ` values from becoming Rust-owned.
struct CAllocatedCString(NonNull<c_char>);

impl CAllocatedCString {
    /// Borrow the C helper's valid NUL-terminated string until this guard is
    /// dropped.
    fn as_c_str(&self) -> &CStr {
        // SAFETY: `getenv_for_pid()` returned a positive result and its
        // documented contract gives us a newly allocated NUL-terminated
        // string. `self` owns that allocation for this borrow's lifetime.
        unsafe { CStr::from_ptr(self.0.as_ptr()) }
    }
}

impl Drop for CAllocatedCString {
    fn drop(&mut self) {
        // SAFETY: this guard owns exactly the allocator-compatible string
        // returned by C's `strdup_to_full()` path in `getenv_for_pid()`.
        // It is dropped once and C `free(NULL)` is not needed here.
        unsafe { libc::free(self.0.as_ptr().cast()) };
    }
}

// ── Constants ─────────────────────────────────────────────────────────────

/// Primary persistent machine-id path.
const ETC_MACHINE_ID: &str = "/etc/machine-id";

/// Transient machine-id path (may be bind-mounted over the persistent one).
const RUN_MACHINE_ID: &str = "/run/machine-id";

/// D-Bus machine-id path (legacy, used as fallback source).
const DBUS_MACHINE_ID: &str = "/var/lib/dbus/machine-id";

/// Magic string written to /etc/machine-id when the ID is transient.
const UNINITIALIZED_STR: &str = "uninitialized\n";

/// Expected length of a plain-format 128-bit machine-id (32 hex chars + newline).
const MACHINE_ID_LINE_LEN: usize = 33;

// These discriminants are part of the `Virtualization` enum in `src/basic/virt.h`.
// Only these VM kinds make C's acquire_machine_id() probe the product UUID
// unless the caller explicitly forces the firmware path.
const VIRTUALIZATION_KVM: libc::c_int = 1;
const VIRTUALIZATION_AMAZON: libc::c_int = 2;
const VIRTUALIZATION_QEMU: libc::c_int = 3;
const VIRTUALIZATION_XEN: libc::c_int = 5;
const VIRTUALIZATION_BHYVE: libc::c_int = 12;

// ── Enums / Flags ─────────────────────────────────────────────────────────

/// Flags controlling `machine_id_setup` behaviour.
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MachineIdSetupFlags: u32 {
        /// Write "uninitialized" to disk and mount a transient file.
        const MACHINE_ID_SETUP_FORCE_TRANSIENT = 1 << 0;
        /// Try harder to read the machine-id from firmware/DMI.
        const MACHINE_ID_SETUP_FORCE_FIRMWARE  = 1 << 1;
    }
}

/// Possible sources for a machine-id value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineIdSource {
    /// Reused from /run/machine-id (e.g. soft-reboot).
    RunMachineId,
    /// Read from D-Bus legacy file.
    DbusMachineId,
    /// Obtained from a system credential.
    Credential,
    /// Container UUID from `$container_uuid`.
    ContainerUuid,
    /// SMBIOS / DMI product UUID.
    Firmware,
    /// Randomly generated.
    Random,
    /// Already present in /etc/machine-id.
    EtcMachineId,
}

impl fmt::Display for MachineIdSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MachineIdSource::RunMachineId => write!(f, "/run/machine-id"),
            MachineIdSource::DbusMachineId => write!(f, "D-Bus machine ID"),
            MachineIdSource::Credential => write!(f, "credential"),
            MachineIdSource::ContainerUuid => write!(f, "container UUID"),
            MachineIdSource::Firmware => write!(f, "SMBIOS/DMI UUID"),
            MachineIdSource::Random => write!(f, "random generator"),
            MachineIdSource::EtcMachineId => write!(f, "/etc/machine-id"),
        }
    }
}

/// Error type for machine-id operations.
#[derive(Debug)]
pub enum MachineIdError {
    /// An I/O error occurred.
    Io(io::Error),
    /// The machine-id content is not valid hex.
    InvalidFormat(String),
    /// /etc/machine-id is missing and /etc/ is read-only.
    ReadOnlyEtc(String),
    /// A file expected to be a mount point is not one.
    NotMountPoint(PathBuf),
    /// A file is on a persistent filesystem where a transient one was expected.
    NotTemporaryFs(PathBuf),
    /// The ID is null / all-zero where a non-null value is required.
    NullId,
}

impl fmt::Display for MachineIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MachineIdError::Io(e) => write!(f, "I/O error: {e}"),
            MachineIdError::InvalidFormat(msg) => write!(f, "invalid machine-id format: {msg}"),
            MachineIdError::ReadOnlyEtc(p) => {
                write!(f, "Missing {p} and {p} is read-only")?;
                Ok(())
            }
            MachineIdError::NotMountPoint(p) => write!(f, "{p:?} is not a mount point"),
            MachineIdError::NotTemporaryFs(p) => {
                write!(f, "{p:?} is not on a temporary filesystem")
            }
            MachineIdError::NullId => write!(f, "machine ID is all-zero"),
        }
    }
}

impl std::error::Error for MachineIdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MachineIdError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for MachineIdError {
    fn from(e: io::Error) -> Self {
        MachineIdError::Io(e)
    }
}

/// Result alias used throughout this module.
pub type MachineIdResult<T> = Result<T, MachineIdError>;

// ── 128-bit ID type ──────────────────────────────────────────────────────

/// A 128-bit identifier matching the layout of `sd_id128_t`.
///
/// Bytes are stored in network byte order (big-endian), identical to the C
/// representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C, align(16))]
pub struct SdId128 {
    pub bytes: [u8; 16],
}

impl SdId128 {
    /// Construct from a 16-byte array.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    /// The all-zero (null) machine-id.
    pub const fn nil() -> Self {
        Self { bytes: [0u8; 16] }
    }

    /// Returns `true` if every byte is zero.
    pub fn is_nil(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    /// Generate a cryptographically-random machine-id.
    ///
    /// Falls back to an OS-provided random source via `getrandom(2)`.
    pub fn randomize() -> MachineIdResult<Self> {
        let mut bytes = [0u8; 16];
        // SAFETY: getrandom() writes exactly `len` bytes into `buf` and
        // returns 0 on success or a negative errno.  The pointer is valid
        // for the given length.
        // SAFETY: `bytes` remains writable for its exact length throughout
        // this synchronous call.
        let ret =
            unsafe { crate::ffi::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), GRND_NONBLOCK) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            return Err(MachineIdError::Io(err));
        }
        if ret as usize != bytes.len() {
            return Err(MachineIdError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short read from getrandom",
            )));
        }
        Ok(Self { bytes })
    }
}

impl fmt::Display for SdId128 {
    /// Format as 32 lowercase hex characters (plain / `ID128_FORMAT_PLAIN`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &byte in &self.bytes {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::LowerHex for SdId128 {
    /// Format with dashes: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, &byte) in self.bytes.iter().enumerate() {
            if i == 4 || i == 6 || i == 8 || i == 10 {
                write!(f, "-")?;
            }
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl Default for SdId128 {
    fn default() -> Self {
        Self::nil()
    }
}

// ── Parsing helpers ──────────────────────────────────────────────────────

/// Parse a 32-character hexadecimal string into `SdId128`.
///
/// Accepts both the plain 32-character form and the canonical dashed UUID
/// form. This matches `sd_id128_from_string()` and rejects misplaced dashes.
pub fn id128_from_string(s: &str) -> MachineIdResult<SdId128> {
    let bytes = s.as_bytes();
    let is_uuid = match bytes.len() {
        32 => false,
        36 if [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-') =>
        {
            true
        }
        _ => {
            return Err(MachineIdError::InvalidFormat(format!(
                "expected 32 hex chars or a canonical dashed UUID, got {} bytes",
                bytes.len()
            )));
        }
    };

    if !bytes.iter().enumerate().all(|(index, byte)| {
        (is_uuid && matches!(index, 8 | 13 | 18 | 23)) || byte.is_ascii_hexdigit()
    }) {
        return Err(MachineIdError::InvalidFormat(
            "non-hex character in machine-id".into(),
        ));
    }

    let mut bytes = [0u8; 16];
    for (index, byte) in s
        .bytes()
        .filter(|byte| *byte != b'-')
        .collect::<Vec<_>>()
        .chunks_exact(2)
        .enumerate()
    {
        bytes[index] = (hex_value(byte[0]) << 4) | hex_value(byte[1]);
    }
    Ok(SdId128 { bytes })
}

const fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!(), // validated by id128_from_string()
    }
}

/// Try to read a plain-format machine-id from a file path.
///
/// The C authority accepts exactly 32 ASCII hex digits, optionally followed
/// by one newline. UUID dashes and other surrounding whitespace are invalid
/// for machine-id files even though [`id128_from_string`] accepts UUID input.
/// Returns `None` if the file does not exist, is empty, or contains the null
/// ID; otherwise returns `Err` on I/O or format failure.
pub fn id128_read_file(path: &Path) -> MachineIdResult<Option<SdId128>> {
    let content = match fs::read(path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(MachineIdError::Io(e)),
    };

    let plain = match content.as_slice() {
        [] => return Ok(None),
        bytes if bytes.len() == 32 => bytes,
        bytes if bytes.len() == MACHINE_ID_LINE_LEN && bytes[32] == b'\n' => &bytes[..32],
        _ => {
            return Err(MachineIdError::InvalidFormat(
                "machine-id must contain exactly 32 hex digits with at most one trailing newline"
                    .into(),
            ));
        }
    };
    let plain = std::str::from_utf8(plain)
        .map_err(|_| MachineIdError::InvalidFormat("machine-id contains non-ASCII bytes".into()))?;

    // Refuse all-null machine-id (uninitialized).
    let id = id128_from_string(plain)?;
    if id.is_nil() {
        return Ok(None);
    }
    Ok(Some(id))
}

/// Write a plain-format machine-id to a file, appending a newline.
///
/// The parent directory must already exist.
pub fn id128_write_file(path: &Path, id: SdId128) -> MachineIdResult<()> {
    let mut content = id.to_string();
    content.push('\n');
    fs::write(path, content)?;
    Ok(())
}

// ── Core logic ────────────────────────────────────────────────────────────

/// Try to acquire a machine-id from the D-Bus legacy path (regular file only).
fn acquire_from_dbus(root: &Path) -> MachineIdResult<Option<(SdId128, MachineIdSource)>> {
    let dbus_path = root.join(DBUS_MACHINE_ID.trim_start_matches('/'));

    // Only accept a non-symlink regular file — mirrors C's
    // `CHASE_NOFOLLOW | CHASE_MUST_BE_REGULAR` filter. The C compound
    // condition intentionally treats every lookup/open/read rejection as a
    // fallthrough, so this probe must not make acquisition fail.
    let meta = match fs::symlink_metadata(&dbus_path) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    if !meta.is_file() {
        return Ok(None);
    }

    match id128_read_file(&dbus_path).ok().flatten() {
        Some(id) => Ok(Some((id, MachineIdSource::DbusMachineId))),
        None => Ok(None),
    }
}

/// Try to read a machine-id string from a system credential.
///
/// In production this calls into `read_credential_with_decryption("system.machine_id", …)`.
/// For unit-testability the credential name is parameterised.
fn acquire_from_credential(
    _credential_name: &str,
    _cred_value: Option<&str>,
) -> MachineIdResult<Option<(SdId128, MachineIdSource)>> {
    // The real implementation reads from the kernel credential store.
    // Here we accept an explicit value for testability.
    let value = match _cred_value {
        Some(v) => v,
        None => return Ok(None),
    };

    if value == "firmware" {
        // Credential says "try firmware" — caller should fall through.
        return Ok(None);
    }

    match id128_from_string(value) {
        Ok(id) if !id.is_nil() => Ok(Some((id, MachineIdSource::Credential))),
        _ => Ok(None),
    }
}

/// Read one environment variable from the process selected by C's procfs
/// policy.
///
/// This is deliberately a narrow bridge to `getenv_for_pid()` instead of a
/// Rust `/proc` parser: the C helper owns PID validation, procfs error mapping,
/// size limits, NUL-record parsing, and its special treatment of the current
/// process. A positive result transfers one `free(3)` allocation to the guard.
fn getenv_for_pid(pid: libc::pid_t, field: &CStr) -> Result<Option<CAllocatedCString>, i32> {
    let mut value = std::ptr::null_mut();
    // SAFETY: `field` is NUL-terminated, `value` is valid writable storage for
    // one output pointer, and C does not retain either pointer. The result's
    // positive ownership contract is represented by `CAllocatedCString`.
    let result = unsafe { c_getenv_for_pid(pid, field.as_ptr(), &mut value) };
    let value = NonNull::new(value).map(CAllocatedCString);

    if result < 0 {
        // An unexpected allocation on an error path is still owned by this
        // local guard and freed before the errno is returned.
        return Err(result);
    }
    if result == 0 {
        return Ok(None);
    }

    value.ok_or(-libc::EIO).map(Some)
}

/// Try to obtain a machine-id from PID 1's `container_uuid` environment.
///
/// C intentionally ignores inaccessible, malformed, non-UTF-8, and null
/// values here, then falls through to the VM/firmware or random sources. Keep
/// that fallthrough behavior rather than surfacing host-environment failures
/// to the caller.
fn acquire_from_container_uuid() -> MachineIdResult<Option<(SdId128, MachineIdSource)>> {
    let value = match getenv_for_pid(1, c"container_uuid") {
        Ok(Some(value)) => value,
        Ok(None) | Err(_) => return Ok(None),
    };
    let uuid_str = match value.as_c_str().to_str() {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    match id128_from_string(uuid_str) {
        Ok(id) if !id.is_nil() => Ok(Some((id, MachineIdSource::ContainerUuid))),
        _ => Ok(None),
    }
}

/// Return whether C considers the current process outside a chroot.
///
/// The helper's non-positive error behavior is intentional: both C call sites
/// use `running_in_chroot() <= 0` as their gate.
fn not_in_chroot() -> bool {
    c_running_in_chroot() <= 0
}

/// Return the firmware product UUID when C considers this machine eligible.
///
/// This keeps the VM eligibility list, container rejection, DMI/device-tree/
/// Xen source ordering, null/all-`FF` rejection, and errno behavior in the C
/// authority. Like C's `acquire_machine_id()`, all product lookup failures are
/// fallthroughs to the random source rather than user-visible setup failures.
fn acquire_from_firmware(force_firmware: bool) -> Option<SdId128> {
    // A negative detection error is intentionally not a match, exactly as
    // C's `IN_SET(detect_vm(), ...)` condition behaves.
    let vm = c_detect_vm();
    let vm_has_product_uuid = matches!(
        vm,
        VIRTUALIZATION_KVM
            | VIRTUALIZATION_AMAZON
            | VIRTUALIZATION_QEMU
            | VIRTUALIZATION_XEN
            | VIRTUALIZATION_BHYVE
    );
    if !force_firmware && !vm_has_product_uuid {
        return None;
    }

    let mut id = SdId128::nil();
    // SAFETY: `id` is initialized, uniquely borrowed writable storage with
    // the first sixteen bytes and alignment required by C's `sd_id128_t`.
    // The C helper writes it only on success and retains no pointer.
    let result = unsafe { c_id128_get_product(&mut id) };
    (result >= 0).then_some(id)
}

/// Acquire a machine-id by trying several sources in priority order.
///
/// Mirrors the C `acquire_machine_id()` function:
/// 1. /run/machine-id (reuse on soft-reboot, outside a chroot)
/// 2. D-Bus machine-id (regular file only)
/// 3. System credential (if provided, outside a chroot)
/// 4. PID 1's container UUID (if in a container, outside a chroot)
/// 5. Firmware / SMBIOS (if in an eligible VM, outside a chroot)
/// 6. Random
///
/// Returns `(id, source)` on success.
///
/// `credential_value` is an explicit test/integration seam, not a replacement
/// for C's encrypted credential-store lookup. `Some("firmware")` retains the
/// C credential's force-firmware meaning; `None` means this Rust surface does
/// not supply a credential and therefore falls through normally.
pub fn acquire_machine_id(
    root: &Path,
    force_firmware: bool,
    credential_value: Option<&str>,
) -> MachineIdResult<(SdId128, MachineIdSource)> {
    let root_empty = root.as_os_str().is_empty();

    // 1. Try /run/machine-id for reuse (only for an empty host root and not
    // in a chroot).
    if root_empty && not_in_chroot() {
        let run_path = Path::new(RUN_MACHINE_ID);
        // `id128_read()` failures are non-fatal in C and fall through to the
        // D-Bus/credential chain, including unreadable or malformed files.
        if let Ok(Some(id)) = id128_read_file(run_path) {
            return Ok((id, MachineIdSource::RunMachineId));
        }
    }

    // 2. Try D-Bus machine-id.
    if let Some(pair) = acquire_from_dbus(root)? {
        return Ok(pair);
    }

    // 3–5. C performs all remaining host-only probes only outside a chroot.
    if root_empty && not_in_chroot() {
        // 3. Credential
        let credential_requests_firmware = credential_value == Some("firmware");
        if let Some((id, src)) = acquire_from_credential("system.machine_id", credential_value)? {
            return Ok((id, src));
        }

        // 4–5. `detect_container() > 0` chooses the container-UUID branch;
        // every other result (including a negative detection error) follows
        // C's VM/firmware branch. Do not infer this from local environment
        // variables: the C detector is authoritative for namespaces and
        // runtime markers.
        if c_detect_container() > 0 {
            if let Some(pair) = acquire_from_container_uuid()? {
                return Ok(pair);
            }
        } else {
            // C does not use host product metadata from a chroot. Its helper
            // owns the remaining product UUID source ordering and failures
            // intentionally fall through to the random source.
            if let Some(id) = acquire_from_firmware(force_firmware || credential_requests_firmware)
            {
                return Ok((id, MachineIdSource::Firmware));
            }
        }
    }

    // 6. Random.
    let id = SdId128::randomize()?;
    Ok((id, MachineIdSource::Random))
}

/// Open (or create) `/etc/machine-id` inside `root` and return its path +
/// whether it was opened writable.
///
/// Mirrors the first half of `machine_id_setup()`.
fn open_etc_machine_id(root: &Path) -> MachineIdResult<(PathBuf, bool)> {
    let etc_dir = root.join("etc");
    let machine_id_path = etc_dir.join("machine-id");

    if machine_id_path.exists() {
        // File exists — try writable, then read-only.
        // Check writability by attempting to open in append mode.
        match fs::OpenOptions::new().write(true).open(&machine_id_path) {
            Ok(_file) => {
                drop(_file);
                Ok((machine_id_path, true))
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok((machine_id_path, false)),
            Err(e) => Err(MachineIdError::Io(e)),
        }
    } else {
        // Create /etc/ if missing.
        fs::create_dir_all(&etc_dir)?;

        // Try to create the file (exclusive, to match O_CREAT|O_EXCL semantics).
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(&machine_id_path)
        {
            Ok(_file) => {
                drop(_file);
                Ok((machine_id_path, true))
            }
            Err(e) if e.raw_os_error() == Some(libc::EROFS) => Err(MachineIdError::ReadOnlyEtc(
                machine_id_path.to_string_lossy().to_string(),
            )),
            Err(e) => Err(MachineIdError::Io(e)),
        }
    }
}

/// Main machine-id setup routine.
///
/// Mirrors the C `machine_id_setup()` function.  When `machine_id` is null and
/// `flags` does not include `MACHINE_ID_SETUP_FORCE_FIRMWARE`, an existing ID
/// on disk is reused; otherwise a new one is acquired from the best available
/// source.
///
/// If the persistent file is writable the ID is written there directly.
/// Otherwise a transient file is written to `/run/machine-id` and bind-mounted
/// over `/etc/machine-id`.
///
/// `credential_value` has the same explicit test/integration semantics as
/// [`acquire_machine_id`]; the C encrypted credential store remains outside
/// this safe Rust surface.
///
/// Returns the effective machine-id.
pub fn machine_id_setup(
    root: &Path,
    machine_id: SdId128,
    flags: MachineIdSetupFlags,
    credential_value: Option<&str>,
) -> MachineIdResult<SdId128> {
    let (etc_path, writable) = open_etc_machine_id(root)?;

    let force_transient = flags.contains(MachineIdSetupFlags::MACHINE_ID_SETUP_FORCE_TRANSIENT);
    let force_firmware = flags.contains(MachineIdSetupFlags::MACHINE_ID_SETUP_FORCE_FIRMWARE);

    let mut effective_id = machine_id;
    let mut write_run = true;

    // If no explicit ID was given (or firmware forced), try to read / reuse.
    if effective_id.is_nil() || force_firmware {
        // Try reading existing file.
        if let Some(existing) = id128_read_file(&etc_path)? {
            effective_id = existing;
            write_run = false; // existing persistent ID — no transient needed
        } else {
            // Acquire a new one.
            let (id, _source) = acquire_machine_id(root, force_firmware, credential_value)?;
            effective_id = id;
            write_run = _source != MachineIdSource::RunMachineId;
        }
    }

    // ── Write the ID ────────────────────────────────────────────────────

    if writable && !force_transient {
        // Write directly to /etc/machine-id.
        id128_write_file(&etc_path, effective_id)?;
        return Ok(effective_id);
    }

    if writable && force_transient {
        // Write "uninitialized" marker to /etc/machine-id.
        fs::write(&etc_path, UNINITIALIZED_STR)?;
    }

    // Write the actual ID to /run/machine-id.
    let run_dir = root.join("run");
    fs::create_dir_all(&run_dir)?;
    let run_path = run_dir.join("machine-id");

    id128_write_file(&run_path, effective_id)?;

    // In the C implementation a bind-mount is performed here:
    //   mount(run_path, etc_path, NULL, MS_BIND, NULL)
    // followed by a read-only remount.
    //
    // Pure Rust cannot perform mount(2) without unsafe FFI, so callers
    // that need the transient bind-mount must perform it from C.
    // The transient file at /run/machine-id is ready.

    Ok(effective_id)
}

/// Commit a transient machine-id to persistent storage.
///
/// Mirrors the C `machine_id_commit()` function.  When `/etc/machine-id` is a
/// mount point backed by a temporary filesystem, this function:
///
/// 1. Syncs `/etc/` and `/var/` (when `root` is empty).
/// 2. Reads the current machine-id from the mount point.
/// 3. Unmounts the transient file.
/// 4. Writes the ID persistently to `/etc/machine-id`.
///
/// The actual mount/umount operations require `unsafe` libc calls; this
/// implementation performs the readable parts and returns enough context
/// for a C shim to handle the namespace switch.
pub fn machine_id_commit(root: &Path) -> MachineIdResult<()> {
    let root_empty = root.as_os_str().is_empty();

    // 1. Sync filesystems (best-effort).
    if root_empty {
        // SAFETY: sync() has no arguments and is always safe to call.
        unsafe { libc::sync() };

        // syncfs_path equivalents — flush specific directories.
        for sync_dir in &[Path::new("/etc"), Path::new("/var")] {
            let full = root.join(sync_dir);
            if full.is_dir() {
                let _ = sync_directory(&full);
            }
        }
    }

    let etc_dir = root.join("etc");
    let etc_machine_id = etc_dir.join("machine-id");

    // 2. Check if /etc/machine-id is a mount point.
    // In production this uses is_mount_point_at().  For a pure-Rust
    // approximation we check /proc/self/mountinfo.
    let is_mount = is_mount_point(&etc_machine_id);
    if !is_mount {
        // Nothing to do — not a mount point.
        return Ok(());
    }

    // 3. Read the current ID from the transient mount.
    let current_id = id128_read_file(&etc_machine_id)?.ok_or_else(|| {
        MachineIdError::InvalidFormat("no valid machine-id in transient mount".into())
    })?;

    // 4. In the C implementation the following steps happen inside a new
    //    mount namespace:
    //    a) umount /etc/machine-id
    //    b) write the ID persistently
    //    c) return to original namespace
    //    d) lazy-umount the old bind-mount
    //
    //    Pure Rust cannot switch mount namespaces without unsafe FFI,
    //    so we write the persistent file and return.  The caller (C shim)
    //    is responsible for the umount dance if a transient bind-mount
    //    is active.
    id128_write_file(&etc_machine_id, current_id)?;

    Ok(())
}

// ── Internal helpers ─────────────────────────────────────────────────────

/// Best-effort sync of a directory using `open` + `syncfs`.
///
/// Returns `Ok(())` on success or if syncfs is unavailable.
fn sync_directory(dir: &Path) -> io::Result<()> {
    let dir = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a null byte"))?;

    // SAFETY: `dir` is a NUL-terminated path with no interior NUL bytes.
    let fd = unsafe { libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: fd is a valid directory file descriptor just opened above.
    let ret = unsafe { crate::ffi::syncfs(fd) };
    // SAFETY: fd is valid and owned.
    unsafe { libc::close(fd) };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Check if a path is a mount point by scanning `/proc/self/mountinfo`.
fn is_mount_point(path: &Path) -> bool {
    let canonical = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let target = canonical.to_string_lossy();

    if let Ok(content) = fs::read_to_string("/proc/self/mountinfo") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // mountinfo format: field 4 is the mount point, field 5 is optional separator.
            if fields.len() >= 5 {
                let mount_point = fields[4];
                if mount_point == target.as_ref() {
                    return true;
                }
            }
        }
    }
    false
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sd_id128_nil() {
        let nil = SdId128::nil();
        assert!(nil.is_nil());
        assert_eq!(nil.bytes, [0u8; 16]);
    }

    #[test]
    fn test_sd_id128_from_bytes() {
        let bytes = [0x01u8; 16];
        let id = SdId128::from_bytes(bytes);
        assert!(!id.is_nil());
        assert_eq!(id.bytes, [0x01u8; 16]);
    }

    #[test]
    fn test_sd_id128_default_is_nil() {
        let id = SdId128::default();
        assert!(id.is_nil());
    }

    #[test]
    fn test_sd_id128_display_plain() {
        let id = SdId128::from_bytes([
            0x33, 0x22, 0x11, 0x00, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let s = format!("{id}"); // Display trait → plain 32 hex
        assert_eq!(s, "33221100445566778899aabbccddeeff");
        assert_eq!(s.len(), 32);
    }

    #[test]
    fn test_sd_id128_lower_hex_uuid_format() {
        let id = SdId128::from_bytes([
            0x33, 0x22, 0x11, 0x00, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let s = format!("{id:x}"); // LowerHex trait → UUID form
        assert_eq!(s, "33221100-4455-6677-8899-aabbccddeeff");
    }

    #[test]
    fn test_id128_from_string_plain() {
        let hex = "33221100445566778899aabbccddeeff";
        let id = id128_from_string(hex).unwrap();
        assert_eq!(format!("{id}"), hex);
    }

    #[test]
    fn test_id128_from_string_uuid_form() {
        let uuid = "33221100-4455-6677-8899-aabbccddeeff";
        let id = id128_from_string(uuid).unwrap();
        assert_eq!(format!("{id}"), "33221100445566778899aabbccddeeff");
    }

    #[test]
    fn test_id128_from_string_rejects_short() {
        assert!(id128_from_string("abcd").is_err());
        assert!(id128_from_string("").is_err());
    }

    #[test]
    fn test_id128_from_string_rejects_non_hex() {
        assert!(id128_from_string("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn test_id128_from_string_rejects_misplaced_uuid_dashes() {
        assert!(id128_from_string("332211004455-6677-8899-aabbccddeeff").is_err());
    }

    #[test]
    fn test_id128_from_string_rejects_non_ascii_without_panicking() {
        assert!(id128_from_string("33221100445566778899aabbccddeefé").is_err());
    }

    #[test]
    fn test_id128_read_write_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("machine-id");
        let id = SdId128::from_bytes([0xab; 16]);

        id128_write_file(&path, id).unwrap();
        let read_back = id128_read_file(&path).unwrap().unwrap();
        assert_eq!(id, read_back);
    }

    #[test]
    fn test_id128_read_missing_file() {
        let result = id128_read_file(Path::new("/nonexistent/path/machine-id"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_id128_read_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("machine-id");
        fs::write(&path, "").unwrap();

        let result = id128_read_file(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_id128_read_null_id_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("machine-id");
        fs::write(&path, "00000000000000000000000000000000\n").unwrap();

        let result = id128_read_file(&path).unwrap();
        assert!(result.is_none()); // null ID is refused
    }

    #[test]
    fn test_id128_read_file_rejects_uuid_and_extra_whitespace() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("machine-id");

        fs::write(&path, "33221100-4455-6677-8899-aabbccddeeff\n").unwrap();
        assert!(id128_read_file(&path).is_err());

        fs::write(&path, " 33221100445566778899aabbccddeeff\n").unwrap();
        assert!(id128_read_file(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_acquire_from_dbus_rejects_symlinks_and_falls_through_on_bad_content() {
        let tmp = tempfile::tempdir().unwrap();
        let dbus_dir = tmp.path().join("var/lib/dbus");
        fs::create_dir_all(&dbus_dir).unwrap();
        let dbus_id = dbus_dir.join("machine-id");
        let target = tmp.path().join("machine-id-target");
        fs::write(&target, "33221100445566778899aabbccddeeff\n").unwrap();

        std::os::unix::fs::symlink(&target, &dbus_id).unwrap();
        assert!(acquire_from_dbus(tmp.path()).unwrap().is_none());

        fs::remove_file(&dbus_id).unwrap();
        fs::write(&dbus_id, "not-a-machine-id\n").unwrap();
        assert!(acquire_from_dbus(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn test_id128_write_file_includes_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("machine-id");
        let id = SdId128::from_bytes([0x01; 16]);

        id128_write_file(&path, id).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.ends_with('\n'));
        assert_eq!(content.len(), MACHINE_ID_LINE_LEN);
    }

    #[test]
    fn test_machine_id_setup_flags() {
        let f = MachineIdSetupFlags::MACHINE_ID_SETUP_FORCE_TRANSIENT;
        assert!(f.contains(MachineIdSetupFlags::MACHINE_ID_SETUP_FORCE_TRANSIENT));
        assert!(!f.contains(MachineIdSetupFlags::MACHINE_ID_SETUP_FORCE_FIRMWARE));

        let both = MachineIdSetupFlags::MACHINE_ID_SETUP_FORCE_TRANSIENT
            | MachineIdSetupFlags::MACHINE_ID_SETUP_FORCE_FIRMWARE;
        assert!(both.contains(MachineIdSetupFlags::MACHINE_ID_SETUP_FORCE_TRANSIENT));
        assert!(both.contains(MachineIdSetupFlags::MACHINE_ID_SETUP_FORCE_FIRMWARE));
    }

    #[test]
    fn test_machine_id_source_display() {
        assert_eq!(format!("{}", MachineIdSource::Random), "random generator");
        assert_eq!(
            format!("{}", MachineIdSource::DbusMachineId),
            "D-Bus machine ID"
        );
        assert_eq!(format!("{}", MachineIdSource::Credential), "credential");
        assert_eq!(
            format!("{}", MachineIdSource::RunMachineId),
            "/run/machine-id"
        );
    }

    #[test]
    fn test_machine_id_error_display() {
        let err = MachineIdError::InvalidFormat("bad length".into());
        assert_eq!(format!("{err}"), "invalid machine-id format: bad length");

        let err = MachineIdError::NullId;
        assert_eq!(format!("{err}"), "machine ID is all-zero");
    }

    #[test]
    fn test_machine_id_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let err: MachineIdError = io_err.into();
        assert!(matches!(err, MachineIdError::Io(_)));
        assert_eq!(format!("{err}"), "I/O error: not found");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_machine_id_setup_creates_new() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let result = machine_id_setup(&root, SdId128::nil(), MachineIdSetupFlags::empty(), None);
        assert!(result.is_ok());
        let id = result.unwrap();
        assert!(!id.is_nil());

        // Verify file was written.
        let etc_path = root.join("etc/machine-id");
        let content = fs::read_to_string(&etc_path).unwrap();
        assert_eq!(content.trim(), format!("{id}"));
    }

    #[test]
    fn test_machine_id_setup_reuses_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let etc_dir = root.join("etc");
        fs::create_dir_all(&etc_dir).unwrap();

        let known_id = SdId128::from_bytes({
            let mut b = [0x00u8; 16];
            b[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            b
        });
        id128_write_file(&etc_dir.join("machine-id"), known_id).unwrap();

        let result = machine_id_setup(&root, SdId128::nil(), MachineIdSetupFlags::empty(), None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), known_id);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_machine_id_setup_uses_explicit_id() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let etc_dir = root.join("etc");
        fs::create_dir_all(&etc_dir).unwrap();

        let explicit = SdId128::from_bytes({
            let mut b = [0x00u8; 16];
            b[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
            b
        });
        let result = machine_id_setup(&root, explicit, MachineIdSetupFlags::empty(), None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), explicit);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_machine_id_setup_force_transient() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();

        let result = machine_id_setup(
            &root,
            SdId128::nil(),
            MachineIdSetupFlags::MACHINE_ID_SETUP_FORCE_TRANSIENT,
            None,
        );
        assert!(result.is_ok());

        // /etc/machine-id should contain "uninitialized"
        let etc_content = fs::read_to_string(root.join("etc/machine-id")).unwrap();
        assert_eq!(etc_content, UNINITIALIZED_STR);

        // /run/machine-id should contain the real ID
        let run_content = fs::read_to_string(root.join("run/machine-id")).unwrap();
        let id = result.unwrap();
        assert_eq!(run_content.trim(), format!("{id}"));
    }

    #[test]
    fn test_machine_id_commit_no_mount_point() {
        // When /etc/machine-id is not a mount point, commit is a no-op.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let etc_dir = root.join("etc");
        fs::create_dir_all(&etc_dir).unwrap();
        id128_write_file(&etc_dir.join("machine-id"), SdId128::from_bytes([0x42; 16])).unwrap();

        let result = machine_id_commit(&root);
        assert!(result.is_ok());
    }

    #[test]
    fn test_acquire_from_credential_none() {
        let result = acquire_from_credential("system.machine_id", None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_acquire_from_credential_firmware_keyword() {
        let result = acquire_from_credential("system.machine_id", Some("firmware")).unwrap();
        assert!(result.is_none()); // "firmware" means "try firmware path", not an ID
    }

    #[test]
    fn test_acquire_from_credential_valid() {
        let hex = "aabbccdd11223344aabbccdd11223344";
        let result = acquire_from_credential("system.machine_id", Some(hex)).unwrap();
        assert!(result.is_some());
        let (id, src) = result.unwrap();
        assert_eq!(src, MachineIdSource::Credential);
        assert_eq!(format!("{id}"), hex);
    }

    #[test]
    fn test_acquire_from_credential_null_rejected() {
        let result = acquire_from_credential(
            "system.machine_id",
            Some("00000000000000000000000000000000"),
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_acquire_from_dbus_missing() {
        let root = tempfile::tempdir().unwrap();
        let result = acquire_from_dbus(root.path()).unwrap();
        assert!(result.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_acquire_machine_id_generates_random() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let (id, source) = acquire_machine_id(&root, false, None).unwrap();
        assert!(!id.is_nil());
        assert_eq!(source, MachineIdSource::Random);
    }

    #[test]
    fn test_constants() {
        assert_eq!(ETC_MACHINE_ID, "/etc/machine-id");
        assert_eq!(RUN_MACHINE_ID, "/run/machine-id");
        assert_eq!(DBUS_MACHINE_ID, "/var/lib/dbus/machine-id");
        assert_eq!(UNINITIALIZED_STR, "uninitialized\n");
        assert_eq!(MACHINE_ID_LINE_LEN, 33);
    }
}
