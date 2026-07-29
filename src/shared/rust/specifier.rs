// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/specifier.c, src/shared/specifier.h

use crate::ffi::*;
use std::any::Any;
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const POSSIBLE_SPECIFIERS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789%";
const EBADSLT: i32 = 57;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeScope {
    Global,
    System,
    User,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpecifierData {
    None,
    String(String),
    Path(PathBuf),
    Id128([u8; 16]),
    UInt64(u64),
    RuntimeScope(RuntimeScope),
}

pub type SpecifierLookup =
    fn(char, &SpecifierData, Option<&Path>, Option<&dyn Any>) -> Result<Option<String>, i32>;

#[derive(Clone, Copy, Debug)]
pub struct Specifier {
    pub specifier: char,
    pub lookup: SpecifierLookup,
    pub data: &'static SpecifierData,
}

const DATA_NONE: SpecifierData = SpecifierData::None;

pub const COMMON_SYSTEM_SPECIFIERS: &[Specifier] = &[
    Specifier {
        specifier: 'a',
        lookup: specifier_architecture,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'A',
        lookup: specifier_os_image_version,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'b',
        lookup: specifier_boot_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'B',
        lookup: specifier_os_build_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'H',
        lookup: specifier_hostname,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'l',
        lookup: specifier_short_hostname,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'q',
        lookup: specifier_pretty_hostname,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'm',
        lookup: specifier_machine_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'M',
        lookup: specifier_os_image_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'o',
        lookup: specifier_os_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'v',
        lookup: specifier_kernel_release,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'w',
        lookup: specifier_os_version_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'W',
        lookup: specifier_os_variant_id,
        data: &DATA_NONE,
    },
];

pub const COMMON_TMP_SPECIFIERS: &[Specifier] = &[
    Specifier {
        specifier: 'T',
        lookup: specifier_tmp_dir,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'V',
        lookup: specifier_var_tmp_dir,
        data: &DATA_NONE,
    },
];

pub const SYSTEM_AND_TMP_SPECIFIER_TABLE: &[Specifier] = &[
    Specifier {
        specifier: 'a',
        lookup: specifier_architecture,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'A',
        lookup: specifier_os_image_version,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'b',
        lookup: specifier_boot_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'B',
        lookup: specifier_os_build_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'H',
        lookup: specifier_hostname,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'l',
        lookup: specifier_short_hostname,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'q',
        lookup: specifier_pretty_hostname,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'm',
        lookup: specifier_machine_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'M',
        lookup: specifier_os_image_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'o',
        lookup: specifier_os_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'v',
        lookup: specifier_kernel_release,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'w',
        lookup: specifier_os_version_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'W',
        lookup: specifier_os_variant_id,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'T',
        lookup: specifier_tmp_dir,
        data: &DATA_NONE,
    },
    Specifier {
        specifier: 'V',
        lookup: specifier_var_tmp_dir,
        data: &DATA_NONE,
    },
];

fn errno_from_io(err: io::Error) -> i32 {
    -err.raw_os_error().unwrap_or(libc::EIO)
}

fn root_join(root: Option<&Path>, path: &Path) -> PathBuf {
    match root {
        Some(root_dir) if path.is_absolute() => {
            root_dir.join(path.strip_prefix("/").unwrap_or(path))
        }
        Some(root_dir) => root_dir.join(path),
        None => path.to_path_buf(),
    }
}

fn is_empty_string(value: Option<&str>) -> bool {
    value.is_none_or(str::is_empty)
}

fn parse_id128(input: &str) -> Result<[u8; 16], i32> {
    let hex: String = input.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(-libc::EINVAL);
    }

    let mut out = [0u8; 16];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| -libc::EINVAL)?;
        out[idx] = u8::from_str_radix(s, 16).map_err(|_| -libc::EINVAL)?;
    }
    Ok(out)
}

fn id128_to_string(id: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in id {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn id128_to_uuid_string(id: &[u8; 16]) -> String {
    let hex = id128_to_string(id);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn read_first_existing(paths: &[PathBuf]) -> Result<String, i32> {
    let mut saw_missing = false;

    for path in paths {
        match fs::read_to_string(path) {
            Ok(contents) => return Ok(contents),
            Err(err) if err.kind() == io::ErrorKind::NotFound => saw_missing = true,
            Err(err) => return Err(errno_from_io(err)),
        }
    }

    if saw_missing {
        Err(-libc::ENOENT)
    } else {
        Err(-libc::EIO)
    }
}

fn parse_env_assignment(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(stripped) = trimmed
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        let mut out = String::new();
        let mut escaped = false;
        for ch in stripped.chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                out.push(ch);
            }
        }
        if escaped {
            out.push('\\');
        }
        out
    } else {
        trimmed.to_string()
    }
}

fn parse_os_release_field(root: Option<&Path>, key: &str) -> Result<Option<String>, i32> {
    let contents = read_first_existing(&[
        root_join(root, Path::new("/etc/os-release")),
        root_join(root, Path::new("/usr/lib/os-release")),
    ])
    .map_err(|e| if e == -libc::ENOENT { -EUNATCH } else { e })?;

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };
        if lhs.trim() == key {
            return Ok(Some(parse_env_assignment(rhs)));
        }
    }

    Ok(None)
}

fn get_hostname_raw() -> Result<String, i32> {
    let mut buffer = vec![0u8; 256];
    // SAFETY: `buffer` is a valid writable byte array for the duration of the call.
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if rc < 0 {
        return Err(-io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }

    let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    Ok(String::from_utf8_lossy(&buffer[..end]).into_owned())
}

fn get_short_hostname_raw() -> Result<String, i32> {
    let hostname = get_hostname_raw()?;
    Ok(hostname.split('.').next().unwrap_or("").to_string())
}

fn lookup_passwd(uid: libc::uid_t) -> Result<Option<(String, String, String)>, i32> {
    // SAFETY: `sysconf` has no additional safety preconditions.
    let buf_len = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let capacity = if buf_len <= 0 {
        16_384
    } else {
        buf_len as usize
    };
    let mut buf = vec![0u8; capacity];
    let mut pwd = MaybeUninit::<libc::passwd>::zeroed();
    let mut result = std::ptr::null_mut();

    // SAFETY: all pointers are valid and remain alive for the duration of the call.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(-rc);
    }
    if result.is_null() {
        return Ok(None);
    }

    // SAFETY: `result` points at the initialized `passwd` written above.
    let pwd = unsafe { pwd.assume_init() };
    // SAFETY: libc guarantees these pointers remain valid while `buf` lives.
    let name = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: see above.
    let dir = unsafe { CStr::from_ptr(pwd.pw_dir) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: see above.
    let shell = unsafe { CStr::from_ptr(pwd.pw_shell) }
        .to_string_lossy()
        .into_owned();
    Ok(Some((name, dir, shell)))
}

fn lookup_group(gid: libc::gid_t) -> Result<Option<String>, i32> {
    // SAFETY: `sysconf` has no additional safety preconditions.
    let buf_len = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
    let capacity = if buf_len <= 0 {
        16_384
    } else {
        buf_len as usize
    };
    let mut buf = vec![0u8; capacity];
    let mut grp = MaybeUninit::<libc::group>::zeroed();
    let mut result = std::ptr::null_mut();

    // SAFETY: all pointers are valid and remain alive for the duration of the call.
    let rc = unsafe {
        libc::getgrgid_r(
            gid,
            grp.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(-rc);
    }
    if result.is_null() {
        return Ok(None);
    }

    // SAFETY: `result` points at the initialized `group` written above.
    let grp = unsafe { grp.assume_init() };
    // SAFETY: libc guarantees this pointer remains valid while `buf` lives.
    Ok(Some(
        unsafe { CStr::from_ptr(grp.gr_name) }
            .to_string_lossy()
            .into_owned(),
    ))
}

fn current_uid() -> libc::uid_t {
    // SAFETY: getuid has no arguments or preconditions and only reads the
    // calling process's kernel-maintained real UID.
    unsafe { libc::getuid() }
}

fn runtime_uid(scope: RuntimeScope) -> Result<libc::uid_t, i32> {
    match scope {
        RuntimeScope::Global => Err(-libc::EINVAL),
        RuntimeScope::System => Ok(0),
        RuntimeScope::User => Ok(current_uid()),
    }
}

fn runtime_gid(scope: RuntimeScope) -> Result<libc::gid_t, i32> {
    match scope {
        RuntimeScope::Global => Err(-libc::EINVAL),
        RuntimeScope::System => Ok(0),
        RuntimeScope::User => {
            // SAFETY: `getgid` has no preconditions.
            Ok(unsafe { libc::getgid() })
        }
    }
}

fn scope_from_data(data: &SpecifierData) -> Result<RuntimeScope, i32> {
    match data {
        SpecifierData::RuntimeScope(scope) => Ok(*scope),
        _ => Err(-libc::EINVAL),
    }
}

fn path_from_data(data: &SpecifierData) -> Result<&Path, i32> {
    match data {
        SpecifierData::Path(path) => Ok(path.as_path()),
        SpecifierData::String(path) => Ok(Path::new(path)),
        _ => Err(-libc::ENOENT),
    }
}

fn id128_from_data(data: &SpecifierData) -> Result<[u8; 16], i32> {
    match data {
        SpecifierData::Id128(id) => Ok(*id),
        _ => Err(-libc::EINVAL),
    }
}

pub fn specifier_printf(
    text: &str,
    max_length: usize,
    table: &[Specifier],
    root: Option<&Path>,
    userdata: Option<&dyn Any>,
) -> Result<String, i32> {
    let mut result = String::with_capacity(text.len());
    let mut percent = false;

    for ch in text.chars() {
        if percent {
            percent = false;

            if ch == '%' {
                result.push('%');
            } else if let Some(entry) = table.iter().find(|entry| entry.specifier == ch) {
                let replacement = (entry.lookup)(entry.specifier, entry.data, root, userdata)?;
                if is_empty_string(replacement.as_deref()) {
                    continue;
                }
                result.push_str(replacement.as_deref().unwrap_or_default());
            } else if POSSIBLE_SPECIFIERS.contains(ch) {
                return Err(-EBADSLT);
            } else {
                result.push('%');
                result.push(ch);
            }
        } else if ch == '%' {
            percent = true;
            continue;
        } else {
            result.push(ch);
        }

        if result.len() > max_length {
            return Err(-libc::ENAMETOOLONG);
        }
    }

    if percent {
        result.push('%');
        if result.len() > max_length {
            return Err(-libc::ENAMETOOLONG);
        }
    }

    Ok(result)
}

pub fn specifier_string(
    _specifier: char,
    data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    match data {
        SpecifierData::None => Ok(None),
        SpecifierData::String(value) => Ok(Some(value.clone())),
        SpecifierData::Path(path) => Ok(Some(path.to_string_lossy().into_owned())),
        _ => Err(-libc::EINVAL),
    }
}

pub fn specifier_real_path(
    _specifier: char,
    data: &SpecifierData,
    root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    let path = path_from_data(data)?;
    let real = fs::canonicalize(root_join(root, path)).map_err(errno_from_io)?;
    Ok(Some(real.to_string_lossy().into_owned()))
}

pub fn specifier_real_directory(
    specifier: char,
    data: &SpecifierData,
    root: Option<&Path>,
    userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    let path = specifier_real_path(specifier, data, root, userdata)?.ok_or(-libc::ENOENT)?;
    let directory = Path::new(&path)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    Ok(Some(directory.to_string_lossy().into_owned()))
}

pub fn specifier_id128(
    _specifier: char,
    data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    Ok(Some(id128_to_string(&id128_from_data(data)?)))
}

pub fn specifier_uuid(
    _specifier: char,
    data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    Ok(Some(id128_to_uuid_string(&id128_from_data(data)?)))
}

pub fn specifier_uint64(
    _specifier: char,
    data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    match data {
        SpecifierData::UInt64(value) => Ok(Some(value.to_string())),
        _ => Err(-libc::EINVAL),
    }
}

pub fn specifier_machine_id(
    _specifier: char,
    _data: &SpecifierData,
    root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    let contents = read_first_existing(&[
        root_join(root, Path::new("/etc/machine-id")),
        root_join(root, Path::new("/var/lib/dbus/machine-id")),
    ])
    .map_err(|e| if e == -libc::ENOENT { -EUNATCH } else { e })?;
    let id = parse_id128(contents.trim())?;
    Ok(Some(id128_to_string(&id)))
}

pub fn specifier_boot_id(
    _specifier: char,
    _data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    let contents = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(errno_from_io)?;
    let id = parse_id128(contents.trim())?;
    Ok(Some(id128_to_string(&id)))
}

pub fn specifier_hostname(
    _specifier: char,
    _data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    Ok(Some(get_hostname_raw()?))
}

pub fn specifier_short_hostname(
    _specifier: char,
    _data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    Ok(Some(get_short_hostname_raw()?))
}

pub fn specifier_pretty_hostname(
    _specifier: char,
    _data: &SpecifierData,
    root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    if let Ok(Some(pretty)) = parse_os_release_field(root, "PRETTY_HOSTNAME")
        .or_else(|_| parse_machine_info_field(root, "PRETTY_HOSTNAME"))
    {
        return Ok(Some(pretty));
    }
    Ok(Some(get_short_hostname_raw()?))
}

fn parse_machine_info_field(root: Option<&Path>, key: &str) -> Result<Option<String>, i32> {
    let path = root_join(root, Path::new("/etc/machine-info"));
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(errno_from_io(err)),
    };

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };
        if lhs.trim() == key {
            return Ok(Some(parse_env_assignment(rhs)));
        }
    }

    Ok(None)
}

pub fn specifier_kernel_release(
    _specifier: char,
    _data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    let mut uts = MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: `uts` points to valid writable memory.
    let rc = unsafe { libc::uname(uts.as_mut_ptr()) };
    if rc < 0 {
        return Err(-io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    // SAFETY: `uname` succeeded and initialized `uts`.
    let uts = unsafe { uts.assume_init() };
    // SAFETY: `uname` returns NUL-terminated strings in `utsname` fields.
    let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Ok(Some(release))
}

pub fn specifier_architecture(
    _specifier: char,
    _data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    Ok(Some(std::env::consts::ARCH.to_string()))
}

fn os_release_specifier(root: Option<&Path>, key: &str) -> Result<Option<String>, i32> {
    parse_os_release_field(root, key)
}

pub fn specifier_os_id(
    _specifier: char,
    _data: &SpecifierData,
    root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    os_release_specifier(root, "ID")
}

pub fn specifier_os_version_id(
    _specifier: char,
    _data: &SpecifierData,
    root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    os_release_specifier(root, "VERSION_ID")
}

pub fn specifier_os_build_id(
    _specifier: char,
    _data: &SpecifierData,
    root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    os_release_specifier(root, "BUILD_ID")
}

pub fn specifier_os_variant_id(
    _specifier: char,
    _data: &SpecifierData,
    root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    os_release_specifier(root, "VARIANT_ID")
}

pub fn specifier_os_image_id(
    _specifier: char,
    _data: &SpecifierData,
    root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    os_release_specifier(root, "IMAGE_ID")
}

pub fn specifier_os_image_version(
    _specifier: char,
    _data: &SpecifierData,
    root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    os_release_specifier(root, "IMAGE_VERSION")
}

pub fn specifier_group_name(
    _specifier: char,
    data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    let gid = runtime_gid(scope_from_data(data)?)?;
    Ok(Some(lookup_group(gid)?.unwrap_or_else(|| gid.to_string())))
}

pub fn specifier_group_id(
    _specifier: char,
    data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    Ok(Some(runtime_gid(scope_from_data(data)?)?.to_string()))
}

pub fn specifier_user_name(
    _specifier: char,
    data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    let uid = runtime_uid(scope_from_data(data)?)?;
    let name = lookup_passwd(uid)?
        .map(|(name, _, _)| name)
        .unwrap_or_else(|| uid.to_string());
    Ok(Some(name))
}

pub fn specifier_user_id(
    _specifier: char,
    data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    Ok(Some(runtime_uid(scope_from_data(data)?)?.to_string()))
}

pub fn specifier_user_home(
    _specifier: char,
    data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    let uid = runtime_uid(scope_from_data(data)?)?;
    if let Some((_, home, _)) = lookup_passwd(uid)? {
        return Ok(Some(home));
    }
    if uid == current_uid() {
        if let Some(home) = std::env::var_os("HOME") {
            return Ok(Some(home.to_string_lossy().into_owned()));
        }
    }
    Err(-libc::ENOENT)
}

pub fn specifier_user_shell(
    _specifier: char,
    data: &SpecifierData,
    _root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    let uid = runtime_uid(scope_from_data(data)?)?;
    if let Some((_, _, shell)) = lookup_passwd(uid)? {
        return Ok(Some(shell));
    }
    if uid == current_uid() {
        if let Some(shell) = std::env::var_os("SHELL") {
            return Ok(Some(shell.to_string_lossy().into_owned()));
        }
    }
    Err(-libc::ENOENT)
}

fn env_tmp_dir(default: &str) -> String {
    ["TMPDIR", "TEMP", "TMP"]
        .into_iter()
        .find_map(std::env::var_os)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| default.to_string())
}

pub fn specifier_tmp_dir(
    _specifier: char,
    _data: &SpecifierData,
    root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    Ok(Some(if root.is_some() {
        "/tmp".to_string()
    } else {
        env_tmp_dir("/tmp")
    }))
}

pub fn specifier_var_tmp_dir(
    _specifier: char,
    _data: &SpecifierData,
    root: Option<&Path>,
    _userdata: Option<&dyn Any>,
) -> Result<Option<String>, i32> {
    Ok(Some(if root.is_some() {
        "/var/tmp".to_string()
    } else {
        env_tmp_dir("/var/tmp")
    }))
}

pub fn specifier_escape(string: &str) -> String {
    string.replace('%', "%%")
}

pub fn specifier_escape_strv(values: &[String]) -> Vec<String> {
    values.iter().map(|value| specifier_escape(value)).collect()
}

pub fn common_creds_specifiers(scope: RuntimeScope) -> [Specifier; 4] {
    let data = Box::leak(Box::new(SpecifierData::RuntimeScope(scope)));
    [
        Specifier {
            specifier: 'g',
            lookup: specifier_group_name,
            data,
        },
        Specifier {
            specifier: 'G',
            lookup: specifier_group_id,
            data,
        },
        Specifier {
            specifier: 'u',
            lookup: specifier_user_name,
            data,
        },
        Specifier {
            specifier: 'U',
            lookup: specifier_user_id,
            data,
        },
    ]
}

pub fn c_escape_length(text: &CStr) -> Result<i32, i32> {
    let escaped = specifier_escape(text.to_str().map_err(|_| -libc::EINVAL)?);
    i32::try_from(escaped.len()).map_err(|_| -libc::EOVERFLOW)
}

pub fn to_cstring(value: &str) -> Result<CString, i32> {
    CString::new(value).map_err(|_| -libc::EINVAL)
}

pub fn c_path_string(path: &Path) -> Result<CString, i32> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| -libc::EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("specifier-rs-test-{}-{}", std::process::id(), id));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn specifier_printf_replaces_known_specifiers() {
        let machine = Box::leak(Box::new(SpecifierData::String("machine".into())));
        let host = Box::leak(Box::new(SpecifierData::String("host".into())));
        let table = [
            Specifier {
                specifier: 'm',
                lookup: specifier_string,
                data: machine,
            },
            Specifier {
                specifier: 'H',
                lookup: specifier_string,
                data: host,
            },
        ];
        assert_eq!(
            specifier_printf("%m@%H", 32, &table, None, None).unwrap(),
            "machine@host"
        );
    }

    #[test]
    fn specifier_printf_escapes_percent() {
        assert_eq!(
            specifier_printf("100%%", 4, &[], None, None).unwrap(),
            "100%"
        );
    }

    #[test]
    fn specifier_printf_rejects_unknown_ascii_specifier() {
        assert_eq!(specifier_printf("%x", 16, &[], None, None), Err(-EBADSLT));
    }

    #[test]
    fn specifier_printf_keeps_unknown_non_specifier_literal() {
        assert_eq!(specifier_printf("%/", 16, &[], None, None).unwrap(), "%/");
    }

    #[test]
    fn specifier_printf_keeps_trailing_percent() {
        assert_eq!(
            specifier_printf("abc%", 4, &[], None, None).unwrap(),
            "abc%"
        );
    }

    #[test]
    fn specifier_printf_enforces_max_length() {
        assert_eq!(
            specifier_printf("abcdef", 3, &[], None, None),
            Err(-libc::ENAMETOOLONG)
        );
    }

    #[test]
    fn specifier_printf_skips_empty_replacements() {
        let empty = Box::leak(Box::new(SpecifierData::String(String::new())));
        let table = [Specifier {
            specifier: 'x',
            lookup: specifier_string,
            data: empty,
        }];
        assert_eq!(
            specifier_printf("a%xb", 8, &table, None, None).unwrap(),
            "ab"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn specifier_real_path_and_directory_follow_root() {
        let root = temp_root();
        let file = Path::new("/var/lib/demo/file.txt");
        write_file(&root.join("var/lib/demo/file.txt"), "x");
        let data = SpecifierData::Path(file.into());

        let real = specifier_real_path('p', &data, Some(&root), None)
            .unwrap()
            .unwrap();
        assert!(real.ends_with("/var/lib/demo/file.txt"));

        let dir = specifier_real_directory('d', &data, Some(&root), None)
            .unwrap()
            .unwrap();
        assert!(dir.ends_with("/var/lib/demo"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn specifier_id128_and_uuid_format_correctly() {
        let data = SpecifierData::Id128([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        assert_eq!(
            specifier_id128('m', &data, None, None).unwrap().unwrap(),
            "00112233445566778899aabbccddeeff"
        );
        assert_eq!(
            specifier_uuid('m', &data, None, None).unwrap().unwrap(),
            "00112233-4455-6677-8899-aabbccddeeff"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn specifier_machine_id_reads_from_root() {
        let root = temp_root();
        write_file(
            &root.join("etc/machine-id"),
            "00112233445566778899aabbccddeeff\n",
        );
        assert_eq!(
            specifier_machine_id('m', &SpecifierData::None, Some(&root), None)
                .unwrap()
                .unwrap(),
            "00112233445566778899aabbccddeeff"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn specifier_machine_id_missing_maps_to_eunatch() {
        let root = temp_root();
        assert_eq!(
            specifier_machine_id('m', &SpecifierData::None, Some(&root), None),
            Err(-EUNATCH)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn os_release_fields_are_parsed() {
        let root = temp_root();
        write_file(
            &root.join("etc/os-release"),
            "ID=fedora\nVERSION_ID=40\nBUILD_ID=2024\nVARIANT_ID=cloud\nIMAGE_ID=my-image\nIMAGE_VERSION=1.2\n",
        );
        assert_eq!(
            specifier_os_id('o', &SpecifierData::None, Some(&root), None).unwrap(),
            Some("fedora".into())
        );
        assert_eq!(
            specifier_os_version_id('w', &SpecifierData::None, Some(&root), None).unwrap(),
            Some("40".into())
        );
        assert_eq!(
            specifier_os_build_id('B', &SpecifierData::None, Some(&root), None).unwrap(),
            Some("2024".into())
        );
        assert_eq!(
            specifier_os_variant_id('W', &SpecifierData::None, Some(&root), None).unwrap(),
            Some("cloud".into())
        );
        assert_eq!(
            specifier_os_image_id('M', &SpecifierData::None, Some(&root), None).unwrap(),
            Some("my-image".into())
        );
        assert_eq!(
            specifier_os_image_version('A', &SpecifierData::None, Some(&root), None).unwrap(),
            Some("1.2".into())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_os_release_maps_to_eunatch() {
        let root = temp_root();
        assert_eq!(
            specifier_os_id('o', &SpecifierData::None, Some(&root), None),
            Err(-EUNATCH)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pretty_hostname_prefers_machine_info() {
        let root = temp_root();
        write_file(
            &root.join("etc/machine-info"),
            "PRETTY_HOSTNAME=\"Pretty Box\"\n",
        );
        assert_eq!(
            specifier_pretty_hostname('q', &SpecifierData::None, Some(&root), None)
                .unwrap()
                .unwrap(),
            "Pretty Box"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn temp_specifiers_honor_root_override() {
        assert_eq!(
            specifier_tmp_dir('T', &SpecifierData::None, Some(Path::new("/x")), None).unwrap(),
            Some("/tmp".into())
        );
        assert_eq!(
            specifier_var_tmp_dir('V', &SpecifierData::None, Some(Path::new("/x")), None).unwrap(),
            Some("/var/tmp".into())
        );
    }

    #[test]
    fn scope_based_ids_match_current_process() {
        let user = SpecifierData::RuntimeScope(RuntimeScope::User);
        let system = SpecifierData::RuntimeScope(RuntimeScope::System);
        assert_eq!(
            specifier_user_id('U', &user, None, None).unwrap(),
            Some(current_uid().to_string())
        );
        assert_eq!(
            specifier_group_id('G', &system, None, None).unwrap(),
            Some("0".into())
        );
    }

    #[test]
    fn global_scope_is_rejected_for_credentials() {
        let global = SpecifierData::RuntimeScope(RuntimeScope::Global);
        assert_eq!(
            specifier_user_id('U', &global, None, None),
            Err(-libc::EINVAL)
        );
        assert_eq!(
            specifier_group_name('g', &global, None, None),
            Err(-libc::EINVAL)
        );
    }

    #[test]
    fn specifier_escape_helpers_work() {
        assert_eq!(specifier_escape("a%b%c"), "a%%b%%c");
        assert_eq!(
            specifier_escape_strv(&["a%b".into(), "%c".into()]),
            vec!["a%%b".to_string(), "%%c".to_string()]
        );
    }

    #[test]
    fn c_escape_length_counts_escaped_bytes() {
        let text = CString::new("a%b").unwrap();
        assert_eq!(c_escape_length(&text).unwrap(), 4);
    }
}
