// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/osc-context.c

use openssl::error::ErrorStack;
use openssl::rand::rand_bytes;
use openssl::sha::sha256;
use std::ffi::CStr;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::process;
use std::sync::OnceLock;

const ANSI_OSC: &str = "\x1b]";
const ANSI_ST: &str = "\x1b\\";
const APP_SPECIFIC_ID: Id128 = Id128([
    0x5d, 0x63, 0xa5, 0x8d, 0x96, 0xfd, 0x45, 0xd0, 0xa0, 0xf0, 0x63, 0x50, 0xfc, 0xd8, 0x9a, 0xcd,
]);
static DEFAULT_CONTEXT_ID: OnceLock<Id128> = OnceLock::new();

#[derive(Debug)]
pub enum OscContextError {
    Io(io::Error),
    Crypto(ErrorStack),
    InvalidId(String),
}

impl fmt::Display for OscContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Crypto(err) => write!(f, "{err}"),
            Self::InvalidId(value) => write!(f, "invalid 128-bit id: {value}"),
        }
    }
}

impl std::error::Error for OscContextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Crypto(err) => Some(err),
            Self::InvalidId(_) => None,
        }
    }
}

impl From<io::Error> for OscContextError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ErrorStack> for OscContextError {
    fn from(value: ErrorStack) -> Self {
        Self::Crypto(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id128([u8; 16]);

impl Id128 {
    pub const NULL: Self = Self([0; 16]);
    pub const ALL_F: Self = Self([0xff; 16]);

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }

    pub const fn is_null(self) -> bool {
        let mut i = 0;
        while i < 16 {
            if self.0[i] != Self::NULL.0[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    pub const fn is_allf(self) -> bool {
        let mut i = 0;
        while i < 16 {
            if self.0[i] != Self::ALL_F.0[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    pub fn parse(value: &str) -> Result<Self, OscContextError> {
        let normalized: String = value.chars().filter(|ch| *ch != '-').collect();
        if normalized.len() != 32 || !normalized.bytes().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(OscContextError::InvalidId(value.to_string()));
        }

        let mut bytes = [0; 16];
        for (idx, chunk) in normalized.as_bytes().chunks_exact(2).enumerate() {
            let part = std::str::from_utf8(chunk)
                .map_err(|_| OscContextError::InvalidId(value.to_string()))?;
            bytes[idx] = u8::from_str_radix(part, 16)
                .map_err(|_| OscContextError::InvalidId(value.to_string()))?;
        }

        Ok(Self(bytes))
    }

    pub fn random() -> Result<Self, OscContextError> {
        let mut bytes = [0; 16];
        rand_bytes(&mut bytes)?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Ok(Self(bytes))
    }

    pub fn to_hex_string(self) -> String {
        let mut out = String::with_capacity(32);
        for byte in self.0 {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

impl fmt::Display for Id128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OscContextType {
    Boot,
    Container {
        name: Option<String>,
    },
    Vm {
        name: String,
    },
    ChPriv {
        target_user: String,
    },
    Session {
        user: Option<String>,
        session_id: Option<String>,
    },
    Service {
        unit: Option<String>,
        invocation_id: Id128,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OscContext {
    context_type: OscContextType,
    context_id: Option<Id128>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct IdentityInfo {
    user: Option<String>,
    hostname: Option<String>,
    machine_id: Option<Id128>,
    boot_id: Option<Id128>,
    pid: u32,
    comm: Option<String>,
}

impl OscContext {
    pub fn boot() -> Self {
        Self {
            context_type: OscContextType::Boot,
            context_id: None,
        }
    }

    pub fn container(name: Option<&str>) -> Result<Self, OscContextError> {
        Ok(Self {
            context_type: OscContextType::Container {
                name: name.map(str::to_string),
            },
            context_id: Some(Id128::random()?),
        })
    }

    pub fn vm(name: &str) -> Result<Self, OscContextError> {
        Ok(Self {
            context_type: OscContextType::Vm {
                name: name.to_string(),
            },
            context_id: Some(Id128::random()?),
        })
    }

    pub fn chpriv(target_user: &str) -> Result<Self, OscContextError> {
        Ok(Self {
            context_type: OscContextType::ChPriv {
                target_user: target_user.to_string(),
            },
            context_id: Some(Id128::random()?),
        })
    }

    pub fn session(user: Option<&str>, session_id: Option<&str>) -> Result<Self, OscContextError> {
        Ok(Self {
            context_type: OscContextType::Session {
                user: user.map(str::to_string),
                session_id: session_id.map(str::to_string),
            },
            context_id: Some(Id128::random()?),
        })
    }

    pub fn service(unit: Option<&str>, invocation_id: Id128) -> Self {
        Self {
            context_type: OscContextType::Service {
                unit: unit.map(str::to_string),
                invocation_id,
            },
            context_id: Some(osc_context_id_from_invocation_id(invocation_id)),
        }
    }

    pub fn context_id(&self) -> Option<Id128> {
        self.context_id
    }

    pub fn context_type(&self) -> &OscContextType {
        &self.context_type
    }

    pub fn open_sequence(&self) -> Result<String, OscContextError> {
        let identity = read_identity();
        self.open_sequence_with(&identity)
    }

    pub fn close_sequence(&self) -> Result<Option<String>, OscContextError> {
        match self.context_id {
            Some(id) => osc_context_close(id),
            None => Ok(None),
        }
    }

    fn open_sequence_with(&self, identity: &IdentityInfo) -> Result<String, OscContextError> {
        let open_id = self.context_id.unwrap_or(default_context_id()?);
        let mut seq = format!("{ANSI_OSC}3008;start={open_id}");
        osc_append_identity_with(&mut seq, identity);

        match &self.context_type {
            OscContextType::Boot => seq.push_str(";type=boot"),
            OscContextType::Container { name } => {
                if let Some(name) = name.as_deref() {
                    strextend_escaped(&mut seq, ";container=", name);
                }
                seq.push_str(";type=container");
            }
            OscContextType::Vm { name } => {
                strextend_escaped(&mut seq, ";vm=", name);
                seq.push_str(";type=vm");
            }
            OscContextType::ChPriv { target_user } => match identity.user.as_deref() {
                Some(current_user) if current_user == target_user => {
                    seq.push_str(";type=subcontext")
                }
                _ if target_user == "root" || target_user == "0" => seq.push_str(";type=elevate"),
                _ => {
                    strextend_escaped(&mut seq, ";targetuser=", target_user);
                    seq.push_str(";type=chpriv");
                }
            },
            OscContextType::Session { user, session_id } => {
                if let Some(user) = user.as_deref() {
                    strextend_escaped(&mut seq, ";targetuser=", user);
                }
                if let Some(session_id) = session_id.as_deref() {
                    strextend_escaped(&mut seq, ";sessionid=", session_id);
                }
                seq.push_str(";type=session");
            }
            OscContextType::Service {
                unit,
                invocation_id,
            } => {
                if let Some(unit) = unit.as_deref() {
                    strextend_escaped(&mut seq, ";servicename=", unit);
                }
                seq.push_str(";invocationid=");
                seq.push_str(&invocation_id.to_string());
                seq.push_str(";type=service");
            }
        }

        seq.push_str(ANSI_ST);
        Ok(seq)
    }
}

pub fn strextend_escaped(out: &mut String, prefix: &str, value: &str) {
    out.push_str(prefix);
    for ch in value.chars() {
        match ch {
            ';' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
}

pub fn osc_append_identity(out: &mut String) -> Result<(), OscContextError> {
    let identity = read_identity();
    osc_append_identity_with(out, &identity);
    Ok(())
}

pub fn osc_context_open_boot() -> Result<String, OscContextError> {
    OscContext::boot().open_sequence()
}

pub fn osc_context_open_container(name: Option<&str>) -> Result<(String, Id128), OscContextError> {
    let context = OscContext::container(name)?;
    let id = context.context_id().unwrap_or(Id128::NULL);
    Ok((context.open_sequence()?, id))
}

pub fn osc_context_open_vm(name: &str) -> Result<(String, Id128), OscContextError> {
    let context = OscContext::vm(name)?;
    let id = context.context_id().unwrap_or(Id128::NULL);
    Ok((context.open_sequence()?, id))
}

pub fn osc_context_open_chpriv(target_user: &str) -> Result<(String, Id128), OscContextError> {
    let context = OscContext::chpriv(target_user)?;
    let id = context.context_id().unwrap_or(Id128::NULL);
    Ok((context.open_sequence()?, id))
}

pub fn osc_context_open_session(
    user: Option<&str>,
    session_id: Option<&str>,
) -> Result<(String, Id128), OscContextError> {
    let context = OscContext::session(user, session_id)?;
    let id = context.context_id().unwrap_or(Id128::NULL);
    Ok((context.open_sequence()?, id))
}

pub fn osc_context_open_service(
    unit: Option<&str>,
    invocation_id: Id128,
) -> Result<(String, Id128), OscContextError> {
    let context = OscContext::service(unit, invocation_id);
    let id = context.context_id().unwrap_or(Id128::NULL);
    Ok((context.open_sequence()?, id))
}

pub fn osc_context_close(id: Id128) -> Result<Option<String>, OscContextError> {
    if id.is_null() {
        return Ok(None);
    }

    let close_id = if id.is_allf() {
        default_context_id()?
    } else {
        id
    };
    Ok(Some(format!("{ANSI_OSC}3008;end={close_id}{ANSI_ST}")))
}

pub fn osc_context_id_from_invocation_id(invocation_id: Id128) -> Id128 {
    let mut input = [0_u8; 32];
    input[..16].copy_from_slice(&invocation_id.as_bytes());
    input[16..].copy_from_slice(&APP_SPECIFIC_ID.as_bytes());

    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&sha256(&input)[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Id128::from_bytes(bytes)
}

fn osc_append_identity_with(out: &mut String, identity: &IdentityInfo) {
    if let Some(user) = identity.user.as_deref() {
        strextend_escaped(out, ";user=", user);
    }
    if let Some(hostname) = identity.hostname.as_deref() {
        strextend_escaped(out, ";hostname=", hostname);
    }
    if let Some(machine_id) = identity.machine_id {
        out.push_str(";machineid=");
        out.push_str(&machine_id.to_string());
    }
    if let Some(boot_id) = identity.boot_id {
        out.push_str(";bootid=");
        out.push_str(&boot_id.to_string());
    }

    out.push_str(";pid=");
    out.push_str(&identity.pid.to_string());

    if let Some(comm) = identity.comm.as_deref() {
        strextend_escaped(out, ";comm=", comm);
    }
}

fn default_context_id() -> Result<Id128, OscContextError> {
    if let Some(id) = DEFAULT_CONTEXT_ID.get() {
        return Ok(*id);
    }

    let id = Id128::random()?;
    let _ = DEFAULT_CONTEXT_ID.set(id);
    Ok(*DEFAULT_CONTEXT_ID.get().expect("default context id is set"))
}

fn read_identity() -> IdentityInfo {
    IdentityInfo {
        user: read_username(),
        hostname: read_hostname(),
        machine_id: read_id128_file("/etc/machine-id").ok(),
        boot_id: read_id128_file("/proc/sys/kernel/random/boot_id").ok(),
        pid: process::id(),
        comm: read_comm(),
    }
}

fn read_id128_file(path: &str) -> Result<Id128, OscContextError> {
    let raw = fs::read_to_string(path)?;
    Id128::parse(raw.trim())
}

fn read_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let mut buffer = [0_u8; 256];
            // SAFETY: `buffer` is writable for exactly the supplied length.
            // It is pre-initialized so a hostname that fills the buffer
            // without a trailing NUL is still safely treated as a full slice.
            let status = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
            if status < 0 {
                return None;
            }

            let end = buffer
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(buffer.len());
            String::from_utf8(buffer[..end].to_vec())
                .ok()
                .filter(|value| !value.is_empty())
        })
}

fn read_username() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|value| !value.is_empty())
        // SAFETY: getpwuid_r receives writable `pwd`, `result`, and buffer
        // storage. On success with non-null result it initializes the record
        // and its string pointers remain valid while `buffer` is alive.
        .or_else(|| unsafe {
            let uid = libc::geteuid();
            let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
            let mut result = std::ptr::null_mut();
            let mut buffer = vec![0_u8; 4096];
            let status = libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            );

            if status != 0 || result.is_null() {
                return None;
            }

            // A successful getpwuid_r with a non-null result initialized the
            // passwd record, including a NUL-terminated `pw_name` when it is
            // non-null; the backing buffer is still alive.
            let pwd = pwd.assume_init();
            if pwd.pw_name.is_null() {
                return None;
            }
            // `pw_name` was validated non-null and is NUL-terminated by the
            // successful getpwuid_r call described above.
            CStr::from_ptr(pwd.pw_name)
                .to_str()
                .ok()
                .map(str::to_string)
                .filter(|value| !value.is_empty())
        })
}

fn read_comm() -> Option<String> {
    fs::read_to_string("/proc/self/comm")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::args_os().next().and_then(|value| {
                Path::new(&value)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .filter(|name| !name.is_empty())
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(hex: &str) -> Id128 {
        Id128::parse(hex).unwrap()
    }

    fn identity() -> IdentityInfo {
        IdentityInfo {
            user: Some("alice".to_string()),
            hostname: Some("host;name\\x".to_string()),
            machine_id: Some(id("00112233445566778899aabbccddeeff")),
            boot_id: Some(id("fedcba98765432100123456789abcdef")),
            pid: 4242,
            comm: Some("systemctl;run\\test".to_string()),
        }
    }

    #[test]
    fn strextend_escaped_escapes_semicolons_and_backslashes() {
        let mut out = String::from("prefix");
        strextend_escaped(&mut out, ";key=", r"a;b\c");
        assert_eq!(out, r"prefix;key=a\;b\\c");
    }

    #[test]
    fn id128_parse_accepts_dashed_uuid() {
        let parsed = Id128::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(parsed.to_string(), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn id128_parse_rejects_invalid_input() {
        assert!(matches!(
            Id128::parse("not-an-id"),
            Err(OscContextError::InvalidId(_))
        ));
    }

    #[test]
    fn osc_append_identity_formats_all_supported_fields() {
        let mut out = String::new();
        osc_append_identity_with(&mut out, &identity());
        assert_eq!(
            out,
            ";user=alice;hostname=host\\;name\\\\x;machineid=00112233445566778899aabbccddeeff;bootid=fedcba98765432100123456789abcdef;pid=4242;comm=systemctl\\;run\\\\test"
        );
    }

    #[test]
    fn boot_context_formats_open_sequence() {
        let seq = OscContext::boot().open_sequence_with(&identity()).unwrap();
        assert!(seq.starts_with("\x1b]3008;start="));
        assert!(seq.contains(";type=boot\x1b\\"));
        assert!(seq.contains(";user=alice"));
    }

    #[test]
    fn container_context_formats_name() {
        let context = OscContext {
            context_type: OscContextType::Container {
                name: Some("demo;box\\one".to_string()),
            },
            context_id: Some(id("11111111111111111111111111111111")),
        };
        let seq = context.open_sequence_with(&identity()).unwrap();
        assert!(seq.contains(r";container=demo\;box\\one"));
        assert!(seq.contains(";type=container"));
    }

    #[test]
    fn chpriv_context_uses_subcontext_for_same_user() {
        let context = OscContext {
            context_type: OscContextType::ChPriv {
                target_user: "alice".to_string(),
            },
            context_id: Some(id("22222222222222222222222222222222")),
        };
        let seq = context.open_sequence_with(&identity()).unwrap();
        assert!(seq.contains(";type=subcontext"));
        assert!(!seq.contains(";targetuser="));
    }

    #[test]
    fn chpriv_context_uses_elevate_for_root() {
        let context = OscContext {
            context_type: OscContextType::ChPriv {
                target_user: "root".to_string(),
            },
            context_id: Some(id("33333333333333333333333333333333")),
        };
        let seq = context.open_sequence_with(&identity()).unwrap();
        assert!(seq.contains(";type=elevate"));
    }

    #[test]
    fn chpriv_context_uses_chpriv_for_other_user() {
        let context = OscContext {
            context_type: OscContextType::ChPriv {
                target_user: "bob".to_string(),
            },
            context_id: Some(id("44444444444444444444444444444444")),
        };
        let seq = context.open_sequence_with(&identity()).unwrap();
        assert!(seq.contains(";targetuser=bob"));
        assert!(seq.contains(";type=chpriv"));
    }

    #[test]
    fn session_context_formats_optional_fields() {
        let context = OscContext {
            context_type: OscContextType::Session {
                user: Some("bob".to_string()),
                session_id: Some("s;1\\x".to_string()),
            },
            context_id: Some(id("55555555555555555555555555555555")),
        };
        let seq = context.open_sequence_with(&identity()).unwrap();
        assert!(seq.contains(";targetuser=bob"));
        assert!(seq.contains(r";sessionid=s\;1\\x"));
        assert!(seq.contains(";type=session"));
    }

    #[test]
    fn service_context_uses_app_specific_id() {
        let invocation_id = id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let context = OscContext::service(Some("demo.service"), invocation_id);
        let seq = context.open_sequence_with(&identity()).unwrap();
        assert!(seq.contains(";servicename=demo.service"));
        assert!(seq.contains(";invocationid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(seq.contains(";type=service"));
        assert_eq!(
            context.context_id(),
            Some(osc_context_id_from_invocation_id(invocation_id))
        );
    }

    #[test]
    fn close_sequence_returns_none_for_null_id() {
        assert_eq!(osc_context_close(Id128::NULL).unwrap(), None);
    }

    #[test]
    fn close_sequence_formats_end_sequence() {
        let close = osc_context_close(id("0123456789abcdef0123456789abcdef"))
            .unwrap()
            .unwrap();
        assert_eq!(
            close,
            "\x1b]3008;end=0123456789abcdef0123456789abcdef\x1b\\"
        );
    }

    #[test]
    fn invocation_id_mapping_is_deterministic_and_distinct() {
        let first = id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let second = id("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(
            osc_context_id_from_invocation_id(first),
            osc_context_id_from_invocation_id(first)
        );
        assert_ne!(
            osc_context_id_from_invocation_id(first),
            osc_context_id_from_invocation_id(second)
        );
    }
}
