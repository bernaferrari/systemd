// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/cryptsetup-tpm2.c, src/shared/cryptsetup-tpm2.h

use crate::ffi::*;
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use openssl::hash::MessageDigest;
use openssl::pkcs5;

use crate::ask_password_api::{ask_password_auto, AskPasswordFlags, AskPasswordRequest};
use crate::tpm2_util::{
    tpm2_asym_alg_from_string, tpm2_hash_alg_from_string, Tpm2Flags, TPM2_ALG_ECC, TPM2_PCRS_MAX,
};

const PBKDF2_HMAC_SHA256_ITERATIONS: usize = 10_000;
const TPM2_TOKEN_TYPE: &str = "systemd-tpm2";
const PIN_PROMPT: &str = "Please enter TPM2 PIN:";
const ANY_PCR_MASK: u32 = u32::MAX;

pub type Result<T> = std::result::Result<T, Tpm2Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2Error {
    errno: i32,
    message: String,
}

impl Tpm2Error {
    pub fn new(errno: i32, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
        }
    }

    pub fn errno(&self) -> i32 {
        self.errno
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Tpm2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (errno={})", self.message, self.errno)
    }
}

impl std::error::Error for Tpm2Error {}

impl From<io::Error> for Tpm2Error {
    fn from(value: io::Error) -> Self {
        Self::new(value.raw_os_error().unwrap_or(libc::EIO), value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquireTpm2KeyRequest<'a> {
    pub volume_name: &'a str,
    pub device: Option<&'a str>,
    pub hash_pcr_mask: u32,
    pub pcr_bank: u16,
    pub pubkey: Option<&'a [u8]>,
    pub pubkey_pcr_mask: u32,
    pub signature_path: Option<&'a str>,
    pub pcrlock_path: Option<&'a str>,
    pub primary_alg: u16,
    pub key_file: Option<&'a Path>,
    pub key_file_size: usize,
    pub key_file_offset: u64,
    pub blobs: Vec<Vec<u8>>,
    pub policy_hash: Vec<Vec<u8>>,
    pub salt: Option<&'a [u8]>,
    pub srk: Option<&'a [u8]>,
    pub pcrlock_nv: Option<&'a [u8]>,
    pub flags: Tpm2Flags,
    pub until: Option<Duration>,
    pub askpw_credential: Option<&'a str>,
    pub askpw_flags: AskPasswordFlags,
}

impl<'a> Default for AcquireTpm2KeyRequest<'a> {
    fn default() -> Self {
        Self {
            volume_name: "",
            device: None,
            hash_pcr_mask: 0,
            pcr_bank: u16::MAX,
            pubkey: None,
            pubkey_pcr_mask: 0,
            signature_path: None,
            pcrlock_path: None,
            primary_alg: TPM2_ALG_ECC,
            key_file: None,
            key_file_size: 0,
            key_file_offset: 0,
            blobs: Vec::new(),
            policy_hash: Vec::new(),
            salt: None,
            srk: None,
            pcrlock_nv: None,
            flags: Tpm2Flags::empty(),
            until: None,
            askpw_credential: None,
            askpw_flags: AskPasswordFlags::empty(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2AutoData {
    pub hash_pcr_mask: u32,
    pub pcr_bank: u16,
    pub pubkey: Option<Vec<u8>>,
    pub pubkey_pcr_mask: u32,
    pub primary_alg: u16,
    pub blobs: Vec<Vec<u8>>,
    pub policy_hash: Vec<Vec<u8>>,
    pub salt: Option<Vec<u8>>,
    pub srk: Option<Vec<u8>>,
    pub pcrlock_nv: Option<Vec<u8>>,
    pub flags: Tpm2Flags,
    pub keyslot: i32,
    pub token: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2SignatureJson(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2PcrlockPolicy {
    pub source: Tpm2PcrlockPolicySource,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tpm2PcrlockPolicySource {
    File,
    Credentials,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsealError {
    Integrity,
    PolicyMismatch,
    DictionaryAttackLockout,
    BadPin,
    Errno(i32, String),
}

impl UnsealError {
    fn other(errno: i32, message: impl Into<String>) -> Self {
        Self::Errno(errno, message.into())
    }
}

pub struct UnsealRequest<'a> {
    pub hash_pcr_mask: u32,
    pub pcr_bank: u16,
    pub pubkey: Option<&'a [u8]>,
    pub pubkey_pcr_mask: u32,
    pub signature_json: Option<&'a Tpm2SignatureJson>,
    pub pin: Option<&'a str>,
    pub pcrlock_policy: Option<&'a Tpm2PcrlockPolicy>,
    pub primary_alg: u16,
    pub blobs: &'a [Vec<u8>],
    pub policy_hash: &'a [Vec<u8>],
    pub srk: Option<&'a [u8]>,
}

pub trait Tpm2Connection {
    fn unseal(&self, request: &UnsealRequest<'_>) -> std::result::Result<Vec<u8>, UnsealError>;
}

pub trait Tpm2Backend {
    type Connection: Tpm2Connection;

    fn find_device_auto(&self) -> Result<Option<String>>;
    fn load_pcr_signature(&self, path: &str) -> Result<Tpm2SignatureJson>;
    fn load_pcrlock_policy(&self, path: &str) -> Result<Option<Tpm2PcrlockPolicy>>;
    fn pcrlock_policy_from_credentials(
        &self,
        srk: Option<&[u8]>,
        pcrlock_nv: Option<&[u8]>,
    ) -> Result<Option<Tpm2PcrlockPolicy>>;
    fn open(&self, device: &str) -> Result<Self::Connection>;
}

pub trait PinProvider {
    fn get_pin(
        &self,
        until: Option<Duration>,
        askpw_credential: Option<&str>,
        askpw_flags: AskPasswordFlags,
    ) -> Result<String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemPinProvider;

impl PinProvider for SystemPinProvider {
    fn get_pin(
        &self,
        until: Option<Duration>,
        askpw_credential: Option<&str>,
        askpw_flags: AskPasswordFlags,
    ) -> Result<String> {
        if let Some(pin) = getenv_steal_erase("PIN") {
            return Ok(pin);
        }

        if askpw_flags.contains(AskPasswordFlags::HEADLESS) {
            return Err(Tpm2Error::new(
                ENOPKG,
                "PIN querying disabled via 'headless' option. Use the '$PIN' environment variable.",
            ));
        }

        let req = AskPasswordRequest {
            tty_fd: -libc::EBADF,
            message: PIN_PROMPT.to_string(),
            icon: Some("drive-harddisk".to_string()),
            keyring: Some("tpm2-pin".to_string()),
            credential: askpw_credential.map(str::to_owned),
            until,
            hup_fd: -libc::EBADF,
            ..AskPasswordRequest::default()
        };

        let pins = ask_password_auto(&req, askpw_flags)
            .map_err(|e| Tpm2Error::new(e.raw_os_error().unwrap_or(libc::EIO), e.to_string()))?;

        match pins.as_slice() {
            [pin] => Ok(pin.clone()),
            [] => Err(Tpm2Error::new(
                libc::EINVAL,
                "no PIN returned by ask-password",
            )),
            _ => Err(Tpm2Error::new(
                libc::EINVAL,
                "expected exactly one PIN from ask-password",
            )),
        }
    }
}

pub trait CryptsetupTokenSource {
    fn token_max(&self) -> usize;
    fn read_tpm2_token_json(&self, token: usize) -> Result<Option<String>>;
}

pub fn acquire_tpm2_key<B: Tpm2Backend, P: PinProvider>(
    request: &AcquireTpm2KeyRequest<'_>,
    backend: &B,
    pin_provider: &P,
) -> Result<Vec<u8>> {
    let device = match request.device {
        Some(device) => device.to_string(),
        None => backend
            .find_device_auto()?
            .ok_or_else(|| Tpm2Error::new(libc::EAGAIN, "Could not find TPM2 device"))?,
    };

    let blobs = if request.blobs.is_empty() {
        let key_file = request.key_file.ok_or_else(|| {
            Tpm2Error::new(
                libc::EINVAL,
                "key file path required when no TPM2 blobs are supplied",
            )
        })?;
        vec![read_blob_from_path(
            key_file,
            request.key_file_offset,
            request.key_file_size,
            request.volume_name,
        )?]
    } else {
        request.blobs.clone()
    };

    if blobs.is_empty() {
        return Err(Tpm2Error::new(libc::EINVAL, "no TPM2 blobs available"));
    }
    if request.policy_hash.is_empty() {
        return Err(Tpm2Error::new(
            libc::EINVAL,
            "no TPM2 policy hash available",
        ));
    }

    let signature_json = if request.pubkey_pcr_mask != 0 {
        let path = request.signature_path.ok_or_else(|| {
            Tpm2Error::new(
                libc::EINVAL,
                "PCR signature path required when public-key PCRs are used",
            )
        })?;
        Some(backend.load_pcr_signature(path)?)
    } else {
        None
    };

    let pcrlock_policy = if request.flags.contains(Tpm2Flags::USE_PCRLOCK) {
        match request.pcrlock_path {
            Some(path) => match backend.load_pcrlock_policy(path)? {
                Some(policy) => Some(policy),
                None => backend
                    .pcrlock_policy_from_credentials(request.srk, request.pcrlock_nv)?
                    .ok_or_else(|| {
                        Tpm2Error::new(libc::EREMOTE, "Couldn't find pcrlock policy for volume.")
                    })
                    .map(Some)?,
            },
            None => backend
                .pcrlock_policy_from_credentials(request.srk, request.pcrlock_nv)?
                .ok_or_else(|| {
                    Tpm2Error::new(libc::EREMOTE, "Couldn't find pcrlock policy for volume.")
                })
                .map(Some)?,
        }
    } else {
        None
    };

    let connection = backend.open(&device)?;

    if !request.flags.contains(Tpm2Flags::USE_PIN) {
        return map_unseal_result(connection.unseal(&UnsealRequest {
            hash_pcr_mask: request.hash_pcr_mask,
            pcr_bank: request.pcr_bank,
            pubkey: request.pubkey,
            pubkey_pcr_mask: request.pubkey_pcr_mask,
            signature_json: signature_json.as_ref(),
            pin: None,
            pcrlock_policy: pcrlock_policy.as_ref(),
            primary_alg: request.primary_alg,
            blobs: &blobs,
            policy_hash: &request.policy_hash,
            srk: request.srk,
        }));
    }

    let mut askpw_flags = request.askpw_flags;

    for remaining in (1..=5).rev() {
        if remaining == 0 {
            break;
        }

        let pin = pin_provider.get_pin(request.until, request.askpw_credential, askpw_flags)?;
        askpw_flags.remove(AskPasswordFlags::ACCEPT_CACHED);

        let pin = match request.salt {
            Some(salt) if !salt.is_empty() => salted_pin(&pin, salt)?,
            _ => pin,
        };

        match connection.unseal(&UnsealRequest {
            hash_pcr_mask: request.hash_pcr_mask,
            pcr_bank: request.pcr_bank,
            pubkey: request.pubkey,
            pubkey_pcr_mask: request.pubkey_pcr_mask,
            signature_json: signature_json.as_ref(),
            pin: Some(pin.as_str()),
            pcrlock_policy: pcrlock_policy.as_ref(),
            primary_alg: request.primary_alg,
            blobs: &blobs,
            policy_hash: &request.policy_hash,
            srk: request.srk,
        }) {
            Ok(secret) => return Ok(secret),
            Err(UnsealError::BadPin) if remaining > 1 => continue,
            Err(UnsealError::BadPin) => {
                return Err(Tpm2Error::new(libc::EACCES, "Bad PIN."));
            }
            Err(other) => return Err(map_unseal_error(other)),
        }
    }

    Err(Tpm2Error::new(libc::EACCES, "Too many bad PIN attempts"))
}

pub fn find_tpm2_auto_data<S: CryptsetupTokenSource>(
    source: &S,
    search_pcr_mask: u32,
    start_token: usize,
) -> Result<Tpm2AutoData> {
    for token in start_token..source.token_max() {
        let Some(text) = source.read_tpm2_token_json(token)? else {
            continue;
        };

        let parsed = match Tpm2Luks2Token::from_json_str(&text) {
            Ok(token) => token,
            Err(ParseTokenError::Skip) => continue,
            Err(ParseTokenError::Error(err)) => return Err(err),
        };

        if search_pcr_mask == ANY_PCR_MASK || search_pcr_mask == parsed.hash_pcr_mask {
            return Ok(Tpm2AutoData {
                hash_pcr_mask: parsed.hash_pcr_mask,
                pcr_bank: parsed.pcr_bank,
                pubkey: parsed.pubkey,
                pubkey_pcr_mask: parsed.pubkey_pcr_mask,
                primary_alg: parsed.primary_alg,
                blobs: parsed.blobs,
                policy_hash: parsed.policy_hash,
                salt: parsed.salt,
                srk: parsed.srk,
                pcrlock_nv: parsed.pcrlock_nv,
                flags: parsed.flags,
                keyslot: parsed.keyslot,
                token,
            });
        }
    }

    Err(Tpm2Error::new(
        libc::ENXIO,
        "No valid TPM2 token data found.",
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tpm2Luks2Token {
    keyslot: i32,
    hash_pcr_mask: u32,
    pcr_bank: u16,
    pubkey: Option<Vec<u8>>,
    pubkey_pcr_mask: u32,
    primary_alg: u16,
    blobs: Vec<Vec<u8>>,
    policy_hash: Vec<Vec<u8>>,
    salt: Option<Vec<u8>>,
    srk: Option<Vec<u8>>,
    pcrlock_nv: Option<Vec<u8>>,
    flags: Tpm2Flags,
}

impl Tpm2Luks2Token {
    fn from_json_str(text: &str) -> std::result::Result<Self, ParseTokenError> {
        let json = JsonParser::new(text)
            .parse()
            .map_err(|e| ParseTokenError::Error(Tpm2Error::new(libc::EINVAL, e)))?;
        let object = json.as_object().ok_or_else(|| {
            ParseTokenError::Error(Tpm2Error::new(
                libc::EINVAL,
                "TPM2 token JSON is not an object",
            ))
        })?;

        if let Some(ty) = object.get("type") {
            let ty = ty.as_str().ok_or_else(|| {
                ParseTokenError::Error(Tpm2Error::new(
                    libc::EINVAL,
                    "TPM2 token type is not a string",
                ))
            })?;
            if ty != TPM2_TOKEN_TYPE {
                return Err(ParseTokenError::Skip);
            }
        }

        let keyslot = parse_keyslot(object)?;
        let hash_pcr_mask = parse_pcr_mask(required_field(object, "tpm2-pcrs")?)?;

        let pcr_bank = match object.get("tpm2-pcr-bank") {
            Some(value) => {
                let name = value.as_str().ok_or_else(|| {
                    ParseTokenError::Error(Tpm2Error::new(
                        libc::EINVAL,
                        "TPM2 PCR bank is not a string",
                    ))
                })?;
                tpm2_hash_alg_from_string(name).ok_or_else(|| {
                    ParseTokenError::Error(Tpm2Error::new(
                        libc::EINVAL,
                        format!("TPM2 PCR bank invalid or not supported: {name}"),
                    ))
                })? as u16
            }
            None => u16::MAX,
        };

        let primary_alg = match object.get("tpm2-primary-alg") {
            Some(value) => {
                let name = value.as_str().ok_or_else(|| {
                    ParseTokenError::Error(Tpm2Error::new(
                        libc::EINVAL,
                        "TPM2 primary key algorithm is not a string",
                    ))
                })?;
                tpm2_asym_alg_from_string(name).ok_or_else(|| {
                    ParseTokenError::Error(Tpm2Error::new(
                        libc::EINVAL,
                        format!("TPM2 asymmetric algorithm invalid or not supported: {name}"),
                    ))
                })? as u16
            }
            None => 0,
        };

        let blobs = parse_shard_array(
            required_field(object, "tpm2-blob")?,
            decode_base64,
            "tpm2-blob",
        )?;
        let policy_hash = parse_shard_array(
            required_field(object, "tpm2-policy-hash")?,
            decode_hex,
            "tpm2-policy-hash",
        )?;

        let mut flags = Tpm2Flags::empty();

        if let Some(value) = object.get("tpm2-pin") {
            if !value.is_bool() {
                return Err(ParseTokenError::Error(Tpm2Error::new(
                    libc::EINVAL,
                    "TPM2 PIN policy is not a boolean.",
                )));
            }
            if value.as_bool() == Some(true) {
                flags |= Tpm2Flags::USE_PIN;
            }
        }

        if let Some(value) = object.get("tpm2_pcrlock") {
            if !value.is_bool() {
                return Err(ParseTokenError::Error(Tpm2Error::new(
                    libc::EINVAL,
                    "TPM2 pclock policy is not a boolean.",
                )));
            }
            if value.as_bool() == Some(true) {
                flags |= Tpm2Flags::USE_PCRLOCK;
            }
        }

        let salt = optional_binary(object.get("tpm2_salt"), "tpm2_salt")?;
        let pubkey_pcr_mask = match object.get("tpm2_pubkey_pcrs") {
            Some(value) => parse_pcr_mask(value)?,
            None => 0,
        };
        let pubkey = optional_binary(object.get("tpm2_pubkey"), "tpm2_pubkey")?;
        if pubkey_pcr_mask != 0 && pubkey.is_none() {
            return Err(ParseTokenError::Error(Tpm2Error::new(
                libc::EINVAL,
                "Public key PCR mask set, but not public key included in JSON data, refusing.",
            )));
        }

        let srk = optional_binary(object.get("tpm2_srk"), "tpm2_srk")?;
        let pcrlock_nv = optional_binary(object.get("tpm2_pcrlock_nv"), "tpm2_pcrlock_nv")?;

        Ok(Self {
            keyslot,
            hash_pcr_mask,
            pcr_bank,
            pubkey,
            pubkey_pcr_mask,
            primary_alg,
            blobs,
            policy_hash,
            salt,
            srk,
            pcrlock_nv,
            flags,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseTokenError {
    Skip,
    Error(Tpm2Error),
}

fn parse_keyslot(
    object: &BTreeMap<String, JsonValue>,
) -> std::result::Result<i32, ParseTokenError> {
    let Some(value) = object.get("keyslots") else {
        return Err(ParseTokenError::Skip);
    };
    let Some(array) = value.as_array() else {
        return Err(ParseTokenError::Skip);
    };
    let Some(first) = array.first() else {
        return Err(ParseTokenError::Skip);
    };
    let Some(text) = first.as_str() else {
        return Err(ParseTokenError::Skip);
    };
    text.parse::<i32>().map_err(|_| ParseTokenError::Skip)
}

fn required_field<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> std::result::Result<&'a JsonValue, ParseTokenError> {
    object.get(name).ok_or_else(|| {
        ParseTokenError::Error(Tpm2Error::new(
            libc::EINVAL,
            format!("TPM2 token data lacks '{name}' field."),
        ))
    })
}

fn parse_pcr_mask(value: &JsonValue) -> std::result::Result<u32, ParseTokenError> {
    let Some(array) = value.as_array() else {
        return Err(ParseTokenError::Error(Tpm2Error::new(
            libc::EINVAL,
            "TPM2 PCR array is not a JSON array.",
        )));
    };

    let mut mask = 0u32;
    for entry in array {
        let Some(index) = entry.as_u64() else {
            return Err(ParseTokenError::Error(Tpm2Error::new(
                libc::EINVAL,
                "TPM2 PCR is not an unsigned integer.",
            )));
        };
        if index >= TPM2_PCRS_MAX as u64 {
            return Err(ParseTokenError::Error(Tpm2Error::new(
                libc::EINVAL,
                format!("TPM2 PCR number out of range: {index}"),
            )));
        }
        mask |= 1u32 << index;
    }

    Ok(mask)
}

fn parse_shard_array(
    value: &JsonValue,
    decoder: fn(&str) -> std::result::Result<Vec<u8>, String>,
    name: &str,
) -> std::result::Result<Vec<Vec<u8>>, ParseTokenError> {
    match value {
        JsonValue::Array(array) => {
            if array.is_empty() {
                return Err(ParseTokenError::Error(Tpm2Error::new(
                    libc::EINVAL,
                    format!("TPM2 token data contains empty '{name}' array."),
                )));
            }

            array
                .iter()
                .map(|entry| {
                    let text = entry.as_str().ok_or_else(|| {
                        ParseTokenError::Error(Tpm2Error::new(
                            libc::EINVAL,
                            format!("Invalid data in '{name}' field."),
                        ))
                    })?;
                    decoder(text).map_err(|err| {
                        ParseTokenError::Error(Tpm2Error::new(
                            libc::EINVAL,
                            format!("Invalid data in '{name}' field: {err}"),
                        ))
                    })
                })
                .collect()
        }
        JsonValue::String(text) => decoder(text)
            .map(|v| vec![v])
            .map_err(|err| ParseTokenError::Error(Tpm2Error::new(libc::EINVAL, err))),
        _ => Err(ParseTokenError::Error(Tpm2Error::new(
            libc::EINVAL,
            format!("Invalid data in '{name}' field."),
        ))),
    }
}

fn optional_binary(
    value: Option<&JsonValue>,
    name: &str,
) -> std::result::Result<Option<Vec<u8>>, ParseTokenError> {
    value
        .map(|value| {
            let text = value.as_str().ok_or_else(|| {
                ParseTokenError::Error(Tpm2Error::new(
                    libc::EINVAL,
                    format!("Invalid base64 data in '{name}' field."),
                ))
            })?;
            decode_base64(text).map_err(|_| {
                ParseTokenError::Error(Tpm2Error::new(
                    libc::EINVAL,
                    format!("Invalid base64 data in '{name}' field."),
                ))
            })
        })
        .transpose()
}

fn read_blob_from_path(
    path: &Path,
    offset: u64,
    size: usize,
    _volume_name: &str,
) -> Result<Vec<u8>> {
    let metadata = path.metadata()?;

    let mut data = Vec::new();
    if metadata.file_type().is_socket() {
        let mut stream = UnixStream::connect(path)?;
        stream.read_to_end(&mut data)?;
    } else {
        let mut file = File::open(path)?;
        if offset != 0 {
            file.seek(SeekFrom::Start(offset))?;
        }
        if size == 0 {
            file.read_to_end(&mut data)?;
        } else {
            let mut limited = file.take(size as u64);
            limited.read_to_end(&mut data)?;
        }
    }

    Ok(data)
}

fn getenv_steal_erase(name: &str) -> Option<String> {
    let value = env::var(name).ok();
    if value.is_some() {
        env::remove_var(name);
    }
    value
}

fn salted_pin(pin: &str, salt: &[u8]) -> Result<String> {
    let mut derived = [0u8; 32];
    pkcs5::pbkdf2_hmac(
        pin.as_bytes(),
        salt,
        PBKDF2_HMAC_SHA256_ITERATIONS,
        MessageDigest::sha256(),
        &mut derived,
    )
    .map_err(|e| Tpm2Error::new(libc::EIO, format!("Failed to perform PBKDF2: {e}")))?;

    Ok(encode_base64(&derived))
}

fn map_unseal_result(result: std::result::Result<Vec<u8>, UnsealError>) -> Result<Vec<u8>> {
    result.map_err(map_unseal_error)
}

fn map_unseal_error(error: UnsealError) -> Tpm2Error {
    match error {
        UnsealError::Integrity => Tpm2Error::new(
            libc::EREMOTE,
            "TPM key integrity check failed. Key enrolled in superblock most likely does not belong to this TPM.",
        ),
        UnsealError::PolicyMismatch => Tpm2Error::new(
            libc::ESTALE,
            "TPM policy does not match current system state. Either system has been tempered with or policy out-of-date.",
        ),
        UnsealError::DictionaryAttackLockout => {
            Tpm2Error::new(libc::ENOLCK, "TPM is in dictionary attack lock-out mode.")
        }
        UnsealError::BadPin => Tpm2Error::new(libc::EILSEQ, "Bad PIN."),
        UnsealError::Errno(errno, message) => Tpm2Error::new(
            errno,
            format!("Failed to unseal secret using TPM2: {message}"),
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    fn is_bool(&self) -> bool {
        matches!(self, Self::Bool(_))
    }
}

struct JsonParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn parse(mut self) -> std::result::Result<JsonValue, String> {
        self.skip_ws();
        let value = self.parse_value()?;
        self.skip_ws();
        if self.pos != self.input.len() {
            return Err("trailing data after JSON value".to_string());
        }
        Ok(value)
    }

    fn parse_value(&mut self) -> std::result::Result<JsonValue, String> {
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b't') => self.parse_true(),
            Some(b'f') => self.parse_false(),
            Some(b'n') => self.parse_null(),
            Some(b'0'..=b'9') => self.parse_number(),
            _ => Err("unexpected JSON token".to_string()),
        }
    }

    fn parse_object(&mut self) -> std::result::Result<JsonValue, String> {
        self.expect(b'{')?;
        self.skip_ws();
        let mut object = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(object));
        }

        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.parse_value()?;
            object.insert(key, value);
            self.skip_ws();

            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err("expected ',' or '}' in JSON object".to_string()),
            }
        }

        Ok(JsonValue::Object(object))
    }

    fn parse_array(&mut self) -> std::result::Result<JsonValue, String> {
        self.expect(b'[')?;
        self.skip_ws();
        let mut array = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(array));
        }

        loop {
            self.skip_ws();
            array.push(self.parse_value()?);
            self.skip_ws();

            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err("expected ',' or ']' in JSON array".to_string()),
            }
        }

        Ok(JsonValue::Array(array))
    }

    fn parse_string(&mut self) -> std::result::Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();

        while let Some(byte) = self.next() {
            match byte {
                b'"' => return Ok(out),
                b'\\' => out.push(self.parse_escape()?),
                byte if byte < 0x20 => return Err("control character in JSON string".to_string()),
                byte => out.push(byte as char),
            }
        }

        Err("unterminated JSON string".to_string())
    }

    fn parse_escape(&mut self) -> std::result::Result<char, String> {
        match self.next() {
            Some(b'"') => Ok('"'),
            Some(b'\\') => Ok('\\'),
            Some(b'/') => Ok('/'),
            Some(b'b') => Ok('\u{0008}'),
            Some(b'f') => Ok('\u{000c}'),
            Some(b'n') => Ok('\n'),
            Some(b'r') => Ok('\r'),
            Some(b't') => Ok('\t'),
            Some(b'u') => {
                let code = self.parse_hex_quad()?;
                char::from_u32(code).ok_or_else(|| "invalid unicode escape".to_string())
            }
            _ => Err("invalid JSON escape".to_string()),
        }
    }

    fn parse_hex_quad(&mut self) -> std::result::Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..4 {
            let nibble = match self.next() {
                Some(b'0'..=b'9') => self.input[self.pos - 1] - b'0',
                Some(b'a'..=b'f') => self.input[self.pos - 1] - b'a' + 10,
                Some(b'A'..=b'F') => self.input[self.pos - 1] - b'A' + 10,
                _ => return Err("invalid unicode escape".to_string()),
            };
            value = (value << 4) | nibble as u32;
        }
        Ok(value)
    }

    fn parse_true(&mut self) -> std::result::Result<JsonValue, String> {
        self.expect_bytes(b"true")?;
        Ok(JsonValue::Bool(true))
    }

    fn parse_false(&mut self) -> std::result::Result<JsonValue, String> {
        self.expect_bytes(b"false")?;
        Ok(JsonValue::Bool(false))
    }

    fn parse_null(&mut self) -> std::result::Result<JsonValue, String> {
        self.expect_bytes(b"null")?;
        Ok(JsonValue::Null)
    }

    fn parse_number(&mut self) -> std::result::Result<JsonValue, String> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| "invalid number".to_string())?;
        let value = text
            .parse::<u64>()
            .map_err(|_| "invalid number".to_string())?;
        Ok(JsonValue::Number(value))
    }

    fn expect(&mut self, byte: u8) -> std::result::Result<(), String> {
        match self.next() {
            Some(found) if found == byte => Ok(()),
            _ => Err(format!("expected byte '{}'", byte as char)),
        }
    }

    fn expect_bytes(&mut self, bytes: &[u8]) -> std::result::Result<(), String> {
        for byte in bytes {
            self.expect(*byte)?;
        }
        Ok(())
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }
}

fn encode_base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;

        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }

    out
}

fn decode_base64(text: &str) -> std::result::Result<Vec<u8>, String> {
    let cleaned: Vec<u8> = text.bytes().filter(|b| !b" \n\r\t".contains(b)).collect();
    if cleaned.len() % 4 != 0 {
        return Err("invalid base64 length".to_string());
    }

    let mut out = Vec::with_capacity((cleaned.len() / 4) * 3);
    for chunk in cleaned.chunks(4) {
        let mut values = [0u8; 4];
        let mut padding = 0usize;
        for (index, byte) in chunk.iter().copied().enumerate() {
            if byte == b'=' {
                padding += 1;
                values[index] = 0;
            } else {
                values[index] = decode_base64_char(byte)?;
            }
        }

        let n = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | values[3] as u32;

        out.push(((n >> 16) & 0xff) as u8);
        if padding < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if padding < 1 {
            out.push((n & 0xff) as u8);
        }
    }

    Ok(out)
}

fn decode_base64_char(byte: u8) -> std::result::Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("invalid base64 character".to_string()),
    }
}

fn decode_hex(text: &str) -> std::result::Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }

    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn decode_hex_nibble(byte: u8) -> std::result::Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::os::unix::net::UnixListener;
    use std::rc::Rc;
    use std::thread;

    use tempfile::tempdir;

    #[derive(Debug, Clone)]
    struct MockConnection {
        calls: Rc<RefCell<Vec<Option<String>>>>,
        responses: Rc<RefCell<Vec<std::result::Result<Vec<u8>, UnsealError>>>>,
    }

    impl MockConnection {
        fn new(responses: Vec<std::result::Result<Vec<u8>, UnsealError>>) -> Self {
            Self {
                calls: Rc::new(RefCell::new(Vec::new())),
                responses: Rc::new(RefCell::new(responses)),
            }
        }
    }

    impl Tpm2Connection for MockConnection {
        fn unseal(&self, request: &UnsealRequest<'_>) -> std::result::Result<Vec<u8>, UnsealError> {
            self.calls
                .borrow_mut()
                .push(request.pin.map(str::to_string));
            self.responses.borrow_mut().remove(0)
        }
    }

    struct MockBackend {
        auto_device: Option<String>,
        signature: Option<Tpm2SignatureJson>,
        pcrlock_file: Option<Tpm2PcrlockPolicy>,
        pcrlock_creds: Option<Tpm2PcrlockPolicy>,
        connection: MockConnection,
    }

    impl Tpm2Backend for MockBackend {
        type Connection = MockConnection;

        fn find_device_auto(&self) -> Result<Option<String>> {
            Ok(self.auto_device.clone())
        }

        fn load_pcr_signature(&self, _path: &str) -> Result<Tpm2SignatureJson> {
            self.signature
                .clone()
                .ok_or_else(|| Tpm2Error::new(libc::ENOENT, "missing signature"))
        }

        fn load_pcrlock_policy(&self, _path: &str) -> Result<Option<Tpm2PcrlockPolicy>> {
            Ok(self.pcrlock_file.clone())
        }

        fn pcrlock_policy_from_credentials(
            &self,
            _srk: Option<&[u8]>,
            _pcrlock_nv: Option<&[u8]>,
        ) -> Result<Option<Tpm2PcrlockPolicy>> {
            Ok(self.pcrlock_creds.clone())
        }

        fn open(&self, _device: &str) -> Result<Self::Connection> {
            Ok(self.connection.clone())
        }
    }

    struct MockPinProvider {
        pins: RefCell<Vec<std::result::Result<String, Tpm2Error>>>,
        flags_seen: RefCell<Vec<AskPasswordFlags>>,
    }

    impl MockPinProvider {
        fn new(pins: Vec<std::result::Result<String, Tpm2Error>>) -> Self {
            Self {
                pins: RefCell::new(pins),
                flags_seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl PinProvider for MockPinProvider {
        fn get_pin(
            &self,
            _until: Option<Duration>,
            _askpw_credential: Option<&str>,
            askpw_flags: AskPasswordFlags,
        ) -> Result<String> {
            self.flags_seen.borrow_mut().push(askpw_flags);
            self.pins.borrow_mut().remove(0)
        }
    }

    struct MockTokenSource {
        tokens: Vec<Result<Option<String>>>,
    }

    impl CryptsetupTokenSource for MockTokenSource {
        fn token_max(&self) -> usize {
            self.tokens.len()
        }

        fn read_tpm2_token_json(&self, token: usize) -> Result<Option<String>> {
            self.tokens[token].clone()
        }
    }

    fn sample_token_json(hash_pcrs: &str) -> String {
        format!(
            r#"{{
                "type": "systemd-tpm2",
                "keyslots": ["3"],
                "tpm2-pcrs": {hash_pcrs},
                "tpm2-pcr-bank": "sha256",
                "tpm2-primary-alg": "ecc",
                "tpm2-blob": ["AQID", "BAUG"],
                "tpm2-policy-hash": ["deadbeef"],
                "tpm2-pin": true,
                "tpm2_pcrlock": true,
                "tpm2_salt": "c2FsdA==",
                "tpm2_pubkey_pcrs": [7],
                "tpm2_pubkey": "cHVia2V5",
                "tpm2_srk": "c3Jr",
                "tpm2_pcrlock_nv": "bnY="
            }}"#
        )
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"systemd-tpm2";
        let encoded = encode_base64(data);
        assert_eq!(decode_base64(&encoded).unwrap(), data);
    }

    #[test]
    fn hex_decode_works() {
        assert_eq!(
            decode_hex("deadBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn json_parser_handles_escaped_strings() {
        let parsed = JsonParser::new(r#"{"x":"line\nnext"}"#).parse().unwrap();
        let object = parsed.as_object().unwrap();
        assert_eq!(object.get("x").unwrap().as_str(), Some("line\nnext"));
    }

    #[test]
    fn parse_luks2_token_full() {
        let token = Tpm2Luks2Token::from_json_str(&sample_token_json("[7, 11]")).unwrap();
        assert_eq!(token.keyslot, 3);
        assert_eq!(token.hash_pcr_mask, (1 << 7) | (1 << 11));
        assert_eq!(token.pcr_bank, 0x000B);
        assert_eq!(token.primary_alg, TPM2_ALG_ECC);
        assert_eq!(token.blobs, vec![vec![1, 2, 3], vec![4, 5, 6]]);
        assert_eq!(token.policy_hash, vec![vec![0xde, 0xad, 0xbe, 0xef]]);
        assert_eq!(token.salt, Some(b"salt".to_vec()));
        assert!(token.flags.contains(Tpm2Flags::USE_PIN));
        assert!(token.flags.contains(Tpm2Flags::USE_PCRLOCK));
    }

    #[test]
    fn parse_luks2_token_requires_pubkey_when_mask_set() {
        let json = r#"{
            "type": "systemd-tpm2",
            "keyslots": ["1"],
            "tpm2-pcrs": [7],
            "tpm2-blob": "AQID",
            "tpm2-policy-hash": "deadbeef",
            "tpm2_pubkey_pcrs": [11]
        }"#;
        let error = Tpm2Luks2Token::from_json_str(json).unwrap_err();
        assert!(matches!(error, ParseTokenError::Error(_)));
    }

    #[test]
    fn parse_luks2_token_skips_invalid_keyslot_shape() {
        let json = r#"{
            "type": "systemd-tpm2",
            "keyslots": [false],
            "tpm2-pcrs": [7],
            "tpm2-blob": "AQID",
            "tpm2-policy-hash": "deadbeef"
        }"#;
        assert!(matches!(
            Tpm2Luks2Token::from_json_str(json),
            Err(ParseTokenError::Skip)
        ));
    }

    #[test]
    fn find_tpm2_auto_data_matches_requested_mask() {
        let source = MockTokenSource {
            tokens: vec![
                Ok(Some(sample_token_json("[7]"))),
                Ok(Some(sample_token_json("[11]"))),
            ],
        };
        let data = find_tpm2_auto_data(&source, 1 << 11, 0).unwrap();
        assert_eq!(data.token, 1);
        assert_eq!(data.hash_pcr_mask, 1 << 11);
    }

    #[test]
    fn find_tpm2_auto_data_skips_non_tpm2_tokens() {
        let source = MockTokenSource {
            tokens: vec![
                Ok(Some("{\"type\":\"other\"}".to_string())),
                Ok(Some(sample_token_json("[7]"))),
            ],
        };
        let data = find_tpm2_auto_data(&source, ANY_PCR_MASK, 0).unwrap();
        assert_eq!(data.token, 1);
    }

    #[test]
    fn find_tpm2_auto_data_errors_when_no_match_exists() {
        let source = MockTokenSource {
            tokens: vec![Ok(Some(sample_token_json("[7]")))],
        };
        let error = find_tpm2_auto_data(&source, 1 << 5, 0).unwrap_err();
        assert_eq!(error.errno(), libc::ENXIO);
    }

    #[test]
    fn acquire_without_pin_uses_direct_unseal() {
        let backend = MockBackend {
            auto_device: Some("/dev/tpmrm0".into()),
            signature: None,
            pcrlock_file: None,
            pcrlock_creds: None,
            connection: MockConnection::new(vec![Ok(vec![9, 9, 9])]),
        };
        let pin_provider = MockPinProvider::new(vec![]);
        let result = acquire_tpm2_key(
            &AcquireTpm2KeyRequest {
                volume_name: "vol",
                blobs: vec![vec![1, 2, 3]],
                policy_hash: vec![vec![4, 5, 6]],
                ..AcquireTpm2KeyRequest::default()
            },
            &backend,
            &pin_provider,
        )
        .unwrap();
        assert_eq!(result, vec![9, 9, 9]);
    }

    #[test]
    fn acquire_with_pin_retries_and_disables_cached_after_first_try() {
        let backend = MockBackend {
            auto_device: Some("/dev/tpmrm0".into()),
            signature: None,
            pcrlock_file: None,
            pcrlock_creds: None,
            connection: MockConnection::new(vec![Err(UnsealError::BadPin), Ok(vec![1, 2, 3])]),
        };
        let pin_provider = MockPinProvider::new(vec![Ok("1111".into()), Ok("2222".into())]);
        let result = acquire_tpm2_key(
            &AcquireTpm2KeyRequest {
                volume_name: "vol",
                blobs: vec![vec![1]],
                policy_hash: vec![vec![2]],
                flags: Tpm2Flags::USE_PIN,
                askpw_flags: AskPasswordFlags::ACCEPT_CACHED,
                ..AcquireTpm2KeyRequest::default()
            },
            &backend,
            &pin_provider,
        )
        .unwrap();
        assert_eq!(result, vec![1, 2, 3]);
        let flags = pin_provider.flags_seen.borrow();
        assert!(flags[0].contains(AskPasswordFlags::ACCEPT_CACHED));
        assert!(!flags[1].contains(AskPasswordFlags::ACCEPT_CACHED));
    }

    #[test]
    fn acquire_with_salt_pbkdf2_base64_encodes_pin() {
        let backend = MockBackend {
            auto_device: Some("/dev/tpmrm0".into()),
            signature: None,
            pcrlock_file: None,
            pcrlock_creds: None,
            connection: MockConnection::new(vec![Ok(vec![7])]),
        };
        let pin_provider = MockPinProvider::new(vec![Ok("1234".into())]);
        let salt = b"salt";
        let _ = acquire_tpm2_key(
            &AcquireTpm2KeyRequest {
                volume_name: "vol",
                blobs: vec![vec![1]],
                policy_hash: vec![vec![2]],
                salt: Some(salt),
                flags: Tpm2Flags::USE_PIN,
                ..AcquireTpm2KeyRequest::default()
            },
            &backend,
            &pin_provider,
        )
        .unwrap();
        let pins = backend.connection.calls.borrow();
        let pin = pins[0].as_ref().unwrap();
        assert_ne!(pin, "1234");
        assert!(pin.ends_with('='));
    }

    #[test]
    fn acquire_uses_pcrlock_credentials_fallback() {
        let backend = MockBackend {
            auto_device: Some("/dev/tpmrm0".into()),
            signature: None,
            pcrlock_file: None,
            pcrlock_creds: Some(Tpm2PcrlockPolicy {
                source: Tpm2PcrlockPolicySource::Credentials,
                payload: vec![1],
            }),
            connection: MockConnection::new(vec![Ok(vec![8])]),
        };
        let pin_provider = MockPinProvider::new(vec![]);
        let result = acquire_tpm2_key(
            &AcquireTpm2KeyRequest {
                volume_name: "vol",
                blobs: vec![vec![1]],
                policy_hash: vec![vec![2]],
                flags: Tpm2Flags::USE_PCRLOCK,
                ..AcquireTpm2KeyRequest::default()
            },
            &backend,
            &pin_provider,
        )
        .unwrap();
        assert_eq!(result, vec![8]);
    }

    #[test]
    fn acquire_requires_pcrlock_policy_when_requested() {
        let backend = MockBackend {
            auto_device: Some("/dev/tpmrm0".into()),
            signature: None,
            pcrlock_file: None,
            pcrlock_creds: None,
            connection: MockConnection::new(vec![Ok(vec![8])]),
        };
        let pin_provider = MockPinProvider::new(vec![]);
        let error = acquire_tpm2_key(
            &AcquireTpm2KeyRequest {
                volume_name: "vol",
                blobs: vec![vec![1]],
                policy_hash: vec![vec![2]],
                flags: Tpm2Flags::USE_PCRLOCK,
                ..AcquireTpm2KeyRequest::default()
            },
            &backend,
            &pin_provider,
        )
        .unwrap_err();
        assert_eq!(error.errno(), libc::EREMOTE);
    }

    #[test]
    fn acquire_maps_integrity_error() {
        let backend = MockBackend {
            auto_device: Some("/dev/tpmrm0".into()),
            signature: None,
            pcrlock_file: None,
            pcrlock_creds: None,
            connection: MockConnection::new(vec![Err(UnsealError::Integrity)]),
        };
        let pin_provider = MockPinProvider::new(vec![]);
        let error = acquire_tpm2_key(
            &AcquireTpm2KeyRequest {
                volume_name: "vol",
                blobs: vec![vec![1]],
                policy_hash: vec![vec![2]],
                ..AcquireTpm2KeyRequest::default()
            },
            &backend,
            &pin_provider,
        )
        .unwrap_err();
        assert_eq!(error.errno(), libc::EREMOTE);
    }

    #[test]
    fn acquire_reads_blob_from_regular_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.bin");
        fs::write(&path, b"abcdef").unwrap();

        let backend = MockBackend {
            auto_device: Some("/dev/tpmrm0".into()),
            signature: None,
            pcrlock_file: None,
            pcrlock_creds: None,
            connection: MockConnection::new(vec![Ok(vec![1])]),
        };
        let pin_provider = MockPinProvider::new(vec![]);
        let _ = acquire_tpm2_key(
            &AcquireTpm2KeyRequest {
                volume_name: "vol",
                key_file: Some(path.as_path()),
                key_file_offset: 2,
                key_file_size: 3,
                policy_hash: vec![vec![2]],
                ..AcquireTpm2KeyRequest::default()
            },
            &backend,
            &pin_provider,
        )
        .unwrap();

        let calls = backend.connection.calls.borrow();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn acquire_reads_blob_from_unix_socket() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            use std::io::Write;
            stream.write_all(b"socket-data").unwrap();
        });

        let bytes = read_blob_from_path(&path, 0, 0, "vol").unwrap();
        handle.join().unwrap();
        assert_eq!(bytes, b"socket-data");
    }

    #[test]
    fn system_pin_provider_steals_pin_from_environment() {
        env::set_var("PIN", "9999");
        let pin = SystemPinProvider
            .get_pin(None, None, AskPasswordFlags::empty())
            .unwrap();
        assert_eq!(pin, "9999");
        assert!(env::var("PIN").is_err());
    }

    #[test]
    fn system_pin_provider_rejects_headless_without_env_pin() {
        env::remove_var("PIN");
        let error = SystemPinProvider
            .get_pin(None, None, AskPasswordFlags::HEADLESS)
            .unwrap_err();
        assert_eq!(error.errno(), ENOPKG);
    }
}
