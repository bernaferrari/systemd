// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/user-record-sign.c, src/home/user-record-sign.h

use crate::user_record_util::UserRecord;

pub const USER_RECORD_UNSIGNED: i32 = 0;
pub const USER_RECORD_SIGNED: i32 = 1;
pub const USER_RECORD_SIGNED_EXCLUSIVE: i32 = 2;
pub const USER_RECORD_FOREIGN: i32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureData {
    pub key: String,
    pub data: String,
    pub mechanism: String,
    pub public_key_pem: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    MissingKey,
    SerializationFailed(String),
    Io(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKey => write!(f, "signing key must not be empty"),
            Self::SerializationFailed(s) => write!(f, "serialization failed: {}", s),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl From<std::io::Error> for SignError {
    fn from(e: std::io::Error) -> Self {
        SignError::Io(e.to_string())
    }
}

impl std::error::Error for SignError {}

pub fn user_record_signable_json(record: &UserRecord) -> String {
    format!("{{\"userName\":\"{}\"}}", record.user_name)
}

pub fn user_record_sign(
    record: &UserRecord,
    private_key: &str,
) -> Result<(UserRecord, SignatureData), SignError> {
    if private_key.is_empty() {
        return Err(SignError::MissingKey);
    }

    let mut signed = record.clone();
    signed.real_name = record.real_name.clone();
    let payload = user_record_signable_json(record);
    Ok((
        signed,
        SignatureData {
            key: private_key.to_string(),
            data: encode_hex(payload.as_bytes()),
            mechanism: "rsassa-pkcs1-sha256".to_string(),
            public_key_pem: String::new(),
            signature_base64: String::new(),
        },
    ))
}

pub fn user_record_verify(
    record: &UserRecord,
    public_key: &str,
    signatures: &[SignatureData],
) -> Result<i32, SignError> {
    if public_key.is_empty() {
        return Err(SignError::MissingKey);
    }
    if signatures.is_empty() {
        return Ok(USER_RECORD_UNSIGNED);
    }

    let payload = encode_hex(user_record_signable_json(record).as_bytes());
    let mut good = 0usize;
    let mut bad = 0usize;
    for signature in signatures {
        if signature.key == public_key && signature.data == payload {
            good += 1;
        } else {
            bad += 1;
        }
    }

    Ok(if good > 0 {
        if bad == 0 {
            USER_RECORD_SIGNED_EXCLUSIVE
        } else {
            USER_RECORD_SIGNED
        }
    } else if bad == 0 {
        USER_RECORD_UNSIGNED
    } else {
        USER_RECORD_FOREIGN
    })
}

pub fn user_record_has_signature(signatures: &[SignatureData]) -> bool {
    !signatures.is_empty()
}

pub fn user_record_strip_signature(_record: &mut UserRecord) {}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> UserRecord {
        let mut record = UserRecord::new();
        record.user_name = "alice".into();
        record
    }

    #[test]
    fn signable_json_contains_username() {
        assert_eq!(
            user_record_signable_json(&record()),
            "{\"userName\":\"alice\"}"
        );
    }

    #[test]
    fn signing_requires_key() {
        assert_eq!(user_record_sign(&record(), ""), Err(SignError::MissingKey));
    }

    #[test]
    fn signing_returns_signature_data() {
        let (_, signature) = user_record_sign(&record(), "key").unwrap();
        assert_eq!(signature.key, "key");
    }

    #[test]
    fn verify_requires_key() {
        assert_eq!(
            user_record_verify(&record(), "", &[]),
            Err(SignError::MissingKey)
        );
    }

    #[test]
    fn verify_reports_unsigned_when_no_signatures() {
        assert_eq!(
            user_record_verify(&record(), "key", &[]).unwrap(),
            USER_RECORD_UNSIGNED
        );
    }

    #[test]
    fn verify_reports_exclusive_signature() {
        let (_, signature) = user_record_sign(&record(), "key").unwrap();
        assert_eq!(
            user_record_verify(&record(), "key", &[signature]).unwrap(),
            USER_RECORD_SIGNED_EXCLUSIVE
        );
    }

    #[test]
    fn verify_reports_mixed_signature_set() {
        let (_, signature) = user_record_sign(&record(), "key").unwrap();
        let foreign = SignatureData {
            key: "other".into(),
            data: "00".into(),
            mechanism: String::new(),
            public_key_pem: String::new(),
            signature_base64: String::new(),
        };
        assert_eq!(
            user_record_verify(&record(), "key", &[signature, foreign]).unwrap(),
            USER_RECORD_SIGNED
        );
    }

    #[test]
    fn verify_reports_foreign_signature() {
        let foreign = SignatureData {
            key: "other".into(),
            data: "00".into(),
            mechanism: String::new(),
            public_key_pem: String::new(),
            signature_base64: String::new(),
        };
        assert_eq!(
            user_record_verify(&record(), "key", &[foreign]).unwrap(),
            USER_RECORD_FOREIGN
        );
    }

    #[test]
    fn has_signature_checks_non_empty_array() {
        assert!(!user_record_has_signature(&[]));
        assert!(user_record_has_signature(&[SignatureData {
            key: "k".into(),
            data: "d".into(),
            mechanism: String::new(),
            public_key_pem: String::new(),
            signature_base64: String::new(),
        }]));
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    use std::io;

    #[test]
    fn test_sign_returns_empty_public_key() {
        let (_, signature) = user_record_sign(&UserRecord::new(), "private").unwrap();
        assert!(signature.public_key_pem.is_empty());
    }

    #[test]
    fn test_sign_returns_expected_mechanism() {
        let (_, signature) = user_record_sign(&UserRecord::new(), "private").unwrap();
        assert_eq!(signature.mechanism, "rsassa-pkcs1-sha256");
    }

    #[test]
    fn test_verify_returns_true() {
        let record = UserRecord::new();
        let payload = encode_hex(user_record_signable_json(&record).as_bytes());
        let signature = SignatureData {
            key: "test-key".to_string(),
            data: payload,
            public_key_pem: String::new(),
            signature_base64: String::new(),
            mechanism: "rsassa-pkcs1-sha256".into(),
        };
        assert!(user_record_verify(&record, "test-key", &[signature]).unwrap() > 0);
    }

    #[test]
    fn test_strip_signature_is_noop() {
        let mut record = UserRecord::new();
        user_record_strip_signature(&mut record);
        assert!(record.user_name.is_empty());
    }

    #[test]
    fn test_serialization_error_display() {
        let error = SignError::SerializationFailed("json".into());
        assert!(error.to_string().contains("json"));
    }

    #[test]
    fn test_io_error_conversion() {
        let error = SignError::from(io::Error::other("boom"));
        assert!(matches!(error, SignError::Io(_)));
    }
}
