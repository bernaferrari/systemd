// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homework-fido2.c, src/home/homework-fido2.h

use crate::user_record_util::UserRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2HmacSalt {
    pub salt: Vec<u8>,
    pub up: i32,
    pub uv: i32,
    pub client_pin: i32,
    pub credential_id: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fido2Error {
    MissingCredential,
    MissingSalt,
    UserPresenceNotPermitted,
    UserVerificationNotPermitted,
    MissingTokenPin,
}

impl std::fmt::Display for Fido2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCredential => write!(f, "FIDO2 credential id must not be empty"),
            Self::MissingSalt => write!(f, "FIDO2 salt must not be empty"),
            Self::UserPresenceNotPermitted => write!(f, "user presence not permitted"),
            Self::UserVerificationNotPermitted => write!(f, "user verification not permitted"),
            Self::MissingTokenPin => write!(f, "security token requires PIN"),
        }
    }
}

impl std::error::Error for Fido2Error {}

pub fn fido2_use_token(
    record: &UserRecord,
    secret: &UserRecord,
    salt: &Fido2HmacSalt,
) -> Result<String, Fido2Error> {
    if salt.credential_id.is_empty() {
        return Err(Fido2Error::MissingCredential);
    }
    if salt.salt.is_empty() {
        return Err(Fido2Error::MissingSalt);
    }
    if salt.up > 0 && record.fido2_user_presence_permitted <= 0 {
        return Err(Fido2Error::UserPresenceNotPermitted);
    }
    if salt.uv > 0 && record.fido2_user_verification_permitted <= 0 {
        return Err(Fido2Error::UserVerificationNotPermitted);
    }
    if salt.client_pin > 0 && secret.token_pin.is_empty() {
        return Err(Fido2Error::MissingTokenPin);
    }

    Ok(format!(
        "{}:{}:{}",
        encode_hex(&salt.credential_id),
        encode_hex(&salt.salt),
        secret.token_pin.first().cloned().unwrap_or_default()
    ))
}

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
        record.fido2_user_presence_permitted = 1;
        record.fido2_user_verification_permitted = 1;
        record
    }

    fn secret() -> UserRecord {
        let mut secret = UserRecord::new();
        secret.token_pin.push("1234".into());
        secret
    }

    fn salt() -> Fido2HmacSalt {
        Fido2HmacSalt {
            salt: b"salt".to_vec(),
            up: 0,
            uv: 0,
            client_pin: 0,
            credential_id: b"cred".to_vec(),
        }
    }

    #[test]
    fn use_token_rejects_missing_credential() {
        let mut value = salt();
        value.credential_id.clear();
        assert_eq!(
            fido2_use_token(&record(), &secret(), &value),
            Err(Fido2Error::MissingCredential)
        );
    }

    #[test]
    fn use_token_rejects_missing_salt() {
        let mut value = salt();
        value.salt.clear();
        assert_eq!(
            fido2_use_token(&record(), &secret(), &value),
            Err(Fido2Error::MissingSalt)
        );
    }

    #[test]
    fn use_token_requires_user_presence_permission() {
        let mut value = salt();
        value.up = 1;
        let denied = UserRecord::new();
        assert_eq!(
            fido2_use_token(&denied, &secret(), &value),
            Err(Fido2Error::UserPresenceNotPermitted)
        );
    }

    #[test]
    fn use_token_requires_user_verification_permission() {
        let mut value = salt();
        value.uv = 1;
        let denied = UserRecord::new();
        assert_eq!(
            fido2_use_token(&denied, &secret(), &value),
            Err(Fido2Error::UserVerificationNotPermitted)
        );
    }

    #[test]
    fn use_token_requires_pin_when_requested() {
        let mut value = salt();
        value.client_pin = 1;
        assert_eq!(
            fido2_use_token(&record(), &UserRecord::new(), &value),
            Err(Fido2Error::MissingTokenPin)
        );
    }

    #[test]
    fn use_token_formats_hex_output() {
        let result = fido2_use_token(&record(), &secret(), &salt()).unwrap();
        assert_eq!(result, "63726564:73616c74:1234");
    }

    #[test]
    fn use_token_allows_up_and_uv_when_permitted() {
        let mut value = salt();
        value.up = 1;
        value.uv = 1;
        assert!(fido2_use_token(&record(), &secret(), &value).is_ok());
    }

    #[test]
    fn encode_hex_handles_empty_slice() {
        assert_eq!(encode_hex(&[]), "");
    }

    #[test]
    fn encode_hex_handles_binary_data() {
        assert_eq!(encode_hex(&[0, 15, 255]), "000fff");
    }
}
