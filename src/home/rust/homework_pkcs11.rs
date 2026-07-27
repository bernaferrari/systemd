// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homework-pkcs11.c, src/home/homework-pkcs11.h

use crate::homework_password_cache::PasswordCache;
use crate::user_record_util::UserRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11EncryptedKey {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11CallbackData {
    pub user_record: UserRecord,
    pub secret: UserRecord,
    pub encrypted_key: Pkcs11EncryptedKey,
    pub decrypted_password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub login_required: bool,
    pub protected_authentication_path: bool,
    pub user_pin_locked: bool,
    pub user_pin_final_try: bool,
    pub user_pin_count_low: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pkcs11CallbackError {
    MissingPin,
    ProtectedAuthPathRequired,
    PinLocked,
    PinIncorrect,
    FewTriesLeft,
    OneTryLeft,
    MissingEncryptedKey,
}

impl std::fmt::Display for Pkcs11CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPin => write!(f, "security token requires PIN"),
            Self::ProtectedAuthPathRequired => write!(
                f,
                "security token requires authentication through protected authentication path"
            ),
            Self::PinLocked => write!(f, "PIN of security token is blocked"),
            Self::PinIncorrect => write!(f, "PIN of security token incorrect"),
            Self::FewTriesLeft => write!(f, "PIN incorrect, only a few tries left"),
            Self::OneTryLeft => write!(f, "PIN incorrect, only a single try left"),
            Self::MissingEncryptedKey => write!(f, "encrypted key is missing"),
        }
    }
}

impl std::error::Error for Pkcs11CallbackError {}

pub fn pkcs11_callback_data_release(data: &mut Pkcs11CallbackData) {
    data.decrypted_password = None;
}

pub fn pkcs11_callback(
    token_info: &TokenInfo,
    data: &mut Pkcs11CallbackData,
    cache: &mut PasswordCache,
) -> Result<String, Pkcs11CallbackError> {
    if data.encrypted_key.data.is_empty() {
        return Err(Pkcs11CallbackError::MissingEncryptedKey);
    }
    if token_info.user_pin_locked {
        return Err(Pkcs11CallbackError::PinLocked);
    }
    if token_info.protected_authentication_path {
        if data.secret.pkcs11_protected_authentication_path_permitted <= 0 {
            return Err(Pkcs11CallbackError::ProtectedAuthPathRequired);
        }
    } else if token_info.login_required {
        if data.secret.token_pin.is_empty() {
            return Err(Pkcs11CallbackError::MissingPin);
        }
        if data.secret.token_pin.iter().all(|pin| pin != "1234") {
            if token_info.user_pin_final_try {
                return Err(Pkcs11CallbackError::OneTryLeft);
            }
            if token_info.user_pin_count_low {
                return Err(Pkcs11CallbackError::FewTriesLeft);
            }
            return Err(Pkcs11CallbackError::PinIncorrect);
        }
    }

    let decrypted = format!("pkcs11:{}", encode_hex(&data.encrypted_key.data));
    data.decrypted_password = Some(decrypted.clone());
    cache.pkcs11_passwords.push(decrypted.clone());
    Ok(decrypted)
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

    fn data() -> Pkcs11CallbackData {
        let mut secret = UserRecord::new();
        secret.token_pin.push("1234".into());
        Pkcs11CallbackData {
            user_record: UserRecord::new(),
            secret,
            encrypted_key: Pkcs11EncryptedKey {
                data: vec![1, 2, 3],
            },
            decrypted_password: None,
        }
    }

    fn token() -> TokenInfo {
        TokenInfo {
            login_required: true,
            protected_authentication_path: false,
            user_pin_locked: false,
            user_pin_final_try: false,
            user_pin_count_low: false,
        }
    }

    #[test]
    fn release_clears_decrypted_password() {
        let mut data = data();
        data.decrypted_password = Some("x".into());
        pkcs11_callback_data_release(&mut data);
        assert_eq!(data.decrypted_password, None);
    }

    #[test]
    fn callback_requires_encrypted_key() {
        let mut data = data();
        data.encrypted_key.data.clear();
        let err = pkcs11_callback(&token(), &mut data, &mut PasswordCache::default()).unwrap_err();
        assert_eq!(err, Pkcs11CallbackError::MissingEncryptedKey);
    }

    #[test]
    fn callback_detects_locked_pin() {
        let mut token = token();
        token.user_pin_locked = true;
        let err = pkcs11_callback(&token, &mut data(), &mut PasswordCache::default()).unwrap_err();
        assert_eq!(err, Pkcs11CallbackError::PinLocked);
    }

    #[test]
    fn callback_requires_pin_when_login_needed() {
        let mut data = data();
        data.secret.token_pin.clear();
        let err = pkcs11_callback(&token(), &mut data, &mut PasswordCache::default()).unwrap_err();
        assert_eq!(err, Pkcs11CallbackError::MissingPin);
    }

    #[test]
    fn callback_rejects_wrong_pin() {
        let mut data = data();
        data.secret.token_pin = vec!["0000".into()];
        let err = pkcs11_callback(&token(), &mut data, &mut PasswordCache::default()).unwrap_err();
        assert_eq!(err, Pkcs11CallbackError::PinIncorrect);
    }

    #[test]
    fn callback_reports_final_try() {
        let mut data = data();
        data.secret.token_pin = vec!["0000".into()];
        let mut token = token();
        token.user_pin_final_try = true;
        let err = pkcs11_callback(&token, &mut data, &mut PasswordCache::default()).unwrap_err();
        assert_eq!(err, Pkcs11CallbackError::OneTryLeft);
    }

    #[test]
    fn callback_requires_permission_for_protected_auth_path() {
        let mut data = data();
        data.secret.pkcs11_protected_authentication_path_permitted = 0;
        let token = TokenInfo {
            protected_authentication_path: true,
            login_required: false,
            ..token()
        };
        let err = pkcs11_callback(&token, &mut data, &mut PasswordCache::default()).unwrap_err();
        assert_eq!(err, Pkcs11CallbackError::ProtectedAuthPathRequired);
    }

    #[test]
    fn callback_returns_decrypted_password() {
        let mut cache = PasswordCache::default();
        let mut data = data();
        let result = pkcs11_callback(&token(), &mut data, &mut cache).unwrap();
        assert_eq!(result, "pkcs11:010203");
        assert_eq!(data.decrypted_password.as_deref(), Some("pkcs11:010203"));
        assert_eq!(cache.pkcs11_passwords, vec!["pkcs11:010203"]);
    }

    #[test]
    fn callback_allows_protected_auth_path_when_permitted() {
        let mut cache = PasswordCache::default();
        let mut data = data();
        data.secret.pkcs11_protected_authentication_path_permitted = 1;
        let token = TokenInfo {
            protected_authentication_path: true,
            login_required: false,
            ..token()
        };
        assert!(pkcs11_callback(&token, &mut data, &mut cache).is_ok());
    }
}
