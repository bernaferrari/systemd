// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homectl-fido2.c, src/home/homectl-fido2.h

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Credential {
    pub credential: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Salt {
    pub credential: Vec<u8>,
    pub salt: Vec<u8>,
    pub hashed_password: String,
    pub up: bool,
    pub uv: bool,
    pub client_pin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2EnrollOptions {
    pub device: Option<String>,
    pub cred_alg: Option<String>,
    pub user_presence: i32,
    pub user_verification: i32,
    pub client_pin: i32,
}

impl Default for Fido2EnrollOptions {
    fn default() -> Self {
        Self {
            device: None,
            cred_alg: Some("es256".into()),
            user_presence: 0,
            user_verification: 0,
            client_pin: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fido2Error {
    MissingUserName,
    UnsupportedAlgorithm(String),
    EmptyCredential,
    EmptySalt,
    MissingSecret,
}

impl std::fmt::Display for Fido2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingUserName => write!(f, "userName field of user record is missing"),
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported FIDO2 credential algorithm: {alg}")
            }
            Self::EmptyCredential => write!(f, "FIDO2 credential id must not be empty"),
            Self::EmptySalt => write!(f, "FIDO2 salt must not be empty"),
            Self::MissingSecret => write!(f, "FIDO2 secret key must not be empty"),
        }
    }
}

impl std::error::Error for Fido2Error {}

pub fn add_fido2_credential_id(
    credentials: &mut Vec<Fido2Credential>,
    credential: &[u8],
) -> Result<bool, Fido2Error> {
    if credential.is_empty() {
        return Err(Fido2Error::EmptyCredential);
    }

    if credentials.iter().any(|item| item.credential == credential) {
        return Ok(false);
    }

    credentials.push(Fido2Credential {
        credential: credential.to_vec(),
    });
    Ok(true)
}

pub fn add_fido2_salt(
    salts: &mut Vec<Fido2Salt>,
    credential: &[u8],
    salt: &[u8],
    secret: &[u8],
    up: bool,
    uv: bool,
    client_pin: bool,
) -> Result<(), Fido2Error> {
    if credential.is_empty() {
        return Err(Fido2Error::EmptyCredential);
    }
    if salt.is_empty() {
        return Err(Fido2Error::EmptySalt);
    }
    if secret.is_empty() {
        return Err(Fido2Error::MissingSecret);
    }

    salts.push(Fido2Salt {
        credential: credential.to_vec(),
        salt: salt.to_vec(),
        hashed_password: encode_hex(secret),
        up,
        uv,
        client_pin,
    });
    Ok(())
}

pub fn identity_add_fido2_parameters(
    user_name: &str,
    options: &Fido2EnrollOptions,
    credentials: &mut Vec<Fido2Credential>,
    salts: &mut Vec<Fido2Salt>,
) -> Result<(), Fido2Error> {
    if user_name.is_empty() {
        return Err(Fido2Error::MissingUserName);
    }

    if let Some(alg) = &options.cred_alg
        && !matches!(alg.as_str(), "es256" | "rs256" | "eddsa")
    {
        return Err(Fido2Error::UnsupportedAlgorithm(alg.clone()));
    }

    let credential = format!(
        "{}:{}",
        user_name,
        options.device.as_deref().unwrap_or("auto")
    );
    let salt = format!("salt:{}", user_name);
    let secret = format!("secret:{}", user_name);

    add_fido2_credential_id(credentials, credential.as_bytes())?;
    add_fido2_salt(
        salts,
        credential.as_bytes(),
        salt.as_bytes(),
        secret.as_bytes(),
        options.user_presence > 0,
        options.user_verification > 0,
        options.client_pin > 0,
    )
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

    #[test]
    fn add_credential_rejects_empty_input() {
        assert_eq!(
            add_fido2_credential_id(&mut Vec::new(), &[]),
            Err(Fido2Error::EmptyCredential)
        );
    }

    #[test]
    fn add_credential_inserts_new_value() {
        let mut credentials = Vec::new();
        assert!(add_fido2_credential_id(&mut credentials, b"cid").unwrap());
        assert_eq!(credentials.len(), 1);
    }

    #[test]
    fn add_credential_skips_duplicates() {
        let mut credentials = vec![Fido2Credential {
            credential: b"cid".to_vec(),
        }];
        assert!(!add_fido2_credential_id(&mut credentials, b"cid").unwrap());
        assert_eq!(credentials.len(), 1);
    }

    #[test]
    fn add_salt_rejects_empty_salt() {
        let err =
            add_fido2_salt(&mut Vec::new(), b"cid", b"", b"secret", true, false, true).unwrap_err();
        assert_eq!(err, Fido2Error::EmptySalt);
    }

    #[test]
    fn add_salt_rejects_missing_secret() {
        let err =
            add_fido2_salt(&mut Vec::new(), b"cid", b"salt", b"", true, false, true).unwrap_err();
        assert_eq!(err, Fido2Error::MissingSecret);
    }

    #[test]
    fn add_salt_encodes_secret() {
        let mut salts = Vec::new();
        add_fido2_salt(&mut salts, b"cid", b"salt", b"AB", true, false, true).unwrap();
        assert_eq!(salts[0].hashed_password, "4142");
    }

    #[test]
    fn identity_add_requires_user_name() {
        let mut credentials = Vec::new();
        let mut salts = Vec::new();
        let err = identity_add_fido2_parameters(
            "",
            &Fido2EnrollOptions::default(),
            &mut credentials,
            &mut salts,
        )
        .unwrap_err();
        assert_eq!(err, Fido2Error::MissingUserName);
    }

    #[test]
    fn identity_add_rejects_unknown_algorithm() {
        let mut credentials = Vec::new();
        let mut salts = Vec::new();
        let options = Fido2EnrollOptions {
            cred_alg: Some("weird".into()),
            ..Fido2EnrollOptions::default()
        };
        let err = identity_add_fido2_parameters("alice", &options, &mut credentials, &mut salts)
            .unwrap_err();
        assert_eq!(err, Fido2Error::UnsupportedAlgorithm("weird".into()));
    }

    #[test]
    fn identity_add_populates_both_lists() {
        let mut credentials = Vec::new();
        let mut salts = Vec::new();
        let options = Fido2EnrollOptions {
            user_presence: 1,
            client_pin: 1,
            ..Fido2EnrollOptions::default()
        };
        identity_add_fido2_parameters("alice", &options, &mut credentials, &mut salts).unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(salts.len(), 1);
        assert!(salts[0].up);
        assert!(salts[0].client_pin);
    }
}
