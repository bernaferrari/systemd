// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homectl-recovery-key.c, src/home/homectl-recovery-key.h

pub const RECOVERY_KEY_ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
pub const RECOVERY_KEY_GROUPS: usize = 8;
pub const RECOVERY_KEY_GROUP_SIZE: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryKeyError {
    InvalidLength(usize),
    InvalidCharacter(char),
}

impl std::fmt::Display for RecoveryKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength(length) => write!(f, "invalid recovery key length: {length}"),
            Self::InvalidCharacter(ch) => write!(f, "invalid recovery key character: {ch}"),
        }
    }
}

impl std::error::Error for RecoveryKeyError {}

pub fn generate_recovery_key() -> String {
    let total = RECOVERY_KEY_GROUPS * RECOVERY_KEY_GROUP_SIZE;
    let mut out = String::with_capacity(total + RECOVERY_KEY_GROUPS - 1);
    for index in 0..total {
        if index > 0 && index % RECOVERY_KEY_GROUP_SIZE == 0 {
            out.push('-');
        }
        out.push(RECOVERY_KEY_ALPHABET[(index * 7 + 3) % RECOVERY_KEY_ALPHABET.len()] as char);
    }
    out
}

pub fn normalize_recovery_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| *ch != '-')
        .collect::<String>()
        .to_ascii_uppercase()
}

pub fn validate_recovery_key(value: &str) -> Result<(), RecoveryKeyError> {
    let normalized = normalize_recovery_key(value);
    let expected = RECOVERY_KEY_GROUPS * RECOVERY_KEY_GROUP_SIZE;
    if normalized.len() != expected {
        return Err(RecoveryKeyError::InvalidLength(normalized.len()));
    }

    for ch in normalized.chars() {
        if !RECOVERY_KEY_ALPHABET.contains(&(ch as u8)) {
            return Err(RecoveryKeyError::InvalidCharacter(ch));
        }
    }

    Ok(())
}

pub fn add_public() -> String {
    generate_recovery_key()
}

pub fn add_secret(password: &str) -> Result<String, RecoveryKeyError> {
    validate_recovery_key(password)?;
    Ok(normalize_recovery_key(password))
}

pub fn add_privileged(hashed: &str) -> Result<String, RecoveryKeyError> {
    validate_recovery_key(hashed)?;
    Ok(format!("hashed:{}", normalize_recovery_key(hashed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_has_expected_grouping() {
        let key = generate_recovery_key();
        assert_eq!(key.split('-').count(), RECOVERY_KEY_GROUPS);
    }

    #[test]
    fn generated_key_validates() {
        assert!(validate_recovery_key(&generate_recovery_key()).is_ok());
    }

    #[test]
    fn normalize_strips_dashes_and_uppercases() {
        assert_eq!(normalize_recovery_key("abcd-efgh"), "ABCDEFGH");
    }

    #[test]
    fn validate_rejects_short_key() {
        assert_eq!(
            validate_recovery_key("ABCD"),
            Err(RecoveryKeyError::InvalidLength(4))
        );
    }

    #[test]
    fn validate_rejects_invalid_character() {
        let invalid = format!("{}!", "A".repeat(31));
        assert_eq!(
            validate_recovery_key(&invalid),
            Err(RecoveryKeyError::InvalidCharacter('!'))
        );
    }

    #[test]
    fn add_public_returns_valid_key() {
        assert!(validate_recovery_key(&add_public()).is_ok());
    }

    #[test]
    fn add_secret_returns_normalized_key() {
        let key = generate_recovery_key().to_ascii_lowercase();
        assert_eq!(add_secret(&key).unwrap(), normalize_recovery_key(&key));
    }

    #[test]
    fn add_privileged_prefixes_hash_marker() {
        let key = generate_recovery_key();
        assert!(add_privileged(&key).unwrap().starts_with("hashed:"));
    }

    #[test]
    fn add_secret_reuses_validation() {
        assert_eq!(add_secret("bad"), Err(RecoveryKeyError::InvalidLength(3)));
    }
}
