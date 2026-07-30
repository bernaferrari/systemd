// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/user-record-password-quality.c, src/home/user-record-password-quality.h

use crate::user_record_util::UserRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordQualityError {
    TooShort,
    TooSimple,
    ReusedPassword,
}

impl std::fmt::Display for PasswordQualityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "password is too short"),
            Self::TooSimple => write!(f, "password is too weak"),
            Self::ReusedPassword => write!(f, "password was already used"),
        }
    }
}

impl std::error::Error for PasswordQualityError {}

pub fn check_password_quality(
    password: &str,
    old_password: Option<&str>,
    user_name: &str,
) -> Result<(), PasswordQualityError> {
    if password.len() < 8 {
        return Err(PasswordQualityError::TooShort);
    }

    let has_letter = password.chars().any(char::is_alphabetic);
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());
    if !(has_letter && has_digit && has_symbol) {
        return Err(PasswordQualityError::TooSimple);
    }

    if !user_name.is_empty()
        && password
            .to_ascii_lowercase()
            .contains(&user_name.to_ascii_lowercase())
    {
        return Err(PasswordQualityError::TooSimple);
    }

    if let Some(old_password) = old_password
        && password == old_password
    {
        return Err(PasswordQualityError::ReusedPassword);
    }

    Ok(())
}

pub fn user_record_check_password_quality(
    hr: &UserRecord,
    secret: &UserRecord,
) -> Result<bool, PasswordQualityError> {
    for password in &secret.password {
        if hr.hashed_password.iter().any(|old| old == password) {
            continue;
        }

        let mut checked_against_old = false;
        for old_password in &secret.password {
            if old_password == password {
                continue;
            }

            if hr
                .hashed_password
                .iter()
                .any(|candidate| candidate == old_password)
            {
                check_password_quality(password, Some(old_password), &hr.user_name)?;
                checked_against_old = true;
            }
        }

        if !checked_against_old {
            check_password_quality(password, None, &hr.user_name)?;
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hr() -> UserRecord {
        let mut record = UserRecord::new();
        record.user_name = "alice".into();
        record.hashed_password = vec!["OldPass1!".into()];
        record
    }

    #[test]
    fn short_password_is_rejected() {
        assert_eq!(
            check_password_quality("Aa1!", None, "alice"),
            Err(PasswordQualityError::TooShort)
        );
    }

    #[test]
    fn password_without_symbol_is_rejected() {
        assert_eq!(
            check_password_quality("Password1", None, "alice"),
            Err(PasswordQualityError::TooSimple)
        );
    }

    #[test]
    fn password_containing_username_is_rejected() {
        assert_eq!(
            check_password_quality("Alice123!", None, "alice"),
            Err(PasswordQualityError::TooSimple)
        );
    }

    #[test]
    fn identical_old_password_is_rejected() {
        assert_eq!(
            check_password_quality("OldPass1!", Some("OldPass1!"), "alice"),
            Err(PasswordQualityError::ReusedPassword)
        );
    }

    #[test]
    fn strong_password_is_accepted() {
        assert!(check_password_quality("NewPass1!", Some("OldPass1!"), "alice").is_ok());
    }

    #[test]
    fn old_passwords_present_in_hashed_list_are_skipped_as_new() {
        let mut secret = UserRecord::new();
        secret.password = vec!["OldPass1!".into(), "NewPass1!".into()];
        assert!(user_record_check_password_quality(&hr(), &secret).unwrap());
    }

    #[test]
    fn brand_new_password_without_old_reference_is_checked() {
        let mut secret = UserRecord::new();
        secret.password = vec!["NewPass1!".into()];
        assert!(user_record_check_password_quality(&hr(), &secret).unwrap());
    }

    #[test]
    fn weak_new_password_is_rejected() {
        let mut secret = UserRecord::new();
        secret.password = vec!["OldPass1!".into(), "weakpass".into()];
        assert_eq!(
            user_record_check_password_quality(&hr(), &secret),
            Err(PasswordQualityError::TooSimple)
        );
    }

    #[test]
    fn reused_new_password_against_old_secret_is_rejected() {
        let mut secret = UserRecord::new();
        secret.password = vec!["OldPass1!".into(), "OldPass1!".into(), "NewPass1!".into()];
        assert!(user_record_check_password_quality(&hr(), &secret).is_ok());
    }
}
