// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/pcrextend/pcrextend.c
pub const EXTENSION_STRING_SAFE_LIMIT: usize = 1024;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidBank(String),
    InvalidPcrIndex(u32),
    InvalidNvPcrName(String),
    ConflictingTargets,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBank(bank) => write!(f, "invalid bank {bank:?}"),
            Self::InvalidPcrIndex(index) => write!(f, "invalid PCR index {index}"),
            Self::InvalidNvPcrName(name) => write!(f, "invalid NvPCR name {name:?}"),
            Self::ConflictingTargets => write!(
                f,
                "--file-system, --machine-id and --product-id may not be combined"
            ),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm2UserspaceEventType {
    Ima,
    ImaNg,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendTarget {
    Word(String),
    FileSystem(String),
    MachineId,
    ProductId,
}

pub fn normalize_bank(value: &str) -> Result<String> {
    match value.to_ascii_lowercase().as_str() {
        "sha1" => Ok("SHA1".to_string()),
        "sha256" => Ok("SHA256".to_string()),
        "sha384" => Ok("SHA384".to_string()),
        "sha512" => Ok("SHA512".to_string()),
        other => Err(Error::InvalidBank(other.to_string())),
    }
}

pub fn pcr_index_mask(index: u32) -> Result<u32> {
    if index < 24 {
        Ok(1u32 << index)
    } else {
        Err(Error::InvalidPcrIndex(index))
    }
}

pub fn validate_nvpcr_name(name: &str) -> Result<()> {
    if !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        Ok(())
    } else {
        Err(Error::InvalidNvPcrName(name.to_string()))
    }
}

pub fn event_type_from_string(value: &str) -> Option<Tpm2UserspaceEventType> {
    match value {
        "ima" => Some(Tpm2UserspaceEventType::Ima),
        "ima-ng" => Some(Tpm2UserspaceEventType::ImaNg),
        _ => None,
    }
}

pub fn validate_target_selection(targets: &[ExtendTarget]) -> Result<()> {
    let special_targets = targets
        .iter()
        .filter(|target| !matches!(target, ExtendTarget::Word(_)))
        .count();
    if special_targets > 1 {
        Err(Error::ConflictingTargets)
    } else {
        Ok(())
    }
}

pub fn escape_and_truncate_data(data: &[u8], max_len: usize) -> String {
    let limit = max_len.min(EXTENSION_STRING_SAFE_LIMIT);
    data.iter()
        .take(limit)
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_bank_accepts_supported_hashes() {
        assert_eq!(normalize_bank("sha256").unwrap(), "SHA256");
        assert_eq!(normalize_bank("SHA1").unwrap(), "SHA1");
    }

    #[test]
    fn normalize_bank_rejects_unknown_hash() {
        assert_eq!(
            normalize_bank("md5"),
            Err(Error::InvalidBank("md5".to_string()))
        );
    }

    #[test]
    fn pcr_index_mask_accepts_valid_range() {
        assert_eq!(pcr_index_mask(0).unwrap(), 1);
        assert_eq!(pcr_index_mask(23).unwrap(), 1 << 23);
    }

    #[test]
    fn pcr_index_mask_rejects_out_of_range_index() {
        assert_eq!(pcr_index_mask(24), Err(Error::InvalidPcrIndex(24)));
    }

    #[test]
    fn validate_nvpcr_name_accepts_simple_identifiers() {
        assert_eq!(validate_nvpcr_name("hardware"), Ok(()));
        assert_eq!(validate_nvpcr_name("phase-1"), Ok(()));
    }

    #[test]
    fn validate_nvpcr_name_rejects_spaces() {
        assert_eq!(
            validate_nvpcr_name("bad name"),
            Err(Error::InvalidNvPcrName("bad name".to_string()))
        );
    }

    #[test]
    fn event_type_from_string_matches_known_types() {
        assert_eq!(
            event_type_from_string("ima-ng"),
            Some(Tpm2UserspaceEventType::ImaNg)
        );
        assert_eq!(event_type_from_string("other"), None);
    }

    #[test]
    fn target_selection_rejects_multiple_special_modes() {
        let targets = vec![ExtendTarget::MachineId, ExtendTarget::ProductId];
        assert_eq!(
            validate_target_selection(&targets),
            Err(Error::ConflictingTargets)
        );
    }

    #[test]
    fn escape_and_truncate_data_replaces_non_printable_bytes() {
        assert_eq!(escape_and_truncate_data(b"abc\n\0xyz", 8), "abc..xyz");
    }
}
