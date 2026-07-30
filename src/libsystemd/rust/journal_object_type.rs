// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-journal/journal-file.c, src/libsystemd/sd-journal/journal-def.h

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;
pub const OBJECT_TYPE_MAX: i32 = 8;
pub const OBJECT_TYPE_INVALID: i32 = NEG_EINVAL;

/* Kept in the same order as journal_object_type_table in journal-file.c. */
const JOURNAL_OBJECT_TYPE_TABLE: [&str; OBJECT_TYPE_MAX as usize] = [
    "unused",
    "data",
    "field",
    "entry",
    "data hash table",
    "field hash table",
    "entry array",
    "tag",
];

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Unused = 0,
    Data = 1,
    Field = 2,
    Entry = 3,
    DataHashTable = 4,
    FieldHashTable = 5,
    EntryArray = 6,
    Tag = 7,
}

impl ObjectType {
    pub fn as_str(self) -> &'static str {
        journal_object_type_to_string(self as i32)
            .expect("all ObjectType variants have a journal object type table entry")
    }

    pub fn is_hash_table(self) -> bool {
        matches!(self, Self::DataHashTable | Self::FieldHashTable)
    }

    pub fn is_valid_on_disk(self) -> bool {
        self != Self::Unused
    }
}

impl TryFrom<i32> for ObjectType {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Unused),
            1 => Ok(Self::Data),
            2 => Ok(Self::Field),
            3 => Ok(Self::Entry),
            4 => Ok(Self::DataHashTable),
            5 => Ok(Self::FieldHashTable),
            6 => Ok(Self::EntryArray),
            7 => Ok(Self::Tag),
            _ => Err(OBJECT_TYPE_INVALID),
        }
    }
}

impl TryFrom<u8> for ObjectType {
    type Error = i32;

    fn try_from(value: u8) -> Result<Self> {
        let object_type = Self::try_from(i32::from(value))?;

        /* OBJECT_UNUSED is a wildcard for a requested type, never an object stored on disk. */
        if object_type.is_valid_on_disk() {
            Ok(object_type)
        } else {
            Err(OBJECT_TYPE_INVALID)
        }
    }
}

pub fn journal_object_type_to_string(value: i32) -> Option<&'static str> {
    usize::try_from(value)
        .ok()
        .and_then(|index| JOURNAL_OBJECT_TYPE_TABLE.get(index).copied())
}

pub fn journal_object_type_from_string(s: &str) -> Result<ObjectType> {
    JOURNAL_OBJECT_TYPE_TABLE
        .iter()
        .position(|entry| *entry == s)
        .and_then(|index| ObjectType::try_from(index as i32).ok())
        .ok_or(OBJECT_TYPE_INVALID)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats_unused() {
        assert_eq!(
            journal_object_type_to_string(ObjectType::Unused as i32),
            Some("unused")
        );
    }

    #[test]
    fn formats_data_hash_table() {
        assert_eq!(
            journal_object_type_to_string(ObjectType::DataHashTable as i32),
            Some("data hash table")
        );
    }

    #[test]
    fn parses_entry() {
        assert_eq!(
            journal_object_type_from_string("entry"),
            Ok(ObjectType::Entry)
        );
    }

    #[test]
    fn parses_tag() {
        assert_eq!(journal_object_type_from_string("tag"), Ok(ObjectType::Tag));
    }

    #[test]
    fn rejects_unknown_object_type() {
        assert_eq!(
            journal_object_type_from_string("blob"),
            Err(OBJECT_TYPE_INVALID)
        );
    }

    #[test]
    fn recognizes_hash_table_types() {
        assert!(ObjectType::FieldHashTable.is_hash_table());
    }

    #[test]
    fn rejects_non_hash_table_types() {
        assert!(!ObjectType::EntryArray.is_hash_table());
    }

    #[test]
    fn preserves_enum_values() {
        assert_eq!(ObjectType::Tag as i32, 7);
    }

    #[test]
    fn table_matches_all_c_object_type_entries() {
        for (value, expected) in JOURNAL_OBJECT_TYPE_TABLE.iter().enumerate() {
            assert_eq!(journal_object_type_to_string(value as i32), Some(*expected));
            assert_eq!(
                journal_object_type_from_string(expected),
                ObjectType::try_from(value as i32)
            );
        }
    }

    #[test]
    fn table_rejects_values_outside_c_range() {
        assert_eq!(journal_object_type_to_string(-1), None);
        assert_eq!(journal_object_type_to_string(OBJECT_TYPE_MAX), None);
        assert_eq!(ObjectType::try_from(-1_i32), Err(OBJECT_TYPE_INVALID));
        assert_eq!(
            ObjectType::try_from(OBJECT_TYPE_MAX),
            Err(OBJECT_TYPE_INVALID)
        );
    }

    #[test]
    fn raw_journal_types_reject_unused_and_unknown_values() {
        assert_eq!(ObjectType::try_from(0_u8), Err(OBJECT_TYPE_INVALID));
        assert_eq!(ObjectType::try_from(8_u8), Err(OBJECT_TYPE_INVALID));
        assert_eq!(ObjectType::try_from(u8::MAX), Err(OBJECT_TYPE_INVALID));
    }

    #[test]
    fn raw_journal_type_accepts_valid_stored_type() {
        assert_eq!(ObjectType::try_from(7_u8), Ok(ObjectType::Tag));
        assert!(ObjectType::Tag.is_valid_on_disk());
        assert!(!ObjectType::Unused.is_valid_on_disk());
    }
}
