// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd/sd-journal/journal-file.c, src/libsystemd/sd-journal/journal-def.h

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;

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
        match self {
            Self::Unused => "unused",
            Self::Data => "data",
            Self::Field => "field",
            Self::Entry => "entry",
            Self::DataHashTable => "data hash table",
            Self::FieldHashTable => "field hash table",
            Self::EntryArray => "entry array",
            Self::Tag => "tag",
        }
    }

    pub fn is_hash_table(self) -> bool {
        matches!(self, Self::DataHashTable | Self::FieldHashTable)
    }
}

pub fn journal_object_type_to_string(value: ObjectType) -> &'static str {
    value.as_str()
}

pub fn journal_object_type_from_string(s: &str) -> Result<ObjectType> {
    match s {
        "unused" => Ok(ObjectType::Unused),
        "data" => Ok(ObjectType::Data),
        "field" => Ok(ObjectType::Field),
        "entry" => Ok(ObjectType::Entry),
        "data hash table" => Ok(ObjectType::DataHashTable),
        "field hash table" => Ok(ObjectType::FieldHashTable),
        "entry array" => Ok(ObjectType::EntryArray),
        "tag" => Ok(ObjectType::Tag),
        _ => Err(NEG_EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats_unused() {
        assert_eq!(journal_object_type_to_string(ObjectType::Unused), "unused");
    }
    #[test]
    fn formats_data_hash_table() {
        assert_eq!(
            journal_object_type_to_string(ObjectType::DataHashTable),
            "data hash table"
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
        assert_eq!(journal_object_type_from_string("blob"), Err(NEG_EINVAL));
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
}
