// SPDX-License-Identifier: LGPL-2.1-or-later

use super::model::{Architecture, GptPartitionType, Id128, PartitionDesignator};
use super::table;

fn find_by_uuid(id: Id128) -> Option<GptPartitionType> {
    table::entries()
        .iter()
        .copied()
        .find(|partition_type| partition_type.uuid == id)
}

/// Looks up a canonical partition type name by UUID.
pub fn gpt_partition_type_uuid_to_string(id: Id128) -> Option<String> {
    find_by_uuid(id).map(|partition_type| partition_type.name.to_owned())
}

/// Returns the canonical type name when known, or UUID text otherwise.
pub fn gpt_partition_type_uuid_to_string_harder(id: Id128) -> String {
    gpt_partition_type_uuid_to_string(id).unwrap_or_else(|| id.to_string_uuid())
}

/// Resolves an exact table name or an `sd_id128_from_string`-compatible UUID.
///
/// Alias names are re-resolved through their UUID, which ensures the first,
/// canonical C table spelling is returned.
pub fn gpt_partition_type_from_string(name_or_uuid: &str) -> Option<GptPartitionType> {
    if let Some(id) = table::entries()
        .iter()
        .find(|partition_type| partition_type.name == name_or_uuid)
        .map(|partition_type| partition_type.uuid)
    {
        return Some(gpt_partition_type_from_uuid(id));
    }

    parse_id128_string(name_or_uuid).map(gpt_partition_type_from_uuid)
}

/// Resolves a UUID, preserving unknown UUIDs in an invalid metadata wrapper.
pub fn gpt_partition_type_from_uuid(id: Id128) -> GptPartitionType {
    find_by_uuid(id).unwrap_or(GptPartitionType {
        uuid: id,
        name: "",
        arch: Architecture::Invalid,
        designator: PartitionDesignator::Invalid,
    })
}

/// Returns the first canonical entry for the same designator and architecture.
pub fn gpt_partition_type_override_architecture(
    partition_type: GptPartitionType,
    architecture: Architecture,
) -> GptPartitionType {
    if architecture == Architecture::Invalid {
        return partition_type;
    }

    table::entries()
        .iter()
        .copied()
        .find(|candidate| {
            candidate.designator == partition_type.designator && candidate.arch == architecture
        })
        .unwrap_or(partition_type)
}

/// Returns the architecture associated with a known UUID.
pub fn gpt_partition_type_uuid_to_arch(id: Id128) -> Architecture {
    find_by_uuid(id)
        .map(|partition_type| partition_type.arch)
        .unwrap_or(Architecture::Invalid)
}

/// Returns the C-compatible NUL-separated mountpoint list, if any.
pub fn gpt_partition_type_mountpoint_nulstr(
    partition_type: GptPartitionType,
) -> Option<&'static str> {
    partition_type.designator.mountpoint_nulstr()
}

/// Returns whether the read-only attribute is meaningful for this type.
pub fn gpt_partition_type_knows_read_only(partition_type: GptPartitionType) -> bool {
    matches!(
        partition_type.designator,
        PartitionDesignator::Root
            | PartitionDesignator::Usr
            | PartitionDesignator::RootVerity
            | PartitionDesignator::UsrVerity
            | PartitionDesignator::RootVeritySig
            | PartitionDesignator::UsrVeritySig
            | PartitionDesignator::Home
            | PartitionDesignator::Srv
            | PartitionDesignator::Var
            | PartitionDesignator::Tmp
            | PartitionDesignator::XBootldr
    )
}

/// Returns whether the grow-filesystem attribute is meaningful for this type.
pub fn gpt_partition_type_knows_growfs(partition_type: GptPartitionType) -> bool {
    matches!(
        partition_type.designator,
        PartitionDesignator::Root
            | PartitionDesignator::Usr
            | PartitionDesignator::Home
            | PartitionDesignator::Srv
            | PartitionDesignator::Var
            | PartitionDesignator::Tmp
            | PartitionDesignator::XBootldr
    )
}

/// Returns whether the no-auto attribute is meaningful for this type.
pub fn gpt_partition_type_knows_no_auto(partition_type: GptPartitionType) -> bool {
    matches!(
        partition_type.designator,
        PartitionDesignator::Root
            | PartitionDesignator::RootVerity
            | PartitionDesignator::Usr
            | PartitionDesignator::UsrVerity
            | PartitionDesignator::Home
            | PartitionDesignator::Srv
            | PartitionDesignator::Var
            | PartitionDesignator::Tmp
            | PartitionDesignator::XBootldr
            | PartitionDesignator::Swap
    )
}

/// Returns whether this partition type is expected to contain a filesystem.
pub fn gpt_partition_type_has_filesystem(partition_type: GptPartitionType) -> bool {
    matches!(
        partition_type.designator,
        PartitionDesignator::Root
            | PartitionDesignator::Usr
            | PartitionDesignator::Home
            | PartitionDesignator::Srv
            | PartitionDesignator::Esp
            | PartitionDesignator::XBootldr
            | PartitionDesignator::Tmp
            | PartitionDesignator::Var
    )
}

/// Returns whether version selection applies to this designator.
pub fn partition_designator_is_versioned(designator: PartitionDesignator) -> bool {
    matches!(
        designator,
        PartitionDesignator::Root
            | PartitionDesignator::Usr
            | PartitionDesignator::RootVerity
            | PartitionDesignator::UsrVerity
            | PartitionDesignator::RootVeritySig
            | PartitionDesignator::UsrVeritySig
    )
}

/// Maps a data designator to its verity hash designator.
pub fn partition_verity_hash_of(designator: PartitionDesignator) -> PartitionDesignator {
    match designator {
        PartitionDesignator::Root => PartitionDesignator::RootVerity,
        PartitionDesignator::Usr => PartitionDesignator::UsrVerity,
        _ => PartitionDesignator::Invalid,
    }
}

/// Maps a data designator to its verity signature designator.
pub fn partition_verity_sig_of(designator: PartitionDesignator) -> PartitionDesignator {
    match designator {
        PartitionDesignator::Root => PartitionDesignator::RootVeritySig,
        PartitionDesignator::Usr => PartitionDesignator::UsrVeritySig,
        _ => PartitionDesignator::Invalid,
    }
}

/// Maps a verity hash designator back to its data designator.
pub fn partition_verity_hash_to_data(designator: PartitionDesignator) -> PartitionDesignator {
    match designator {
        PartitionDesignator::RootVerity => PartitionDesignator::Root,
        PartitionDesignator::UsrVerity => PartitionDesignator::Usr,
        _ => PartitionDesignator::Invalid,
    }
}

/// Maps a verity signature designator back to its data designator.
pub fn partition_verity_sig_to_data(designator: PartitionDesignator) -> PartitionDesignator {
    match designator {
        PartitionDesignator::RootVeritySig => PartitionDesignator::Root,
        PartitionDesignator::UsrVeritySig => PartitionDesignator::Usr,
        _ => PartitionDesignator::Invalid,
    }
}

/// Maps either verity designator kind back to its data designator.
pub fn partition_verity_to_data(designator: PartitionDesignator) -> PartitionDesignator {
    let data = partition_verity_hash_to_data(designator);
    if data != PartitionDesignator::Invalid {
        return data;
    }
    partition_verity_sig_to_data(designator)
}

pub fn partition_designator_is_verity_hash(designator: PartitionDesignator) -> bool {
    partition_verity_hash_to_data(designator) != PartitionDesignator::Invalid
}

pub fn partition_designator_is_verity_sig(designator: PartitionDesignator) -> bool {
    partition_verity_sig_to_data(designator) != PartitionDesignator::Invalid
}

pub fn partition_designator_is_verity(designator: PartitionDesignator) -> bool {
    partition_verity_to_data(designator) != PartitionDesignator::Invalid
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Mirrors the two accepted `sd_id128_from_string()` spellings: 32 plain hex
/// digits or the canonical 36-character UUID form.
pub(super) fn parse_id128_string(value: &str) -> Option<Id128> {
    let source = value.as_bytes();
    let positions: &[usize; 16] = match source.len() {
        32 => &[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30],
        36 if source[8] == b'-'
            && source[13] == b'-'
            && source[18] == b'-'
            && source[23] == b'-' =>
        {
            &[0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34]
        }
        _ => return None,
    };

    let mut bytes = [0; 16];
    for (index, position) in positions.iter().copied().enumerate() {
        bytes[index] = (hex_nibble(source[position])? << 4) | hex_nibble(source[position + 1])?;
    }
    Some(Id128::from_bytes(bytes))
}
