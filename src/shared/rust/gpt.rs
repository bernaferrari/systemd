// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/gpt.c, src/shared/gpt.h, src/systemd/sd-gpt.h
//
// Public facade for the safe Rust GPT model and pure lookup/validation logic.
// Runtime probing, target-native aliases, C ABI, and production integration are
// deliberately tracked separately; this module does not claim those boundaries.

mod header;
mod lookup;
mod model;
mod table;
mod table_data;

pub use header::{
    GPT_HEADER_BASE_SIZE, GPT_HEADER_REVISION, GPT_HEADER_SIGNATURE, GPT_LABEL_MAX,
    gpt_header_has_signature, gpt_partition_label_valid,
};
pub use lookup::{
    gpt_partition_type_from_string, gpt_partition_type_from_uuid,
    gpt_partition_type_has_filesystem, gpt_partition_type_knows_growfs,
    gpt_partition_type_knows_no_auto, gpt_partition_type_knows_read_only,
    gpt_partition_type_mountpoint_nulstr, gpt_partition_type_override_architecture,
    gpt_partition_type_uuid_to_arch, gpt_partition_type_uuid_to_string,
    gpt_partition_type_uuid_to_string_harder, partition_designator_is_verity,
    partition_designator_is_verity_hash, partition_designator_is_verity_sig,
    partition_designator_is_versioned, partition_verity_hash_of, partition_verity_hash_to_data,
    partition_verity_sig_of, partition_verity_sig_to_data, partition_verity_to_data,
};
pub use model::{Architecture, GptPartitionType, Id128, PartitionDesignator};
pub use table::gpt_partition_type_table;

#[cfg(test)]
mod tests;
