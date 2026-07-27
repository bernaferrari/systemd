// SPDX-License-Identifier: LGPL-2.1-or-later

use super::model::GptPartitionType;
use super::table_data::GPT_PARTITION_TYPE_TABLE;

/// Returns the architecture-neutral portion of C's GPT partition type table.
///
/// The owned `Vec` preserves the original Rust facade. Internal lookups use the
/// checked-in static slice directly and do not allocate.
pub fn gpt_partition_type_table() -> Vec<GptPartitionType> {
    GPT_PARTITION_TYPE_TABLE.to_vec()
}

pub(super) const fn entries() -> &'static [GptPartitionType] {
    GPT_PARTITION_TYPE_TABLE
}
