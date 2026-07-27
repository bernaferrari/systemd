/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "gpt.h"
#include "tests.h"

TEST(partition_designator) {
        /* String table lookup */
        ASSERT_NOT_NULL(partition_designator_to_string(PARTITION_ROOT));
        ASSERT_NOT_NULL(partition_designator_to_string(PARTITION_USR));
        ASSERT_NOT_NULL(partition_designator_to_string(PARTITION_HOME));

        /* Invalid designator */
        ASSERT_NULL(partition_designator_to_string(_PARTITION_DESIGNATOR_INVALID));

        /* from_string returns value directly */
        PartitionDesignator d = partition_designator_from_string("root");
        ASSERT_GE(d, 0);
        ASSERT_EQ(d, PARTITION_ROOT);
}

TEST(partition_designator_verity) {
        /* verity_hash_of should return a hash designator */
        PartitionDesignator h = partition_verity_hash_of(PARTITION_ROOT);
        ASSERT_GE(h, 0);
        ASSERT_NE(h, PARTITION_ROOT);

        /* verity_sig_of should return a sig designator */
        PartitionDesignator s = partition_verity_sig_of(PARTITION_ROOT);
        ASSERT_GE(s, 0);
        ASSERT_NE(s, PARTITION_ROOT);
        ASSERT_NE(s, h);

        /* Non-verity partition should return invalid */
        ASSERT_LT(partition_verity_hash_of(PARTITION_SWAP), 0);
}

TEST(gpt_partition_type_knows) {
        /* Root partition type from table */
        GptPartitionType t = gpt_partition_type_table[PARTITION_ROOT];

        /* Root knows read-only */
        ASSERT_TRUE(gpt_partition_type_knows_read_only(t));

        /* Swap does have a filesystem type */
        t = gpt_partition_type_table[PARTITION_SWAP];
        ASSERT_TRUE(gpt_partition_type_has_filesystem(t));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
