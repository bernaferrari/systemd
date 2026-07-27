/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "gpt.h"
#include "tests.h"

TEST(partition_designator_to_string) {
        ASSERT_STREQ(partition_designator_to_string(PARTITION_ROOT), "root");
        ASSERT_STREQ(partition_designator_to_string(PARTITION_ROOT_VERITY), "root-verity");
        ASSERT_STREQ(partition_designator_to_string(PARTITION_USR), "usr");
        ASSERT_STREQ(partition_designator_to_string(PARTITION_HOME), "home");
        ASSERT_STREQ(partition_designator_to_string(PARTITION_SRV), "srv");
        ASSERT_STREQ(partition_designator_to_string(PARTITION_ESP), "esp");
        ASSERT_STREQ(partition_designator_to_string(PARTITION_XBOOTLDR), "xbootldr");
        ASSERT_STREQ(partition_designator_to_string(PARTITION_SWAP), "swap");
        ASSERT_STREQ(partition_designator_to_string(PARTITION_VAR), "var");
        ASSERT_STREQ(partition_designator_to_string(PARTITION_TMP), "tmp");
}

TEST(partition_designator_from_string) {
        ASSERT_EQ(partition_designator_from_string("root"), PARTITION_ROOT);
        ASSERT_EQ(partition_designator_from_string("usr"), PARTITION_USR);
        ASSERT_EQ(partition_designator_from_string("home"), PARTITION_HOME);
        ASSERT_EQ(partition_designator_from_string("esp"), PARTITION_ESP);
        ASSERT_EQ(partition_designator_from_string("swap"), PARTITION_SWAP);
        ASSERT_EQ(partition_designator_from_string("invalid"), _PARTITION_DESIGNATOR_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
