/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "geneve-util.h"
#include "tests.h"

TEST(geneve_df) {
        ASSERT_STREQ(geneve_df_to_string(NETDEV_GENEVE_DF_UNSET), "unset");
        ASSERT_STREQ(geneve_df_to_string(NETDEV_GENEVE_DF_SET), "set");
        ASSERT_STREQ(geneve_df_to_string(NETDEV_GENEVE_DF_INHERIT), "inherit");
        ASSERT_EQ(geneve_df_from_string("unset"), NETDEV_GENEVE_DF_UNSET);
        ASSERT_EQ(geneve_df_from_string("set"), NETDEV_GENEVE_DF_SET);
        ASSERT_EQ(geneve_df_from_string("inherit"), NETDEV_GENEVE_DF_INHERIT);
        ASSERT_EQ(geneve_df_from_string("invalid"), _NETDEV_GENEVE_DF_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
