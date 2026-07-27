/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "geneve-util.h"
#include "string-util.h"
#include "tests.h"

TEST(geneve_df_to_from_string) {
        assert_se(streq(geneve_df_to_string(NETDEV_GENEVE_DF_UNSET), "unset"));
        assert_se(streq(geneve_df_to_string(NETDEV_GENEVE_DF_SET), "set"));
        assert_se(streq(geneve_df_to_string(NETDEV_GENEVE_DF_INHERIT), "inherit"));

        assert_se(geneve_df_from_string("unset") == NETDEV_GENEVE_DF_UNSET);
        assert_se(geneve_df_from_string("set") == NETDEV_GENEVE_DF_SET);
        assert_se(geneve_df_from_string("inherit") == NETDEV_GENEVE_DF_INHERIT);
        assert_se(geneve_df_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
