/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hostname-setup.h"
#include "tests.h"

TEST(hostname_source_to_string) {
        ASSERT_STREQ(hostname_source_to_string(HOSTNAME_STATIC), "static");
        ASSERT_STREQ(hostname_source_to_string(HOSTNAME_TRANSIENT), "transient");
        ASSERT_STREQ(hostname_source_to_string(HOSTNAME_DEFAULT), "default");
}

TEST(hostname_source_from_string) {
        ASSERT_EQ(hostname_source_from_string("static"), HOSTNAME_STATIC);
        ASSERT_EQ(hostname_source_from_string("transient"), HOSTNAME_TRANSIENT);
        ASSERT_EQ(hostname_source_from_string("default"), HOSTNAME_DEFAULT);
        ASSERT_EQ(hostname_source_from_string("invalid"), _HOSTNAME_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
