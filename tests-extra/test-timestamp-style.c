/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "time-util.h"
#include "tests.h"

TEST(timestamp_style_to_string) {
        ASSERT_STREQ(timestamp_style_to_string(TIMESTAMP_PRETTY), "pretty");
        ASSERT_STREQ(timestamp_style_to_string(TIMESTAMP_US), "us");
        ASSERT_STREQ(timestamp_style_to_string(TIMESTAMP_UTC), "utc");
        ASSERT_STREQ(timestamp_style_to_string(TIMESTAMP_US_UTC), "us+utc");
        ASSERT_STREQ(timestamp_style_to_string(TIMESTAMP_UNIX), "unix");
}

TEST(timestamp_style_from_string) {
        ASSERT_EQ(timestamp_style_from_string("pretty"), TIMESTAMP_PRETTY);
        ASSERT_EQ(timestamp_style_from_string("us"), TIMESTAMP_US);
        ASSERT_EQ(timestamp_style_from_string("utc"), TIMESTAMP_UTC);
        ASSERT_EQ(timestamp_style_from_string("us+utc"), TIMESTAMP_US_UTC);
        ASSERT_EQ(timestamp_style_from_string("unix"), TIMESTAMP_UNIX);

        /* Unicode micro symbol aliases */
        ASSERT_EQ(timestamp_style_from_string("\xC2\xB5s"), TIMESTAMP_US);  /* U+00B5 */
        ASSERT_EQ(timestamp_style_from_string("\xCE\xBCs"), TIMESTAMP_US);  /* U+03BC */
        ASSERT_EQ(timestamp_style_from_string("\xC2\xB5s+utc"), TIMESTAMP_US_UTC);
        ASSERT_EQ(timestamp_style_from_string("\xCE\xBCs+utc"), TIMESTAMP_US_UTC);

        ASSERT_EQ(timestamp_style_from_string("invalid"), _TIMESTAMP_STYLE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
