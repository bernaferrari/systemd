/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "open-file.h"
#include "tests.h"

TEST(open_file_flags_to_from_string) {
        ASSERT_STREQ(open_file_flags_to_string(OPENFILE_READ_ONLY), "read-only");
        ASSERT_STREQ(open_file_flags_to_string(OPENFILE_APPEND), "append");
        ASSERT_STREQ(open_file_flags_to_string(OPENFILE_TRUNCATE), "truncate");
        ASSERT_STREQ(open_file_flags_to_string(OPENFILE_GRACEFUL), "graceful");

        ASSERT_EQ(open_file_flags_from_string("read-only"), OPENFILE_READ_ONLY);
        ASSERT_EQ(open_file_flags_from_string("append"), OPENFILE_APPEND);
        ASSERT_EQ(open_file_flags_from_string("truncate"), OPENFILE_TRUNCATE);
        ASSERT_EQ(open_file_flags_from_string("graceful"), OPENFILE_GRACEFUL);
        ASSERT_EQ(open_file_flags_from_string("invalid"), _OPENFILE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
