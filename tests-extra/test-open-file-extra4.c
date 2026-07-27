/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "open-file.h"
#include "string-util.h"
#include "tests.h"

TEST(open_file_flags_to_from_string) {
        assert_se(streq(open_file_flags_to_string(OPENFILE_READ_ONLY), "read-only"));
        assert_se(streq(open_file_flags_to_string(OPENFILE_APPEND), "append"));
        assert_se(streq(open_file_flags_to_string(OPENFILE_TRUNCATE), "truncate"));
        assert_se(streq(open_file_flags_to_string(OPENFILE_GRACEFUL), "graceful"));

        assert_se(open_file_flags_from_string("read-only") == OPENFILE_READ_ONLY);
        assert_se(open_file_flags_from_string("append") == OPENFILE_APPEND);
        assert_se(open_file_flags_from_string("truncate") == OPENFILE_TRUNCATE);
        assert_se(open_file_flags_from_string("graceful") == OPENFILE_GRACEFUL);
        assert_se(open_file_flags_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
