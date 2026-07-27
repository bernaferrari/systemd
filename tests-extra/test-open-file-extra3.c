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
        assert_se(open_file_flags_from_string("nonsense") < 0);
        assert_se(open_file_flags_from_string("") < 0);
}

TEST(open_file_parse_basic) {
        _cleanup_(open_file_freep) OpenFile *of = NULL;

        assert_se(open_file_parse("/tmp/file", &of) >= 0);
        assert_se(streq(of->path, "/tmp/file"));
        of = open_file_free(of);

        assert_se(open_file_parse("/tmp/file:fdname", &of) >= 0);
        assert_se(streq(of->path, "/tmp/file"));
        assert_se(streq(of->fdname, "fdname"));
        of = open_file_free(of);

        assert_se(open_file_parse("/tmp/file:fdname:read-only", &of) >= 0);
        assert_se(streq(of->path, "/tmp/file"));
        assert_se(FLAGS_SET(of->flags, OPENFILE_READ_ONLY));
        of = open_file_free(of);

        /* Too many colons */
        assert_se(open_file_parse("/tmp/file:fdname:read-only:extra", &of) == -EINVAL);

        /* Empty string */
        assert_se(open_file_parse("", &of) == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
