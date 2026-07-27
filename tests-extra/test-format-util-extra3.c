/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "tests.h"

TEST(format_bytes_full_basic) {
        char buf[FORMAT_BYTES_MAX + 1];

        /* format_bytes_full returns NULL for t == UINT64_MAX */
        assert_se(format_bytes_full(buf, sizeof(buf), UINT64_MAX, 0) == NULL);

        /* Basic formatting */
        assert_se(format_bytes_full(buf, sizeof(buf), 1024, 0) != NULL);
        /* 1024 bytes = "1.0K" */
        assert_se(endswith(buf, "K") || endswith(buf, "B"));

        /* 0 bytes */
        assert_se(format_bytes_full(buf, sizeof(buf), 0, 0) != NULL);
}

TEST(format_bytes_basic) {
        char buf[FORMAT_BYTES_MAX + 1];

        assert_se(format_bytes(buf, sizeof(buf), 512) != NULL);
        assert_se(format_bytes(buf, sizeof(buf), 0) != NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
