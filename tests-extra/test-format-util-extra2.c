/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "tests.h"

TEST(format_bytes_basic) {
        char buf[FORMAT_BYTES_MAX];
        const char *r;

        /* t == UINT64_MAX → returns NULL */
        assert_se(format_bytes_full(buf, sizeof(buf), UINT64_MAX, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_BELOW_POINT|FORMAT_BYTES_TRAILING_B) == NULL);

        /* Basic formatting */
        r = format_bytes_full(buf, sizeof(buf), 0, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_BELOW_POINT|FORMAT_BYTES_TRAILING_B);
        assert_se(r && streq(r, "0B"));

        r = format_bytes_full(buf, sizeof(buf), 512, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_BELOW_POINT|FORMAT_BYTES_TRAILING_B);
        assert_se(r && streq(r, "512B"));

        r = format_bytes_full(buf, sizeof(buf), 1024, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_BELOW_POINT);
        assert_se(r && endswith(r, "K"));

        r = format_bytes_full(buf, sizeof(buf), 1048576, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_BELOW_POINT);
        assert_se(r && endswith(r, "M"));

        r = format_bytes_full(buf, sizeof(buf), 1073741824ULL, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_BELOW_POINT);
        assert_se(r && endswith(r, "G"));

        r = format_bytes_full(buf, sizeof(buf), 1099511627776ULL, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_BELOW_POINT);
        assert_se(r && endswith(r, "T"));

        /* Without IEC → uses SI (1000-based) */
        r = format_bytes_full(buf, sizeof(buf), 1000, FORMAT_BYTES_BELOW_POINT);
        assert_se(r && endswith(r, "K"));

        r = format_bytes_full(buf, sizeof(buf), 0, 0);
        assert_se(r && streq(r, "0"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
