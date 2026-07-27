/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "string-util.h"
#include "tests.h"

TEST(format_bytes_full_exact_values) {
        char buf[FORMAT_BYTES_MAX];
        const char *r;

        /* IEC mode with below point */
        r = format_bytes_full(buf, sizeof(buf), 1536, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_BELOW_POINT);
        assert_se(r && streq(r, "1.5K"));

        r = format_bytes_full(buf, sizeof(buf), 1048576, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_BELOW_POINT);
        assert_se(r && endswith(r, "M"));

        r = format_bytes_full(buf, sizeof(buf), 1073741824ULL, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_BELOW_POINT);
        assert_se(r && endswith(r, "G"));

        /* Without below point → no decimal */
        r = format_bytes_full(buf, sizeof(buf), 1536, FORMAT_BYTES_USE_IEC);
        assert_se(r && streq(r, "1K"));

        /* With trailing B */
        r = format_bytes_full(buf, sizeof(buf), 512, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_TRAILING_B);
        assert_se(r && streq(r, "512B"));

        /* With ALWAYS_POINT */
        r = format_bytes_full(buf, sizeof(buf), 1024, FORMAT_BYTES_USE_IEC|FORMAT_BYTES_ALWAYS_POINT);
        assert_se(r && streq(r, "1.0K"));

        /* SI mode (1000-based) */
        r = format_bytes_full(buf, sizeof(buf), 1500, FORMAT_BYTES_BELOW_POINT);
        assert_se(r && streq(r, "1.5K"));

        /* Large values */
        r = format_bytes_full(buf, sizeof(buf), UINT64_C(1125899906842624), FORMAT_BYTES_USE_IEC|FORMAT_BYTES_BELOW_POINT);
        assert_se(r && endswith(r, "P"));
}

TEST(format_bytes_macro) {
        const char *r;
        r = FORMAT_BYTES(0);
        assert_se(r && streq(r, "0B"));

        r = FORMAT_BYTES(1024);
        assert_se(r && endswith(r, "K"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
