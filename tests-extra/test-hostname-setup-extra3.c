/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hostname-setup.h"
#include "string-util.h"
#include "tests.h"

TEST(hostname_source_to_string) {
        assert_se(streq(hostname_source_to_string(HOSTNAME_STATIC), "static"));
        assert_se(streq(hostname_source_to_string(HOSTNAME_TRANSIENT), "transient"));
        assert_se(streq(hostname_source_to_string(HOSTNAME_DEFAULT), "default"));
}

TEST(hostname_source_from_string) {
        assert_se(hostname_source_from_string("static") == HOSTNAME_STATIC);
        assert_se(hostname_source_from_string("transient") == HOSTNAME_TRANSIENT);
        assert_se(hostname_source_from_string("default") == HOSTNAME_DEFAULT);
        assert_se(hostname_source_from_string("invalid") == _HOSTNAME_INVALID);
}

TEST(shorten_overlong_basic) {
        _cleanup_free_ char *ret = NULL;

        /* Valid hostname is returned as-is */
        assert_se(shorten_overlong("myhost", &ret) >= 0);
        assert_se(streq(ret, "myhost"));
        ret = mfree(ret);

        /* Truncates at first dot for overlong hostnames */
        assert_se(shorten_overlong("a.very.long.hostname.that.exceeds.limit", &ret) >= 0);
        assert_se(ret);
        /* Result should be a valid hostname or truncated */
        assert_se(strlen(ret) > 0);
        ret = mfree(ret);

        /* Simple single label */
        assert_se(shorten_overlong("localhost", &ret) >= 0);
        assert_se(streq(ret, "localhost"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
