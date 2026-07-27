/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hostname-setup.h"
#include "string-util.h"
#include "tests.h"

TEST(hostname_source_to_from_string) {
        assert_se(streq(hostname_source_to_string(HOSTNAME_STATIC), "static"));
        assert_se(streq(hostname_source_to_string(HOSTNAME_TRANSIENT), "transient"));
        assert_se(streq(hostname_source_to_string(HOSTNAME_DEFAULT), "default"));

        assert_se(hostname_source_from_string("static") == HOSTNAME_STATIC);
        assert_se(hostname_source_from_string("transient") == HOSTNAME_TRANSIENT);
        assert_se(hostname_source_from_string("default") == HOSTNAME_DEFAULT);
        assert_se(hostname_source_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
