/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "build.h"
#include "string-util.h"
#include "tests.h"

TEST(version_basic) {
        int r = version();
        assert_se(r == 0);
}

TEST(systemd_features_basic) {
        assert_se(!isempty(systemd_features));
        log_debug("systemd_features: %s", systemd_features);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
