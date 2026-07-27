/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "string-util.h"
#include "tests.h"

TEST(log_target_from_string_basic) {
        assert_se(log_target_from_string("console") >= 0);
        assert_se(log_target_from_string("journal") >= 0);
        assert_se(log_target_from_string("syslog") >= 0);
        assert_se(log_target_from_string("kmsg") >= 0);
        assert_se(log_target_from_string("null") >= 0);
        assert_se(log_target_from_string("invalid") < 0);
}

TEST(log_target_to_string_roundtrip) {
        for (int i = 0; i < _LOG_TARGET_MAX; i++) {
                const char *s = log_target_to_string(i);
                assert_se(s);
                int v = log_target_from_string(s);
                assert_se(v == i);
        }
}

TEST(log_get_max_level_basic) {
        int level = log_get_max_level();
        assert_se(level >= LOG_EMERG && level <= LOG_DEBUG);
        log_debug("log_get_max_level: %d", level);
}

TEST(log_get_show_color_basic) {
        (void) log_get_show_color();
}

TEST(log_get_show_location_basic) {
        (void) log_get_show_location();
}

DEFINE_TEST_MAIN(LOG_DEBUG);
