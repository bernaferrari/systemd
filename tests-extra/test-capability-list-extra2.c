/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/capability.h>

#include "capability-list.h"
#include "tests.h"

/* Capability IDs (numeric) */
#define CAP_CHOWN_ID 0
#define CAP_DAC_OVERRIDE_ID 1
#define CAP_NET_ADMIN_ID 12
#define CAP_SYS_ADMIN_ID 21
#define CAP_KILL_ID 5

TEST(capability_to_name_basic) {
        assert_se(streq(capability_to_name(CAP_CHOWN_ID), "cap_chown"));
        assert_se(streq(capability_to_name(CAP_DAC_OVERRIDE_ID), "cap_dac_override"));
        assert_se(streq(capability_to_name(CAP_NET_ADMIN_ID), "cap_net_admin"));
        assert_se(streq(capability_to_name(CAP_SYS_ADMIN_ID), "cap_sys_admin"));
        assert_se(streq(capability_to_name(CAP_KILL_ID), "cap_kill"));
        assert_se(capability_to_name(-1) == NULL);
}

TEST(capability_to_string_basic) {
        char buf[CAPABILITY_TO_STRING_MAX];

        assert_se(streq(capability_to_string(CAP_CHOWN_ID, buf), "cap_chown"));
        assert_se(streq(capability_to_string(CAP_NET_ADMIN_ID, buf), "cap_net_admin"));
        assert_se(streq(capability_to_string(CAP_SYS_ADMIN_ID, buf), "cap_sys_admin"));
}

TEST(capability_from_name_basic) {
        /* gperf uses --ignore-case, so accepts mixed case */
        assert_se(capability_from_name("cap_chown") == CAP_CHOWN_ID);
        assert_se(capability_from_name("CAP_DAC_OVERRIDE") == CAP_DAC_OVERRIDE_ID);
        assert_se(capability_from_name("cap_net_admin") == CAP_NET_ADMIN_ID);
        assert_se(capability_from_name("CAP_SYS_ADMIN") == CAP_SYS_ADMIN_ID);
        assert_se(capability_from_name("invalid_capability") == -EINVAL);
}

TEST(capability_from_name_numeric) {
        assert_se(capability_from_name("0") == 0);
        assert_se(capability_from_name("1") == 1);
}

TEST(capability_set_to_string_basic) {
        _cleanup_free_ char *s = NULL;
        uint64_t set = (1ULL << CAP_NET_ADMIN_ID) | (1ULL << CAP_SYS_ADMIN_ID);

        assert_se(capability_set_to_string(set, &s) >= 0);
        assert_se(s);
        assert_se(strstr(s, "cap_net_admin") != NULL);
        assert_se(strstr(s, "cap_sys_admin") != NULL);
}

TEST(capability_set_to_string_empty) {
        _cleanup_free_ char *s = NULL;

        assert_se(capability_set_to_string(0, &s) >= 0);
        assert_se(s);
        assert_se(streq(s, ""));
}

TEST(capability_set_from_string_basic) {
        uint64_t set;

        assert_se(capability_set_from_string("cap_net_admin", &set) > 0);
        assert_se(set == (1ULL << CAP_NET_ADMIN_ID));

        assert_se(capability_set_from_string("cap_net_admin cap_sys_admin", &set) > 0);
        assert_se(set == ((1ULL << CAP_NET_ADMIN_ID) | (1ULL << CAP_SYS_ADMIN_ID)));
}

TEST(capability_set_from_string_empty) {
        uint64_t set = 99;

        assert_se(capability_set_from_string("", &set) > 0);
        assert_se(set == 0);
}

TEST(capability_set_roundtrip) {
        _cleanup_free_ char *s = NULL;
        uint64_t original = (1ULL << CAP_KILL_ID) | (1ULL << CAP_CHOWN_ID);
        uint64_t parsed;

        assert_se(capability_set_to_string(original, &s) >= 0);
        assert_se(capability_set_from_string(s, &parsed) > 0);
        assert_se(parsed == original);
}

TEST(capability_list_length_basic) {
        unsigned len = capability_list_length();
        assert_se(len > 0);
        assert_se(len <= 64);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
