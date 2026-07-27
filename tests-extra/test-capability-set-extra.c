/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/capability.h>

#include "bitfield.h"
#include "capability-list.h"
#include "strv.h"
#include "tests.h"

TEST(capability_set_to_string_empty) {
        _cleanup_free_ char *s = NULL;
        ASSERT_OK(capability_set_to_string(0, &s));
        ASSERT_STREQ(s, "");
}

TEST(capability_set_to_string_single) {
        _cleanup_free_ char *s = NULL;
        uint64_t set = UINT64_C(1) << CAP_CHOWN;
        ASSERT_OK(capability_set_to_string(set, &s));
        ASSERT_STREQ(s, "cap_chown");
}

TEST(capability_set_from_string) {
        uint64_t set = 0;
        ASSERT_OK(capability_set_from_string("cap_chown", &set));
        ASSERT_TRUE(BIT_SET(set, CAP_CHOWN));

        set = 0;
        ASSERT_OK(capability_set_from_string("cap_chown cap_dac_override", &set));
        ASSERT_TRUE(BIT_SET(set, CAP_CHOWN));
        ASSERT_TRUE(BIT_SET(set, CAP_DAC_OVERRIDE));

        /* Empty string produces empty set */
        set = 0;
        ASSERT_OK(capability_set_from_string("", &set));
        ASSERT_EQ(set, UINT64_C(0));

        /* Unknown capabilities are ignored (logged but not error) */
        set = 0;
        ASSERT_OK(capability_set_from_string("cap_chown nonexistent_cap", &set));
        ASSERT_TRUE(BIT_SET(set, CAP_CHOWN));
}

TEST(capability_set_to_strv) {
        _cleanup_strv_free_ char **l = NULL;
        uint64_t set = UINT64_C(1) << CAP_CHOWN;
        ASSERT_OK(capability_set_to_strv(set, &l));
        ASSERT_NOT_NULL(l);
        ASSERT_STREQ(l[0], "cap_chown");
        ASSERT_NULL(l[1]);

        /* Empty set produces NULL strv */
        l = strv_free(l);
        char **l2 = NULL;
        ASSERT_OK(capability_set_to_strv(0, &l2));
        ASSERT_NULL(l2);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
