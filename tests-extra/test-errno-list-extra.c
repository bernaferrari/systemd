/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-list.h"
#include "errno-util.h"
#include "tests.h"

TEST(errno_name_no_fallback) {
        /* errno_name_no_fallback returns NULL for id==0 */
        ASSERT_NULL(errno_name_no_fallback(0));
        ASSERT_STREQ(errno_name_no_fallback(EPERM), "EPERM");
        ASSERT_STREQ(errno_name_no_fallback(ENOENT), "ENOENT");
        ASSERT_STREQ(errno_name_no_fallback(EINVAL), "EINVAL");
        ASSERT_STREQ(errno_name_no_fallback(ENOMEM), "ENOMEM");
}

TEST(errno_from_name) {
        ASSERT_EQ(errno_from_name("EPERM"), EPERM);
        ASSERT_EQ(errno_from_name("ENOENT"), ENOENT);
        ASSERT_EQ(errno_from_name("EINVAL"), EINVAL);
        ASSERT_EQ(errno_from_name("ENOMEM"), ENOMEM);
        ASSERT_EQ(errno_from_name("invalid"), -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
