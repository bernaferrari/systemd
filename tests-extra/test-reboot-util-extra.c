/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "reboot-util.h"
#include "tests.h"

TEST(reboot_parameter_is_valid) {
        ASSERT_TRUE(reboot_parameter_is_valid("halt"));
        ASSERT_TRUE(reboot_parameter_is_valid("poweroff"));
        ASSERT_TRUE(reboot_parameter_is_valid("reboot"));
        ASSERT_TRUE(reboot_parameter_is_valid("kexec"));
        ASSERT_TRUE(reboot_parameter_is_valid(""));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
