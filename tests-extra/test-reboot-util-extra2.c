/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "reboot-util.h"
#include "string-util.h"
#include "tests.h"

TEST(reboot_parameter_is_valid_basic) {
        assert_se(reboot_parameter_is_valid("kexec"));
        assert_se(reboot_parameter_is_valid(""));
        assert_se(reboot_parameter_is_valid("simple-param"));

        /* Non-ASCII rejected */
        assert_se(!reboot_parameter_is_valid("\xff invalid"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
