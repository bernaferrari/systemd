/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "devnum-util.h"
#include "hibernate-util.h"
#include "tests.h"

TEST(hibernation_device_done_basic) {
        HibernationDevice device = {
                .path = strdup("/dev/sda1"),
                .devno = makedev(8, 1),
                .offset = 0,
        };
        assert_se(device.path);

        hibernation_device_done(&device);
}

TEST(hibernation_device_done_null_path) {
        HibernationDevice device = {
                .path = NULL,
        };
        /* Should not crash - free(NULL) is safe */
        hibernation_device_done(&device);
}

TEST(hibernation_device_zero) {
        HibernationDevice device = {
                .devno = 0,
                .offset = 0,
                .path = NULL,
        };

        assert_se(device.devno == 0);
        assert_se(device.path == NULL);

        hibernation_device_done(&device);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
