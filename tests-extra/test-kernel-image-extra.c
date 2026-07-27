/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "kernel-image.h"

TEST(kernel_image_type_to_string) {
        assert_se(streq(kernel_image_type_to_string(KERNEL_IMAGE_TYPE_UNKNOWN), "unknown"));
        assert_se(streq(kernel_image_type_to_string(KERNEL_IMAGE_TYPE_UKI), "uki"));
        assert_se(streq(kernel_image_type_to_string(KERNEL_IMAGE_TYPE_ADDON), "addon"));
        assert_se(streq(kernel_image_type_to_string(KERNEL_IMAGE_TYPE_PE), "pe"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
