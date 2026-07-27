/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "kernel-image.h"
#include "tests.h"

TEST(kernel_image_type_to_string) {
        ASSERT_STREQ(kernel_image_type_to_string(KERNEL_IMAGE_TYPE_UNKNOWN), "unknown");
        ASSERT_STREQ(kernel_image_type_to_string(KERNEL_IMAGE_TYPE_UKI), "uki");
        ASSERT_STREQ(kernel_image_type_to_string(KERNEL_IMAGE_TYPE_ADDON), "addon");
        ASSERT_STREQ(kernel_image_type_to_string(KERNEL_IMAGE_TYPE_PE), "pe");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
