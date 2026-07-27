/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "kernel-image.h"

TEST(kernel_image_type_to_string_extra) {
        /* TO_STRING only - the existing test already covers basics, this adds more checks */
        assert_se(kernel_image_type_to_string(KERNEL_IMAGE_TYPE_UKI) != NULL);
        assert_se(kernel_image_type_to_string(KERNEL_IMAGE_TYPE_ADDON) != NULL);
        assert_se(kernel_image_type_to_string(KERNEL_IMAGE_TYPE_PE) != NULL);

        /* Unknown value */
        assert_se(kernel_image_type_to_string(999) == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
