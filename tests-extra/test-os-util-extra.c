/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "os-util.h"
#include "tests.h"

TEST(image_class_to_from_string) {
        ASSERT_STREQ(image_class_to_string(IMAGE_MACHINE), "machine");
        ASSERT_STREQ(image_class_to_string(IMAGE_PORTABLE), "portable");
        ASSERT_STREQ(image_class_to_string(IMAGE_SYSEXT), "sysext");
        ASSERT_STREQ(image_class_to_string(IMAGE_CONFEXT), "confext");

        ASSERT_EQ(image_class_from_string("machine"), IMAGE_MACHINE);
        ASSERT_EQ(image_class_from_string("portable"), IMAGE_PORTABLE);
        ASSERT_EQ(image_class_from_string("sysext"), IMAGE_SYSEXT);
        ASSERT_EQ(image_class_from_string("confext"), IMAGE_CONFEXT);
        ASSERT_LT(image_class_from_string("invalid"), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
