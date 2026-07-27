/* SPDX-License-Identifier: LGPL-2.1-or-later */


#include "os-util.h"
#include "tests.h"

TEST(image_class_to_string) {
        ASSERT_STREQ(image_class_to_string(IMAGE_MACHINE), "machine");
        ASSERT_STREQ(image_class_to_string(IMAGE_PORTABLE), "portable");
        ASSERT_STREQ(image_class_to_string(IMAGE_SYSEXT), "sysext");
        ASSERT_STREQ(image_class_to_string(IMAGE_CONFEXT), "confext");
}

TEST(image_class_from_string) {
        ASSERT_EQ(image_class_from_string("machine"), IMAGE_MACHINE);
        ASSERT_EQ(image_class_from_string("portable"), IMAGE_PORTABLE);
        ASSERT_EQ(image_class_from_string("sysext"), IMAGE_SYSEXT);
        ASSERT_EQ(image_class_from_string("confext"), IMAGE_CONFEXT);
        ASSERT_EQ(image_class_from_string("invalid"), _IMAGE_CLASS_INVALID);
}

TEST(image_name_is_valid_basic) {
        ASSERT_TRUE(image_name_is_valid("myimage"));
        ASSERT_TRUE(image_name_is_valid("fedora"));
        ASSERT_TRUE(image_name_is_valid("ubuntu-24.04"));
}

TEST(image_name_is_valid_reject) {
        ASSERT_FALSE(image_name_is_valid(""));
        ASSERT_FALSE(image_name_is_valid("."));
        ASSERT_FALSE(image_name_is_valid(".."));
        ASSERT_FALSE(image_name_is_valid("foo/bar"));
        ASSERT_FALSE(image_name_is_valid(NULL));
}

TEST(image_name_is_valid_hidden_temp) {
        /* Names starting with ".#" are rejected (temporary files) */
        ASSERT_FALSE(image_name_is_valid(".#temp"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
