/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "discover-image.h"
#include "tests.h"

TEST(image_type_to_string) {
        ASSERT_STREQ(image_type_to_string(IMAGE_DIRECTORY), "directory");
        ASSERT_STREQ(image_type_to_string(IMAGE_SUBVOLUME), "subvolume");
        ASSERT_STREQ(image_type_to_string(IMAGE_RAW), "raw");
        ASSERT_STREQ(image_type_to_string(IMAGE_BLOCK), "block");
        ASSERT_STREQ(image_type_to_string(IMAGE_MSTACK), "mstack");
}

TEST(image_type_from_string) {
        ASSERT_EQ(image_type_from_string("directory"), IMAGE_DIRECTORY);
        ASSERT_EQ(image_type_from_string("subvolume"), IMAGE_SUBVOLUME);
        ASSERT_EQ(image_type_from_string("raw"), IMAGE_RAW);
        ASSERT_EQ(image_type_from_string("block"), IMAGE_BLOCK);
        ASSERT_EQ(image_type_from_string("mstack"), IMAGE_MSTACK);
        ASSERT_EQ(image_type_from_string("invalid"), _IMAGE_TYPE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
