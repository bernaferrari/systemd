/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "discover-image.h"
#include "string-util.h"
#include "tests.h"

TEST(image_type_to_from_string) {
        assert_se(streq(image_type_to_string(IMAGE_DIRECTORY), "directory"));
        assert_se(streq(image_type_to_string(IMAGE_SUBVOLUME), "subvolume"));
        assert_se(streq(image_type_to_string(IMAGE_RAW), "raw"));
        assert_se(streq(image_type_to_string(IMAGE_BLOCK), "block"));
        assert_se(streq(image_type_to_string(IMAGE_MSTACK), "mstack"));

        assert_se(image_type_from_string("directory") == IMAGE_DIRECTORY);
        assert_se(image_type_from_string("subvolume") == IMAGE_SUBVOLUME);
        assert_se(image_type_from_string("raw") == IMAGE_RAW);
        assert_se(image_type_from_string("block") == IMAGE_BLOCK);
        assert_se(image_type_from_string("mstack") == IMAGE_MSTACK);
        assert_se(image_type_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
