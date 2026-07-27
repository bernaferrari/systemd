/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "discover-image.h"
#include "string-util.h"
#include "tests.h"

TEST(image_type_roundtrip) {
        for (int i = 0; i < _IMAGE_TYPE_MAX; i++) {
                const char *s = image_type_to_string(i);
                assert_se(s);
                ImageType v = image_type_from_string(s);
                assert_se(v == i);
        }
}

TEST(image_type_from_string_invalid) {
        assert_se(image_type_from_string("nonsense") == _IMAGE_TYPE_INVALID);
        assert_se(image_type_from_string("") == _IMAGE_TYPE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
