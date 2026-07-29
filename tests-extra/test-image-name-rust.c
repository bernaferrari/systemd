/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "tests.h"
#include "os-util.h"
#include "rust/misc_validators.h"

/* -- image_name_is_valid ------------------------------------------------- */

static void test_image_name_is_valid(void) {
        /* Valid names */
        assert_se(image_name_is_valid("myimage"));
        assert_se(rs_image_name_is_valid("myimage"));

        assert_se(image_name_is_valid("my.image"));
        assert_se(rs_image_name_is_valid("my.image"));

        assert_se(image_name_is_valid("image-123"));
        assert_se(rs_image_name_is_valid("image-123"));

        assert_se(image_name_is_valid("a"));
        assert_se(rs_image_name_is_valid("a"));

        assert_se(image_name_is_valid("test_image.raw"));
        assert_se(rs_image_name_is_valid("test_image.raw"));

        /* Invalid: NULL */
        assert_se(!image_name_is_valid(NULL));
        assert_se(!rs_image_name_is_valid(NULL));

        /* Invalid: empty */
        assert_se(!image_name_is_valid(""));
        assert_se(!rs_image_name_is_valid(""));

        /* Invalid: starts with .# */
        assert_se(!image_name_is_valid(".#temp"));
        assert_se(!rs_image_name_is_valid(".#temp"));

        /* Invalid: control characters */
        assert_se(!image_name_is_valid("test\x01name"));
        assert_se(!rs_image_name_is_valid("test\x01name"));

        /* Invalid: not valid filename */
        assert_se(!image_name_is_valid("/path/image"));
        assert_se(!rs_image_name_is_valid("/path/image"));

        assert_se(!image_name_is_valid("image/name"));
        assert_se(!rs_image_name_is_valid("image/name"));

        /* Spaces are valid filename bytes; C only rejects control characters. */
        assert_se(image_name_is_valid("image name"));
        assert_se(rs_image_name_is_valid("image name"));

        /* C validates UTF-8 after the filename-shape checks. */
        assert_se(!image_name_is_valid("image\xc3\x28"));
        assert_se(!rs_image_name_is_valid("image\xc3\x28"));
}

int main(int argc, char **argv) {
        test_image_name_is_valid();
        return 0;
}
