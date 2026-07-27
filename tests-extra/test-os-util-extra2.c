/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "os-util.h"
#include "tests.h"

TEST(image_name_is_valid_basic) {
        assert_se(image_name_is_valid("test"));
        assert_se(image_name_is_valid("my-image"));
        assert_se(image_name_is_valid("image123"));
        assert_se(!image_name_is_valid(""));
        assert_se(!image_name_is_valid(".#test"));
        assert_se(!image_name_is_valid(NULL));
}

TEST(os_release_pretty_name_basic) {
        /* Prefers pretty_name, then name, then "Linux" */
        assert_se(streq(os_release_pretty_name("Pretty", "Name"), "Pretty"));
        assert_se(streq(os_release_pretty_name(NULL, "Name"), "Name"));
        assert_se(streq(os_release_pretty_name(NULL, NULL), "Linux"));
}

TEST(path_extract_image_name_basic) {
        _cleanup_free_ char *name = NULL;

        assert_se(path_extract_image_name("/path/to/myimage.raw", &name) >= 0);
        assert_se(streq(name, "myimage"));

        name = mfree(name);
        assert_se(path_extract_image_name("/path/to/myimage.sysext.raw", &name) >= 0);
        assert_se(streq(name, "myimage"));
}

TEST(path_extract_image_name_no_extension) {
        _cleanup_free_ char *name = NULL;

        assert_se(path_extract_image_name("/path/to/myimage", &name) >= 0);
        assert_se(streq(name, "myimage"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
