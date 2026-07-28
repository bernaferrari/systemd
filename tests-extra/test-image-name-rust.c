/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C vs Rust for os_release_pretty_name */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "os-util.h"
#include "rust/image_class.h"
#include "rust/misc_validators.h"
#include "string-util.h"

/* -- os_release_pretty_name ------------------------------------------------ */
/* RUST-CONTRACT: os-release-pretty-name */

static void test_os_release_pretty_name(void) {
        const char *c_str, *rs_str;

        /* Both provided */
        c_str = os_release_pretty_name("Ubuntu 24.04", "ubuntu");
        rs_str = rs_os_release_pretty_name("Ubuntu 24.04", "ubuntu");
        assert_se(streq_ptr(c_str, rs_str));
        assert_se(streq(c_str, "Ubuntu 24.04"));

        /* Only pretty_name */
        c_str = os_release_pretty_name("Debian", NULL);
        rs_str = rs_os_release_pretty_name("Debian", NULL);
        assert_se(streq_ptr(c_str, rs_str));
        assert_se(streq(c_str, "Debian"));

        /* Only name */
        c_str = os_release_pretty_name(NULL, "fedora");
        rs_str = rs_os_release_pretty_name(NULL, "fedora");
        assert_se(streq_ptr(c_str, rs_str));
        assert_se(streq(c_str, "fedora"));

        /* Empty pretty_name, valid name */
        c_str = os_release_pretty_name("", "arch");
        rs_str = rs_os_release_pretty_name("", "arch");
        assert_se(streq_ptr(c_str, rs_str));
        assert_se(streq(c_str, "arch"));

        /* Both NULL */
        c_str = os_release_pretty_name(NULL, NULL);
        rs_str = rs_os_release_pretty_name(NULL, NULL);
        assert_se(streq_ptr(c_str, rs_str));
        assert_se(streq(c_str, "Linux"));

        /* Both empty */
        c_str = os_release_pretty_name("", "");
        rs_str = rs_os_release_pretty_name("", "");
        assert_se(streq_ptr(c_str, rs_str));
        assert_se(streq(c_str, "Linux"));

        /* Empty pretty_name, NULL name */
        c_str = os_release_pretty_name("", NULL);
        rs_str = rs_os_release_pretty_name("", NULL);
        assert_se(streq_ptr(c_str, rs_str));
        assert_se(streq(c_str, "Linux"));

        /* Valid pretty_name, empty name */
        c_str = os_release_pretty_name("SUSE", "");
        rs_str = rs_os_release_pretty_name("SUSE", "");
        assert_se(streq_ptr(c_str, rs_str));
        assert_se(streq(c_str, "SUSE"));
}

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
        test_os_release_pretty_name();
        test_image_name_is_valid();
        return 0;
}
