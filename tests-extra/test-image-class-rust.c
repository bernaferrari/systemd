/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <string.h>

#include "tests.h"
#include "os-util.h"
#include "rust/image_class.h"

/* ── image_class_to_string ─────────────────────────────────────────────── */

static void test_image_class_to_string_all(void) {
        static const struct {
                int c;
                const char *expected;
        } table[] = {
                { IMAGE_MACHINE,   "machine" },
                { IMAGE_PORTABLE,  "portable" },
                { IMAGE_SYSEXT,    "sysext" },
                { IMAGE_CONFEXT,   "confext" },
        };

        for (int i = 0; i < (int)ELEMENTSOF(table); i++) {
                const char *r_c = image_class_to_string(table[i].c);
                const char *r_r = rs_image_class_to_string(table[i].c);
                assert_se(r_c && r_r);
                assert_se(streq(r_c, r_r));
                assert_se(streq(r_c, table[i].expected));
        }
}

static void test_image_class_to_string_invalid(void) {
        const char *r_c = image_class_to_string(-1);
        const char *r_r = rs_image_class_to_string(-1);
        assert_se(!r_c && !r_r);

        r_c = image_class_to_string(4);
        r_r = rs_image_class_to_string(4);
        assert_se(!r_c && !r_r);
}

/* ── image_class_from_string ───────────────────────────────────────────── */

static void test_image_class_from_string_all(void) {
        static const struct {
                const char *name;
                int expected;
        } table[] = {
                { "machine",  IMAGE_MACHINE },
                { "portable", IMAGE_PORTABLE },
                { "sysext",   IMAGE_SYSEXT },
                { "confext",  IMAGE_CONFEXT },
        };

        for (int i = 0; i < (int)ELEMENTSOF(table); i++) {
                int r_c = image_class_from_string(table[i].name);
                int r_r = rs_image_class_from_string(table[i].name);
                assert_se(r_c == r_r);
                assert_se(r_c >= 0);
                assert_se(r_c == table[i].expected);
        }
}

static void test_image_class_from_string_invalid(void) {
        int r_c = image_class_from_string("foobar");
        int r_r = rs_image_class_from_string("foobar");
        assert_se(r_c == r_r);
        assert_se(r_c < 0);

        r_c = image_class_from_string("Machine");
        r_r = rs_image_class_from_string("Machine");
        assert_se(r_c == r_r);
        assert_se(r_c < 0);
}

/* ── roundtrip ─────────────────────────────────────────────────────────── */

static void test_image_class_roundtrip(void) {
        for (int c = 0; c <= 3; c++) {
                const char *s_c = image_class_to_string(c);
                const char *s_r = rs_image_class_to_string(c);
                assert_se(s_c && s_r);
                assert_se(streq(s_c, s_r));

                int r_c = image_class_from_string(s_c);
                int r_r = rs_image_class_from_string(s_r);
                assert_se(r_c == r_r);
                assert_se(r_c == c);
        }
}

/* ── os_release_pretty_name ────────────────────────────────────────────── */

static void test_os_release_pretty_name_both(void) {
        const char *r_c = os_release_pretty_name("My OS", "myos");
        const char *r_r = rs_os_release_pretty_name("My OS", "myos");
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
        assert_se(streq(r_c, "My OS"));
}

static void test_os_release_pretty_name_pretty_null(void) {
        const char *r_c = os_release_pretty_name(NULL, "myos");
        const char *r_r = rs_os_release_pretty_name(NULL, "myos");
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
        assert_se(streq(r_c, "myos"));
}

static void test_os_release_pretty_name_pretty_empty(void) {
        const char *r_c = os_release_pretty_name("", "myos");
        const char *r_r = rs_os_release_pretty_name("", "myos");
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
        assert_se(streq(r_c, "myos"));
}

static void test_os_release_pretty_name_both_null(void) {
        const char *r_c = os_release_pretty_name(NULL, NULL);
        const char *r_r = rs_os_release_pretty_name(NULL, NULL);
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
        assert_se(streq(r_c, "Linux"));
}

static void test_os_release_pretty_name_both_empty(void) {
        const char *r_c = os_release_pretty_name("", "");
        const char *r_r = rs_os_release_pretty_name("", "");
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
        assert_se(streq(r_c, "Linux"));
}

static void test_os_release_pretty_name_name_null(void) {
        const char *r_c = os_release_pretty_name("Pretty", NULL);
        const char *r_r = rs_os_release_pretty_name("Pretty", NULL);
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
        assert_se(streq(r_c, "Pretty"));
}

static void test_os_release_pretty_name_name_empty(void) {
        const char *r_c = os_release_pretty_name("Pretty", "");
        const char *r_r = rs_os_release_pretty_name("Pretty", "");
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
        assert_se(streq(r_c, "Pretty"));
}

static void test_os_release_pretty_name_pretty_null_name_empty(void) {
        const char *r_c = os_release_pretty_name(NULL, "");
        const char *r_r = rs_os_release_pretty_name(NULL, "");
        assert_se(r_c && r_r);
        assert_se(streq(r_c, r_r));
        assert_se(streq(r_c, "Linux"));
}

int main(int argc, char *argv[]) {
        test_image_class_to_string_all();
        test_image_class_to_string_invalid();
        test_image_class_from_string_all();
        test_image_class_from_string_invalid();
        test_image_class_roundtrip();
        test_os_release_pretty_name_both();
        test_os_release_pretty_name_pretty_null();
        test_os_release_pretty_name_pretty_empty();
        test_os_release_pretty_name_both_null();
        test_os_release_pretty_name_both_empty();
        test_os_release_pretty_name_name_null();
        test_os_release_pretty_name_name_empty();
        test_os_release_pretty_name_pretty_null_name_empty();

        return 0;
}
