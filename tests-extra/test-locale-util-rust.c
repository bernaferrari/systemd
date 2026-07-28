/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "rust/locale_util.h"

/* C references */
#include "locale-util.h"
#include "string-util.h"

/* RUST-CONTRACT: locale-variable-to-string */
static void test_locale_variable_to_string(void) {
        const char *c_ret, *r_ret;

        c_ret = locale_variable_to_string(VARIABLE_LANG);
        r_ret = rs_locale_variable_to_string(VARIABLE_LANG);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = locale_variable_to_string(VARIABLE_LANGUAGE);
        r_ret = rs_locale_variable_to_string(VARIABLE_LANGUAGE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = locale_variable_to_string(VARIABLE_LC_CTYPE);
        r_ret = rs_locale_variable_to_string(VARIABLE_LC_CTYPE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = locale_variable_to_string(VARIABLE_LC_MESSAGES);
        r_ret = rs_locale_variable_to_string(VARIABLE_LC_MESSAGES);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = locale_variable_to_string(VARIABLE_LC_IDENTIFICATION);
        r_ret = rs_locale_variable_to_string(VARIABLE_LC_IDENTIFICATION);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Invalid */
        c_ret = locale_variable_to_string(-1);
        r_ret = rs_locale_variable_to_string(-1);
        assert_se(streq_ptr(c_ret, r_ret));

        c_ret = locale_variable_to_string(99);
        r_ret = rs_locale_variable_to_string(99);
        assert_se(streq_ptr(c_ret, r_ret));
}

/* RUST-CONTRACT: locale-variable-from-string */
static void test_locale_variable_from_string(void) {
        int c_ret, r_ret;

        c_ret = locale_variable_from_string("LANG");
        r_ret = rs_locale_variable_from_string("LANG");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == VARIABLE_LANG);

        c_ret = locale_variable_from_string("LANGUAGE");
        r_ret = rs_locale_variable_from_string("LANGUAGE");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == VARIABLE_LANGUAGE);

        c_ret = locale_variable_from_string("LC_CTYPE");
        r_ret = rs_locale_variable_from_string("LC_CTYPE");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == VARIABLE_LC_CTYPE);

        c_ret = locale_variable_from_string("LC_IDENTIFICATION");
        r_ret = rs_locale_variable_from_string("LC_IDENTIFICATION");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == VARIABLE_LC_IDENTIFICATION);

        /* Invalid */
        c_ret = locale_variable_from_string("BOGUS");
        r_ret = rs_locale_variable_from_string("BOGUS");
        assert_se(c_ret == r_ret);
        assert_se(c_ret == -EINVAL);

        c_ret = locale_variable_from_string(NULL);
        r_ret = rs_locale_variable_from_string(NULL);
        assert_se(c_ret == r_ret);
}

/* RUST-CONTRACT: locale-is-valid */
static void test_locale_is_valid(void) {
        bool c_ret, r_ret;

        c_ret = locale_is_valid("en_US.UTF-8");
        r_ret = rs_locale_is_valid("en_US.UTF-8");
        assert_se(c_ret == r_ret);

        c_ret = locale_is_valid("de_DE");
        r_ret = rs_locale_is_valid("de_DE");
        assert_se(c_ret == r_ret);

        c_ret = locale_is_valid("fr_FR.iso88591");
        r_ret = rs_locale_is_valid("fr_FR.iso88591");
        assert_se(c_ret == r_ret);

        c_ret = locale_is_valid("C");
        r_ret = rs_locale_is_valid("C");
        assert_se(c_ret == r_ret);

        c_ret = locale_is_valid("POSIX");
        r_ret = rs_locale_is_valid("POSIX");
        assert_se(c_ret == r_ret);

        c_ret = locale_is_valid("en_US.UTF-8@modifier");
        r_ret = rs_locale_is_valid("en_US.UTF-8@modifier");
        assert_se(c_ret == r_ret);

        /* Invalid: NULL */
        c_ret = locale_is_valid(NULL);
        r_ret = rs_locale_is_valid(NULL);
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);

        /* Invalid: empty */
        c_ret = locale_is_valid("");
        r_ret = rs_locale_is_valid("");
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);

        /* Invalid: too long (>128 chars) */
        char buf[129];
        memset(buf, 'a', 128);
        buf[128] = '\0';
        c_ret = locale_is_valid(buf);
        r_ret = rs_locale_is_valid(buf);
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);

        /* Invalid: has slash (fails filename check) */
        c_ret = locale_is_valid("en/US");
        r_ret = rs_locale_is_valid("en/US");
        assert_se(c_ret == r_ret);

        /* Invalid filenames in the C helper, despite '.' being in the charset. */
        c_ret = locale_is_valid(".");
        r_ret = rs_locale_is_valid(".");
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);

        c_ret = locale_is_valid("..");
        r_ret = rs_locale_is_valid("..");
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);

        /* C strings need byte-wise validation, not lossy UTF-8 conversion. */
        static const char invalid_utf8[] = { 'e', (char) 0xff, 0 };
        c_ret = locale_is_valid(invalid_utf8);
        r_ret = rs_locale_is_valid(invalid_utf8);
        assert_se(c_ret == r_ret);
        assert_se(!c_ret);
}

int main(int argc, char **argv) {
        test_locale_variable_to_string();
        test_locale_variable_from_string();
        test_locale_is_valid();
        return 0;
}
