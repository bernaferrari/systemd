/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C credential validators vs Rust */

#include <string.h>

#include "log.h"
#include "tests.h"

/* C header */
#include "creds-util.h"

/* Rust FFI */
#include "rust/credential_validators.h"

static void test_credential_name_valid(void) {
        bool cv, rv;

        cv = credential_name_valid("foo");
        rv = rs_credential_name_valid("foo");
        assert_se(cv == rv);
        assert_se(cv);

        cv = credential_name_valid("foo.bar");
        rv = rs_credential_name_valid("foo.bar");
        assert_se(cv == rv);

        cv = credential_name_valid("foo-bar");
        rv = rs_credential_name_valid("foo-bar");
        assert_se(cv == rv);

        cv = credential_name_valid(NULL);
        rv = rs_credential_name_valid(NULL);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = credential_name_valid("");
        rv = rs_credential_name_valid("");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Colon is not valid as fdname */
        cv = credential_name_valid("foo:bar");
        rv = rs_credential_name_valid("foo:bar");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Slash is not valid as filename */
        cv = credential_name_valid("foo/bar");
        rv = rs_credential_name_valid("foo/bar");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Dot and dot-dot are not valid filenames */
        cv = credential_name_valid(".");
        rv = rs_credential_name_valid(".");
        assert_se(cv == rv);
        assert_se(!cv);

        cv = credential_name_valid("..");
        rv = rs_credential_name_valid("..");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Control characters not valid */
        cv = credential_name_valid("foo\x01bar");
        rv = rs_credential_name_valid("foo\x01bar");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Simple valid name with underscore */
        cv = credential_name_valid("my_credential");
        rv = rs_credential_name_valid("my_credential");
        assert_se(cv == rv);
}

static void test_credential_glob_valid(void) {
        bool cv, rv;

        cv = credential_glob_valid("foo");
        rv = rs_credential_glob_valid("foo");
        assert_se(cv == rv);
        assert_se(cv);

        /* Complete wildcard */
        cv = credential_glob_valid("*");
        rv = rs_credential_glob_valid("*");
        assert_se(cv == rv);
        assert_se(cv);

        /* Trailing wildcard */
        cv = credential_glob_valid("foo*");
        rv = rs_credential_glob_valid("foo*");
        assert_se(cv == rv);
        assert_se(cv);

        cv = credential_glob_valid("foo.bar*");
        rv = rs_credential_glob_valid("foo.bar*");
        assert_se(cv == rv);
        assert_se(cv);

        /* Empty is not valid */
        cv = credential_glob_valid("");
        rv = rs_credential_glob_valid("");
        assert_se(cv == rv);
        assert_se(!cv);

        cv = credential_glob_valid(NULL);
        rv = rs_credential_glob_valid(NULL);
        assert_se(cv == rv);
        assert_se(!cv);

        /* Only ? wildcards are not allowed */
        cv = credential_glob_valid("foo?");
        rv = rs_credential_glob_valid("foo?");
        assert_se(cv == rv);
        assert_se(!cv);

        /* [] wildcards not allowed */
        cv = credential_glob_valid("foo[bar]");
        rv = rs_credential_glob_valid("foo[bar]");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Wildcard in middle not allowed */
        cv = credential_glob_valid("foo*bar");
        rv = rs_credential_glob_valid("foo*bar");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Invalid prefix */
        cv = credential_glob_valid("foo/bar*");
        rv = rs_credential_glob_valid("foo/bar*");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Colon in prefix not valid */
        cv = credential_glob_valid("foo:bar*");
        rv = rs_credential_glob_valid("foo:bar*");
        assert_se(cv == rv);
        assert_se(!cv);
}

int main(int argc, char **argv) {
        test_credential_name_valid();
        test_credential_glob_valid();

        return 0;
}
