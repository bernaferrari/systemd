/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootspec.h"
#include "string-util.h"
#include "tests.h"

TEST(boot_filename_extract_tries) {
        _cleanup_free_ char *stripped = NULL;
        unsigned tries_left, tries_done;
        int r;

        /* Filename with tries: name+3-0.efi → stripped=name.efi, left=3, done=0 */
        r = boot_filename_extract_tries("myboot+3-0.efi", &stripped, &tries_left, &tries_done);
        assert_se(r >= 0);
        assert_se(streq(stripped, "myboot.efi"));
        assert_se(tries_left == 3);
        assert_se(tries_done == 0);
        stripped = mfree(stripped);

        /* Only tries_left, no tries_done */
        r = boot_filename_extract_tries("myboot+5.efi", &stripped, &tries_left, &tries_done);
        assert_se(r >= 0);
        assert_se(streq(stripped, "myboot.efi"));
        assert_se(tries_left == 5);
        assert_se(tries_done == UINT_MAX);
        stripped = mfree(stripped);

        /* No tries info → stripped = original, tries = UINT_MAX */
        r = boot_filename_extract_tries("myboot.efi", &stripped, &tries_left, &tries_done);
        assert_se(r >= 0);
        assert_se(streq(stripped, "myboot.efi"));
        assert_se(tries_left == UINT_MAX);
        assert_se(tries_done == UINT_MAX);
        stripped = mfree(stripped);

        /* No dot suffix → stripped = original */
        r = boot_filename_extract_tries("myboot+3", &stripped, &tries_left, &tries_done);
        assert_se(r >= 0);
        assert_se(streq(stripped, "myboot+3"));
        assert_se(tries_left == UINT_MAX);
        assert_se(tries_done == UINT_MAX);
        stripped = mfree(stripped);

        /* Tries with larger numbers */
        r = boot_filename_extract_tries("kernel+100-99.efi", &stripped, &tries_left, &tries_done);
        assert_se(r >= 0);
        assert_se(streq(stripped, "kernel.efi"));
        assert_se(tries_left == 100);
        assert_se(tries_done == 99);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
