/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "string-util.h"
#include "tests.h"
#include "vpick.h"

TEST(pick_result_done) {
        PickResult p = PICK_RESULT_NULL;
        p.path = strdup("/test/path");
        assert_se(p.path != NULL);
        p.version = strdup("1.0");
        assert_se(p.version != NULL);

        pick_result_done(&p);

        assert_se(p.path == NULL);
        assert_se(p.version == NULL);
        assert_se(p.fd == -EBADF);
}

TEST(pick_result_done_null) {
        /* PICK_RESULT_NULL already has NULLs and -EBADF */
        PickResult p = PICK_RESULT_NULL;
        pick_result_done(&p);
        assert_se(p.path == NULL);
        assert_se(p.fd == -EBADF);
}

TEST(pick_result_compare_version) {
        PickResult a = PICK_RESULT_NULL, b = PICK_RESULT_NULL;

        /* With version: newer is better (> 0) */
        a.version = strdup("2.0");
        a.path = strdup("/a");
        b.version = strdup("1.0");
        b.path = strdup("/b");
        assert_se(a.version && a.path && b.version && b.path);
        assert_se(pick_result_compare(&a, &b, 0) > 0);
        a.version = mfree(a.version);
        a.path = mfree(a.path);
        b.version = mfree(b.version);
        b.path = mfree(b.path);

        /* Equal versions → falls through to path comparison */
        a.version = strdup("1.0");
        a.path = strdup("/a");
        b.version = strdup("1.0");
        b.path = strdup("/b");
        assert_se(a.version && a.path && b.version && b.path);
        int r = pick_result_compare(&a, &b, 0);
        /* With same version, path_compare_filename decides */
        assert_se(r != 0 || streq(a.path, b.path));
        a.version = mfree(a.version);
        a.path = mfree(a.path);
        b.version = mfree(b.version);
        b.path = mfree(b.path);
}

TEST(pick_result_compare_tries) {
        PickResult a = PICK_RESULT_NULL, b = PICK_RESULT_NULL;
        a.path = strdup("/a");
        b.path = strdup("/b");
        assert_se(a.path && b.path);

        a.tries_left = 3;
        b.tries_left = 0;

        /* With PICK_TRIES: a has tries left → a is better */
        assert_se(pick_result_compare(&a, &b, PICK_TRIES) > 0);

        /* Both with tries: more tries is better */
        a.tries_left = 5;
        b.tries_left = 3;
        assert_se(pick_result_compare(&a, &b, PICK_TRIES) > 0);

        a.path = mfree(a.path);
        b.path = mfree(b.path);
}

TEST(pick_result_compare_tries_done) {
        PickResult a = PICK_RESULT_NULL, b = PICK_RESULT_NULL;
        a.path = strdup("/a");
        b.path = strdup("/b");
        assert_se(a.path && b.path);

        a.tries_left = 3;
        a.tries_done = 1;
        b.tries_left = 3;
        b.tries_done = 5;

        /* Same tries_left, fewer tries_done is better */
        int r = pick_result_compare(&a, &b, PICK_TRIES);
        assert_se(r > 0);

        a.path = mfree(a.path);
        b.path = mfree(b.path);
}

TEST(path_uses_vpick) {
        /* Path ending with .v */
        assert_se(path_uses_vpick("/some/path/image.raw.v") > 0);

        /* Regular path → 0 */
        assert_se(path_uses_vpick("/some/path/image.raw") == 0);

        /* Root path → 0 */
        assert_se(path_uses_vpick("/") == 0);
}

TEST(pick_filter_image_raw) {
        /* Verify the global filter is accessible */
        assert_se(pick_filter_image_raw != NULL);
        assert_se(pick_filter_image_raw[0].basename != NULL || pick_filter_image_raw[0].suffix != NULL);
}

TEST(pick_filter_image_dir) {
        assert_se(pick_filter_image_dir != NULL);
}

TEST(pick_filter_image_mstack) {
        assert_se(pick_filter_image_mstack != NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
