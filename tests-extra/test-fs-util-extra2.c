/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "os-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"

static char *test_dir = NULL;

static int setup_test_dir(void) {
        test_dir = strdup("/tmp/test-fs-util-extra2-XXXXXX");
        assert_se(test_dir);
        assert_se(mkdtemp(test_dir));
        return 0;
}

static void teardown_test_dir(void) {
        if (test_dir) {
                (void) rm_rf(test_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
                free(test_dir);
                test_dir = NULL;
        }
}

TEST(tmp_dir_basic) {
        const char *d;
        assert_se(tmp_dir(&d) >= 0);
        assert_se(!isempty(d));
        log_debug("tmp_dir: %s", d);
}

TEST(var_tmp_dir_basic) {
        const char *d;
        assert_se(var_tmp_dir(&d) >= 0);
        assert_se(!isempty(d));
        log_debug("var_tmp_dir: %s", d);
}

TEST(path_is_os_tree_basic) {
        /* / is an OS tree */
        int r = path_is_os_tree("/");
        log_debug("path_is_os_tree(\"/\"): %d", r);
        /* Result depends on environment, just verify no crash */
}

TEST(unlink_or_warn_basic) {
        setup_test_dir();
        assert_se(test_dir);

        const char *path = strjoina(test_dir, "/nonexistent");
        /* Should not crash on nonexistent file */
        (void) unlink_or_warn(path);

        /* Create and then unlink */
        const char *file = strjoina(test_dir, "/to-delete");
        assert_se(touch(file) >= 0);
        assert_se(unlink_or_warn(file) >= 0);
        assert_se(access(file, F_OK) < 0);

        teardown_test_dir();
}

TEST(access_nofollow_basic) {
        setup_test_dir();
        assert_se(test_dir);

        const char *file = strjoina(test_dir, "/file");
        assert_se(write_string_file(file, "test", WRITE_STRING_FILE_CREATE) >= 0);

        int r = access_nofollow(file, R_OK);
        assert_se(r >= 0);

        teardown_test_dir();
}

TEST(chmod_and_chown_at_basic) {
        setup_test_dir();
        assert_se(test_dir);

        const char *file = strjoina(test_dir, "/file");
        assert_se(write_string_file(file, "test", WRITE_STRING_FILE_CREATE) >= 0);

        /* Just chmod, no chown (use -1 for uid/gid) */
        assert_se(chmod_and_chown_at(AT_FDCWD, file, 0644, UID_INVALID, GID_INVALID) >= 0);

        teardown_test_dir();
}

DEFINE_TEST_MAIN(LOG_DEBUG);
