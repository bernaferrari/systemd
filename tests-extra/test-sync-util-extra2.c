/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioctl.h>

#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "sync-util.h"
#include "tests.h"

static char *test_dir = NULL;

static int setup_test_dir(void) {
        test_dir = strdup("/tmp/test-sync-util-extra2-XXXXXX");
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

TEST(fsync_full_basic) {
        setup_test_dir();
        assert_se(test_dir);

        const char *path = strjoina(test_dir, "/file");
        assert_se(write_string_file(path, "data", WRITE_STRING_FILE_CREATE) >= 0);

        _cleanup_close_ int fd = open(path, O_RDWR);
        assert_se(fd >= 0);
        assert_se(fsync_full(fd) >= 0);

        teardown_test_dir();
}

TEST(fsync_path_at_basic) {
        setup_test_dir();
        assert_se(test_dir);

        const char *path = strjoina(test_dir, "/file");
        assert_se(write_string_file(path, "data", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(fsync_path_at(AT_FDCWD, path) >= 0);

        teardown_test_dir();
}

TEST(fsync_parent_at_basic) {
        setup_test_dir();
        assert_se(test_dir);

        const char *path = strjoina(test_dir, "/file");
        assert_se(write_string_file(path, "data", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(fsync_parent_at(AT_FDCWD, path) >= 0);

        teardown_test_dir();
}

TEST(fsync_path_and_parent_at_basic) {
        setup_test_dir();
        assert_se(test_dir);

        const char *path = strjoina(test_dir, "/file");
        assert_se(write_string_file(path, "data", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(fsync_path_and_parent_at(AT_FDCWD, path) >= 0);

        teardown_test_dir();
}

DEFINE_TEST_MAIN(LOG_DEBUG);
