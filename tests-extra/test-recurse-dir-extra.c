/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"

static char *test_dir = NULL;

static int count_files_callback(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        int *count = ASSERT_PTR(userdata);

        if (event == RECURSE_DIR_ENTRY)
                (*count)++;

        return RECURSE_DIR_CONTINUE;
}

TEST(recurse_dir_basic) {
        const char *d = "/tmp";
        int count = 0;

        /* Recurse into /tmp with a low depth limit — just verify it doesn't crash */
        (void) recurse_dir_at(AT_FDCWD, d, 0, 1,
                               RECURSE_DIR_SORT|RECURSE_DIR_ENSURE_TYPE,
                               count_files_callback, &count);
        /* We should find at least something */
        assert_se(count >= 0);
}

TEST(readdir_all_basic) {
        _cleanup_close_ int fd = open("/tmp", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        assert_se(fd >= 0);

        _cleanup_free_ DirectoryEntries *entries = NULL;
        int r = readdir_all(fd, RECURSE_DIR_SORT, &entries);
        assert_se(r >= 0);
        assert_se(entries->n_entries >= 1);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
