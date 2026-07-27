/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "stat-util.h"
#include "time-util.h"
#include "tests.h"

TEST(stat_is_set) {
        struct stat st = {};

        /* Zeroed struct is NOT set */
        assert_se(!stat_is_set(&st));

        /* Non-zero st_dev makes it set */
        st.st_dev = 1;
        assert_se(stat_is_set(&st));

        /* NULL is not set */
        assert_se(!stat_is_set(NULL));
}

TEST(statx_is_set) {
        struct statx sx = {};

        assert_se(!statx_is_set(&sx));
        assert_se(!statx_is_set(NULL));

        sx.stx_mask = STATX_TYPE;
        assert_se(statx_is_set(&sx));
}

TEST(inode_type_can_hardlink) {
        /* Regular file */
        assert_se(inode_type_can_hardlink(S_IFREG));
        /* Symlink */
        assert_se(inode_type_can_hardlink(S_IFLNK));
        /* Socket */
        assert_se(inode_type_can_hardlink(S_IFSOCK));
        /* Block device */
        assert_se(inode_type_can_hardlink(S_IFBLK));
        /* Char device */
        assert_se(inode_type_can_hardlink(S_IFCHR));
        /* FIFO */
        assert_se(inode_type_can_hardlink(S_IFIFO));

        /* Directory cannot be hardlinked */
        assert_se(!inode_type_can_hardlink(S_IFDIR));
}

TEST(stat_inode_same_basic) {
        struct stat a = {}, b = {};

        /* Both zero → not same (st_dev==0 fails stat_is_set) */
        assert_se(!stat_inode_same(&a, &b));

        /* Same dev+ino+mode → same */
        a.st_dev = 42;
        a.st_ino = 100;
        a.st_mode = S_IFREG | 0644;
        b.st_dev = 42;
        b.st_ino = 100;
        b.st_mode = S_IFREG | 0644;
        assert_se(stat_inode_same(&a, &b));

        /* Different dev → not same */
        b.st_dev = 99;
        assert_se(!stat_inode_same(&a, &b));

        /* Different ino → not same */
        b.st_dev = 42;
        b.st_ino = 200;
        assert_se(!stat_inode_same(&a, &b));

        /* Different inode type → not same */
        b.st_ino = 100;
        b.st_mode = S_IFDIR | 0755;
        assert_se(!stat_inode_same(&a, &b));
}

TEST(stat_inode_unmodified_basic) {
        struct stat a = {}, b = {};

        /* Both zero → not unmodified (stat_is_set fails) */
        assert_se(!stat_inode_unmodified(&a, &b));

        /* Set matching fields */
        a.st_dev = 42;
        a.st_ino = 100;
        a.st_mode = S_IFREG | 0644;
        a.st_size = 1234;
        a.st_mtim.tv_sec = 1000;

        b = a;
        assert_se(stat_inode_unmodified(&a, &b));

        /* Different size → modified */
        b.st_size = 5678;
        assert_se(!stat_inode_unmodified(&a, &b));
}

TEST(statx_timestamp_load_basic) {
        struct statx_timestamp ts = {
                .tv_sec = 1000,
                .tv_nsec = 500000,
        };

        usec_t usec = statx_timestamp_load(&ts);
        assert_se(usec == USEC_PER_SEC * 1000 + 500);

        /* Zero */
        ts.tv_sec = 0;
        ts.tv_nsec = 0;
        assert_se(statx_timestamp_load(&ts) == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
