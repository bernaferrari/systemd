/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/statfs.h>
#include <sys/vfs.h>

#include "stat-util.h"
#include "siphash24.h"
#include "tests.h"

TEST(stat_inode_same_basic) {
        struct stat a = {}, b = {};

        /* Both unset (st_dev == 0, st_mode == MODE_INVALID) → stat_is_set returns false */
        assert_se(!stat_inode_same(&a, &b));

        /* Set them to look like real inodes */
        a.st_dev = 1;
        a.st_ino = 100;
        a.st_mode = S_IFREG | 0644;
        b.st_dev = 1;
        b.st_ino = 100;
        b.st_mode = S_IFREG | 0755;
        assert_se(stat_inode_same(&a, &b));

        /* Different inode */
        b.st_ino = 200;
        assert_se(!stat_inode_same(&a, &b));

        /* Different device */
        b.st_ino = 100;
        b.st_dev = 2;
        assert_se(!stat_inode_same(&a, &b));

        /* Different type */
        b.st_dev = 1;
        b.st_mode = S_IFDIR | 0755;
        assert_se(!stat_inode_same(&a, &b));
}

TEST(stat_inode_unmodified_basic) {
        struct stat a = {}, b = {};

        a.st_dev = 1; a.st_ino = 100; a.st_mode = S_IFREG | 0644;
        b.st_dev = 1; b.st_ino = 100; b.st_mode = S_IFREG | 0644;
        assert_se(stat_inode_unmodified(&a, &b));

        /* Different mtime */
        b.st_mtim.tv_sec = 1;
        assert_se(!stat_inode_unmodified(&a, &b));
}

TEST(stat_may_be_dev_null_basic) {
        struct stat st = {};
        st.st_mode = S_IFCHR;
        assert_se(stat_may_be_dev_null(&st));

        st.st_mode = S_IFREG;
        assert_se(!stat_may_be_dev_null(&st));

        st.st_mode = S_IFDIR;
        assert_se(!stat_may_be_dev_null(&st));
}

TEST(stat_is_empty_basic) {
        struct stat st = {};
        st.st_mode = S_IFREG;
        st.st_size = 0;
        assert_se(stat_is_empty(&st));

        st.st_size = -1;
        assert_se(stat_is_empty(&st));

        st.st_size = 100;
        assert_se(!stat_is_empty(&st));

        st.st_mode = S_IFDIR;
        st.st_size = 0;
        assert_se(!stat_is_empty(&st));
}

TEST(is_fs_type_basic) {
        struct statfs sfs = {};
        sfs.f_type = 0x01021994; /* TMPFS_MAGIC */
        assert_se(is_fs_type(&sfs, 0x01021994));
        assert_se(!is_fs_type(&sfs, 0x6969)); /* NFS_SUPER_MAGIC */
}

TEST(inode_hash_func_basic) {
        struct stat st = {
                .st_dev = 42,
                .st_ino = 12345,
                .st_mode = S_IFREG | 0644,
        };
        struct siphash state;
        siphash24_init(&state, (const uint8_t[16]){});
        inode_hash_func(&st, &state);
        uint64_t h = siphash24_finalize(&state);
        assert_se(h != 0 || st.st_dev != 0); /* just exercise */
}

TEST(inode_compare_func_basic) {
        struct stat a = { .st_dev = 1, .st_ino = 100, .st_mode = S_IFREG };
        struct stat b = { .st_dev = 1, .st_ino = 100, .st_mode = S_IFREG };
        assert_se(inode_compare_func(&a, &b) == 0);

        b.st_ino = 200;
        assert_se(inode_compare_func(&a, &b) < 0);
        assert_se(inode_compare_func(&b, &a) > 0);

        b.st_ino = 100;
        b.st_dev = 2;
        assert_se(inode_compare_func(&a, &b) < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
