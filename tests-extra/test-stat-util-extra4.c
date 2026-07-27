/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "siphash24.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"

TEST(stat_inode_same_basic) {
        struct stat a = {}, b = {};

        /* Same dev and ino */
        a.st_dev = 42;
        a.st_ino = 100;
        b.st_dev = 42;
        b.st_ino = 100;
        assert_se(stat_inode_same(&a, &b));

        /* Different ino */
        b.st_ino = 101;
        assert_se(!stat_inode_same(&a, &b));

        /* Different dev */
        b.st_dev = 43;
        b.st_ino = 100;
        assert_se(!stat_inode_same(&a, &b));
}

TEST(stat_inode_unmodified_basic) {
        struct stat a = {}, b = {};

        a.st_dev = 1; a.st_ino = 10; a.st_mode = S_IFREG | 0644; a.st_size = 100; a.st_mtim.tv_sec = 5;
        b = a;
        assert_se(stat_inode_unmodified(&a, &b));

        /* Size changed (for regular files) */
        b.st_size = 200;
        assert_se(!stat_inode_unmodified(&a, &b));

        /* mtime changed */
        b = a;
        b.st_mtim.tv_sec = 6;
        assert_se(!stat_inode_unmodified(&a, &b));

        /* dev changed */
        b = a;
        b.st_dev = 2;
        assert_se(!stat_inode_unmodified(&a, &b));
}

TEST(inode_hash_compare_func) {
        struct stat a = { .st_dev = 1, .st_ino = 10 };
        struct stat b = { .st_dev = 1, .st_ino = 10 };
        struct stat c = { .st_dev = 2, .st_ino = 10 };

        assert_se(inode_compare_func(&a, &b) == 0);
        assert_se(inode_compare_func(&a, &c) != 0);

        struct siphash state;
        const uint8_t key[16] = {};
        siphash24_init(&state, key);
        inode_hash_func(&a, &state);
}

TEST(inode_unmodified_hash_compare_func) {
        struct stat a = { .st_dev = 1, .st_ino = 10, .st_mode = 0644, .st_size = 100, .st_mtim.tv_sec = 5 };
        struct stat b = a;

        assert_se(inode_unmodified_compare_func(&a, &b) == 0);

        struct siphash state;
        const uint8_t key[16] = {};
        siphash24_init(&state, key);
        inode_unmodified_hash_func(&a, &state);
}

TEST(statx_inode_same_basic) {
        struct statx a = {}, b = {};

        a.stx_mask = STATX_TYPE | STATX_INO;
        a.stx_dev_major = 1; a.stx_dev_minor = 0; a.stx_ino = 100;
        b = a;
        assert_se(statx_inode_same(&a, &b));

        b.stx_ino = 200;
        assert_se(!statx_inode_same(&a, &b));
}

TEST(statx_mount_same_basic) {
        struct statx a = {}, b = {};

        /* Need STATX_MNT_ID set in mask */
        a.stx_mask = STATX_MNT_ID; a.stx_mnt_id = 42;
        b = a;
        assert_se(statx_mount_same(&a, &b));

        b.stx_mnt_id = 99;
        assert_se(!statx_mount_same(&a, &b));

        /* Mask set but no MNT_ID → returns -ENODATA */
        a.stx_mask = STATX_TYPE; b.stx_mask = STATX_TYPE;
        assert_se(statx_mount_same(&a, &b) == -ENODATA);

        /* No mask set → statx_is_set returns false → returns false */
        a.stx_mask = 0; b.stx_mask = 0;
        assert_se(statx_mount_same(&a, &b) == false);
}

TEST(is_fs_type_basic) {
        struct statfs s = {};

        /* Just test the comparison logic with an arbitrary value */
        s.f_type = 0x01021994;
        assert_se(is_fs_type(&s, 0x01021994));
        assert_se(!is_fs_type(&s, 0xDEADBEEF));
}

TEST(statx_timestamp_load_basic) {
        struct statx_timestamp ts = {
                .tv_sec = 1000,
                .tv_nsec = 500000000,
        };

        usec_t usec = statx_timestamp_load(&ts);
        assert_se(usec == USEC_PER_SEC * 1000 + 500000);

        nsec_t nsec = statx_timestamp_load_nsec(&ts);
        assert_se(nsec == NSEC_PER_SEC * 1000 + 500000000);
}

TEST(inode_type_can_hardlink_basic) {
        assert_se(inode_type_can_hardlink(S_IFREG));
        assert_se(inode_type_can_hardlink(S_IFLNK));
        assert_se(inode_type_can_hardlink(S_IFSOCK));
        assert_se(inode_type_can_hardlink(S_IFCHR));
        assert_se(inode_type_can_hardlink(S_IFBLK));
        assert_se(inode_type_can_hardlink(S_IFIFO));
        assert_se(!inode_type_can_hardlink(S_IFDIR));
        assert_se(!inode_type_can_hardlink(0));
}

TEST(inode_type_to_string_basic) {
        assert_se(streq(inode_type_to_string(S_IFREG), "reg"));
        assert_se(streq(inode_type_to_string(S_IFDIR), "dir"));
        assert_se(streq(inode_type_to_string(S_IFLNK), "lnk"));
        assert_se(streq(inode_type_to_string(S_IFCHR), "chr"));
        assert_se(streq(inode_type_to_string(S_IFBLK), "blk"));
        assert_se(streq(inode_type_to_string(S_IFIFO), "fifo"));
        assert_se(streq(inode_type_to_string(S_IFSOCK), "sock"));
        assert_se(inode_type_to_string(0) == NULL);

        assert_se(inode_type_from_string("reg") == S_IFREG);
        assert_se(inode_type_from_string("dir") == S_IFDIR);
        assert_se(inode_type_from_string("lnk") == S_IFLNK);
        assert_se(inode_type_from_string("invalid") == (mode_t)-1);
}

TEST(stat_is_set_basic) {
        struct stat st = {};
        assert_se(!stat_is_set(&st));

        st.st_dev = 1;
        st.st_mode = 0644;
        assert_se(stat_is_set(&st));

        /* dev=0 means not set */
        st.st_dev = 0;
        assert_se(!stat_is_set(&st));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
