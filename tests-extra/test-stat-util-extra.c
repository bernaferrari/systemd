/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "stat-util.h"
#include "tests.h"

TEST(inode_type_to_string) {
        ASSERT_STREQ(inode_type_to_string(S_IFREG), "reg");
        ASSERT_STREQ(inode_type_to_string(S_IFDIR), "dir");
        ASSERT_STREQ(inode_type_to_string(S_IFLNK), "lnk");
        ASSERT_STREQ(inode_type_to_string(S_IFCHR), "chr");
        ASSERT_STREQ(inode_type_to_string(S_IFBLK), "blk");
        ASSERT_STREQ(inode_type_to_string(S_IFIFO), "fifo");
        ASSERT_STREQ(inode_type_to_string(S_IFSOCK), "sock");

        /* Unknown type */
        ASSERT_NULL(inode_type_to_string(0));
        ASSERT_NULL(inode_type_to_string(S_IFMT)); /* all type bits set */
}

TEST(inode_type_from_string) {
        ASSERT_EQ(inode_type_from_string("reg"), S_IFREG);
        ASSERT_EQ(inode_type_from_string("dir"), S_IFDIR);
        ASSERT_EQ(inode_type_from_string("lnk"), S_IFLNK);
        ASSERT_EQ(inode_type_from_string("chr"), S_IFCHR);
        ASSERT_EQ(inode_type_from_string("blk"), S_IFBLK);
        ASSERT_EQ(inode_type_from_string("fifo"), S_IFIFO);
        ASSERT_EQ(inode_type_from_string("sock"), S_IFSOCK);

        /* Unknown */
        ASSERT_EQ(inode_type_from_string("unknown"), MODE_INVALID);
        ASSERT_EQ(inode_type_from_string(NULL), MODE_INVALID);
}

TEST(stat_may_be_dev_null) {
        struct stat st;

        /* Character device */
        st = (struct stat){ .st_mode = S_IFCHR | 0666 };
        ASSERT_TRUE(stat_may_be_dev_null(&st));

        /* Regular file */
        st = (struct stat){ .st_mode = S_IFREG | 0644 };
        ASSERT_FALSE(stat_may_be_dev_null(&st));

        /* Directory */
        st = (struct stat){ .st_mode = S_IFDIR | 0755 };
        ASSERT_FALSE(stat_may_be_dev_null(&st));
}

TEST(stat_is_empty) {
        struct stat st;

        /* Empty regular file */
        st = (struct stat){ .st_mode = S_IFREG, .st_size = 0 };
        ASSERT_TRUE(stat_is_empty(&st));

        /* Non-empty regular file */
        st = (struct stat){ .st_mode = S_IFREG, .st_size = 100 };
        ASSERT_FALSE(stat_is_empty(&st));

        /* Directory is not "empty" in this sense */
        st = (struct stat){ .st_mode = S_IFDIR, .st_size = 0 };
        ASSERT_FALSE(stat_is_empty(&st));

        /* Character device is not "empty" */
        st = (struct stat){ .st_mode = S_IFCHR, .st_size = 0 };
        ASSERT_FALSE(stat_is_empty(&st));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
