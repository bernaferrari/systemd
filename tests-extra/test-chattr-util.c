/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "chattr-util.h"
#include "tests.h"

TEST(inode_type_can_chattr_regular) {
        ASSERT_TRUE(inode_type_can_chattr(S_IFREG));
}

TEST(inode_type_can_chattr_directory) {
        ASSERT_TRUE(inode_type_can_chattr(S_IFDIR));
}

TEST(inode_type_can_chattr_fifo) {
        ASSERT_FALSE(inode_type_can_chattr(S_IFIFO));
}

TEST(inode_type_can_chattr_char_device) {
        ASSERT_FALSE(inode_type_can_chattr(S_IFCHR));
}

TEST(inode_type_can_chattr_block_device) {
        ASSERT_FALSE(inode_type_can_chattr(S_IFBLK));
}

TEST(inode_type_can_chattr_socket) {
        ASSERT_FALSE(inode_type_can_chattr(S_IFSOCK));
}

TEST(inode_type_can_chattr_symlink) {
        ASSERT_FALSE(inode_type_can_chattr(S_IFLNK));
}

TEST(inode_type_can_chattr_zero) {
        ASSERT_FALSE(inode_type_can_chattr(0));
}

TEST(chattr_secret_flags) {
        /* Verify CHATTR_SECRET_FLAGS is non-zero and has expected bits */
        ASSERT_TRUE(FLAGS_SET(CHATTR_SECRET_FLAGS, FS_SECRM_FL));
        ASSERT_TRUE(FLAGS_SET(CHATTR_SECRET_FLAGS, FS_NODUMP_FL));
        ASSERT_TRUE(FLAGS_SET(CHATTR_SECRET_FLAGS, FS_SYNC_FL));
        ASSERT_TRUE(FLAGS_SET(CHATTR_SECRET_FLAGS, FS_NOCOW_FL));
}

TEST(chattr_all_flags_nonzero) {
        /* Verify CHATTR_ALL_FL includes common flags */
        ASSERT_TRUE(FLAGS_SET(CHATTR_ALL_FL, FS_NOATIME_FL));
        ASSERT_TRUE(FLAGS_SET(CHATTR_ALL_FL, FS_SYNC_FL));
        ASSERT_TRUE(FLAGS_SET(CHATTR_ALL_FL, FS_APPEND_FL));
        ASSERT_TRUE(FLAGS_SET(CHATTR_ALL_FL, FS_IMMUTABLE_FL));
}

TEST(chattr_early_flags_nonzero) {
        /* Verify CHATTR_EARLY_FL is non-zero and has expected bits */
        ASSERT_TRUE(FLAGS_SET(CHATTR_EARLY_FL, FS_NOATIME_FL));
        ASSERT_TRUE(FLAGS_SET(CHATTR_EARLY_FL, FS_COMPR_FL));
        ASSERT_TRUE(FLAGS_SET(CHATTR_EARLY_FL, FS_NOCOW_FL));
        ASSERT_TRUE(FLAGS_SET(CHATTR_EARLY_FL, FS_PROJINHERIT_FL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
