/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "chattr-util.h"
#include "tests.h"

TEST(inode_type_can_chattr_basic) {
        assert_se(inode_type_can_chattr(S_IFREG));
        assert_se(inode_type_can_chattr(S_IFDIR));
        assert_se(inode_type_can_chattr(0100644));  /* regular file with permissions */
        assert_se(inode_type_can_chattr(0040755));  /* directory with permissions */

        assert_se(!inode_type_can_chattr(S_IFLNK));
        assert_se(!inode_type_can_chattr(S_IFCHR));
        assert_se(!inode_type_can_chattr(S_IFBLK));
        assert_se(!inode_type_can_chattr(S_IFIFO));
        assert_se(!inode_type_can_chattr(S_IFSOCK));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
