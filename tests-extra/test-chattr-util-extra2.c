/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "chattr-util.h"
#include "tests.h"

TEST(inode_type_can_chattr) {
        /* Regular files and directories can chattr */
        assert_se(inode_type_can_chattr(S_IFREG));
        assert_se(inode_type_can_chattr(S_IFDIR));

        /* Symlinks, devices, fifos, sockets cannot */
        assert_se(!inode_type_can_chattr(S_IFLNK));
        assert_se(!inode_type_can_chattr(S_IFBLK));
        assert_se(!inode_type_can_chattr(S_IFCHR));
        assert_se(!inode_type_can_chattr(S_IFIFO));
        assert_se(!inode_type_can_chattr(S_IFSOCK));

        /* Zero mode (unknown) */
        assert_se(!inode_type_can_chattr(0));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
