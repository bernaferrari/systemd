/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include "stat-util.h"
#include "tests.h"

TEST(stat_is_set_basic) {
        struct stat st = {};
        /* All zeros: st_dev == 0 → not set */
        assert_se(!stat_is_set(&st));
        assert_se(!stat_is_set(NULL));

        /* st_dev != 0 and st_mode != MODE_INVALID → set */
        st.st_dev = 1;
        /* st_mode = 0 is not MODE_INVALID (which is (mode_t)-1), so this IS set */
        assert_se(stat_is_set(&st));

        /* st_mode = MODE_INVALID → not set */
        st.st_mode = MODE_INVALID;
        assert_se(!stat_is_set(&st));

        /* Both valid */
        st.st_mode = S_IFREG;
        assert_se(stat_is_set(&st));
}

TEST(is_fs_type_basic) {
        struct statfs s = {};

        s.f_type = TMPFS_MAGIC;
        assert_se(is_fs_type(&s, TMPFS_MAGIC));
        assert_se(!is_fs_type(&s, PROC_SUPER_MAGIC));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
