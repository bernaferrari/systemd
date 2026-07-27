/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/quota.h>
#include "tests.h"
#include "quota-util.h"

TEST(quota_dqblk_is_populated) {
        struct dqblk dq = {};

        /* Zero dqblk → not populated */
        dq.dqb_valid = QIF_BLIMITS|QIF_SPACE|QIF_ILIMITS|QIF_INODES|QIF_BTIME|QIF_ITIME;
        assert_se(!quota_dqblk_is_populated(&dq));

        /* With a non-zero limit → populated */
        dq.dqb_bhardlimit = 1024;
        assert_se(quota_dqblk_is_populated(&dq));

        /* With a non-zero soft limit → populated */
        dq = (struct dqblk){};
        dq.dqb_valid = QIF_BLIMITS|QIF_SPACE|QIF_ILIMITS|QIF_INODES|QIF_BTIME|QIF_ITIME;
        dq.dqb_bsoftlimit = 512;
        assert_se(quota_dqblk_is_populated(&dq));

        /* With cur space > 0 */
        dq = (struct dqblk){};
        dq.dqb_valid = QIF_BLIMITS|QIF_SPACE|QIF_ILIMITS|QIF_INODES|QIF_BTIME|QIF_ITIME;
        dq.dqb_curspace = 1;
        assert_se(quota_dqblk_is_populated(&dq));

        /* With cur inodes > 0 */
        dq = (struct dqblk){};
        dq.dqb_valid = QIF_BLIMITS|QIF_SPACE|QIF_ILIMITS|QIF_INODES|QIF_BTIME|QIF_ITIME;
        dq.dqb_curinodes = 1;
        assert_se(quota_dqblk_is_populated(&dq));

        /* Missing valid flags → not populated even with data */
        dq = (struct dqblk){};
        dq.dqb_bhardlimit = 1024;
        assert_se(!quota_dqblk_is_populated(&dq));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
