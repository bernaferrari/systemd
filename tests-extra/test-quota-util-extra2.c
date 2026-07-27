/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/quota.h>

#include "quota-util.h"
#include "tests.h"

TEST(quota_dqblk_is_populated) {
        struct dqblk req = {};

        /* Zeroed → not populated */
        assert_se(!quota_dqblk_is_populated(&req));

        /* Set valid flags but no actual limits → not populated */
        req.dqb_valid = QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES | QIF_BTIME | QIF_ITIME;
        assert_se(!quota_dqblk_is_populated(&req));

        /* Set one hard limit → populated */
        req.dqb_bhardlimit = 100;
        assert_se(quota_dqblk_is_populated(&req));

        /* Reset and set soft limit */
        req = (struct dqblk) {};
        req.dqb_valid = QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES | QIF_BTIME | QIF_ITIME;
        req.dqb_bsoftlimit = 50;
        assert_se(quota_dqblk_is_populated(&req));

        /* Reset and set inode limits */
        req = (struct dqblk) {};
        req.dqb_valid = QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES | QIF_BTIME | QIF_ITIME;
        req.dqb_ihardlimit = 10;
        assert_se(quota_dqblk_is_populated(&req));

        /* Reset and set curspace */
        req = (struct dqblk) {};
        req.dqb_valid = QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES | QIF_BTIME | QIF_ITIME;
        req.dqb_curspace = 1024;
        assert_se(quota_dqblk_is_populated(&req));

        /* Reset and set curinodes */
        req = (struct dqblk) {};
        req.dqb_valid = QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES | QIF_BTIME | QIF_ITIME;
        req.dqb_curinodes = 5;
        assert_se(quota_dqblk_is_populated(&req));

        /* Reset and set btime */
        req = (struct dqblk) {};
        req.dqb_valid = QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES | QIF_BTIME | QIF_ITIME;
        req.dqb_btime = 60;
        assert_se(quota_dqblk_is_populated(&req));

        /* Reset and set itime */
        req = (struct dqblk) {};
        req.dqb_valid = QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES | QIF_BTIME | QIF_ITIME;
        req.dqb_itime = 120;
        assert_se(quota_dqblk_is_populated(&req));

        /* Missing valid flags → not populated even with data */
        req = (struct dqblk) {};
        req.dqb_bhardlimit = 100;
        assert_se(!quota_dqblk_is_populated(&req));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
