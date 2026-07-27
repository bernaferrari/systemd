/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "ioprio-util.h"
#include "tests.h"
#include "vlan-util.h"

/* ── ioprio_parse_priority ─────────────────────────────────────────── */

TEST(ioprio_parse_priority_basic) {
        int v;
        int r;

        /* Valid numeric priorities (0 to IOPRIO_NR_LEVELS-1 = 7) */
        r = ioprio_parse_priority("0", &v);
        ASSERT_EQ(r, 0);
        ASSERT_GE(v, 0);

        r = ioprio_parse_priority("7", &v);
        ASSERT_EQ(r, 0);
        ASSERT_GE(v, 0);

        /* Above max level */
        r = ioprio_parse_priority("8", &v);
        ASSERT_EQ(r, -EINVAL);

        /* Not a number */
        r = ioprio_parse_priority("abc", &v);
        ASSERT_EQ(r, -EINVAL);

        /* Negative */
        r = ioprio_parse_priority("-1", &v);
        ASSERT_LT(r, 0);

        /* Empty */
        r = ioprio_parse_priority("", &v);
        ASSERT_EQ(r, -EINVAL);
}

/* ── parse_vlanid ──────────────────────────────────────────────────── */

TEST(parse_vlanid_basic) {
        uint16_t id;
        int r;

        r = parse_vlanid("0", &id);
        ASSERT_EQ(r, 0);
        assert_se(id == 0);

        r = parse_vlanid("100", &id);
        ASSERT_EQ(r, 0);
        assert_se(id == 100);

        r = parse_vlanid("4094", &id);
        ASSERT_EQ(r, 0);
        assert_se(id == 4094);

        /* Max + 1 is invalid */
        r = parse_vlanid("4095", &id);
        ASSERT_EQ(r, -ERANGE);

        /* Not a number */
        r = parse_vlanid("abc", &id);
        ASSERT_EQ(r, -EINVAL);

        /* Negative */
        r = parse_vlanid("-1", &id);
        ASSERT_LT(r, 0);
}

/* ── parse_vid_range ──────────────────────────────────────────────── */

TEST(parse_vid_range_basic) {
        uint16_t vid, vid_end;
        int r;

        /* Single VLAN ID */
        r = parse_vid_range("100", &vid, &vid_end);
        ASSERT_EQ(r, 0);
        assert_se(vid == 100);
        assert_se(vid_end == 100);

        /* Range */
        r = parse_vid_range("100-200", &vid, &vid_end);
        ASSERT_EQ(r, 0);
        assert_se(vid == 100);
        assert_se(vid_end == 200);

        /* Full range */
        r = parse_vid_range("0-4094", &vid, &vid_end);
        ASSERT_EQ(r, 0);
        assert_se(vid == 0);
        assert_se(vid_end == 4094);

        /* Reversed range */
        r = parse_vid_range("200-100", &vid, &vid_end);
        ASSERT_EQ(r, -EINVAL);

        /* Above max */
        r = parse_vid_range("4095", &vid, &vid_end);
        ASSERT_EQ(r, -EINVAL);

        /* Not a number */
        r = parse_vid_range("abc", &vid, &vid_end);
        ASSERT_EQ(r, -EINVAL);
}

/* ── cg_weight_parse ──────────────────────────────────────────────── */

TEST(cg_weight_parse_basic) {
        uint64_t w;
        int r;

        r = cg_weight_parse("1", &w);
        ASSERT_EQ(r, 0);
        assert_se(w == CGROUP_WEIGHT_MIN);

        r = cg_weight_parse("10000", &w);
        ASSERT_EQ(r, 0);
        assert_se(w == CGROUP_WEIGHT_MAX);

        r = cg_weight_parse("500", &w);
        ASSERT_EQ(r, 0);
        assert_se(w == 500);

        /* Empty string → INVALID */
        r = cg_weight_parse("", &w);
        ASSERT_EQ(r, 0);
        assert_se(w == CGROUP_WEIGHT_INVALID);

        /* Below min */
        r = cg_weight_parse("0", &w);
        ASSERT_EQ(r, -ERANGE);

        /* Above max */
        r = cg_weight_parse("10001", &w);
        ASSERT_EQ(r, -ERANGE);

        /* Not a number */
        r = cg_weight_parse("abc", &w);
        ASSERT_EQ(r, -EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
