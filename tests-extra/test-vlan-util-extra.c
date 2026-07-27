/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "vlan-util.h"

TEST(vlanid_is_valid) {
        assert_se(vlanid_is_valid(0));
        assert_se(vlanid_is_valid(1));
        assert_se(vlanid_is_valid(4094));
        assert_se(!vlanid_is_valid(4095));
        assert_se(!vlanid_is_valid(UINT16_MAX));
}

TEST(parse_vlanid) {
        uint16_t id;

        assert_se(parse_vlanid("0", &id) >= 0 && id == 0);
        assert_se(parse_vlanid("1", &id) >= 0 && id == 1);
        assert_se(parse_vlanid("4094", &id) >= 0 && id == 4094);
        assert_se(parse_vlanid("100", &id) >= 0 && id == 100);

        assert_se(parse_vlanid("4095", &id) == -ERANGE);
        assert_se(parse_vlanid("65535", &id) == -ERANGE);
        assert_se(parse_vlanid("-1", &id) < 0);
        assert_se(parse_vlanid("abc", &id) < 0);
        assert_se(parse_vlanid("", &id) < 0);
}

TEST(parse_vid_range) {
        uint16_t vid, vid_end;

        assert_se(parse_vid_range("1-100", &vid, &vid_end) >= 0);
        assert_se(vid == 1 && vid_end == 100);

        assert_se(parse_vid_range("0-4094", &vid, &vid_end) >= 0);
        assert_se(vid == 0 && vid_end == 4094);

        assert_se(parse_vid_range("100-100", &vid, &vid_end) >= 0);
        assert_se(vid == 100 && vid_end == 100);

        assert_se(parse_vid_range("4095-4096", &vid, &vid_end) == -EINVAL);
        assert_se(parse_vid_range("100-50", &vid, &vid_end) == -EINVAL);
        assert_se(parse_vid_range("abc", &vid, &vid_end) < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
