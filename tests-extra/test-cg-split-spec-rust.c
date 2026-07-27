/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: cg_split_spec */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "cgroup-util.h"
#include "rust/unit_def.h"

static void test_cg_split_spec(void) {
        _cleanup_free_ char *c_ctrl = NULL, *rs_ctrl = NULL;
        _cleanup_free_ char *c_path = NULL, *rs_path = NULL;
        int c_ret, rs_ret;

        /* Empty spec */
        c_ret = cg_split_spec("", &c_ctrl, &c_path);
        rs_ret = rs_cg_split_spec("", &rs_ctrl, &rs_path);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_ctrl == NULL || isempty(c_ctrl));
        assert_se(rs_ctrl == NULL || isempty(rs_ctrl));
        c_ctrl = mfree(c_ctrl); rs_ctrl = mfree(rs_ctrl);
        c_path = mfree(c_path); rs_path = mfree(rs_path);

        /* Absolute path only (no controller) */
        c_ret = cg_split_spec("/user.slice", &c_ctrl, &c_path);
        rs_ret = rs_cg_split_spec("/user.slice", &rs_ctrl, &rs_path);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_ctrl == NULL || isempty(c_ctrl));
        assert_se(rs_ctrl == NULL || isempty(rs_ctrl));
        assert_se(c_path != NULL && rs_path != NULL);
        assert_se(streq(c_path, rs_path));
        c_ctrl = mfree(c_ctrl); rs_ctrl = mfree(rs_ctrl);
        c_path = mfree(c_path); rs_path = mfree(rs_path);

        /* Controller only */
        c_ret = cg_split_spec("cpu", &c_ctrl, &c_path);
        rs_ret = rs_cg_split_spec("cpu", &rs_ctrl, &rs_path);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_ctrl != NULL && rs_ctrl != NULL);
        assert_se(streq(c_ctrl, rs_ctrl));
        assert_se(streq(c_ctrl, "cpu"));
        assert_se(c_path == NULL || isempty(c_path));
        c_ctrl = mfree(c_ctrl); rs_ctrl = mfree(rs_ctrl);
        c_path = mfree(c_path); rs_path = mfree(rs_path);

        /* Controller and path */
        c_ret = cg_split_spec("cpu:/user.slice", &c_ctrl, &c_path);
        rs_ret = rs_cg_split_spec("cpu:/user.slice", &rs_ctrl, &rs_path);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_ctrl, rs_ctrl));
        assert_se(streq(c_ctrl, "cpu"));
        assert_se(streq(c_path, rs_path));
        assert_se(streq(c_path, "/user.slice"));
        c_ctrl = mfree(c_ctrl); rs_ctrl = mfree(rs_ctrl);
        c_path = mfree(c_path); rs_path = mfree(rs_path);

        /* Controller and path with dots */
        c_ret = cg_split_spec("memory:/user-1000.slice/user.slice", &c_ctrl, &c_path);
        rs_ret = rs_cg_split_spec("memory:/user-1000.slice/user.slice", &rs_ctrl, &rs_path);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_ctrl, "memory"));
        assert_se(streq(c_path, rs_path));
        c_ctrl = mfree(c_ctrl); rs_ctrl = mfree(rs_ctrl);
        c_path = mfree(c_path); rs_path = mfree(rs_path);

        /* Invalid: relative path after colon */
        c_ret = cg_split_spec("cpu:relative/path", &c_ctrl, &c_path);
        rs_ret = rs_cg_split_spec("cpu:relative/path", &rs_ctrl, &rs_path);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret < 0);
        c_ctrl = mfree(c_ctrl); rs_ctrl = mfree(rs_ctrl);
        c_path = mfree(c_path); rs_path = mfree(rs_path);

        /* Invalid: path with dot-dot */
        c_ret = cg_split_spec("cpu:/user/../etc", &c_ctrl, &c_path);
        rs_ret = rs_cg_split_spec("cpu:/user/../etc", &rs_ctrl, &rs_path);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret < 0);
        c_ctrl = mfree(c_ctrl); rs_ctrl = mfree(rs_ctrl);
        c_path = mfree(c_path); rs_path = mfree(rs_path);

        /* Controller with empty path (colon at end) */
        c_ret = cg_split_spec("cpu:", &c_ctrl, &c_path);
        rs_ret = rs_cg_split_spec("cpu:", &rs_ctrl, &rs_path);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_ctrl, rs_ctrl));
        c_ctrl = mfree(c_ctrl); rs_ctrl = mfree(rs_ctrl);
        c_path = mfree(c_path); rs_path = mfree(rs_path);

        /* Root path only */
        c_ret = cg_split_spec("/", &c_ctrl, &c_path);
        rs_ret = rs_cg_split_spec("/", &rs_ctrl, &rs_path);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_path, rs_path));
        c_ctrl = mfree(c_ctrl); rs_ctrl = mfree(rs_ctrl);
        c_path = mfree(c_path); rs_path = mfree(rs_path);
}

int main(int argc, char **argv) {
        test_cg_split_spec();
        return 0;
}
