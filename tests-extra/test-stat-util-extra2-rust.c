/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: stat-util.h inline functions (stat_is_set, statx_is_set) vs Rust */

#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include "tests.h"
#include "stat-util.h"
#include "rust/stat_util.h"

static void test_stat_is_set(void) {
        struct stat st;

        /* Zeroed stat → not set */
        memset(&st, 0, sizeof(st));
        assert_se(!stat_is_set(&st));
        assert_se(!rs_stat_is_set(&st));

        /* Set st_dev and st_mode → set */
        st.st_dev = 1;
        st.st_mode = S_IFREG;
        assert_se(stat_is_set(&st));
        assert_se(rs_stat_is_set(&st));

        /* MODE_INVALID → not set */
        st.st_mode = (mode_t)-1;
        assert_se(!stat_is_set(&st));
        assert_se(!rs_stat_is_set(&st));

        /* NULL */
        assert_se(!stat_is_set(NULL));
        assert_se(!rs_stat_is_set(NULL));
}

static void test_statx_is_set(void) {
        struct statx sx;

        /* Zeroed statx → not set */
        memset(&sx, 0, sizeof(sx));
        assert_se(!statx_is_set(&sx));
        assert_se(!rs_statx_is_set(&sx));

        /* Non-zero mask → set */
        sx.stx_mask = 1;
        assert_se(statx_is_set(&sx));
        assert_se(rs_statx_is_set(&sx));

        /* NULL */
        assert_se(!statx_is_set(NULL));
        assert_se(!rs_statx_is_set(NULL));
}

int main(int argc, char **argv) {
        test_stat_is_set();
        test_statx_is_set();
        return 0;
}
