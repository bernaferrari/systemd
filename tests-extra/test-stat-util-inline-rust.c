/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: stat-util.h inline functions vs Rust */

#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include "tests.h"
#include "stat-util.h"
#include "time-util.h"
#include "rust/stat_util.h"

/* ── stat_is_set ───────────────────────────────────────────────────────── */

/* RUST-CONTRACT: stat-is-set */
static void test_stat_is_set(void) {
        struct stat st;

        /* NULL → not set */
        assert_se(!rs_stat_is_set(NULL));

        /* Zeroed stat → not set (st_dev == 0) */
        memset(&st, 0, sizeof(st));
        assert_se(stat_is_set(&st) == rs_stat_is_set(&st));
        assert_se(!stat_is_set(&st));

        /* Set st_dev, keep st_mode valid */
        memset(&st, 0, sizeof(st));
        st.st_dev = 1;
        assert_se(stat_is_set(&st) == rs_stat_is_set(&st));
        assert_se(stat_is_set(&st));

        /* Set st_mode to MODE_INVALID */
        memset(&st, 0, sizeof(st));
        st.st_dev = 1;
        st.st_mode = (mode_t)-1;
        assert_se(stat_is_set(&st) == rs_stat_is_set(&st));
        assert_se(!stat_is_set(&st));
}

/* ── statx_is_set ──────────────────────────────────────────────────────── */

static void test_statx_is_set(void) {
        struct statx sx;

        /* NULL → not set */
        assert_se(!rs_statx_is_set(NULL));

        /* Zeroed statx → not set (stx_mask == 0) */
        memset(&sx, 0, sizeof(sx));
        assert_se(statx_is_set(&sx) == rs_statx_is_set(&sx));
        assert_se(!statx_is_set(&sx));

        /* Set stx_mask */
        memset(&sx, 0, sizeof(sx));
        sx.stx_mask = 1;
        assert_se(statx_is_set(&sx) == rs_statx_is_set(&sx));
        assert_se(statx_is_set(&sx));
}

/* ── statx_timestamp_load ──────────────────────────────────────────────── */

/* RUST-CONTRACT: statx-timestamp */
static void test_statx_timestamp_load(void) {
        struct statx_timestamp ts;

        /* NULL → USEC_INFINITY */
        assert_se(rs_statx_timestamp_load(NULL) == USEC_INFINITY);
        assert_se(rs_statx_timestamp_load_nsec(NULL) == NSEC_INFINITY);

        /* Zero timestamp → 0 */
        memset(&ts, 0, sizeof(ts));
        assert_se(statx_timestamp_load(&ts) == rs_statx_timestamp_load(&ts));
        assert_se(statx_timestamp_load(&ts) == 0);

        /* Specific value: 1 sec = 1000000 usec */
        memset(&ts, 0, sizeof(ts));
        ts.tv_sec = 1;
        assert_se(statx_timestamp_load(&ts) == rs_statx_timestamp_load(&ts));
        assert_se(statx_timestamp_load(&ts) == USEC_PER_SEC);

        /* 1 sec = 1000000000 nsec */
        memset(&ts, 0, sizeof(ts));
        ts.tv_sec = 1;
        assert_se(statx_timestamp_load_nsec(&ts) == rs_statx_timestamp_load_nsec(&ts));
        assert_se(statx_timestamp_load_nsec(&ts) == NSEC_PER_SEC);

        /* Negative tv_sec → USEC_INFINITY */
        memset(&ts, 0, sizeof(ts));
        ts.tv_sec = -1;
        assert_se(statx_timestamp_load(&ts) == USEC_INFINITY);
        assert_se(rs_statx_timestamp_load(&ts) == USEC_INFINITY);

        /* Large value with nsec: 1 sec + 500000 nsec */
        memset(&ts, 0, sizeof(ts));
        ts.tv_sec = 1;
        ts.tv_nsec = 500000;
        assert_se(statx_timestamp_load(&ts) == rs_statx_timestamp_load(&ts));
        assert_se(statx_timestamp_load(&ts) == USEC_PER_SEC + 500); /* 500000 / 1000 */
        assert_se(statx_timestamp_load_nsec(&ts) == rs_statx_timestamp_load_nsec(&ts));
        assert_se(statx_timestamp_load_nsec(&ts) == NSEC_PER_SEC + 500000);
}

/* ── is_fs_type ────────────────────────────────────────────────────────── */

/* RUST-CONTRACT: is-fs-type */
static void test_is_fs_type(void) {
        struct statfs s;

        /* NULL → false */
        assert_se(!rs_is_fs_type(NULL, 0));

        /* Matching type */
        memset(&s, 0, sizeof(s));
        s.f_type = 0x01021994; /* TMPFS_MAGIC */
        assert_se(is_fs_type(&s, 0x01021994) == rs_is_fs_type(&s, 0x01021994));
        assert_se(is_fs_type(&s, 0x01021994));

        /* Non-matching type */
        assert_se(is_fs_type(&s, 0x6969) == rs_is_fs_type(&s, 0x6969));
        assert_se(!is_fs_type(&s, 0x6969));

        /* Zero type vs zero magic */
        memset(&s, 0, sizeof(s));
        assert_se(is_fs_type(&s, 0) == rs_is_fs_type(&s, 0));
}

int main(int argc, char **argv) {
        test_stat_is_set();
        test_statx_is_set();
        test_statx_timestamp_load();
        test_is_fs_type();
        return 0;
}
