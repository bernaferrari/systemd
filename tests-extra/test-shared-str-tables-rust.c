/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C shared/ string tables vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "macvlan-util.h"
#include "ipvlan-util.h"
#include "geneve-util.h"
#include "sleep-config.h"
#include "factory-reset.h"
#include "hostname-setup.h"
#include "numa-util.h"
#include "output-mode.h"

/* Rust FFI */
#include "rust/netdev_str_tables.h"

/* ── macvlan_mode ─────────────────────────────────────────────────────── */

static void test_macvlan_mode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = macvlan_mode_to_string(NETDEV_MACVLAN_MODE_PRIVATE);
        r_ret = rs_macvlan_mode_to_string(NETDEV_MACVLAN_MODE_PRIVATE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = macvlan_mode_to_string(NETDEV_MACVLAN_MODE_BRIDGE);
        r_ret = rs_macvlan_mode_to_string(NETDEV_MACVLAN_MODE_BRIDGE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = macvlan_mode_to_string(NETDEV_MACVLAN_MODE_SOURCE);
        r_ret = rs_macvlan_mode_to_string(NETDEV_MACVLAN_MODE_SOURCE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = macvlan_mode_from_string("private");
        rv = rs_macvlan_mode_from_string("private");
        assert_se((int)cv == rv);

        cv = macvlan_mode_from_string("bogus");
        rv = rs_macvlan_mode_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── ipvlan_mode ──────────────────────────────────────────────────────── */

static void test_ipvlan_mode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L2);
        r_ret = rs_ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L2);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L3S);
        r_ret = rs_ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L3S);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = ipvlan_mode_from_string("L2");
        rv = rs_ipvlan_mode_from_string("L2");
        assert_se((int)cv == rv);
}

/* ── ipvlan_flags ─────────────────────────────────────────────────────── */

static void test_ipvlan_flags(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_BRIGDE);
        r_ret = rs_ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_BRIGDE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_PRIVATE);
        r_ret = rs_ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_PRIVATE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = ipvlan_flags_from_string("vepa");
        rv = rs_ipvlan_flags_from_string("vepa");
        assert_se((int)cv == rv);
}

/* ── geneve_df ────────────────────────────────────────────────────────── */

static void test_geneve_df(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = geneve_df_to_string(NETDEV_GENEVE_DF_UNSET);
        r_ret = rs_geneve_df_to_string(NETDEV_GENEVE_DF_UNSET);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = geneve_df_to_string(NETDEV_GENEVE_DF_INHERIT);
        r_ret = rs_geneve_df_to_string(NETDEV_GENEVE_DF_INHERIT);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = geneve_df_from_string("set");
        rv = rs_geneve_df_from_string("set");
        assert_se((int)cv == rv);
}

/* ── sleep_operation ──────────────────────────────────────────────────── */

static void test_sleep_operation(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = sleep_operation_to_string(SLEEP_SUSPEND);
        r_ret = rs_sleep_operation_to_string(SLEEP_SUSPEND);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = sleep_operation_to_string(SLEEP_HIBERNATE);
        r_ret = rs_sleep_operation_to_string(SLEEP_HIBERNATE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = sleep_operation_to_string(SLEEP_SUSPEND_THEN_HIBERNATE);
        r_ret = rs_sleep_operation_to_string(SLEEP_SUSPEND_THEN_HIBERNATE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = sleep_operation_from_string("hybrid-sleep");
        rv = rs_sleep_operation_from_string("hybrid-sleep");
        assert_se((int)cv == rv);

        cv = sleep_operation_from_string("bogus");
        rv = rs_sleep_operation_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── factory_reset_mode ───────────────────────────────────────────────── */

static void test_factory_reset_mode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = factory_reset_mode_to_string(FACTORY_RESET_UNSUPPORTED);
        r_ret = rs_factory_reset_mode_to_string(FACTORY_RESET_UNSUPPORTED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = factory_reset_mode_to_string(FACTORY_RESET_ON);
        r_ret = rs_factory_reset_mode_to_string(FACTORY_RESET_ON);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = factory_reset_mode_to_string(FACTORY_RESET_PENDING);
        r_ret = rs_factory_reset_mode_to_string(FACTORY_RESET_PENDING);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = factory_reset_mode_from_string("off");
        rv = rs_factory_reset_mode_from_string("off");
        assert_se((int)cv == rv);
}

/* ── hostname_source ──────────────────────────────────────────────────── */

static void test_hostname_source(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = hostname_source_to_string(HOSTNAME_STATIC);
        r_ret = rs_hostname_source_to_string(HOSTNAME_STATIC);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = hostname_source_to_string(HOSTNAME_TRANSIENT);
        r_ret = rs_hostname_source_to_string(HOSTNAME_TRANSIENT);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = hostname_source_from_string("default");
        rv = rs_hostname_source_from_string("default");
        assert_se((int)cv == rv);
}

/* ── mpol ─────────────────────────────────────────────────────────────── */

static void test_mpol(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = mpol_to_string(MPOL_DEFAULT);
        r_ret = rs_mpol_to_string(MPOL_DEFAULT);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = mpol_to_string(MPOL_LOCAL);
        r_ret = rs_mpol_to_string(MPOL_LOCAL);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = mpol_to_string(MPOL_WEIGHTED_INTERLEAVE);
        r_ret = rs_mpol_to_string(MPOL_WEIGHTED_INTERLEAVE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = mpol_from_string("interleave");
        rv = rs_mpol_from_string("interleave");
        assert_se((int)cv == rv);

        cv = mpol_from_string("bogus");
        rv = rs_mpol_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── output_mode ──────────────────────────────────────────────────────── */

static void test_output_mode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = output_mode_to_string(OUTPUT_SHORT);
        r_ret = rs_output_mode_to_string(OUTPUT_SHORT);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = output_mode_to_string(OUTPUT_JSON_PRETTY);
        r_ret = rs_output_mode_to_string(OUTPUT_JSON_PRETTY);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = output_mode_to_string(OUTPUT_WITH_UNIT);
        r_ret = rs_output_mode_to_string(OUTPUT_WITH_UNIT);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = output_mode_from_string("json");
        rv = rs_output_mode_from_string("json");
        assert_se((int)cv == rv);

        cv = output_mode_from_string("bogus");
        rv = rs_output_mode_from_string("bogus");
        assert_se((int)cv == rv);
}

int main(int argc, char **argv) {
        test_macvlan_mode();
        test_ipvlan_mode();
        test_ipvlan_flags();
        test_geneve_df();
        test_sleep_operation();
        test_factory_reset_mode();
        test_hostname_source();
        test_mpol();
        test_output_mode();
        return 0;
}
