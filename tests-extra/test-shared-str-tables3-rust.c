/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C shared/ string tables batch 3 vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "socket-label.h"
#include "metrics.h"
#include "mstack.h"
#include "bus-util.h"
#include "user-record.h"
#include "gpt.h"
#include "netif-naming-scheme.h"
#include "condition.h"

/* Rust FFI */
#include "rust/netdev_str_tables.h"

/* ── socket_address_bind_ipv6_only ───────────────────────────────────── */

static void test_socket_address_bind_ipv6_only(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = socket_address_bind_ipv6_only_to_string(SOCKET_ADDRESS_DEFAULT);
        r_ret = rs_socket_address_bind_ipv6_only_to_string(SOCKET_ADDRESS_DEFAULT);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = socket_address_bind_ipv6_only_to_string(SOCKET_ADDRESS_IPV6_ONLY);
        r_ret = rs_socket_address_bind_ipv6_only_to_string(SOCKET_ADDRESS_IPV6_ONLY);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = socket_address_bind_ipv6_only_from_string("both");
        rv = rs_socket_address_bind_ipv6_only_from_string("both");
        assert_se((int)cv == rv);
}

/* ── metric_family_type (to_string only) ─────────────────────────────── */

static void test_metric_family_type(void) {
        const char *c_ret, *r_ret;

        c_ret = metric_family_type_to_string(METRIC_FAMILY_TYPE_COUNTER);
        r_ret = rs_metric_family_type_to_string(METRIC_FAMILY_TYPE_COUNTER);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = metric_family_type_to_string(METRIC_FAMILY_TYPE_STRING);
        r_ret = rs_metric_family_type_to_string(METRIC_FAMILY_TYPE_STRING);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = metric_family_type_to_string(METRIC_FAMILY_TYPE_OBJECT);
        r_ret = rs_metric_family_type_to_string(METRIC_FAMILY_TYPE_OBJECT);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

/* ── mstack_mount_type (to_string only) ──────────────────────────────── */

static void test_mstack_mount_type(void) {
        const char *c_ret, *r_ret;

        c_ret = mstack_mount_type_to_string(MSTACK_ROOT);
        r_ret = rs_mstack_mount_type_to_string(MSTACK_ROOT);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = mstack_mount_type_to_string(MSTACK_ROBIND);
        r_ret = rs_mstack_mount_type_to_string(MSTACK_ROBIND);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

/* ── bus_transport (to_string only) ──────────────────────────────────── */

static void test_bus_transport(void) {
        const char *c_ret, *r_ret;

        c_ret = bus_transport_to_string(BUS_TRANSPORT_LOCAL);
        r_ret = rs_bus_transport_to_string(BUS_TRANSPORT_LOCAL);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = bus_transport_to_string(BUS_TRANSPORT_CAPSULE);
        r_ret = rs_bus_transport_to_string(BUS_TRANSPORT_CAPSULE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

/* ── user_storage ────────────────────────────────────────────────────── */

static void test_user_storage(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = user_storage_to_string(USER_CLASSIC);
        r_ret = rs_user_storage_to_string(USER_CLASSIC);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = user_storage_to_string(USER_CIFS);
        r_ret = rs_user_storage_to_string(USER_CIFS);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = user_storage_from_string("luks");
        rv = rs_user_storage_from_string("luks");
        assert_se((int)cv == rv);

        cv = user_storage_from_string("bogus");
        rv = rs_user_storage_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── user_disposition ───────────────────────────────────────────────── */

static void test_user_disposition(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = user_disposition_to_string(USER_INTRINSIC);
        r_ret = rs_user_disposition_to_string(USER_INTRINSIC);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = user_disposition_to_string(USER_RESERVED);
        r_ret = rs_user_disposition_to_string(USER_RESERVED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = user_disposition_from_string("regular");
        rv = rs_user_disposition_from_string("regular");
        assert_se((int)cv == rv);
}

/* ── auto_resize_mode ────────────────────────────────────────────────── */

static void test_auto_resize_mode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = auto_resize_mode_to_string(AUTO_RESIZE_OFF);
        r_ret = rs_auto_resize_mode_to_string(AUTO_RESIZE_OFF);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = auto_resize_mode_to_string(AUTO_RESIZE_SHRINK_AND_GROW);
        r_ret = rs_auto_resize_mode_to_string(AUTO_RESIZE_SHRINK_AND_GROW);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = auto_resize_mode_from_string("grow");
        rv = rs_auto_resize_mode_from_string("grow");
        assert_se((int)cv == rv);
}

/* ── partition_designator ────────────────────────────────────────────── */

static void test_partition_designator(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = partition_designator_to_string(PARTITION_ROOT);
        r_ret = rs_partition_designator_to_string(PARTITION_ROOT);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = partition_designator_to_string(PARTITION_VAR);
        r_ret = rs_partition_designator_to_string(PARTITION_VAR);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = partition_designator_to_string(PARTITION_USR_VERITY_SIG);
        r_ret = rs_partition_designator_to_string(PARTITION_USR_VERITY_SIG);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = partition_designator_from_string("esp");
        rv = rs_partition_designator_from_string("esp");
        assert_se((int)cv == rv);

        cv = partition_designator_from_string("bogus");
        rv = rs_partition_designator_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── name_policy ─────────────────────────────────────────────────────── */

static void test_name_policy(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = name_policy_to_string(NAMEPOLICY_KERNEL);
        r_ret = rs_name_policy_to_string(NAMEPOLICY_KERNEL);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = name_policy_to_string(NAMEPOLICY_MAC);
        r_ret = rs_name_policy_to_string(NAMEPOLICY_MAC);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = name_policy_from_string("database");
        rv = rs_name_policy_from_string("database");
        assert_se((int)cv == rv);

        cv = name_policy_from_string("bogus");
        rv = rs_name_policy_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── alternative_names_policy ─────────────────────────────────────────── */

static void test_alternative_names_policy(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = alternative_names_policy_to_string(NAMEPOLICY_DATABASE);
        r_ret = rs_alternative_names_policy_to_string(NAMEPOLICY_DATABASE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = alternative_names_policy_to_string(NAMEPOLICY_MAC);
        r_ret = rs_alternative_names_policy_to_string(NAMEPOLICY_MAC);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = alternative_names_policy_from_string("path");
        rv = rs_alternative_names_policy_from_string("path");
        assert_se((int)cv == rv);
}

/* ── condition_result ────────────────────────────────────────────────── */

static void test_condition_result(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = condition_result_to_string(CONDITION_UNTESTED);
        r_ret = rs_condition_result_to_string(CONDITION_UNTESTED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = condition_result_to_string(CONDITION_ERROR);
        r_ret = rs_condition_result_to_string(CONDITION_ERROR);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = condition_result_from_string("succeeded");
        rv = rs_condition_result_from_string("succeeded");
        assert_se((int)cv == rv);

        cv = condition_result_from_string("bogus");
        rv = rs_condition_result_from_string("bogus");
        assert_se((int)cv == rv);
}

int main(int argc, char **argv) {
        test_socket_address_bind_ipv6_only();
        test_metric_family_type();
        test_mstack_mount_type();
        test_bus_transport();
        test_user_storage();
        test_user_disposition();
        test_auto_resize_mode();
        test_partition_designator();
        test_name_policy();
        test_alternative_names_policy();
        test_condition_result();
        return 0;
}
