/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Shadow test for D-Bus match node type parsing ported from
 * src/libsystemd/sd-bus/bus-match.c (bus_match_node_type_from_string)
 * to src/basic/rust/bus_match_util.rs
 *
 * Note: The C original lives in libsystemd which is not linked here,
 * so we use expected-value assertions instead of C-vs-Rust comparison. */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "tests.h"

#include "rust/bus_match_util.h"

/* Match node type enum values (from bus-match.h) */
#define BUS_MATCH_ROOT            0
#define BUS_MATCH_VALUE           1
#define BUS_MATCH_LEAF            2
#define BUS_MATCH_SENDER          3
#define BUS_MATCH_MESSAGE_TYPE    4
#define BUS_MATCH_DESTINATION     5
#define BUS_MATCH_INTERFACE       6
#define BUS_MATCH_MEMBER          7
#define BUS_MATCH_PATH            8
#define BUS_MATCH_PATH_NAMESPACE  9
#define BUS_MATCH_ARG             10
#define BUS_MATCH_ARG_LAST        73
#define BUS_MATCH_ARG_PATH        74
#define BUS_MATCH_ARG_PATH_LAST   137
#define BUS_MATCH_ARG_NAMESPACE   138
#define BUS_MATCH_ARG_NAMESPACE_LAST 201
#define BUS_MATCH_ARG_HAS         202
#define BUS_MATCH_ARG_HAS_LAST    265

/* ── named types ───────────────────────────────────────────────────────── */

static void test_named_types(void) {
        assert_se(rs_bus_match_node_type_from_string("type", 4) == BUS_MATCH_MESSAGE_TYPE);
        assert_se(rs_bus_match_node_type_from_string("sender", 6) == BUS_MATCH_SENDER);
        assert_se(rs_bus_match_node_type_from_string("destination", 11) == BUS_MATCH_DESTINATION);
        assert_se(rs_bus_match_node_type_from_string("interface", 9) == BUS_MATCH_INTERFACE);
        assert_se(rs_bus_match_node_type_from_string("member", 6) == BUS_MATCH_MEMBER);
        assert_se(rs_bus_match_node_type_from_string("path", 4) == BUS_MATCH_PATH);
        assert_se(rs_bus_match_node_type_from_string("path_namespace", 14) == BUS_MATCH_PATH_NAMESPACE);
}

/* ── arg single digit ─────────────────────────────────────────────────── */

static void test_arg_single_digit(void) {
        assert_se(rs_bus_match_node_type_from_string("arg0", 4) == BUS_MATCH_ARG + 0);
        assert_se(rs_bus_match_node_type_from_string("arg1", 4) == BUS_MATCH_ARG + 1);
        assert_se(rs_bus_match_node_type_from_string("arg5", 4) == BUS_MATCH_ARG + 5);
        assert_se(rs_bus_match_node_type_from_string("arg9", 4) == BUS_MATCH_ARG + 9);
}

/* ── arg two digit ────────────────────────────────────────────────────── */

static void test_arg_two_digit(void) {
        /* "arg00" is invalid (a<=0 rejects leading zero); use "arg10" */
        assert_se(rs_bus_match_node_type_from_string("arg00", 5) == -EINVAL);
        assert_se(rs_bus_match_node_type_from_string("arg10", 5) == BUS_MATCH_ARG + 10);
        assert_se(rs_bus_match_node_type_from_string("arg63", 5) == BUS_MATCH_ARG_LAST);
}

/* ── argXpath single digit ────────────────────────────────────────────── */

static void test_arg_path_single_digit(void) {
        assert_se(rs_bus_match_node_type_from_string("arg0path", 8) == BUS_MATCH_ARG_PATH + 0);
        assert_se(rs_bus_match_node_type_from_string("arg5path", 8) == BUS_MATCH_ARG_PATH + 5);
        assert_se(rs_bus_match_node_type_from_string("arg9path", 8) == BUS_MATCH_ARG_PATH + 9);
}

/* ── argXXpath two digit ──────────────────────────────────────────────── */

static void test_arg_path_two_digit(void) {
        assert_se(rs_bus_match_node_type_from_string("arg00path", 9) == -EINVAL);
        assert_se(rs_bus_match_node_type_from_string("arg10path", 9) == BUS_MATCH_ARG_PATH + 10);
        assert_se(rs_bus_match_node_type_from_string("arg63path", 9) == BUS_MATCH_ARG_PATH_LAST);
}

/* ── argXnamespace single digit ───────────────────────────────────────── */

static void test_arg_namespace_single_digit(void) {
        assert_se(rs_bus_match_node_type_from_string("arg0namespace", 13) == BUS_MATCH_ARG_NAMESPACE + 0);
        assert_se(rs_bus_match_node_type_from_string("arg9namespace", 13) == BUS_MATCH_ARG_NAMESPACE + 9);
}

/* ── argXXnamespace two digit ─────────────────────────────────────────── */

static void test_arg_namespace_two_digit(void) {
        assert_se(rs_bus_match_node_type_from_string("arg00namespace", 14) == -EINVAL);
        assert_se(rs_bus_match_node_type_from_string("arg63namespace", 14) == BUS_MATCH_ARG_NAMESPACE_LAST);
}

/* ── argXhas single digit ────────────────────────────────────────────── */

static void test_arg_has_single_digit(void) {
        assert_se(rs_bus_match_node_type_from_string("arg0has", 7) == BUS_MATCH_ARG_HAS + 0);
        assert_se(rs_bus_match_node_type_from_string("arg9has", 7) == BUS_MATCH_ARG_HAS + 9);
}

/* ── argXXhas two digit ───────────────────────────────────────────────── */

static void test_arg_has_two_digit(void) {
        assert_se(rs_bus_match_node_type_from_string("arg00has", 8) == -EINVAL);
        assert_se(rs_bus_match_node_type_from_string("arg63has", 8) == BUS_MATCH_ARG_HAS_LAST);
}

/* ── invalid inputs ───────────────────────────────────────────────────── */

static void test_invalid(void) {
        assert_se(rs_bus_match_node_type_from_string("foo", 3) == -EINVAL);
        assert_se(rs_bus_match_node_type_from_string("arg", 3) == -EINVAL);
        assert_se(rs_bus_match_node_type_from_string("argZ", 4) == -EINVAL);
        assert_se(rs_bus_match_node_type_from_string(NULL, 4) == -EINVAL);

        /* Wrong length for a known type */
        assert_se(rs_bus_match_node_type_from_string("typ", 3) == -EINVAL);
        assert_se(rs_bus_match_node_type_from_string("types", 5) == -EINVAL);
}

int main(int argc, char *argv[]) {
        test_named_types();
        test_arg_single_digit();
        test_arg_two_digit();
        test_arg_path_single_digit();
        test_arg_path_two_digit();
        test_arg_namespace_single_digit();
        test_arg_namespace_two_digit();
        test_arg_has_single_digit();
        test_arg_has_two_digit();
        test_invalid();

        return 0;
}
