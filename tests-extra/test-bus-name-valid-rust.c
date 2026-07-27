/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Shadow test for D-Bus name/path validation functions ported from
 * src/libsystemd/sd-bus/bus-internal.c to src/basic/rust/bus_name_valid.rs
 *
 * Note: The C originals live in libsystemd which is not linked here,
 * so we use expected-value assertions instead of C-vs-Rust comparison. */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "tests.h"

#include "rust/bus_name_valid.h"

/* ── object_path_is_valid ──────────────────────────────────────────────── */

static void test_object_path_valid_basic(void) {
        assert_se(rs_object_path_is_valid("/"));
        assert_se(rs_object_path_is_valid("/foo"));
        assert_se(rs_object_path_is_valid("/foo/bar"));
        assert_se(rs_object_path_is_valid("/foo/bar/baz"));
        assert_se(rs_object_path_is_valid("/_underscore"));
        assert_se(rs_object_path_is_valid("/foo/Bar_123"));
}

static void test_object_path_valid_null_and_empty(void) {
        assert_se(!rs_object_path_is_valid(NULL));
        assert_se(!rs_object_path_is_valid(""));
}

static void test_object_path_valid_rejects(void) {
        assert_se(!rs_object_path_is_valid("foo"));
        assert_se(!rs_object_path_is_valid("//"));
        assert_se(!rs_object_path_is_valid("/foo//bar"));
        assert_se(!rs_object_path_is_valid("/foo/bar/"));
        assert_se(!rs_object_path_is_valid("/foo-bar"));
        assert_se(!rs_object_path_is_valid("/foo.bar"));
        assert_se(!rs_object_path_is_valid("/foo bar"));
}

/* ── object_path_startswith ────────────────────────────────────────────── */

static void test_object_path_startswith_basic(void) {
        const char *a = "/org/freedesktop/systemd1/job/42";
        const char *r;

        r = rs_object_path_startswith(a, "/org/freedesktop/systemd1");
        assert_se(r != NULL);
        assert_se(streq(r, "job/42"));

        /* Root path matches everything */
        r = rs_object_path_startswith(a, "/");
        assert_se(r != NULL);
        assert_se(streq(r, "org/freedesktop/systemd1/job/42"));

        /* Exact match → points to NUL */
        r = rs_object_path_startswith("/org/foo", "/org/foo");
        assert_se(r != NULL);
        assert_se(*r == '\0');

        /* No match */
        r = rs_object_path_startswith(a, "/org/com/example");
        assert_se(r == NULL);

        /* Partial label match must fail */
        r = rs_object_path_startswith("/foo/bar", "/foo/ba");
        assert_se(r == NULL);

        /* Invalid paths → NULL */
        r = rs_object_path_startswith(NULL, "/foo");
        assert_se(r == NULL);
        r = rs_object_path_startswith("/foo", NULL);
        assert_se(r == NULL);
}

/* ── interface_name_is_valid ───────────────────────────────────────────── */

static void test_interface_name_valid_basic(void) {
        assert_se(rs_interface_name_is_valid("org.freedesktop.DBus"));
        assert_se(rs_interface_name_is_valid("a.b"));
        assert_se(rs_interface_name_is_valid("org_1.foo_2"));
}

static void test_interface_name_valid_rejects(void) {
        assert_se(!rs_interface_name_is_valid(NULL));
        assert_se(!rs_interface_name_is_valid(""));
        assert_se(!rs_interface_name_is_valid("nodash"));
        assert_se(!rs_interface_name_is_valid(".foo"));
        assert_se(!rs_interface_name_is_valid("foo."));
        assert_se(!rs_interface_name_is_valid("foo..bar"));
        assert_se(!rs_interface_name_is_valid("1.foo"));      /* digit at start of element */
        assert_se(!rs_interface_name_is_valid("org.foo-bar")); /* hyphen not allowed */
}

/* ── service_name_is_valid ─────────────────────────────────────────────── */

static void test_service_name_valid_basic(void) {
        assert_se(rs_service_name_is_valid("org.freedesktop.systemd1"));
        assert_se(rs_service_name_is_valid(":1.42"));
        assert_se(rs_service_name_is_valid(":1.0"));
        assert_se(rs_service_name_is_valid("com.example.MyApp"));
        assert_se(rs_service_name_is_valid("org.freedesktop.systemd-1"));
}

static void test_service_name_valid_rejects(void) {
        assert_se(!rs_service_name_is_valid(NULL));
        assert_se(!rs_service_name_is_valid(""));
        assert_se(!rs_service_name_is_valid(":"));
        assert_se(!rs_service_name_is_valid(":nodot"));
        assert_se(!rs_service_name_is_valid("nodot"));
        assert_se(!rs_service_name_is_valid("1.foo")); /* digit at start of non-unique */
}

/* ── member_name_is_valid ──────────────────────────────────────────────── */

static void test_member_name_valid_basic(void) {
        assert_se(rs_member_name_is_valid("Start"));
        assert_se(rs_member_name_is_valid("GetAll"));
        assert_se(rs_member_name_is_valid("_underscore"));
        assert_se(rs_member_name_is_valid("abc123"));
}

static void test_member_name_valid_rejects(void) {
        assert_se(!rs_member_name_is_valid(NULL));
        assert_se(!rs_member_name_is_valid(""));
        assert_se(!rs_member_name_is_valid("foo.bar"));
        assert_se(!rs_member_name_is_valid("foo-bar"));
        assert_se(!rs_member_name_is_valid("foo bar"));
}

/* ── namespace_complex_pattern ─────────────────────────────────────────── */

static void test_namespace_complex_pattern(void) {
        /* Equal strings */
        assert_se(rs_namespace_complex_pattern("org.foo", "org.foo"));
        /* Prefix ending with separator character matches */
        assert_se(rs_namespace_complex_pattern("org.foo.", "org.foo.bar"));
        /* Symmetric: longer ending with separator also matches */
        assert_se(rs_namespace_complex_pattern("org.foo.bar", "org.foo."));
        /* "org.foo" does NOT match "org.foo.bar" (no trailing separator) */
        assert_se(!rs_namespace_complex_pattern("org.foo", "org.foo.bar"));
        /* Partial label — not a match */
        assert_se(!rs_namespace_complex_pattern("org.fo", "org.foo"));
        assert_se(!rs_namespace_complex_pattern("org.foo", "org.fo"));
        /* NULL handling */
        assert_se(rs_namespace_complex_pattern(NULL, NULL));
        assert_se(!rs_namespace_complex_pattern(NULL, "org.foo"));
        assert_se(!rs_namespace_complex_pattern("org.foo", NULL));
}

/* ── path_complex_pattern ──────────────────────────────────────────────── */

static void test_path_complex_pattern(void) {
        assert_se(rs_path_complex_pattern("/org/foo", "/org/foo"));
        assert_se(rs_path_complex_pattern("/org/foo/", "/org/foo/bar"));
        assert_se(rs_path_complex_pattern("/org/foo/bar", "/org/foo/"));
        assert_se(!rs_path_complex_pattern("/org/foo", "/org/foo/bar"));
        assert_se(!rs_path_complex_pattern("/org/fo", "/org/foo"));
}

/* ── namespace_simple_pattern ──────────────────────────────────────────── */

static void test_namespace_simple_pattern(void) {
        /* Equal */
        assert_se(rs_namespace_simple_pattern("org.foo", "org.foo"));
        /* a is prefix of b — a ends at separator boundary → match */
        assert_se(rs_namespace_simple_pattern("org.foo", "org.foo.bar"));
        /* a with trailing separator */
        assert_se(rs_namespace_simple_pattern("org.foo.", "org.foo.bar"));
        /* NOT symmetric */
        assert_se(!rs_namespace_simple_pattern("org.foo.bar", "org.foo"));
        /* Partial label */
        assert_se(!rs_namespace_simple_pattern("org.fo", "org.foo"));
}

/* ── path_simple_pattern ───────────────────────────────────────────────── */

static void test_path_simple_pattern(void) {
        assert_se(rs_path_simple_pattern("/org/foo", "/org/foo"));
        assert_se(rs_path_simple_pattern("/org/foo", "/org/foo/bar"));
        assert_se(!rs_path_simple_pattern("/org/foo/bar", "/org/foo"));
}

/* ── bus_message_type_to_string ────────────────────────────────────────── */

static void test_bus_message_type_to_string(void) {
        assert_se(streq(rs_bus_message_type_to_string(4), "signal"));
        assert_se(streq(rs_bus_message_type_to_string(1), "method_call"));
        assert_se(streq(rs_bus_message_type_to_string(3), "error"));
        assert_se(streq(rs_bus_message_type_to_string(2), "method_return"));
        assert_se(rs_bus_message_type_to_string(0) == NULL);
        assert_se(rs_bus_message_type_to_string(99) == NULL);
}

/* ── bus_message_type_from_string ──────────────────────────────────────── */

static void test_bus_message_type_from_string(void) {
        uint8_t u;

        assert_se(rs_bus_message_type_from_string("signal", &u) == 0);
        assert_se(u == 4);

        assert_se(rs_bus_message_type_from_string("method_call", &u) == 0);
        assert_se(u == 1);

        assert_se(rs_bus_message_type_from_string("error", &u) == 0);
        assert_se(u == 3);

        assert_se(rs_bus_message_type_from_string("method_return", &u) == 0);
        assert_se(u == 2);

        assert_se(rs_bus_message_type_from_string("invalid", &u) == -EINVAL);
        assert_se(rs_bus_message_type_from_string(NULL, &u) == -EINVAL);
        assert_se(rs_bus_message_type_from_string("signal", NULL) == -EINVAL);
}

/* ── bus_address_escape ────────────────────────────────────────────────── */

static void test_bus_address_escape(void) {
        char *r;

        /* All safe characters pass through (alphanumeric + _-/. ) */
        r = rs_bus_address_escape("unix-path/run/dbus_system_bus.socket");
        assert_se(r != NULL);
        assert_se(streq(r, "unix-path/run/dbus_system_bus.socket"));
        free(r);

        /* Space is percent-encoded */
        r = rs_bus_address_escape("hello world");
        assert_se(r != NULL);
        assert_se(streq(r, "hello%20world"));
        free(r);

        /* Colon is percent-encoded (not in safe set "_-/." ) */
        r = rs_bus_address_escape("tcp:host=localhost");
        assert_se(r != NULL);
        assert_se(streq(r, "tcp%3ahost%3dlocalhost"));
        free(r);

        /* Empty string */
        r = rs_bus_address_escape("");
        assert_se(r != NULL);
        assert_se(streq(r, ""));
        free(r);

        /* NULL returns NULL */
        assert_se(rs_bus_address_escape(NULL) == NULL);
}

int main(int argc, char *argv[]) {
        test_object_path_valid_basic();
        test_object_path_valid_null_and_empty();
        test_object_path_valid_rejects();
        test_object_path_startswith_basic();
        test_interface_name_valid_basic();
        test_interface_name_valid_rejects();
        test_service_name_valid_basic();
        test_service_name_valid_rejects();
        test_member_name_valid_basic();
        test_member_name_valid_rejects();
        test_namespace_complex_pattern();
        test_path_complex_pattern();
        test_namespace_simple_pattern();
        test_path_simple_pattern();
        test_bus_message_type_to_string();
        test_bus_message_type_from_string();
        test_bus_address_escape();

        return 0;
}
