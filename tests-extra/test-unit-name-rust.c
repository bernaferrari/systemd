/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C unit-name vs Rust rs_unit_name */

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "string-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "rust/unit_name.h"

/* ── Validation: unit_name_is_valid ────────────────────────────────────── */

static void test_unit_name_is_valid_plain(void) {
        assert_se(unit_name_is_valid("foo.service", UNIT_NAME_PLAIN) == rs_unit_name_is_valid("foo.service", UNIT_NAME_PLAIN));
        assert_se(unit_name_is_valid("foo@bar.service", UNIT_NAME_PLAIN) == rs_unit_name_is_valid("foo@bar.service", UNIT_NAME_PLAIN));
        assert_se(unit_name_is_valid("foo@.service", UNIT_NAME_PLAIN) == rs_unit_name_is_valid("foo@.service", UNIT_NAME_PLAIN));
        assert_se(unit_name_is_valid(NULL, UNIT_NAME_PLAIN) == rs_unit_name_is_valid(NULL, UNIT_NAME_PLAIN));
        assert_se(unit_name_is_valid("", UNIT_NAME_PLAIN) == rs_unit_name_is_valid("", UNIT_NAME_PLAIN));
        assert_se(unit_name_is_valid("nope", UNIT_NAME_PLAIN) == rs_unit_name_is_valid("nope", UNIT_NAME_PLAIN));
}

static void test_unit_name_is_valid_instance(void) {
        assert_se(unit_name_is_valid("foo@bar.service", UNIT_NAME_INSTANCE) == rs_unit_name_is_valid("foo@bar.service", UNIT_NAME_INSTANCE));
        assert_se(unit_name_is_valid("foo@.service", UNIT_NAME_INSTANCE) == rs_unit_name_is_valid("foo@.service", UNIT_NAME_INSTANCE));
        assert_se(unit_name_is_valid("foo.service", UNIT_NAME_INSTANCE) == rs_unit_name_is_valid("foo.service", UNIT_NAME_INSTANCE));
}

static void test_unit_name_is_valid_template(void) {
        assert_se(unit_name_is_valid("foo@.service", UNIT_NAME_TEMPLATE) == rs_unit_name_is_valid("foo@.service", UNIT_NAME_TEMPLATE));
        assert_se(unit_name_is_valid("foo@bar.service", UNIT_NAME_TEMPLATE) == rs_unit_name_is_valid("foo@bar.service", UNIT_NAME_TEMPLATE));
        assert_se(unit_name_is_valid("foo.service", UNIT_NAME_TEMPLATE) == rs_unit_name_is_valid("foo.service", UNIT_NAME_TEMPLATE));
}

static void test_unit_name_is_valid_any(void) {
        assert_se(unit_name_is_valid("foo.service", UNIT_NAME_ANY) == rs_unit_name_is_valid("foo.service", UNIT_NAME_ANY));
        assert_se(unit_name_is_valid("foo@bar.service", UNIT_NAME_ANY) == rs_unit_name_is_valid("foo@bar.service", UNIT_NAME_ANY));
        assert_se(unit_name_is_valid("foo@.service", UNIT_NAME_ANY) == rs_unit_name_is_valid("foo@.service", UNIT_NAME_ANY));
        assert_se(unit_name_is_valid("@.service", UNIT_NAME_ANY) == rs_unit_name_is_valid("@.service", UNIT_NAME_ANY));
        assert_se(unit_name_is_valid("foo.badtype", UNIT_NAME_ANY) == rs_unit_name_is_valid("foo.badtype", UNIT_NAME_ANY));
}

/* ── Validation: prefix/instance/suffix ────────────────────────────────── */

static void test_unit_prefix_is_valid(void) {
        assert_se(unit_prefix_is_valid("foo") == rs_unit_prefix_is_valid("foo"));
        assert_se(unit_prefix_is_valid("foo-bar") == rs_unit_prefix_is_valid("foo-bar"));
        assert_se(unit_prefix_is_valid("foo@bar") == rs_unit_prefix_is_valid("foo@bar"));
        assert_se(unit_prefix_is_valid("") == rs_unit_prefix_is_valid(""));
        assert_se(unit_prefix_is_valid(NULL) == rs_unit_prefix_is_valid(NULL));
        assert_se(unit_prefix_is_valid("foo/bar") == rs_unit_prefix_is_valid("foo/bar"));
}

static void test_unit_instance_is_valid(void) {
        assert_se(unit_instance_is_valid("bar") == rs_unit_instance_is_valid("bar"));
        assert_se(unit_instance_is_valid("bar@baz") == rs_unit_instance_is_valid("bar@baz"));
        assert_se(unit_instance_is_valid("") == rs_unit_instance_is_valid(""));
        assert_se(unit_instance_is_valid(NULL) == rs_unit_instance_is_valid(NULL));
}

static void test_unit_suffix_is_valid(void) {
        assert_se(unit_suffix_is_valid(".service") == rs_unit_suffix_is_valid(".service"));
        assert_se(unit_suffix_is_valid(".mount") == rs_unit_suffix_is_valid(".mount"));
        assert_se(unit_suffix_is_valid("service") == rs_unit_suffix_is_valid("service"));
        assert_se(unit_suffix_is_valid("") == rs_unit_suffix_is_valid(""));
        assert_se(unit_suffix_is_valid(".badtype") == rs_unit_suffix_is_valid(".badtype"));
}

/* ── Parsing: to_prefix ────────────────────────────────────────────────── */

static void test_unit_name_to_prefix(void) {
        char *c_ret = NULL, *r_ret = NULL;

        assert_se(unit_name_to_prefix("foo.service", &c_ret) >= 0);
        assert_se(rs_unit_name_to_prefix("foo.service", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        assert_se(unit_name_to_prefix("foo@bar.service", &c_ret) >= 0);
        assert_se(rs_unit_name_to_prefix("foo@bar.service", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        assert_se(unit_name_to_prefix("foo@.service", &c_ret) >= 0);
        assert_se(rs_unit_name_to_prefix("foo@.service", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        /* The prefix ends at '@', not at the suffix. */
        assert_se(unit_name_to_prefix("foo@bar.service", &c_ret) >= 0);
        assert_se(rs_unit_name_to_prefix("foo@bar.service", &r_ret) >= 0);
        assert_se(streq(c_ret, "foo") && streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;
}

/* ── Parsing: to_instance ──────────────────────────────────────────────── */

static void test_unit_name_to_instance(void) {
        char *c_ret = NULL, *r_ret = NULL;
        UnitNameFlags c_flags, r_flags;

        /* Plain */
        c_flags = unit_name_to_instance("foo.service", &c_ret);
        r_flags = rs_unit_name_to_instance("foo.service", &r_ret);
        assert_se(c_flags == r_flags);
        assert_se(c_ret == NULL && r_ret == NULL);

        /* Instance */
        c_flags = unit_name_to_instance("foo@bar.service", &c_ret);
        r_flags = rs_unit_name_to_instance("foo@bar.service", &r_ret);
        assert_se(c_flags == r_flags);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        /* Template */
        c_flags = unit_name_to_instance("foo@.service", &c_ret);
        r_flags = rs_unit_name_to_instance("foo@.service", &r_ret);
        assert_se(c_flags == r_flags);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;
}

/* ── Parsing: to_type ──────────────────────────────────────────────────── */

static void test_unit_name_to_type(void) {
        assert_se(unit_name_to_type("foo.service") == rs_unit_name_to_type("foo.service"));
        assert_se(unit_name_to_type("foo.mount") == rs_unit_name_to_type("foo.mount"));
        assert_se(unit_name_to_type("foo.socket") == rs_unit_name_to_type("foo.socket"));
        assert_se(unit_name_to_type("foo@bar.target") == rs_unit_name_to_type("foo@bar.target"));
}

/* ── Parsing: to_prefix_and_instance ───────────────────────────────────── */

static void test_unit_name_to_prefix_and_instance(void) {
        char *c_ret = NULL, *r_ret = NULL;

        assert_se(unit_name_to_prefix_and_instance("foo@bar.service", &c_ret) >= 0);
        assert_se(rs_unit_name_to_prefix_and_instance("foo@bar.service", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        assert_se(unit_name_to_prefix_and_instance("foo.service", &c_ret) >= 0);
        assert_se(rs_unit_name_to_prefix_and_instance("foo.service", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;
}

/* ── Building: change_suffix ───────────────────────────────────────────── */

static void test_unit_name_change_suffix(void) {
        char *c_ret = NULL, *r_ret = NULL;

        assert_se(unit_name_change_suffix("foo.service", ".mount", &c_ret) >= 0);
        assert_se(rs_unit_name_change_suffix("foo.service", ".mount", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        assert_se(unit_name_change_suffix("foo@bar.service", ".target", &c_ret) >= 0);
        assert_se(rs_unit_name_change_suffix("foo@bar.service", ".target", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;
}

/* ── Building: build ───────────────────────────────────────────────────── */

static void test_unit_name_build(void) {
        char *c_ret = NULL, *r_ret = NULL;

        assert_se(unit_name_build("foo", NULL, ".service", &c_ret) >= 0);
        assert_se(rs_unit_name_build("foo", NULL, ".service", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        assert_se(unit_name_build("foo", "bar", ".service", &c_ret) >= 0);
        assert_se(rs_unit_name_build("foo", "bar", ".service", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;
}

/* ── Escape/unescape ───────────────────────────────────────────────────── */

static void test_unit_name_escape_unescape(void) {
        char *c_escaped, *r_escaped;
        char *c_unescaped = NULL, *r_unescaped = NULL;

        c_escaped = unit_name_escape("/foo/bar");
        r_escaped = rs_unit_name_escape("/foo/bar");
        assert_se(c_escaped && r_escaped);
        assert_se(streq(c_escaped, r_escaped));

        assert_se(unit_name_unescape(c_escaped, &c_unescaped) >= 0);
        assert_se(rs_unit_name_unescape(r_escaped, &r_unescaped) >= 0);
        assert_se(streq(c_unescaped, r_unescaped));
        assert_se(streq(c_unescaped, "/foo/bar"));

        free(c_escaped); free(r_escaped);
        free(c_unescaped); free(r_unescaped);
}

static void test_unit_name_escape_leading_dot(void) {
        char *c_escaped, *r_escaped;
        char *c_unescaped = NULL, *r_unescaped = NULL;

        c_escaped = unit_name_escape(".hidden");
        r_escaped = rs_unit_name_escape(".hidden");
        assert_se(c_escaped && r_escaped);
        assert_se(streq(c_escaped, r_escaped));

        assert_se(unit_name_unescape(c_escaped, &c_unescaped) >= 0);
        assert_se(rs_unit_name_unescape(r_escaped, &r_unescaped) >= 0);
        assert_se(streq(c_unescaped, r_unescaped));

        free(c_escaped); free(r_escaped);
        free(c_unescaped); free(r_unescaped);
}

/* ── Template ──────────────────────────────────────────────────────────── */

static void test_unit_name_template(void) {
        char *c_ret = NULL, *r_ret = NULL;

        assert_se(unit_name_template("foo@bar.service", &c_ret) >= 0);
        assert_se(rs_unit_name_template("foo@bar.service", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "foo@.service"));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;
}

/* ── Replace instance ──────────────────────────────────────────────────── */

static void test_unit_name_replace_instance(void) {
        char *c_ret = NULL, *r_ret = NULL;

        assert_se(unit_name_replace_instance("foo@old.service", "new", &c_ret) >= 0);
        assert_se(rs_unit_name_replace_instance_full("foo@old.service", "new", false, &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "foo@new.service"));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;
}

/* ── Slice operations ──────────────────────────────────────────────────── */

static void test_slice_name_is_valid(void) {
        assert_se(slice_name_is_valid("-.slice") == rs_slice_name_is_valid("-.slice"));
        assert_se(slice_name_is_valid("foo.slice") == rs_slice_name_is_valid("foo.slice"));
        assert_se(slice_name_is_valid("foo-bar.slice") == rs_slice_name_is_valid("foo-bar.slice"));
        assert_se(slice_name_is_valid("foo--bar.slice") == rs_slice_name_is_valid("foo--bar.slice"));
        assert_se(slice_name_is_valid("-foo.slice") == rs_slice_name_is_valid("-foo.slice"));
        assert_se(slice_name_is_valid("foo-.slice") == rs_slice_name_is_valid("foo-.slice"));
}

static void test_slice_build_parent_slice(void) {
        char *c_ret = NULL, *r_ret = NULL;

        assert_se(slice_build_parent_slice("foo-bar.slice", &c_ret) >= 0);
        assert_se(rs_slice_build_parent_slice("foo-bar.slice", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "foo.slice"));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        /* A plain slice has the root slice as its parent and returns 1. */
        assert_se(slice_build_parent_slice("foo.slice", &c_ret) == 1);
        assert_se(rs_slice_build_parent_slice("foo.slice", &r_ret) == 1);
        assert_se(streq(c_ret, "-.slice") && streq(c_ret, r_ret));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        /* Root slice returns NULL */
        assert_se(slice_build_parent_slice("-.slice", &c_ret) >= 0);
        assert_se(rs_slice_build_parent_slice("-.slice", &r_ret) >= 0);
        assert_se(c_ret == NULL && r_ret == NULL);
}

static void test_slice_build_subslice(void) {
        char *c_ret = NULL, *r_ret = NULL;

        assert_se(slice_build_subslice("-.slice", "foo", &c_ret) >= 0);
        assert_se(rs_slice_build_subslice("-.slice", "foo", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "foo.slice"));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;

        assert_se(slice_build_subslice("foo.slice", "bar", &c_ret) >= 0);
        assert_se(rs_slice_build_subslice("foo.slice", "bar", &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "foo-bar.slice"));
        free(c_ret); c_ret = NULL;
        free(r_ret); r_ret = NULL;
}

/* ── Prefix equal ──────────────────────────────────────────────────────── */

static void test_unit_name_prefix_equal(void) {
        assert_se(unit_name_prefix_equal("foo@bar.service", "foo@baz.service") == rs_unit_name_prefix_equal("foo@bar.service", "foo@baz.service"));
        assert_se(unit_name_prefix_equal("foo@bar.service", "foo.service") == rs_unit_name_prefix_equal("foo@bar.service", "foo.service"));
        assert_se(unit_name_prefix_equal("foo.service", "bar.service") == rs_unit_name_prefix_equal("foo.service", "bar.service"));
}

/* ── unit_name_is_hashed ───────────────────────────────────────────────── */

static void test_unit_name_is_hashed(void) {
        /* Hashed names end with a 16-char hex hash before the suffix */
        assert_se(unit_name_is_hashed("foo.service") == rs_unit_name_is_hashed("foo.service"));
        assert_se(unit_name_is_hashed("foo@bar.service") == rs_unit_name_is_hashed("foo@bar.service"));
        /* A name that's long enough and has hex chars before the suffix */
        assert_se(unit_name_is_hashed("abc123def456abc12345.service") == rs_unit_name_is_hashed("abc123def456abc12345.service"));
        /* Too short to be hashed */
        assert_se(unit_name_is_hashed("abc.service") == rs_unit_name_is_hashed("abc.service"));
        /* NULL and empty */
        assert_se(unit_name_is_hashed(NULL) == rs_unit_name_is_hashed(NULL));
        assert_se(unit_name_is_hashed("") == rs_unit_name_is_hashed(""));
}

/* ── unit_name_build_from_type ─────────────────────────────────────────── */

static void test_unit_name_build_from_type(void) {
        _cleanup_free_ char *c_ret = NULL, *r_ret = NULL;

        assert_se(unit_name_build_from_type("foo", NULL, UNIT_SERVICE, &c_ret) >= 0);
        assert_se(rs_unit_name_build_from_type("foo", NULL, UNIT_SERVICE, &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "foo.service"));
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        assert_se(unit_name_build_from_type("foo", "bar", UNIT_SERVICE, &c_ret) >= 0);
        assert_se(rs_unit_name_build_from_type("foo", "bar", UNIT_SERVICE, &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "foo@bar.service"));
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        assert_se(unit_name_build_from_type("foo", NULL, UNIT_MOUNT, &c_ret) >= 0);
        assert_se(rs_unit_name_build_from_type("foo", NULL, UNIT_MOUNT, &r_ret) >= 0);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "foo.mount"));
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        /* Rust-only: test invalid type (C asserts on this) */
        assert_se(rs_unit_name_build_from_type("foo", NULL, 99, &r_ret) < 0);
}

static void test_unit_name_error_and_byte_boundaries(void) {
        char *c_ret = NULL, *r_ret = NULL;
        char *escaped;
        static const char non_utf8_name[] = { 'f', (char) 0xff, 'o', '.', 's', 'e', 'r', 'v', 'i', 'c', 'e', 0 };

        assert_se(unit_name_is_valid(non_utf8_name, UNIT_NAME_ANY) == rs_unit_name_is_valid(non_utf8_name, UNIT_NAME_ANY));
        assert_se(unit_name_to_type("foo.servicex") == rs_unit_name_to_type("foo.servicex"));

        assert_se(unit_name_to_prefix("not-a-unit", &c_ret) == rs_unit_name_to_prefix("not-a-unit", &r_ret));
        assert_se(c_ret == NULL && r_ret == NULL);

        assert_se(unit_name_to_instance("not-a-unit", &c_ret) == rs_unit_name_to_instance("not-a-unit", &r_ret));
        assert_se(c_ret == NULL && r_ret == NULL);

        assert_se(unit_name_change_suffix("foo.service", ".invalid", &c_ret) ==
                  rs_unit_name_change_suffix("foo.service", ".invalid", &r_ret));
        assert_se(c_ret == NULL && r_ret == NULL);

        assert_se(unit_name_build("bad/prefix", NULL, ".service", &c_ret) ==
                  rs_unit_name_build("bad/prefix", NULL, ".service", &r_ret));
        assert_se(c_ret == NULL && r_ret == NULL);

        assert_se(unit_name_unescape("bad\\q", &c_ret) == rs_unit_name_unescape("bad\\q", &r_ret));
        assert_se(c_ret == NULL && r_ret == NULL);

        assert_se(unit_name_replace_instance_full("foo@old.service", "bad/name", false, &c_ret) ==
                  rs_unit_name_replace_instance_full("foo@old.service", "bad/name", false, &r_ret));
        assert_se(c_ret == NULL && r_ret == NULL);

        assert_se(unit_name_template("foo.service", &c_ret) == rs_unit_name_template("foo.service", &r_ret));
        assert_se(c_ret == NULL && r_ret == NULL);

        /* Both result families use the C allocator, so free() is the exact
         * ownership operation for a Rust-produced result as well. */
        escaped = rs_unit_name_escape("/allocator-check");
        assert_se(escaped);
        free(escaped);
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_unit_name_is_valid_plain();
        test_unit_name_is_valid_instance();
        test_unit_name_is_valid_template();
        test_unit_name_is_valid_any();
        test_unit_prefix_is_valid();
        test_unit_instance_is_valid();
        test_unit_suffix_is_valid();
        test_unit_name_to_prefix();
        test_unit_name_to_instance();
        test_unit_name_to_type();
        test_unit_name_to_prefix_and_instance();
        test_unit_name_change_suffix();
        test_unit_name_build();
        test_unit_name_escape_unescape();
        test_unit_name_escape_leading_dot();
        test_unit_name_template();
        test_unit_name_replace_instance();
        test_slice_name_is_valid();
        test_slice_build_parent_slice();
        test_slice_build_subslice();
        test_unit_name_prefix_equal();
        test_unit_name_is_hashed();
        test_unit_name_build_from_type();
        test_unit_name_error_and_byte_boundaries();

        return 0;
}
