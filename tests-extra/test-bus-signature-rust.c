/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Shadow test for D-Bus signature validation functions ported from
 * src/libsystemd/sd-bus/bus-signature.c to src/basic/rust/bus_signature.rs
 *
 * Note: The C originals live in libsystemd which is not linked here,
 * so we use expected-value assertions instead of C-vs-Rust comparison. */

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "tests.h"

#include "rust/bus_signature.h"

/* ── signature_element_length ──────────────────────────────────────────── */

static void test_element_length_basic(void) {
        size_t l;
        const char basic[] = "ybnqiuxtdsoghv";

        for (int i = 0; basic[i]; i++) {
                char s[2] = { basic[i], '\0' };
                assert_se(rs_signature_element_length(s, &l) == 0);
                assert_se(l == 1);
        }
}

static void test_element_length_array(void) {
        size_t l;

        assert_se(rs_signature_element_length("ai", &l) == 0);
        assert_se(l == 2);

        assert_se(rs_signature_element_length("as", &l) == 0);
        assert_se(l == 2);

        assert_se(rs_signature_element_length("av", &l) == 0);
        assert_se(l == 2);
}

static void test_element_length_struct(void) {
        size_t l;

        assert_se(rs_signature_element_length("(ii)", &l) == 0);
        assert_se(l == 4);

        assert_se(rs_signature_element_length("(sss)", &l) == 0);
        assert_se(l == 5);

        assert_se(rs_signature_element_length("(sa{sv}i)", &l) == 0);
        assert_se(l == 9);
}

static void test_element_length_dict_entry(void) {
        size_t l;

        assert_se(rs_signature_element_length("{sv}", &l) == 0);
        assert_se(l == 4);

        assert_se(rs_signature_element_length("{si}", &l) == 0);
        assert_se(l == 4);

        assert_se(rs_signature_element_length("{sas}", &l) == 0);
        assert_se(l == 5);
}

static void test_element_length_nested(void) {
        size_t l;

        assert_se(rs_signature_element_length("a{sv}", &l) == 0);
        assert_se(l == 5);

        assert_se(rs_signature_element_length("a(ss)", &l) == 0);
        assert_se(l == 5);

        assert_se(rs_signature_element_length("aa{si}", &l) == 0);
        assert_se(l == 6);
}

static void test_element_length_errors(void) {
        size_t l;

        /* Empty struct */
        assert_se(rs_signature_element_length("()", &l) < 0);

        /* Dict entry with non-basic key */
        assert_se(rs_signature_element_length("{(s)s}", &l) < 0);

        /* Dict entry with only one element */
        assert_se(rs_signature_element_length("{s}", &l) < 0);

        /* Dict entry with three elements */
        assert_se(rs_signature_element_length("{sss}", &l) < 0);

        /* NULL input */
        assert_se(rs_signature_element_length(NULL, &l) < 0);

        /* Invalid type character */
        assert_se(rs_signature_element_length("z", &l) < 0);

        /* Incomplete struct */
        assert_se(rs_signature_element_length("(i", &l) < 0);

        /* Incomplete dict entry */
        assert_se(rs_signature_element_length("{si", &l) < 0);

        /* NULL output */
        assert_se(rs_signature_element_length("i", NULL) < 0);
}

/* ── signature_is_single ──────────────────────────────────────────────── */

static void test_signature_is_single(void) {
        /* Basic types */
        assert_se(rs_signature_is_single("i", true));
        assert_se(rs_signature_is_single("s", true));
        assert_se(rs_signature_is_single("v", true));
        assert_se(rs_signature_is_single("b", true));

        /* Compound types */
        assert_se(rs_signature_is_single("ai", true));
        assert_se(rs_signature_is_single("(ii)", true));
        assert_se(rs_signature_is_single("{sv}", true));
        assert_se(rs_signature_is_single("a{sv}", true));
        assert_se(rs_signature_is_single("a(ss)", true));

        /* Not single (multiple types) */
        assert_se(!rs_signature_is_single("ii", true));
        assert_se(!rs_signature_is_single("sis", true));
        assert_se(!rs_signature_is_single("a{sv}i", true));

        /* Dict entry only when allowed */
        assert_se(rs_signature_is_single("{sv}", true));
        assert_se(!rs_signature_is_single("{sv}", false));

        /* NULL */
        assert_se(!rs_signature_is_single(NULL, true));
}

/* ── signature_is_pair ────────────────────────────────────────────────── */

static void test_signature_is_pair(void) {
        assert_se(rs_signature_is_pair("ii"));
        assert_se(rs_signature_is_pair("ss"));
        assert_se(rs_signature_is_pair("sv"));
        assert_se(rs_signature_is_pair("si"));
        assert_se(rs_signature_is_pair("bv"));
        assert_se(rs_signature_is_pair("sa{sv}"));

        /* Not a pair */
        assert_se(!rs_signature_is_pair("(ii)"));
        assert_se(!rs_signature_is_pair("ai"));
        assert_se(!rs_signature_is_pair("iii"));
        assert_se(!rs_signature_is_pair("i"));

        /* NULL */
        assert_se(!rs_signature_is_pair(NULL));
}

/* ── signature_is_valid ───────────────────────────────────────────────── */

static void test_signature_is_valid(void) {
        /* Valid complete signatures */
        assert_se(rs_signature_is_valid("", true));
        assert_se(rs_signature_is_valid("i", true));
        assert_se(rs_signature_is_valid("ii", true));
        assert_se(rs_signature_is_valid("sis", true));
        assert_se(rs_signature_is_valid("a{sv}", true));
        assert_se(rs_signature_is_valid("ssa{sv}as", true));
        assert_se(rs_signature_is_valid("oa{sa{sv}}", true));

        /* Invalid */
        assert_se(!rs_signature_is_valid("z", true));
        assert_se(!rs_signature_is_valid("i(", true));
        assert_se(!rs_signature_is_valid("{sv}", false));

        /* NULL */
        assert_se(!rs_signature_is_valid(NULL, true));
}

/* ── bus_validate_nul ──────────────────────────────────────────────────── */

static void test_bus_validate_nul(void) {
        assert_se(rs_bus_validate_nul("hello", 5));
        assert_se(rs_bus_validate_nul("", 0));
        assert_se(!rs_bus_validate_nul("he\0llo", 5));
        assert_se(!rs_bus_validate_nul("hello\0world", 7));
        assert_se(!rs_bus_validate_nul(NULL, 0));
}

/* ── bus_validate_string ───────────────────────────────────────────────── */

static void test_bus_validate_string(void) {
        assert_se(rs_bus_validate_string("hello", 5));
        assert_se(!rs_bus_validate_string("he\0llo", 5));
}

/* ── bus_validate_signature ───────────────────────────────────────────── */

static void test_bus_validate_signature(void) {
        assert_se(rs_bus_validate_signature("i", 1));
        assert_se(rs_bus_validate_signature("a{sv}", 5));
        assert_se(!rs_bus_validate_signature("i\0x", 3));
        assert_se(!rs_bus_validate_signature("z", 1));
}

/* ── bus_validate_object_path ──────────────────────────────────────────── */

static void test_bus_validate_object_path(void) {
        assert_se(rs_bus_validate_object_path("/foo/bar", 8));
        assert_se(rs_bus_validate_object_path("/", 1));
        assert_se(!rs_bus_validate_object_path("foo", 3));
        assert_se(!rs_bus_validate_object_path("/foo\0bar", 8));
}

int main(int argc, char *argv[]) {
        test_element_length_basic();
        test_element_length_array();
        test_element_length_struct();
        test_element_length_dict_entry();
        test_element_length_nested();
        test_element_length_errors();
        test_signature_is_single();
        test_signature_is_pair();
        test_signature_is_valid();
        test_bus_validate_nul();
        test_bus_validate_string();
        test_bus_validate_signature();
        test_bus_validate_object_path();

        return 0;
}
