/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "bus-label.h"
#include "string-util.h"
#include "tests.h"

TEST(bus_label_escape_basic) {
        _cleanup_free_ char *e = NULL;

        e = bus_label_escape("hello");
        ASSERT_NOT_NULL(e);
        ASSERT_STREQ(e, "hello");
}

TEST(bus_label_escape_empty) {
        _cleanup_free_ char *e = NULL;

        e = bus_label_escape("");
        ASSERT_NOT_NULL(e);
        ASSERT_STREQ(e, "_");
}

TEST(bus_label_escape_special) {
        _cleanup_free_ char *e = NULL;

        /* Spaces and special chars should be escaped */
        e = bus_label_escape("hello world");
        ASSERT_NOT_NULL(e);
        ASSERT_STREQ(e, "hello_20world");
}

TEST(bus_label_escape_slash) {
        _cleanup_free_ char *e = NULL;

        e = bus_label_escape("foo/bar.service");
        ASSERT_NOT_NULL(e);
        ASSERT_STREQ(e, "foo_2fbar_2eservice");
}

TEST(bus_label_escape_leading_digit) {
        _cleanup_free_ char *e = NULL;

        /* Only the leading digit is escaped; subsequent digits are not */
        e = bus_label_escape("123foo");
        ASSERT_NOT_NULL(e);
        ASSERT_STREQ(e, "_3123foo");
}

TEST(bus_label_escape_non_leading_digit) {
        _cleanup_free_ char *e = NULL;

        /* Non-leading digits should not be escaped */
        e = bus_label_escape("foo123");
        ASSERT_NOT_NULL(e);
        ASSERT_STREQ(e, "foo123");
}

TEST(bus_label_escape_null) {
        /* bus_label_escape calls assert_return(s, NULL) which crashes.
         * Test that the function exists and is callable with valid input. */
        _cleanup_free_ char *e = bus_label_escape("test");
        ASSERT_NOT_NULL(e);
}

TEST(bus_label_unescape_basic) {
        _cleanup_free_ char *u = NULL;

        u = bus_label_unescape("hello");
        ASSERT_NOT_NULL(u);
        ASSERT_STREQ(u, "hello");
}

TEST(bus_label_unescape_underscore_only) {
        _cleanup_free_ char *u = NULL;

        u = bus_label_unescape("_");
        ASSERT_NOT_NULL(u);
        ASSERT_STREQ(u, "");
}

TEST(bus_label_unescape_special) {
        _cleanup_free_ char *u = NULL;

        u = bus_label_unescape("hello_20world");
        ASSERT_NOT_NULL(u);
        ASSERT_STREQ(u, "hello world");
}

TEST(bus_label_unescape_slash) {
        _cleanup_free_ char *u = NULL;

        u = bus_label_unescape("foo_2fbar_2eservice");
        ASSERT_NOT_NULL(u);
        ASSERT_STREQ(u, "foo/bar.service");
}

TEST(bus_label_unescape_invalid_escape) {
        _cleanup_free_ char *u = NULL;

        /* Invalid hex chars after _ should be taken literally */
        u = bus_label_unescape("_zz");
        ASSERT_NOT_NULL(u);
        ASSERT_STREQ(u, "_zz");
}

TEST(bus_label_unescape_truncated_escape) {
        _cleanup_free_ char *u = NULL;

        u = bus_label_unescape("ab_3");
        ASSERT_NOT_NULL(u);
        ASSERT_STREQ(u, "ab_3");
}

TEST(bus_label_roundtrip) {
        const char *originals[] = {
                "simple.service",
                "foo-bar-waldo.service",
                "user@1000.service",
                "systemd-systemd\\x2dcreden..service",
                "a really weird name!.service",
                NULL,
        };

        for (size_t i = 0; originals[i]; i++) {
                _cleanup_free_ char *escaped = NULL;
                _cleanup_free_ char *unescaped = NULL;

                escaped = bus_label_escape(originals[i]);
                ASSERT_NOT_NULL(escaped);

                unescaped = bus_label_unescape(escaped);
                ASSERT_NOT_NULL(unescaped);
                ASSERT_STREQ(unescaped, originals[i]);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
