/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C specifier/efi-loader functions vs Rust */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "tests.h"
#include "specifier.h"
#include "efi-loader.h"
#include "strv.h"

/* Rust FFI */
#include "rust/specifier_util.h"

/* ── specifier_escape ─────────────────────────────────────────────────── */

/* RUST-CONTRACT: specifier-escape */
static void test_specifier_escape(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;

        /* No percent signs */
        cr = specifier_escape("hello world");
        rr = rs_specifier_escape("hello world");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        cr = mfree(cr); rr = mfree(rr);

        /* Single percent */
        cr = specifier_escape("100%");
        rr = rs_specifier_escape("100%");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        cr = mfree(cr); rr = mfree(rr);

        /* Multiple percents */
        cr = specifier_escape("%CPU%MEM%IOW");
        rr = rs_specifier_escape("%CPU%MEM%IOW");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "%%CPU%%MEM%%IOW"));
        cr = mfree(cr); rr = mfree(rr);

        /* Empty string */
        cr = specifier_escape("");
        rr = rs_specifier_escape("");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        cr = mfree(cr); rr = mfree(rr);

        /* Already escaped */
        cr = specifier_escape("%%test%%");
        rr = rs_specifier_escape("%%test%%");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "%%%%test%%%%"));
        cr = mfree(cr); rr = mfree(rr);

        /* Only percent */
        cr = specifier_escape("%");
        rr = rs_specifier_escape("%");
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "%%"));
        cr = mfree(cr); rr = mfree(rr);

        /* NULL */
        cr = specifier_escape(NULL);
        rr = rs_specifier_escape(NULL);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Raw bytes and a suffix after NUL are copied with C-string semantics. */
        {
                static const char input[] = { 'a', '%', '\xff', '%', 0, 'x', 0 };
                static const char expected[] = { 'a', '%', '%', '\xff', '%', '%', 0 };

                cr = specifier_escape(input);
                rr = rs_specifier_escape(input);
                assert_se(cr && rr);
                assert_se(streq(cr, rr));
                assert_se(streq(rr, expected));
                cr = mfree(cr); rr = mfree(rr);
        }
}

/* ── efi_loader_entry_name_valid ──────────────────────────────────────── */

/* RUST-CONTRACT: efi-loader-entry-name-validation */
static void test_efi_loader_entry_name_valid(void) {
        bool cb, rb;

        /* Valid: alphanumeric */
        cb = efi_loader_entry_name_valid("abc123");
        rb = rs_efi_loader_entry_name_valid("abc123");
        assert_se(cb == rb); assert_se(cb == true);

        /* Valid: with special chars */
        cb = efi_loader_entry_name_valid("my-loader.entry@1");
        rb = rs_efi_loader_entry_name_valid("my-loader.entry@1");
        assert_se(cb == rb); assert_se(cb == true);

        cb = efi_loader_entry_name_valid("systemd-boot+123.conf");
        rb = rs_efi_loader_entry_name_valid("systemd-boot+123.conf");
        assert_se(cb == rb); assert_se(cb == true);

        /* Valid: single char */
        cb = efi_loader_entry_name_valid("a");
        rb = rs_efi_loader_entry_name_valid("a");
        assert_se(cb == rb); assert_se(cb == true);

        /* Invalid: empty */
        cb = efi_loader_entry_name_valid("");
        rb = rs_efi_loader_entry_name_valid("");
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: contains space */
        cb = efi_loader_entry_name_valid("my loader");
        rb = rs_efi_loader_entry_name_valid("my loader");
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: contains slash */
        cb = efi_loader_entry_name_valid("path/to/entry");
        rb = rs_efi_loader_entry_name_valid("path/to/entry");
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: contains colon */
        cb = efi_loader_entry_name_valid("entry:name");
        rb = rs_efi_loader_entry_name_valid("entry:name");
        assert_se(cb == rb); assert_se(cb == false);

        /* NUL in string literal: C sees "bad" which is valid */
        cb = efi_loader_entry_name_valid("bad\0name");
        rb = rs_efi_loader_entry_name_valid("bad\0name");
        assert_se(cb == rb); assert_se(cb == true);

        /* Valid: starts with dot (filename_is_valid allows it) */
        cb = efi_loader_entry_name_valid(".hidden");
        rb = rs_efi_loader_entry_name_valid(".hidden");
        assert_se(cb == rb); assert_se(cb == true);

        /* Invalid: dot-dot */
        cb = efi_loader_entry_name_valid("..");
        rb = rs_efi_loader_entry_name_valid("..");
        assert_se(cb == rb); assert_se(cb == false);

        /* Invalid: hash char not in allowed set */
        cb = efi_loader_entry_name_valid("entry#1");
        rb = rs_efi_loader_entry_name_valid("entry#1");
        assert_se(cb == rb); assert_se(cb == false);

        /* NULL */
        cb = efi_loader_entry_name_valid(NULL);
        rb = rs_efi_loader_entry_name_valid(NULL);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-UTF-8 bytes are rejected by the ASCII-only charset. */
        cb = efi_loader_entry_name_valid("entry\xff");
        rb = rs_efi_loader_entry_name_valid("entry\xff");
        assert_se(cb == rb); assert_se(cb == false);

        /* filename_is_valid() accepts NAME_MAX bytes, but no more. */
        {
                char name[NAME_MAX + 2];

                memset(name, 'a', NAME_MAX);
                name[NAME_MAX] = 0;
                assert_se(efi_loader_entry_name_valid(name) == rs_efi_loader_entry_name_valid(name));
                assert_se(rs_efi_loader_entry_name_valid(name));

                name[NAME_MAX] = 'a';
                name[NAME_MAX + 1] = 0;
                assert_se(efi_loader_entry_name_valid(name) == rs_efi_loader_entry_name_valid(name));
                assert_se(!rs_efi_loader_entry_name_valid(name));
        }
}

/* ── specifier_escape_strv ─────────────────────────────────────────────── */

/* RUST-CONTRACT: specifier-escape-strv */
static void test_specifier_escape_strv(void) {
        _cleanup_strv_free_ char **cr = NULL, **rr = NULL;

        /* Empty strv (NULL) */
        assert_se(specifier_escape_strv(NULL, &cr) == 0);
        assert_se(cr == NULL);
        assert_se(rs_specifier_escape_strv(NULL, &rr) == 0);
        assert_se(rr == NULL);

        /* Successful empty input replaces the prior output with NULL. */
        cr = STRV_EMPTY;
        rr = STRV_EMPTY;
        assert_se(specifier_escape_strv(NULL, &cr) == 0);
        assert_se(cr == NULL);
        assert_se(rs_specifier_escape_strv(NULL, &rr) == 0);
        assert_se(rr == NULL);

        /* Empty strv (array with NULL sentinel) */
        {
                char *empty[] = { NULL };
                assert_se(specifier_escape_strv(empty, &cr) == 0);
                assert_se(cr == NULL);
                cr = strv_free(cr);
                assert_se(rs_specifier_escape_strv(empty, &rr) == 0);
                assert_se(rr == NULL);
                rr = strv_free(rr);
        }

        /* Single string with percent */
        {
                char *input[] = { (char*)"100%", NULL };
                assert_se(specifier_escape_strv(input, &cr) == 0);
                assert_se(rs_specifier_escape_strv(input, &rr) == 0);
                assert_se(cr && rr);
                assert_se(strv_equal(cr, rr));
                assert_se(streq(cr[0], "100%%"));
                cr = strv_free(cr);
                rr = strv_free(rr);
        }

        /* Multiple strings */
        {
                char *input[] = { (char*)"hello", (char*)"world%", (char*)"foo%bar", NULL };
                assert_se(specifier_escape_strv(input, &cr) == 0);
                assert_se(rs_specifier_escape_strv(input, &rr) == 0);
                assert_se(cr && rr);
                assert_se(strv_equal(cr, rr));
                assert_se(streq(cr[0], "hello"));
                assert_se(streq(cr[1], "world%%"));
                assert_se(streq(cr[2], "foo%%bar"));
                cr = strv_free(cr);
                rr = strv_free(rr);
        }

        /* Strings with no percents */
        {
                char *input[] = { (char*)"abc", (char*)"def", NULL };
                assert_se(specifier_escape_strv(input, &cr) == 0);
                assert_se(rs_specifier_escape_strv(input, &rr) == 0);
                assert_se(cr && rr);
                assert_se(strv_equal(cr, rr));
                assert_se(streq(cr[0], "abc"));
                assert_se(streq(cr[1], "def"));
                cr = strv_free(cr);
                rr = strv_free(rr);
        }

        /* Empty strings */
        {
                char *input[] = { (char*)"", (char*)"a", (char*)"", NULL };
                assert_se(specifier_escape_strv(input, &cr) == 0);
                assert_se(rs_specifier_escape_strv(input, &rr) == 0);
                assert_se(cr && rr);
                assert_se(strv_equal(cr, rr));
                cr = strv_free(cr);
                rr = strv_free(rr);
        }

        /* The input strv and all of its strings are borrowed, not consumed or mutated. */
        {
                static char first[] = "a%b";
                static char second[] = "\xff%";
                char *input[] = { first, second, NULL };

                assert_se(specifier_escape_strv(input, &cr) == 0);
                assert_se(input[0] == first && input[1] == second && input[2] == NULL);
                assert_se(streq(first, "a%b") && streq(second, "\xff%"));
                cr = strv_free(cr);

                assert_se(rs_specifier_escape_strv(input, &rr) == 0);
                assert_se(input[0] == first && input[1] == second && input[2] == NULL);
                assert_se(streq(first, "a%b") && streq(second, "\xff%"));
                assert_se(streq(rr[0], "a%%b") && streq(rr[1], "\xff%%"));
                rr = strv_free(rr);
        }

        /* C asserts ret is non-NULL; the Rust ABI facade fails closed instead. */
        assert_se(rs_specifier_escape_strv(NULL, NULL) == -EINVAL);
}

int main(int argc, char **argv) {
        test_specifier_escape();
        test_efi_loader_entry_name_valid();
        test_specifier_escape_strv();
        return 0;
}
