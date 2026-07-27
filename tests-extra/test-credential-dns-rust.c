/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C credential/dns validators vs Rust */

#include "tests.h"
#include "creds-util.h"
#include "dns-domain.h"

/* Rust FFI */
#include "rust/credential_validators.h"
#include "rust/dns_domain_validators.h"

/* ── credential_name_valid ───────────────────────────────────────────── */

static void test_credential_name_valid(void) {
        bool cv, rv;

        /* Valid names */
        cv = credential_name_valid("foo");
        rv = rs_credential_name_valid("foo");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = credential_name_valid("foo_bar");
        rv = rs_credential_name_valid("foo_bar");
        assert_se(cv == rv);

        cv = credential_name_valid("foo.bar");
        rv = rs_credential_name_valid("foo.bar");
        assert_se(cv == rv);

        cv = credential_name_valid("foo-bar");
        rv = rs_credential_name_valid("foo-bar");
        assert_se(cv == rv);

        /* Invalid: empty */
        cv = credential_name_valid("");
        rv = rs_credential_name_valid("");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: NULL */
        cv = credential_name_valid(NULL);
        rv = rs_credential_name_valid(NULL);
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: slash (not a valid filename component) */
        cv = credential_name_valid("foo/bar");
        rv = rs_credential_name_valid("foo/bar");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: control characters */
        cv = credential_name_valid("foo\nbar");
        rv = rs_credential_name_valid("foo\nbar");
        assert_se(cv == rv);
        assert_se(cv == false);
}

/* ── credential_glob_valid ───────────────────────────────────────────── */

static void test_credential_glob_valid(void) {
        bool cv, rv;

        /* Valid globs */
        cv = credential_glob_valid("*");
        rv = rs_credential_glob_valid("*");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = credential_glob_valid("foo*");
        rv = rs_credential_glob_valid("foo*");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = credential_glob_valid("foo_bar*");
        rv = rs_credential_glob_valid("foo_bar*");
        assert_se(cv == rv);

        /* Valid: no glob at all (just a name) */
        cv = credential_glob_valid("foo");
        rv = rs_credential_glob_valid("foo");
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Invalid: empty */
        cv = credential_glob_valid("");
        rv = rs_credential_glob_valid("");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: NULL */
        cv = credential_glob_valid(NULL);
        rv = rs_credential_glob_valid(NULL);
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: non-trailing wildcard */
        cv = credential_glob_valid("f*o");
        rv = rs_credential_glob_valid("f*o");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: question mark */
        cv = credential_glob_valid("foo?");
        rv = rs_credential_glob_valid("foo?");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: bracket expression */
        cv = credential_glob_valid("foo[bar]");
        rv = rs_credential_glob_valid("foo[bar]");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: double wildcard */
        cv = credential_glob_valid("foo**");
        rv = rs_credential_glob_valid("foo**");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: slash in prefix */
        cv = credential_glob_valid("foo/bar*");
        rv = rs_credential_glob_valid("foo/bar*");
        assert_se(cv == rv);
        assert_se(cv == false);
}

/* ── dns_service_name_is_valid ───────────────────────────────────────── */

static void test_dns_service_name_valid(void) {
        bool cv, rv;

        /* Valid service names */
        cv = dns_service_name_is_valid("my service");
        rv = rs_dns_service_name_is_valid("my service");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = dns_service_name_is_valid("My Printer");
        rv = rs_dns_service_name_is_valid("My Printer");
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Valid: single character */
        cv = dns_service_name_is_valid("a");
        rv = rs_dns_service_name_is_valid("a");
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Valid: max length (63 chars) */
        cv = dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        rv = rs_dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_se(cv == rv);

        /* Invalid: NULL */
        cv = dns_service_name_is_valid(NULL);
        rv = rs_dns_service_name_is_valid(NULL);
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: empty */
        cv = dns_service_name_is_valid("");
        rv = rs_dns_service_name_is_valid("");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: control character */
        cv = dns_service_name_is_valid("foo\001bar");
        rv = rs_dns_service_name_is_valid("foo\001bar");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: too long (64 chars) */
        cv = dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        rv = rs_dns_service_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_se(cv == rv);
        assert_se(cv == false);
}

/* ── dns_subtype_name_is_valid ───────────────────────────────────────── */

static void test_dns_subtype_name_valid(void) {
        bool cv, rv;

        /* Valid subtype names */
        cv = dns_subtype_name_is_valid("my subtype");
        rv = rs_dns_subtype_name_is_valid("my subtype");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = dns_subtype_name_is_valid("_sub");
        rv = rs_dns_subtype_name_is_valid("_sub");
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Valid: single character */
        cv = dns_subtype_name_is_valid("a");
        rv = rs_dns_subtype_name_is_valid("a");
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Invalid: NULL */
        cv = dns_subtype_name_is_valid(NULL);
        rv = rs_dns_subtype_name_is_valid(NULL);
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: empty */
        cv = dns_subtype_name_is_valid("");
        rv = rs_dns_subtype_name_is_valid("");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: control character */
        cv = dns_subtype_name_is_valid("foo\177bar");
        rv = rs_dns_subtype_name_is_valid("foo\177bar");
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid: too long */
        cv = dns_subtype_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        rv = rs_dns_subtype_name_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_se(cv == rv);
        assert_se(cv == false);
}

int main(int argc, char **argv) {
        test_credential_name_valid();
        test_credential_glob_valid();
        test_dns_service_name_valid();
        test_dns_subtype_name_valid();
        return 0;
}
