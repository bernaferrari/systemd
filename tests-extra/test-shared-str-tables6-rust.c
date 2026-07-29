/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C shared/ string tables batch 6 vs Rust (WITH_FALLBACK) */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "ioprio-util.h"
#include "dns-rr.h"

/* Rust FFI */
#include "rust/netdev_str_tables.h"

/* ── ioprio_class (WITH_FALLBACK max=7) ───────────────────────────────── */

static void test_ioprio_class(void) {
        char *c_ret = NULL, *r_ret = NULL;
        int cv, rv;
        int cr, rr;

        /* Table entries: to_string_alloc returns strdup'd string */
        cr = ioprio_class_to_string_alloc(IOPRIO_CLASS_NONE, &c_ret);
        rr = rs_ioprio_class_to_string_alloc(IOPRIO_CLASS_NONE, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        cr = ioprio_class_to_string_alloc(IOPRIO_CLASS_IDLE, &c_ret);
        rr = rs_ioprio_class_to_string_alloc(IOPRIO_CLASS_IDLE, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        /* Fallback: value 4 is not in the table but <= max (7) */
        cr = ioprio_class_to_string_alloc(4, &c_ret);
        rr = rs_ioprio_class_to_string_alloc(4, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "4"));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        /* Fallback: value 7 is max */
        cr = ioprio_class_to_string_alloc(7, &c_ret);
        rr = rs_ioprio_class_to_string_alloc(7, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, "7"));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        /* Out of range: value 8 > max (7) */
        cr = ioprio_class_to_string_alloc(8, &c_ret);
        rr = rs_ioprio_class_to_string_alloc(8, &r_ret);
        assert_se(cr == rr);
        assert_se(cr < 0);
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        /* from_string: table lookup */
        cv = ioprio_class_from_string("realtime");
        rv = rs_ioprio_class_from_string("realtime");
        assert_se(cv == rv);
        assert_se(cv == IOPRIO_CLASS_RT);

        cv = ioprio_class_from_string("idle");
        rv = rs_ioprio_class_from_string("idle");
        assert_se(cv == rv);
        assert_se(cv == IOPRIO_CLASS_IDLE);

        /* from_string: numeric fallback */
        cv = ioprio_class_from_string("5");
        rv = rs_ioprio_class_from_string("5");
        assert_se(cv == rv);
        assert_se(cv == 5);

        cv = ioprio_class_from_string("7");
        rv = rs_ioprio_class_from_string("7");
        assert_se(cv == rv);
        assert_se(cv == 7);

        /* safe_atou() grammar used by the C fallback parser */
        static const char * const numeric_forms[] = {
                "0x5",
                "0b101",
                "0o5",
                " +5",
                "\t5",
        };
        for (size_t i = 0; i < ELEMENTSOF(numeric_forms); i++) {
                cv = ioprio_class_from_string(numeric_forms[i]);
                rv = rs_ioprio_class_from_string(numeric_forms[i]);
                assert_se(cv == rv);
                assert_se(cv == 5);
        }

        /* from_string: out of range numeric */
        cv = ioprio_class_from_string("8");
        rv = rs_ioprio_class_from_string("8");
        assert_se(cv == rv);
        assert_se(cv < 0);

        /* from_string: unknown string */
        cv = ioprio_class_from_string("bogus");
        rv = rs_ioprio_class_from_string("bogus");
        assert_se(cv == rv);
        assert_se(cv < 0);
}

/* ── dnssec_algorithm (WITH_FALLBACK max=255) ─────────────────────────── */

static void test_dnssec_algorithm(void) {
        char *c_ret = NULL, *r_ret = NULL;
        int cv, rv;
        int cr, rr;

        /* Table entry */
        cr = dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_RSASHA1, &c_ret);
        rr = rs_dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_RSASHA1, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        /* Sparse entry: RSASHA512=10 (gap at 9) */
        cr = dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_RSASHA512, &c_ret);
        rr = rs_dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_RSASHA512, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        /* Fallback: value 9 is a gap */
        cr = dnssec_algorithm_to_string_alloc(9, &c_ret);
        rr = rs_dnssec_algorithm_to_string_alloc(9, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, "9"));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        /* from_string: table lookup */
        cv = dnssec_algorithm_from_string("RSASHA256");
        rv = rs_dnssec_algorithm_from_string("RSASHA256");
        assert_se(cv == rv);
        assert_se(cv == DNSSEC_ALGORITHM_RSASHA256);

        /* from_string: numeric fallback */
        cv = dnssec_algorithm_from_string("100");
        rv = rs_dnssec_algorithm_from_string("100");
        assert_se(cv == rv);
        assert_se(cv == 100);

        /* from_string: out of range (256 > 255) */
        cv = dnssec_algorithm_from_string("256");
        rv = rs_dnssec_algorithm_from_string("256");
        assert_se(cv == rv);
        assert_se(cv < 0);
}

/* ── dnssec_digest (WITH_FALLBACK max=255) ────────────────────────────── */

static void test_dnssec_digest(void) {
        char *c_ret = NULL, *r_ret = NULL;
        int cv, rv;
        int cr, rr;

        cr = dnssec_digest_to_string_alloc(DNSSEC_DIGEST_SHA256, &c_ret);
        rr = rs_dnssec_digest_to_string_alloc(DNSSEC_DIGEST_SHA256, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        /* Fallback: value 10 not in table */
        cr = dnssec_digest_to_string_alloc(10, &c_ret);
        rr = rs_dnssec_digest_to_string_alloc(10, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, "10"));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        cv = dnssec_digest_from_string("SHA-384");
        rv = rs_dnssec_digest_from_string("SHA-384");
        assert_se(cv == rv);
        assert_se(cv == DNSSEC_DIGEST_SHA384);

        cv = dnssec_digest_from_string("42");
        rv = rs_dnssec_digest_from_string("42");
        assert_se(cv == rv);
        assert_se(cv == 42);
}

/* ── sshfp_algorithm (WITH_FALLBACK max=255, gap at 5) ───────────────── */

static void test_sshfp_algorithm(void) {
        char *c_ret = NULL, *r_ret = NULL;
        int cv, rv;
        int cr, rr;

        cr = sshfp_algorithm_to_string_alloc(SSHFP_ALGORITHM_RSA, &c_ret);
        rr = rs_sshfp_algorithm_to_string_alloc(SSHFP_ALGORITHM_RSA, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        /* Gap at 5 */
        cr = sshfp_algorithm_to_string_alloc(5, &c_ret);
        rr = rs_sshfp_algorithm_to_string_alloc(5, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, "5"));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        cv = sshfp_algorithm_from_string("Ed25519");
        rv = rs_sshfp_algorithm_from_string("Ed25519");
        assert_se(cv == rv);
        assert_se(cv == SSHFP_ALGORITHM_ED25519);

        cv = sshfp_algorithm_from_string("200");
        rv = rs_sshfp_algorithm_from_string("200");
        assert_se(cv == rv);
        assert_se(cv == 200);
}

/* ── sshfp_key_type (WITH_FALLBACK max=255) ───────────────────────────── */

static void test_sshfp_key_type(void) {
        char *c_ret = NULL, *r_ret = NULL;
        int cv, rv;
        int cr, rr;

        cr = sshfp_key_type_to_string_alloc(SSHFP_KEY_TYPE_SHA1, &c_ret);
        rr = rs_sshfp_key_type_to_string_alloc(SSHFP_KEY_TYPE_SHA1, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        cr = sshfp_key_type_to_string_alloc(SSHFP_KEY_TYPE_SHA256, &c_ret);
        rr = rs_sshfp_key_type_to_string_alloc(SSHFP_KEY_TYPE_SHA256, &r_ret);
        assert_se(cr == 0 && rr == 0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        free(c_ret); free(r_ret); c_ret = r_ret = NULL;

        cv = sshfp_key_type_from_string("SHA-256");
        rv = rs_sshfp_key_type_from_string("SHA-256");
        assert_se(cv == rv);
        assert_se(cv == SSHFP_KEY_TYPE_SHA256);

        cv = sshfp_key_type_from_string("99");
        rv = rs_sshfp_key_type_from_string("99");
        assert_se(cv == rv);
        assert_se(cv == 99);
}

int main(int argc, char **argv) {
        test_ioprio_class();
        test_dnssec_algorithm();
        test_dnssec_digest();
        test_sshfp_algorithm();
        test_sshfp_key_type();
        return 0;
}
