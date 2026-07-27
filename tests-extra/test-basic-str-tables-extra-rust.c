/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C basic/ string table lookups vs Rust */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include "tests.h"

/* netinet/ip.h constants — included directly since uapi overrides suppress the header */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY 0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT 0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY 0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST 0x02
#endif

/* C headers */
#include "compress.h"
#include "condition.h"
#include "socket-util.h"
#include "output-mode.h"

/* Rust FFI */
#include "rust/shared_facades/lookups.h"
#include "rust/netdev_str_tables.h"

/* ── compression_lowercase ───────────────────────────────────────────── */

static void test_compression_lowercase(void) {
        const char *cv, *rv;
        Compression cc, rc;

        /* to_string */
        cv = compression_lowercase_to_string(COMPRESSION_NONE);
        rv = rs_compression_lowercase_to_string(COMPRESSION_NONE);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "none"));

        cv = compression_lowercase_to_string(COMPRESSION_XZ);
        rv = rs_compression_lowercase_to_string(COMPRESSION_XZ);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "xz"));

        cv = compression_lowercase_to_string(COMPRESSION_LZ4);
        rv = rs_compression_lowercase_to_string(COMPRESSION_LZ4);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "lz4"));

        cv = compression_lowercase_to_string(COMPRESSION_ZSTD);
        rv = rs_compression_lowercase_to_string(COMPRESSION_ZSTD);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "zstd"));

        /* Invalid */
        cv = compression_lowercase_to_string(-1);
        rv = rs_compression_lowercase_to_string(-1);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        cc = compression_lowercase_from_string("none");
        rc = rs_compression_lowercase_from_string("none");
        assert_se(cc == rc);
        assert_se(cc == COMPRESSION_NONE);

        cc = compression_lowercase_from_string("xz");
        rc = rs_compression_lowercase_from_string("xz");
        assert_se(cc == rc);
        assert_se(cc == COMPRESSION_XZ);

        cc = compression_lowercase_from_string("XZ");
        rc = rs_compression_lowercase_from_string("XZ");
        /* Case-sensitive: "XZ" should fail */
        assert_se(cc < 0);
        assert_se(rc < 0);

        cc = compression_lowercase_from_string("bogus");
        rc = rs_compression_lowercase_from_string("bogus");
        assert_se(cc < 0);
        assert_se(rc < 0);
}

/* ── socket_address_type ─────────────────────────────────────────────── */

static void test_socket_address_type(void) {
        const char *cv, *rv;
        int cc, rc;

        cv = socket_address_type_to_string(SOCK_STREAM);
        rv = rs_socket_address_type_to_string(SOCK_STREAM);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "Stream"));

        cv = socket_address_type_to_string(SOCK_DGRAM);
        rv = rs_socket_address_type_to_string(SOCK_DGRAM);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "Datagram"));

        cv = socket_address_type_to_string(SOCK_RAW);
        rv = rs_socket_address_type_to_string(SOCK_RAW);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "Raw"));

        cv = socket_address_type_to_string(SOCK_SEQPACKET);
        rv = rs_socket_address_type_to_string(SOCK_SEQPACKET);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "SequentialPacket"));

        /* Invalid */
        cv = socket_address_type_to_string(99);
        rv = rs_socket_address_type_to_string(99);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        cc = socket_address_type_from_string("Stream");
        rc = rs_socket_address_type_from_string("Stream");
        assert_se(cc == rc);
        assert_se(cc == SOCK_STREAM);

        cc = socket_address_type_from_string("Datagram");
        rc = rs_socket_address_type_from_string("Datagram");
        assert_se(cc == rc);
        assert_se(cc == SOCK_DGRAM);

        cc = socket_address_type_from_string("bogus");
        rc = rs_socket_address_type_from_string("bogus");
        assert_se(cc < 0);
        assert_se(rc < 0);
}

/* ── netlink_family (WITH_FALLBACK) ──────────────────────────────────── */

static void test_netlink_family(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        int cr_r, rr_r;
        int cc, rc;

        /* to_string_alloc — valid entries */
        cr_r = netlink_family_to_string_alloc(NETLINK_ROUTE, &cr);
        rr_r = rs_netlink_family_to_string_alloc(NETLINK_ROUTE, &rr);
        assert_se(cr_r == rr_r);
        assert_se(cr_r == 0);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "route"));
        cr = mfree(cr);
        rr = mfree(rr);

        cr_r = netlink_family_to_string_alloc(NETLINK_KOBJECT_UEVENT, &cr);
        rr_r = rs_netlink_family_to_string_alloc(NETLINK_KOBJECT_UEVENT, &rr);
        assert_se(cr_r == rr_r);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "kobject-uevent"));
        cr = mfree(cr);
        rr = mfree(rr);

        /* to_string_alloc — fallback for unknown values */
        cr_r = netlink_family_to_string_alloc(99, &cr);
        rr_r = rs_netlink_family_to_string_alloc(99, &rr);
        assert_se(cr_r == rr_r);
        assert_se(cr_r == 0);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "99"));
        cr = mfree(cr);
        rr = mfree(rr);

        /* from_string */
        cc = netlink_family_from_string("route");
        rc = rs_netlink_family_from_string("route");
        assert_se(cc == rc);
        assert_se(cc == NETLINK_ROUTE);

        cc = netlink_family_from_string("generic");
        rc = rs_netlink_family_from_string("generic");
        assert_se(cc == rc);
        assert_se(cc == NETLINK_GENERIC);

        /* from_string — fallback numeric */
        cc = netlink_family_from_string("16");
        rc = rs_netlink_family_from_string("16");
        assert_se(cc == rc);
        assert_se(cc == NETLINK_GENERIC);

        cc = netlink_family_from_string("bogus");
        rc = rs_netlink_family_from_string("bogus");
        assert_se(cc < 0);
        assert_se(rc < 0);
}

/* ── ip_tos (WITH_FALLBACK) ──────────────────────────────────────────── */

static void test_ip_tos(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        int cr_r, rr_r;
        int cc, rc;

        /* to_string_alloc — known values */
        cr_r = ip_tos_to_string_alloc(IPTOS_LOWDELAY, &cr);
        rr_r = rs_ip_tos_to_string_alloc(IPTOS_LOWDELAY, &rr);
        assert_se(cr_r == rr_r);
        assert_se(cr_r == 0);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "low-delay"));
        cr = mfree(cr);
        rr = mfree(rr);

        cr_r = ip_tos_to_string_alloc(IPTOS_THROUGHPUT, &cr);
        rr_r = rs_ip_tos_to_string_alloc(IPTOS_THROUGHPUT, &rr);
        assert_se(cr_r == rr_r);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "throughput"));
        cr = mfree(cr);
        rr = mfree(rr);

        /* to_string_alloc — fallback for unknown values */
        cr_r = ip_tos_to_string_alloc(0x01, &cr);
        rr_r = rs_ip_tos_to_string_alloc(0x01, &rr);
        assert_se(cr_r == rr_r);
        assert_se(cr_r == 0);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "1"));
        cr = mfree(cr);
        rr = mfree(rr);

        /* from_string */
        cc = ip_tos_from_string("low-delay");
        rc = rs_ip_tos_from_string("low-delay");
        assert_se(cc == rc);
        assert_se(cc == IPTOS_LOWDELAY);

        cc = ip_tos_from_string("throughput");
        rc = rs_ip_tos_from_string("throughput");
        assert_se(cc == rc);
        assert_se(cc == IPTOS_THROUGHPUT);

        /* from_string — fallback numeric */
        cc = ip_tos_from_string("8");
        rc = rs_ip_tos_from_string("8");
        assert_se(cc == rc);
        assert_se(cc == IPTOS_THROUGHPUT);

        cc = ip_tos_from_string("16");
        rc = rs_ip_tos_from_string("16");
        assert_se(cc == rc);
        assert_se(cc == IPTOS_LOWDELAY);

        cc = ip_tos_from_string("bogus");
        rc = rs_ip_tos_from_string("bogus");
        assert_se(cc < 0);
        assert_se(rc < 0);
}

/* ── output_mode ───────────────────────────────────────────────────────── */

static void test_output_mode(void) {
        const char *cr, *rr;
        int cv, rv;
        int64_t cj, rj;

        /* to_string: valid values */
        cr = output_mode_to_string(OUTPUT_SHORT);
        rr = rs_output_mode_to_string(OUTPUT_SHORT);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "short"));

        cr = output_mode_to_string(OUTPUT_JSON_PRETTY);
        rr = rs_output_mode_to_string(OUTPUT_JSON_PRETTY);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = output_mode_to_string(OUTPUT_WITH_UNIT);
        rr = rs_output_mode_to_string(OUTPUT_WITH_UNIT);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        /* to_string: invalid */
        cr = output_mode_to_string(-1);
        rr = rs_output_mode_to_string(-1);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = output_mode_to_string(99);
        rr = rs_output_mode_to_string(99);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* from_string */
        cv = output_mode_from_string("short");
        rv = rs_output_mode_from_string("short");
        assert_se(cv == rv);
        assert_se(cv == OUTPUT_SHORT);

        cv = output_mode_from_string("json-pretty");
        rv = rs_output_mode_from_string("json-pretty");
        assert_se(cv == rv);
        assert_se(cv == OUTPUT_JSON_PRETTY);

        cv = output_mode_from_string("cat");
        rv = rs_output_mode_from_string("cat");
        assert_se(cv == rv);
        assert_se(cv == OUTPUT_CAT);

        cv = output_mode_from_string("bogus");
        rv = rs_output_mode_from_string("bogus");
        assert_se(cv < 0);
        assert_se(rv < 0);

        /* to_json_format_flags */
        cj = output_mode_to_json_format_flags(OUTPUT_JSON_SSE);
        rj = rs_output_mode_to_json_format_flags(OUTPUT_JSON_SSE);
        assert_se(cj == rj);

        cj = output_mode_to_json_format_flags(OUTPUT_JSON_SEQ);
        rj = rs_output_mode_to_json_format_flags(OUTPUT_JSON_SEQ);
        assert_se(cj == rj);

        cj = output_mode_to_json_format_flags(OUTPUT_JSON_PRETTY);
        rj = rs_output_mode_to_json_format_flags(OUTPUT_JSON_PRETTY);
        assert_se(cj == rj);

        /* default case */
        cj = output_mode_to_json_format_flags(OUTPUT_SHORT);
        rj = rs_output_mode_to_json_format_flags(OUTPUT_SHORT);
        assert_se(cj == rj);

        cj = output_mode_to_json_format_flags(OUTPUT_VERBOSE);
        rj = rs_output_mode_to_json_format_flags(OUTPUT_VERBOSE);
        assert_se(cj == rj);
}

static void test_assert_type(void) {
        const char *cr, *rr;
        int cv, rv;

        for (int i = 0; i < _CONDITION_TYPE_MAX; i++) {
                cr = assert_type_to_string(i);
                rr = rs_assert_type_to_string(i);
                assert_se(streq_ptr(cr, rr));
                assert_se(assert_type_from_string(cr) == rs_assert_type_from_string(rr));
                assert_se(rs_assert_type_from_string(rr) == i);
        }

        /* Invalid index */
        cr = assert_type_to_string(-1);
        rr = rs_assert_type_to_string(-1);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = assert_type_to_string(99);
        rr = rs_assert_type_to_string(99);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* from_string */
        /* Backward compat: AssertKernelVersion → CONDITION_VERSION. */
        cv = assert_type_from_string("AssertKernelVersion");
        rv = rs_assert_type_from_string("AssertKernelVersion");
        assert_se(cv == rv);
        assert_se(cv == CONDITION_VERSION);

        /* Invalid */
        cv = assert_type_from_string("AssertBogus");
        rv = rs_assert_type_from_string("AssertBogus");
        assert_se(cv < 0);
        assert_se(rv < 0);

        cv = assert_type_from_string(NULL);
        rv = rs_assert_type_from_string(NULL);
        assert_se(cv < 0);
        assert_se(rv < 0);
}

static void test_shared_str_table_ffi_contracts(void) {
        char invalid[] = { 'x', (char) 0xff, 0 };

        /* Current C lookup functions return -EINVAL for invalid byte strings.
         * Their allocation helpers assert on NULL output, so Rust deliberately
         * rejects it rather than crashing at the public ABI boundary. */
        assert_se(rs_condition_type_from_string(invalid) == -EINVAL);
        assert_se(rs_assert_type_from_string(invalid) == -EINVAL);
        assert_se(rs_compression_lowercase_from_string(invalid) == -EINVAL);
        assert_se(rs_socket_address_type_from_string(invalid) == -EINVAL);
        assert_se(rs_netlink_family_from_string(invalid) == -EINVAL);
        assert_se(rs_ip_tos_from_string(invalid) == -EINVAL);
        assert_se(rs_netlink_family_to_string_alloc(NETLINK_ROUTE, NULL) == -EINVAL);
        assert_se(rs_ip_tos_to_string_alloc(IPTOS_LOWDELAY, NULL) == -EINVAL);
}

static void test_condition_result(void) {
        const char *cr, *rr;
        int cv, rv;

        /* to_string */
        cr = condition_result_to_string(0);
        rr = rs_condition_result_to_string(0);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "untested"));

        cr = condition_result_to_string(1);
        rr = rs_condition_result_to_string(1);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "succeeded"));

        cr = condition_result_to_string(2);
        rr = rs_condition_result_to_string(2);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "failed"));

        cr = condition_result_to_string(3);
        rr = rs_condition_result_to_string(3);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "error"));

        /* Invalid */
        cr = condition_result_to_string(-1);
        rr = rs_condition_result_to_string(-1);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = condition_result_to_string(99);
        rr = rs_condition_result_to_string(99);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* from_string */
        cv = condition_result_from_string("untested");
        rv = rs_condition_result_from_string("untested");
        assert_se(cv == rv);
        assert_se(cv == 0);

        cv = condition_result_from_string("succeeded");
        rv = rs_condition_result_from_string("succeeded");
        assert_se(cv == rv);
        assert_se(cv == 1);

        cv = condition_result_from_string("failed");
        rv = rs_condition_result_from_string("failed");
        assert_se(cv == rv);
        assert_se(cv == 2);

        cv = condition_result_from_string("error");
        rv = rs_condition_result_from_string("error");
        assert_se(cv == rv);
        assert_se(cv == 3);

        /* Invalid */
        cv = condition_result_from_string("bogus");
        rv = rs_condition_result_from_string("bogus");
        assert_se(cv < 0);
        assert_se(rv < 0);

        cv = condition_result_from_string(NULL);
        rv = rs_condition_result_from_string(NULL);
        assert_se(cv < 0);
        assert_se(rv < 0);
}

int main(int argc, char **argv) {
        test_compression_lowercase();
        test_socket_address_type();
        test_netlink_family();
        test_ip_tos();
        test_output_mode();
        test_assert_type();
        test_shared_str_table_ffi_contracts();
        test_condition_result();
        return 0;
}
