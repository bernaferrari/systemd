/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: deserialize-usec */
/* RUST-CONTRACT: deserialize-dual-timestamp */
/* Shadow test: C deserialize_usec/deserialize_dual_timestamp vs Rust */

#include <string.h>
#include "tests.h"
#include "time-util.h"
#include "serialize.h"

/* Rust FFI */
#include "rust/serialize.h"

static void test_deserialize_usec(void) {
        usec_t cr, rr;
        int c_ret, r_ret;

        /* Simple value */
        c_ret = deserialize_usec("12345", &cr);
        r_ret = rs_deserialize_usec("12345", &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr == rr);
        assert_se(cr == 12345);

        /* Zero */
        c_ret = deserialize_usec("0", &cr);
        r_ret = rs_deserialize_usec("0", &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr == rr);
        assert_se(cr == 0);

        /* Large value */
        c_ret = deserialize_usec("18446744073709551615", &cr);
        r_ret = rs_deserialize_usec("18446744073709551615", &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr == rr);

        /* Leading zeros: safe_atou64 uses base=0, so "0123" is octal (83 decimal) */
        c_ret = deserialize_usec("00000123", &cr);
        r_ret = rs_deserialize_usec("00000123", &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr == rr);
        assert_se(cr == 83); /* 0123 octal = 83 decimal */

        /* Invalid: not a number */
        c_ret = deserialize_usec("abc", &cr);
        r_ret = rs_deserialize_usec("abc", &rr);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: negative */
        c_ret = deserialize_usec("-1", &cr);
        r_ret = rs_deserialize_usec("-1", &rr);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: empty */
        c_ret = deserialize_usec("", &cr);
        r_ret = rs_deserialize_usec("", &rr);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Base-zero and overflow parity are covered by test_deserialize_abi_edges(). */
}

static void test_deserialize_dual_timestamp(void) {
        dual_timestamp ct, rt;
        int c_ret, r_ret;

        /* Simple values */
        c_ret = deserialize_dual_timestamp("100 200", &ct);
        r_ret = rs_deserialize_dual_timestamp("100 200", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);
        assert_se(ct.realtime == 100);
        assert_se(ct.monotonic == 200);

        /* Both zero */
        c_ret = deserialize_dual_timestamp("0 0", &ct);
        r_ret = rs_deserialize_dual_timestamp("0 0", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);

        /* Large values */
        c_ret = deserialize_dual_timestamp("18446744073709551615 18446744073709551614", &ct);
        r_ret = rs_deserialize_dual_timestamp("18446744073709551615 18446744073709551614", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);

        /* Leading whitespace */
        c_ret = deserialize_dual_timestamp("  100 200", &ct);
        r_ret = rs_deserialize_dual_timestamp("  100 200", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);

        /* Multiple spaces between values */
        c_ret = deserialize_dual_timestamp("100   200", &ct);
        r_ret = rs_deserialize_dual_timestamp("100   200", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);

        /* Leading zeros */
        c_ret = deserialize_dual_timestamp("00100 00200", &ct);
        r_ret = rs_deserialize_dual_timestamp("00100 00200", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);

        /* Invalid: negative first number */
        c_ret = deserialize_dual_timestamp("-100 200", &ct);
        r_ret = rs_deserialize_dual_timestamp("-100 200", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: negative second number */
        c_ret = deserialize_dual_timestamp("100 -200", &ct);
        r_ret = rs_deserialize_dual_timestamp("100 -200", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: trailing garbage */
        c_ret = deserialize_dual_timestamp("100 200 abc", &ct);
        r_ret = rs_deserialize_dual_timestamp("100 200 abc", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: only one number */
        c_ret = deserialize_dual_timestamp("100", &ct);
        r_ret = rs_deserialize_dual_timestamp("100", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: empty */
        c_ret = deserialize_dual_timestamp("", &ct);
        r_ret = rs_deserialize_dual_timestamp("", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: not a number */
        c_ret = deserialize_dual_timestamp("abc def", &ct);
        r_ret = rs_deserialize_dual_timestamp("abc def", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Sign, raw-byte, output-publication, and overflow parity are covered below. */
}

static void test_deserialize_abi_edges(void) {
        static const char non_ascii_usec[] = { '1', '2', '\xff', 0 };
        static const char non_ascii_timestamp[] = { '1', '0', '0', ' ', '2', '0', '0', '\xff', 0 };
        const usec_t usec_sentinel = UINT64_C(0xdeadbeefdeadbeef);
        const dual_timestamp timestamp_sentinel = {
                .realtime = UINT64_C(0xdeadbeefdeadbeef),
                .monotonic = UINT64_C(0xcafebabecafebabe),
        };
        usec_t c_usec, r_usec;
        dual_timestamp c_timestamp, r_timestamp;
        int c_ret, r_ret;

        /* deserialize_usec() keeps safe_atou64's byte-oriented base-zero grammar. */
        c_ret = deserialize_usec(" \t+012", &c_usec);
        r_ret = rs_deserialize_usec(" \t+012", &r_usec);
        assert_se(c_ret == r_ret);
        assert_se(c_usec == r_usec);
        assert_se(c_usec == 10); /* 012 is octal after leading whitespace and '+'. */

        c_usec = r_usec = usec_sentinel;
        c_ret = deserialize_usec(non_ascii_usec, &c_usec);
        r_ret = rs_deserialize_usec(non_ascii_usec, &r_usec);
        assert_se(c_ret == r_ret);
        assert_se(c_usec == usec_sentinel);
        assert_se(r_usec == usec_sentinel);

        c_usec = r_usec = usec_sentinel;
        c_ret = deserialize_usec("18446744073709551616", &c_usec);
        r_ret = rs_deserialize_usec("18446744073709551616", &r_usec);
        assert_se(c_ret == r_ret);
        assert_se(c_usec == usec_sentinel);
        assert_se(r_usec == usec_sentinel);

        /* sscanf() accepts a leading '+', and leading zeroes remain decimal here. */
        c_ret = deserialize_dual_timestamp("\t+00100 +00200\r", &c_timestamp);
        r_ret = rs_deserialize_dual_timestamp("\t+00100 +00200\r", &r_timestamp);
        assert_se(c_ret == r_ret);
        assert_se(c_timestamp.realtime == r_timestamp.realtime);
        assert_se(c_timestamp.monotonic == r_timestamp.monotonic);
        assert_se(c_timestamp.realtime == 100);
        assert_se(c_timestamp.monotonic == 200);

        /* Failed parses must not publish either output field. */
        c_timestamp = r_timestamp = timestamp_sentinel;
        c_ret = deserialize_dual_timestamp("100 -200", &c_timestamp);
        r_ret = rs_deserialize_dual_timestamp("100 -200", &r_timestamp);
        assert_se(c_ret == r_ret);
        assert_se(c_timestamp.realtime == timestamp_sentinel.realtime);
        assert_se(c_timestamp.monotonic == timestamp_sentinel.monotonic);
        assert_se(r_timestamp.realtime == timestamp_sentinel.realtime);
        assert_se(r_timestamp.monotonic == timestamp_sentinel.monotonic);

        c_timestamp = r_timestamp = timestamp_sentinel;
        c_ret = deserialize_dual_timestamp(non_ascii_timestamp, &c_timestamp);
        r_ret = rs_deserialize_dual_timestamp(non_ascii_timestamp, &r_timestamp);
        assert_se(c_ret == r_ret);
        assert_se(c_timestamp.realtime == timestamp_sentinel.realtime);
        assert_se(c_timestamp.monotonic == timestamp_sentinel.monotonic);
        assert_se(r_timestamp.realtime == timestamp_sentinel.realtime);
        assert_se(r_timestamp.monotonic == timestamp_sentinel.monotonic);

        /* The authority leaves sscanf overflow to libc; the facade must too. */
        c_ret = deserialize_dual_timestamp("18446744073709551616 1", &c_timestamp);
        r_ret = rs_deserialize_dual_timestamp("18446744073709551616 1", &r_timestamp);
        assert_se(c_ret == r_ret);
        assert_se(c_timestamp.realtime == r_timestamp.realtime);
        assert_se(c_timestamp.monotonic == r_timestamp.monotonic);
}

int main(int argc, char **argv) {
        test_deserialize_usec();
        test_deserialize_dual_timestamp();
        test_deserialize_abi_edges();
        return 0;
}
