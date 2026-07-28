/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C af-list vs Rust rs_af_list */

#include <netinet/in.h>
#include <string.h>

#include "af-list.h"
#include "rust/af_list.h"
#include "string-util.h"
#include "tests.h"

/* ── af_to_name ───────────────────────────────────────────────────────── */

/* RUST-CONTRACT: af-name-rendering */
static void test_af_to_name(void) {
        const char *cr, *rr;

        cr = af_to_name(AF_INET);
        rr = rs_af_to_name(AF_INET);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        cr = af_to_name(AF_INET6);
        rr = rs_af_to_name(AF_INET6);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        cr = af_to_name(AF_UNIX);
        rr = rs_af_to_name(AF_UNIX);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        cr = af_to_name(AF_NETLINK);
        rr = rs_af_to_name(AF_NETLINK);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        cr = af_to_name(AF_PACKET);
        rr = rs_af_to_name(AF_PACKET);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        /* Zero and negative */
        cr = af_to_name(0);
        rr = rs_af_to_name(0);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = af_to_name(-1);
        rr = rs_af_to_name(-1);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Out of range */
        cr = af_to_name(9999);
        rr = rs_af_to_name(9999);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Exhaust the target-generated C table, including sparse entries. */
        for (int id = -1; id <= af_max(); id++) {
                cr = af_to_name(id);
                rr = rs_af_to_name(id);
                assert_se((cr == NULL) == (rr == NULL));
                if (cr)
                        assert_se(streq(cr, rr));
        }
}

/* ── af_to_name_short ─────────────────────────────────────────────────── */

/* RUST-CONTRACT: af-name-short-rendering */
static void test_af_to_name_short(void) {
        const char *cr, *rr;

        cr = af_to_name_short(AF_INET);
        rr = rs_af_to_name_short(AF_INET);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "INET"));

        cr = af_to_name_short(AF_INET6);
        rr = rs_af_to_name_short(AF_INET6);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "INET6"));

        cr = af_to_name_short(AF_UNIX);
        rr = rs_af_to_name_short(AF_UNIX);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "UNIX"));

        cr = af_to_name_short(AF_NETLINK);
        rr = rs_af_to_name_short(AF_NETLINK);
        assert_se(streq(cr, rr));

        /* AF_UNSPEC returns "*" */
        cr = af_to_name_short(AF_UNSPEC);
        rr = rs_af_to_name_short(AF_UNSPEC);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "*"));

        /* Unknown returns "unknown" */
        cr = af_to_name_short(99999);
        rr = rs_af_to_name_short(99999);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "unknown"));
}

/* ── af_from_name ─────────────────────────────────────────────────────── */

/* RUST-CONTRACT: af-name-parsing */
static void test_af_from_name(void) {
        const char invalid_bytes[] = { (char) 0xff, 0 };
        int cr, rr;

        cr = af_from_name("AF_INET");
        rr = rs_af_from_name("AF_INET");
        assert_se(cr == rr);
        assert_se(cr == AF_INET);

        cr = af_from_name("AF_INET6");
        rr = rs_af_from_name("AF_INET6");
        assert_se(cr == rr);
        assert_se(cr == AF_INET6);

        cr = af_from_name("AF_UNIX");
        rr = rs_af_from_name("AF_UNIX");
        assert_se(cr == rr);
        assert_se(cr == AF_UNIX);

        cr = af_from_name("AF_NETLINK");
        rr = rs_af_from_name("AF_NETLINK");
        assert_se(cr == rr);
        assert_se(cr == AF_NETLINK);

        cr = af_from_name("AF_PACKET");
        rr = rs_af_from_name("AF_PACKET");
        assert_se(cr == rr);

        /* The generated gperf authority accepts aliases and folds ASCII case. */
        cr = af_from_name("AF_LOCAL");
        rr = rs_af_from_name("AF_LOCAL");
        assert_se(cr == rr);
        assert_se(cr == AF_UNIX);

        cr = af_from_name("AF_FILE");
        rr = rs_af_from_name("AF_FILE");
        assert_se(cr == rr);
        assert_se(cr == AF_UNIX);

        cr = af_from_name("AF_ROUTE");
        rr = rs_af_from_name("AF_ROUTE");
        assert_se(cr == rr);
        assert_se(cr == AF_NETLINK);

        cr = af_from_name("aF_iNeT6");
        rr = rs_af_from_name("aF_iNeT6");
        assert_se(cr == rr);
        assert_se(cr == AF_INET6);

        /* Unknown */
        cr = af_from_name("invalid");
        rr = rs_af_from_name("invalid");
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* NULL — C asserts, skip shadow test */
        rr = rs_af_from_name(NULL);
        assert_se(rr < 0);

        /* The ABI is byte-oriented and must reject, not reinterpret, invalid UTF-8. */
        assert_se(af_from_name(invalid_bytes) == rs_af_from_name(invalid_bytes));

        for (int id = 1; id < af_max(); id++) {
                const char *name = af_to_name(id);
                if (name)
                        assert_se(af_from_name(name) == rs_af_from_name(name));
        }
}

/* ── af_to_ipv4_ipv6 / af_from_ipv4_ipv6 ─────────────────────────────── */

/* RUST-CONTRACT: af-ipv4-ipv6-rendering */
static void test_af_ipv4_ipv6(void) {
        const char *cr, *rr;
        int ir, rr2;

        cr = af_to_ipv4_ipv6(AF_INET);
        rr = rs_af_to_ipv4_ipv6(AF_INET);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "ipv4"));

        cr = af_to_ipv4_ipv6(AF_INET6);
        rr = rs_af_to_ipv4_ipv6(AF_INET6);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "ipv6"));

        cr = af_to_ipv4_ipv6(AF_UNIX);
        rr = rs_af_to_ipv4_ipv6(AF_UNIX);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* RUST-CONTRACT: af-ipv4-ipv6-parsing */
        ir = af_from_ipv4_ipv6("ipv4");
        rr2 = rs_af_from_ipv4_ipv6("ipv4");
        assert_se(ir == rr2);
        assert_se(ir == AF_INET);

        ir = af_from_ipv4_ipv6("ipv6");
        rr2 = rs_af_from_ipv4_ipv6("ipv6");
        assert_se(ir == rr2);
        assert_se(ir == AF_INET6);

        ir = af_from_ipv4_ipv6("unix");
        rr2 = rs_af_from_ipv4_ipv6("unix");
        assert_se(ir == rr2);
        assert_se(ir == AF_UNSPEC);

        /* NULL */
        ir = af_from_ipv4_ipv6(NULL);
        rr2 = rs_af_from_ipv4_ipv6(NULL);
        assert_se(ir == rr2);
        assert_se(ir == AF_UNSPEC);
}

/* ── Roundtrip ────────────────────────────────────────────────────────── */

static void test_af_name_roundtrip(void) {
        assert_se(af_from_name(af_to_name(AF_INET)) == AF_INET);
        assert_se(rs_af_from_name(rs_af_to_name(AF_INET)) == AF_INET);

        assert_se(af_from_name(af_to_name(AF_INET6)) == AF_INET6);
        assert_se(rs_af_from_name(rs_af_to_name(AF_INET6)) == AF_INET6);

        assert_se(af_from_name(af_to_name(AF_UNIX)) == AF_UNIX);
        assert_se(rs_af_from_name(rs_af_to_name(AF_UNIX)) == AF_UNIX);
}

/* RUST-CONTRACT: af-max */
static void test_af_max(void) {
        assert_se(af_max() == rs_af_max());
}

int main(int argc, char **argv) {
        test_af_to_name();
        test_af_to_name_short();
        test_af_from_name();
        test_af_ipv4_ipv6();
        test_af_name_roundtrip();
        test_af_max();
        return 0;
}
