/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C arphrd-util vs Rust rs_arphrd_util */

#include <string.h>
#include <linux/if_arp.h>

#include "arphrd-util.h"
#include "rust/arphrd_util.h"
#include "string-util.h"
#include "tests.h"

/* ── arphrd_from_name ─────────────────────────────────────────────────── */

/* RUST-CONTRACT: arphrd-name-conversion */
static void test_arphrd_from_name(void) {
        int cr, rr;

        cr = arphrd_from_name("ETHER");
        rr = rs_arphrd_from_name("ETHER");
        assert_se(cr == rr);
        assert_se(cr == ARPHRD_ETHER);

        cr = arphrd_from_name("LOOPBACK");
        rr = rs_arphrd_from_name("LOOPBACK");
        assert_se(cr == rr);
        assert_se(cr == ARPHRD_LOOPBACK);

        cr = arphrd_from_name("INFINIBAND");
        rr = rs_arphrd_from_name("INFINIBAND");
        assert_se(cr == rr);
        assert_se(cr == ARPHRD_INFINIBAND);

        cr = arphrd_from_name("IEEE802154");
        rr = rs_arphrd_from_name("IEEE802154");
        assert_se(cr == rr);

        /* The generated gperf authority is case-insensitive. */
        cr = arphrd_from_name("ether");
        rr = rs_arphrd_from_name("ether");
        assert_se(cr == rr);
        assert_se(cr == ARPHRD_ETHER);

        /* HDLC aliases CISCO in linux/if_arp.h and the from-name table. */
        cr = arphrd_from_name("HDLC");
        rr = rs_arphrd_from_name("HDLC");
        assert_se(cr == rr);
        assert_se(cr == ARPHRD_CISCO);

        cr = arphrd_from_name("IPDDP");
        rr = rs_arphrd_from_name("IPDDP");
        assert_se(cr == rr);
        assert_se(cr == ARPHRD_IPDDP);

        cr = arphrd_from_name("PIMREG");
        rr = rs_arphrd_from_name("PIMREG");
        assert_se(cr == rr);
        assert_se(cr == ARPHRD_PIMREG);

        cr = arphrd_from_name("VOID");
        rr = rs_arphrd_from_name("VOID");
        assert_se(cr == rr);
        assert_se(cr == ARPHRD_VOID);

        /* Unknown */
        cr = arphrd_from_name("NOTREAL");
        rr = rs_arphrd_from_name("NOTREAL");
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* NULL — C asserts, skip shadow test */
        rr = rs_arphrd_from_name(NULL);
        assert_se(rr < 0);
}

/* ── arphrd_to_name ───────────────────────────────────────────────────── */

/* RUST-CONTRACT: arphrd-name-rendering */
static void test_arphrd_to_name(void) {
        const char *cr, *rr;

        cr = arphrd_to_name(ARPHRD_ETHER);
        rr = rs_arphrd_to_name(ARPHRD_ETHER);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        cr = arphrd_to_name(ARPHRD_LOOPBACK);
        rr = rs_arphrd_to_name(ARPHRD_LOOPBACK);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        cr = arphrd_to_name(ARPHRD_INFINIBAND);
        rr = rs_arphrd_to_name(ARPHRD_INFINIBAND);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        cr = arphrd_to_name(ARPHRD_HDLC);
        rr = rs_arphrd_to_name(ARPHRD_HDLC);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, "CISCO"));
        assert_se(streq(cr, rr));

        /* Unknown value */
        cr = arphrd_to_name(999);
        rr = rs_arphrd_to_name(999);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

/* ── arphrd_to_hw_addr_len ────────────────────────────────────────────── */

/* RUST-CONTRACT: arphrd-hardware-address-length */
static void test_arphrd_to_hw_addr_len(void) {
        size_t cr, rr;

        cr = arphrd_to_hw_addr_len(ARPHRD_ETHER);
        rr = rs_arphrd_to_hw_addr_len(ARPHRD_ETHER);
        assert_se(cr == rr);
        assert_se(cr == 6); /* ETH_ALEN */

        cr = arphrd_to_hw_addr_len(ARPHRD_INFINIBAND);
        rr = rs_arphrd_to_hw_addr_len(ARPHRD_INFINIBAND);
        assert_se(cr == rr);
        assert_se(cr == 20); /* INFINIBAND_ALEN */

        cr = arphrd_to_hw_addr_len(ARPHRD_TUNNEL);
        rr = rs_arphrd_to_hw_addr_len(ARPHRD_TUNNEL);
        assert_se(cr == rr);
        assert_se(cr == 4); /* sizeof(struct in_addr) */

        cr = arphrd_to_hw_addr_len(ARPHRD_SIT);
        rr = rs_arphrd_to_hw_addr_len(ARPHRD_SIT);
        assert_se(cr == rr);
        assert_se(cr == 4);

        cr = arphrd_to_hw_addr_len(ARPHRD_IPGRE);
        rr = rs_arphrd_to_hw_addr_len(ARPHRD_IPGRE);
        assert_se(cr == rr);
        assert_se(cr == 4);

        cr = arphrd_to_hw_addr_len(ARPHRD_TUNNEL6);
        rr = rs_arphrd_to_hw_addr_len(ARPHRD_TUNNEL6);
        assert_se(cr == rr);
        assert_se(cr == 16); /* sizeof(struct in6_addr) */

        cr = arphrd_to_hw_addr_len(ARPHRD_IP6GRE);
        rr = rs_arphrd_to_hw_addr_len(ARPHRD_IP6GRE);
        assert_se(cr == rr);
        assert_se(cr == 16);

        /* Unknown type */
        cr = arphrd_to_hw_addr_len(999);
        rr = rs_arphrd_to_hw_addr_len(999);
        assert_se(cr == rr);
        assert_se(cr == 0);
}

int main(int argc, char **argv) {
        test_arphrd_from_name();
        test_arphrd_to_name();
        test_arphrd_to_hw_addr_len();
        return 0;
}
