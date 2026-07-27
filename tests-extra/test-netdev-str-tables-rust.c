/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C bond/bridge/ethtool/coredump string tables vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers for shared string tables */
#include "bond-util.h"
#include "bridge-util.h"
#include "ethtool-util.h"
#include "coredump-util.h"

/* Rust FFI */
#include "rust/netdev_str_tables.h"
#include "dns-packet.h"

/* ── bond_mode ─────────────────────────────────────────────────────────── */

static void test_bond_mode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_RR);
        r_ret = rs_bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_RR);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = bond_mode_to_string(NETDEV_BOND_MODE_802_3AD);
        r_ret = rs_bond_mode_to_string(NETDEV_BOND_MODE_802_3AD);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_ALB);
        r_ret = rs_bond_mode_to_string(NETDEV_BOND_MODE_BALANCE_ALB);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = bond_mode_from_string("balance-rr");
        rv = rs_bond_mode_from_string("balance-rr");
        assert_se((int)cv == rv);
        assert_se(cv == NETDEV_BOND_MODE_BALANCE_RR);

        cv = bond_mode_from_string("active-backup");
        rv = rs_bond_mode_from_string("active-backup");
        assert_se((int)cv == rv);

        cv = bond_mode_from_string("bogus");
        rv = rs_bond_mode_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── bridge_state ──────────────────────────────────────────────────────── */

static void test_bridge_state(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = bridge_state_to_string(NETDEV_BRIDGE_STATE_DISABLED);
        r_ret = rs_bridge_state_to_string(NETDEV_BRIDGE_STATE_DISABLED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = bridge_state_to_string(NETDEV_BRIDGE_STATE_FORWARDING);
        r_ret = rs_bridge_state_to_string(NETDEV_BRIDGE_STATE_FORWARDING);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* BLOCKING has no to_string in C */
        c_ret = bridge_state_to_string(NETDEV_BRIDGE_STATE_BLOCKING);
        r_ret = rs_bridge_state_to_string(NETDEV_BRIDGE_STATE_BLOCKING);
        assert_se(streq_ptr(c_ret, r_ret));

        cv = bridge_state_from_string("disabled");
        rv = rs_bridge_state_from_string("disabled");
        assert_se((int)cv == rv);
}

/* ── duplex ───────────────────────────────────────────────────────────── */

static void test_duplex(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = duplex_to_string(DUP_HALF);
        r_ret = rs_duplex_to_string(DUP_HALF);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = duplex_to_string(DUP_FULL);
        r_ret = rs_duplex_to_string(DUP_FULL);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = duplex_from_string("half");
        rv = rs_duplex_from_string("half");
        assert_se((int)cv == rv);
}

/* ── net_dev_port ───────────────────────────────────────────────────────── */

static void test_net_dev_port(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = port_to_string(NET_DEV_PORT_TP);
        r_ret = rs_port_to_string(NET_DEV_PORT_TP);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = port_to_string(NET_DEV_PORT_FIBRE);
        r_ret = rs_port_to_string(NET_DEV_PORT_FIBRE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* DA/NONE/OTHER have no to_string in C */
        c_ret = port_to_string(NET_DEV_PORT_DA);
        r_ret = rs_port_to_string(NET_DEV_PORT_DA);
        assert_se(streq_ptr(c_ret, r_ret));

        cv = port_from_string("tp");
        rv = rs_port_from_string("tp");
        assert_se((int)cv == rv);
}

/* ── coredump_filter ───────────────────────────────────────────────────── */

static void test_coredump_filter(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_ANONYMOUS);
        r_ret = rs_coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_ANONYMOUS);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = coredump_filter_to_string(COREDUMP_FILTER_SHARED_DAX);
        r_ret = rs_coredump_filter_to_string(COREDUMP_FILTER_SHARED_DAX);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = coredump_filter_from_string("private-anonymous");
        rv = rs_coredump_filter_from_string("private-anonymous");
        assert_se((int)cv == rv);

        cv = coredump_filter_from_string("elf-headers");
        rv = rs_coredump_filter_from_string("elf-headers");
        assert_se((int)cv == rv);
        assert_se(cv == COREDUMP_FILTER_ELF_HEADERS);
}

/* ── mdi (TO_STRING only) ─────────────────────────────────────────────── */

static void test_mdi(void) {
        const char *cv, *rv;

        cv = mdi_to_string(ETH_TP_MDI_INVALID);
        rv = rs_mdi_to_string(ETH_TP_MDI_INVALID);
        assert_se(streq_ptr(cv, rv));

        cv = mdi_to_string(ETH_TP_MDI);
        rv = rs_mdi_to_string(ETH_TP_MDI);
        assert_se(streq_ptr(cv, rv));

        cv = mdi_to_string(ETH_TP_MDI_X);
        rv = rs_mdi_to_string(ETH_TP_MDI_X);
        assert_se(streq_ptr(cv, rv));

        cv = mdi_to_string(ETH_TP_MDI_AUTO);
        rv = rs_mdi_to_string(ETH_TP_MDI_AUTO);
        assert_se(streq_ptr(cv, rv));

        /* Invalid */
        cv = mdi_to_string(99);
        rv = rs_mdi_to_string(99);
        assert_se(streq_ptr(cv, rv));
}

/* ── dns_ede_rcode_is_dnssec ──────────────────────────────────────────── */

static void test_dns_ede_rcode_is_dnssec(void) {
        bool cv, rv;

        /* All DNSSEC-related EDE codes */
        cv = dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_UNSUPPORTED_DNSKEY_ALG);
        rv = rs_dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_UNSUPPORTED_DNSKEY_ALG);
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_UNSUPPORTED_DS_DIGEST);
        rv = rs_dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_UNSUPPORTED_DS_DIGEST);
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_DNSSEC_INDETERMINATE);
        rv = rs_dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_DNSSEC_INDETERMINATE);
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_DNSSEC_BOGUS);
        rv = rs_dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_DNSSEC_BOGUS);
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_SIG_EXPIRED);
        rv = rs_dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_SIG_EXPIRED);
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_SIG_NOT_YET_VALID);
        rv = rs_dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_SIG_NOT_YET_VALID);
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_DNSKEY_MISSING);
        rv = rs_dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_DNSKEY_MISSING);
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_RRSIG_MISSING);
        rv = rs_dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_RRSIG_MISSING);
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_NO_ZONE_KEY_BIT);
        rv = rs_dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_NO_ZONE_KEY_BIT);
        assert_se(cv == rv);
        assert_se(cv);

        cv = dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_NSEC_MISSING);
        rv = rs_dns_ede_rcode_is_dnssec(DNS_EDE_RCODE_NSEC_MISSING);
        assert_se(cv == rv);
        assert_se(cv);

        /* Non-DNSSEC codes: 0 (UNSPECSIFIED), 3 (STALE_ANSWER), 4 (FORGED_ANSWER) */
        cv = dns_ede_rcode_is_dnssec(0);
        rv = rs_dns_ede_rcode_is_dnssec(0);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = dns_ede_rcode_is_dnssec(3);
        rv = rs_dns_ede_rcode_is_dnssec(3);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = dns_ede_rcode_is_dnssec(4);
        rv = rs_dns_ede_rcode_is_dnssec(4);
        assert_se(cv == rv);
        assert_se(!cv);

        /* Negative */
        cv = dns_ede_rcode_is_dnssec(-1);
        rv = rs_dns_ede_rcode_is_dnssec(-1);
        assert_se(cv == rv);
        assert_se(!cv);

        /* Beyond range */
        cv = dns_ede_rcode_is_dnssec(99);
        rv = rs_dns_ede_rcode_is_dnssec(99);
        assert_se(cv == rv);
        assert_se(!cv);
}

int main(int argc, char **argv) {
        test_bond_mode();
        test_bridge_state();
        test_duplex();
        test_net_dev_port();
        test_coredump_filter();
        test_mdi();
        test_dns_ede_rcode_is_dnssec();
        return 0;
}
