/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C shared/ string tables batch 4 vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "wifi-util.h"
#include "netif-sriov.h"
#include "resolve-util.h"

/* Rust FFI */
#include "rust/netdev_str_tables.h"

/* ── nl80211_iftype ────────────────────────────────────────────────────── */

static void test_nl80211_iftype(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        /* UNSPECIFIED=0 has no string */
        c_ret = nl80211_iftype_to_string(NL80211_IFTYPE_UNSPECIFIED);
        r_ret = rs_nl80211_iftype_to_string(NL80211_IFTYPE_UNSPECIFIED);
        assert_se(c_ret == NULL && r_ret == NULL);

        c_ret = nl80211_iftype_to_string(NL80211_IFTYPE_ADHOC);
        r_ret = rs_nl80211_iftype_to_string(NL80211_IFTYPE_ADHOC);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = nl80211_iftype_to_string(NL80211_IFTYPE_STATION);
        r_ret = rs_nl80211_iftype_to_string(NL80211_IFTYPE_STATION);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = nl80211_iftype_to_string(NL80211_IFTYPE_NAN);
        r_ret = rs_nl80211_iftype_to_string(NL80211_IFTYPE_NAN);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = nl80211_iftype_from_string("ap");
        rv = rs_nl80211_iftype_from_string("ap");
        assert_se(cv == rv);

        cv = nl80211_iftype_from_string("bogus");
        rv = rs_nl80211_iftype_from_string("bogus");
        assert_se(cv == rv);
}

/* ── sr_iov_attribute (to_string only) ────────────────────────────────── */

static void test_sr_iov_attribute(void) {
        const char *c_ret, *r_ret;

        c_ret = sr_iov_attribute_to_string(SR_IOV_VF_MAC);
        r_ret = rs_sr_iov_attribute_to_string(SR_IOV_VF_MAC);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = sr_iov_attribute_to_string(SR_IOV_VF_SPOOFCHK);
        r_ret = rs_sr_iov_attribute_to_string(SR_IOV_VF_SPOOFCHK);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = sr_iov_attribute_to_string(SR_IOV_VF_VLAN_LIST);
        r_ret = rs_sr_iov_attribute_to_string(SR_IOV_VF_VLAN_LIST);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

/* ── resolve_support (WITH_BOOLEAN yes=2) ─────────────────────────────── */

static void test_resolve_support(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = resolve_support_to_string(RESOLVE_SUPPORT_NO);
        r_ret = rs_resolve_support_to_string(RESOLVE_SUPPORT_NO);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = resolve_support_to_string(RESOLVE_SUPPORT_YES);
        r_ret = rs_resolve_support_to_string(RESOLVE_SUPPORT_YES);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = resolve_support_to_string(RESOLVE_SUPPORT_RESOLVE);
        r_ret = rs_resolve_support_to_string(RESOLVE_SUPPORT_RESOLVE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Boolean parsing: "yes" → RESOLVE_SUPPORT_YES */
        cv = resolve_support_from_string("yes");
        rv = rs_resolve_support_from_string("yes");
        assert_se(cv == rv);
        assert_se(cv == RESOLVE_SUPPORT_YES);

        /* Boolean parsing: "no" → RESOLVE_SUPPORT_NO */
        cv = resolve_support_from_string("no");
        rv = rs_resolve_support_from_string("no");
        assert_se(cv == rv);
        assert_se(cv == RESOLVE_SUPPORT_NO);

        /* Case-insensitive boolean */
        cv = resolve_support_from_string("True");
        rv = rs_resolve_support_from_string("True");
        assert_se(cv == rv);

        cv = resolve_support_from_string("FALSE");
        rv = rs_resolve_support_from_string("FALSE");
        assert_se(cv == rv);

        /* Normal table lookup */
        cv = resolve_support_from_string("resolve");
        rv = rs_resolve_support_from_string("resolve");
        assert_se(cv == rv);

        /* Unknown */
        cv = resolve_support_from_string("bogus");
        rv = rs_resolve_support_from_string("bogus");
        assert_se(cv == rv);
}

/* ── dnssec_mode (WITH_BOOLEAN yes=2) ─────────────────────────────────── */

static void test_dnssec_mode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = dnssec_mode_to_string(DNSSEC_NO);
        r_ret = rs_dnssec_mode_to_string(DNSSEC_NO);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dnssec_mode_to_string(DNSSEC_ALLOW_DOWNGRADE);
        r_ret = rs_dnssec_mode_to_string(DNSSEC_ALLOW_DOWNGRADE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dnssec_mode_to_string(DNSSEC_YES);
        r_ret = rs_dnssec_mode_to_string(DNSSEC_YES);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = dnssec_mode_from_string("allow-downgrade");
        rv = rs_dnssec_mode_from_string("allow-downgrade");
        assert_se(cv == rv);

        /* Boolean */
        cv = dnssec_mode_from_string("yes");
        rv = rs_dnssec_mode_from_string("yes");
        assert_se(cv == rv);
        assert_se(cv == DNSSEC_YES);

        cv = dnssec_mode_from_string("no");
        rv = rs_dnssec_mode_from_string("no");
        assert_se(cv == rv);
        assert_se(cv == DNSSEC_NO);
}

/* ── dns_over_tls_mode (WITH_BOOLEAN yes=2) ───────────────────────────── */

static void test_dns_over_tls_mode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = dns_over_tls_mode_to_string(DNS_OVER_TLS_NO);
        r_ret = rs_dns_over_tls_mode_to_string(DNS_OVER_TLS_NO);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_over_tls_mode_to_string(DNS_OVER_TLS_OPPORTUNISTIC);
        r_ret = rs_dns_over_tls_mode_to_string(DNS_OVER_TLS_OPPORTUNISTIC);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_over_tls_mode_to_string(DNS_OVER_TLS_YES);
        r_ret = rs_dns_over_tls_mode_to_string(DNS_OVER_TLS_YES);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = dns_over_tls_mode_from_string("opportunistic");
        rv = rs_dns_over_tls_mode_from_string("opportunistic");
        assert_se(cv == rv);

        cv = dns_over_tls_mode_from_string("yes");
        rv = rs_dns_over_tls_mode_from_string("yes");
        assert_se(cv == rv);

        cv = dns_over_tls_mode_from_string("no");
        rv = rs_dns_over_tls_mode_from_string("no");
        assert_se(cv == rv);
}

/* ── dns_cache_mode (WITH_BOOLEAN yes=1) ──────────────────────────────── */

static void test_dns_cache_mode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = dns_cache_mode_to_string(DNS_CACHE_MODE_NO);
        r_ret = rs_dns_cache_mode_to_string(DNS_CACHE_MODE_NO);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_cache_mode_to_string(DNS_CACHE_MODE_YES);
        r_ret = rs_dns_cache_mode_to_string(DNS_CACHE_MODE_YES);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_cache_mode_to_string(DNS_CACHE_MODE_NO_NEGATIVE);
        r_ret = rs_dns_cache_mode_to_string(DNS_CACHE_MODE_NO_NEGATIVE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = dns_cache_mode_from_string("no-negative");
        rv = rs_dns_cache_mode_from_string("no-negative");
        assert_se(cv == rv);

        /* Boolean: yes → DNS_CACHE_MODE_YES (which is 1) */
        cv = dns_cache_mode_from_string("yes");
        rv = rs_dns_cache_mode_from_string("yes");
        assert_se(cv == rv);
        assert_se(cv == DNS_CACHE_MODE_YES);

        /* Boolean: no → 0 (DNS_CACHE_MODE_NO) */
        cv = dns_cache_mode_from_string("no");
        rv = rs_dns_cache_mode_from_string("no");
        assert_se(cv == rv);
        assert_se(cv == DNS_CACHE_MODE_NO);
}

int main(int argc, char **argv) {
        test_nl80211_iftype();
        test_sr_iov_attribute();
        test_resolve_support();
        test_dnssec_mode();
        test_dns_over_tls_mode();
        test_dns_cache_mode();
        return 0;
}
