/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C shared/ string tables batch 5 vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "dns-packet.h"
#include "dns-type.h"
#include "firewall-util.h"
#include "install.h"
#include "bootspec.h"

/* Rust FFI */
#include "rust/netdev_str_tables.h"

/* ── dns_rcode ─────────────────────────────────────────────────────────── */

static void test_dns_rcode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = dns_rcode_to_string(DNS_RCODE_SUCCESS);
        r_ret = rs_dns_rcode_to_string(DNS_RCODE_SUCCESS);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_rcode_to_string(DNS_RCODE_NXDOMAIN);
        r_ret = rs_dns_rcode_to_string(DNS_RCODE_NXDOMAIN);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_rcode_to_string(DNS_RCODE_BADCOOKIE);
        r_ret = rs_dns_rcode_to_string(DNS_RCODE_BADCOOKIE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Gap at 12-15 returns NULL */
        c_ret = dns_rcode_to_string(12);
        r_ret = rs_dns_rcode_to_string(12);
        assert_se(c_ret == NULL && r_ret == NULL);

        cv = dns_rcode_from_string("REFUSED");
        rv = rs_dns_rcode_from_string("REFUSED");
        assert_se(cv == rv);

        cv = dns_rcode_from_string("bogus");
        rv = rs_dns_rcode_from_string("bogus");
        assert_se(cv == rv);
}

/* ── dns_protocol ─────────────────────────────────────────────────────── */

static void test_dns_protocol(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = dns_protocol_to_string(DNS_PROTOCOL_DNS);
        r_ret = rs_dns_protocol_to_string(DNS_PROTOCOL_DNS);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_protocol_to_string(DNS_PROTOCOL_LLMNR);
        r_ret = rs_dns_protocol_to_string(DNS_PROTOCOL_LLMNR);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = dns_protocol_from_string("mdns");
        rv = rs_dns_protocol_from_string("mdns");
        assert_se(cv == rv);
}

/* ── dns_svc_param_key (to_string only) ───────────────────────────────── */

static void test_dns_svc_param_key(void) {
        const char *c_ret, *r_ret;

        c_ret = dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_MANDATORY);
        r_ret = rs_dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_MANDATORY);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_ECH);
        r_ret = rs_dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_ECH);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_OHTTP);
        r_ret = rs_dns_svc_param_key_to_string(DNS_SVC_PARAM_KEY_OHTTP);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

/* ── dns_ede_rcode (to_string only) ───────────────────────────────────── */

static void test_dns_ede_rcode(void) {
        const char *c_ret, *r_ret;

        c_ret = dns_ede_rcode_to_string(DNS_EDE_RCODE_OTHER);
        r_ret = rs_dns_ede_rcode_to_string(DNS_EDE_RCODE_OTHER);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_ede_rcode_to_string(DNS_EDE_RCODE_DNSSEC_BOGUS);
        r_ret = rs_dns_ede_rcode_to_string(DNS_EDE_RCODE_DNSSEC_BOGUS);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_ede_rcode_to_string(DNS_EDE_RCODE_SYNTHESIZED);
        r_ret = rs_dns_ede_rcode_to_string(DNS_EDE_RCODE_SYNTHESIZED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

/* ── dns_class (case-insensitive from_string) ─────────────────────────── */

static void test_dns_class(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = dns_class_to_string(DNS_CLASS_IN);
        r_ret = rs_dns_class_to_string(DNS_CLASS_IN);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = dns_class_to_string(DNS_CLASS_ANY);
        r_ret = rs_dns_class_to_string(DNS_CLASS_ANY);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Case-insensitive */
        cv = dns_class_from_string("IN");
        rv = rs_dns_class_from_string("IN");
        assert_se(cv == rv);

        cv = dns_class_from_string("in");
        rv = rs_dns_class_from_string("in");
        assert_se(cv == rv);

        cv = dns_class_from_string("any");
        rv = rs_dns_class_from_string("any");
        assert_se(cv == rv);

        cv = dns_class_from_string("ANY");
        rv = rs_dns_class_from_string("ANY");
        assert_se(cv == rv);

        /* Unknown */
        cv = dns_class_from_string("bogus");
        rv = rs_dns_class_from_string("bogus");
        assert_se(cv == rv);
}

/* ── nfproto (non-sequential: ARP=3, BRIDGE=7, INET=1, IPV4=2, IPV6=10, NETDEV=5) ──

 * NFPROTO_* values from <linux/netfilter.h>. Not always available via a C enum,
 * so we use the raw numeric values from the kernel header. */

#ifndef NFPROTO_INET
#define NFPROTO_INET   1
#endif
#ifndef NFPROTO_IPV4
#define NFPROTO_IPV4   2
#endif
#ifndef NFPROTO_ARP
#define NFPROTO_ARP    3
#endif
#ifndef NFPROTO_NETDEV
#define NFPROTO_NETDEV 5
#endif
#ifndef NFPROTO_BRIDGE
#define NFPROTO_BRIDGE 7
#endif
#ifndef NFPROTO_IPV6
#define NFPROTO_IPV6   10
#endif

static void test_nfproto(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = nfproto_to_string(NFPROTO_INET);
        r_ret = rs_nfproto_to_string(NFPROTO_INET);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = nfproto_to_string(NFPROTO_IPV6);
        r_ret = rs_nfproto_to_string(NFPROTO_IPV6);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = nfproto_to_string(NFPROTO_ARP);
        r_ret = rs_nfproto_to_string(NFPROTO_ARP);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = nfproto_from_string("ip");
        rv = rs_nfproto_from_string("ip");
        assert_se(cv == rv);

        cv = nfproto_from_string("bridge");
        rv = rs_nfproto_from_string("bridge");
        assert_se(cv == rv);

        cv = nfproto_from_string("bogus");
        rv = rs_nfproto_from_string("bogus");
        assert_se(cv == rv);
}

/* ── nft_set_source ───────────────────────────────────────────────────── */

static void test_nft_set_source(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = nft_set_source_to_string(NFT_SET_SOURCE_ADDRESS);
        r_ret = rs_nft_set_source_to_string(NFT_SET_SOURCE_ADDRESS);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = nft_set_source_to_string(NFT_SET_SOURCE_GROUP);
        r_ret = rs_nft_set_source_to_string(NFT_SET_SOURCE_GROUP);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = nft_set_source_from_string("cgroup");
        rv = rs_nft_set_source_from_string("cgroup");
        assert_se(cv == rv);
}

/* ── install_change_type ──────────────────────────────────────────────── */

static void test_install_change_type(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = install_change_type_to_string(INSTALL_CHANGE_SYMLINK);
        r_ret = rs_install_change_type_to_string(INSTALL_CHANGE_SYMLINK);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = install_change_type_to_string(INSTALL_CHANGE_AUXILIARY_FAILED);
        r_ret = rs_install_change_type_to_string(INSTALL_CHANGE_AUXILIARY_FAILED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = install_change_type_from_string("masked");
        rv = rs_install_change_type_from_string("masked");
        assert_se(cv == rv);

        cv = install_change_type_from_string("bogus");
        rv = rs_install_change_type_from_string("bogus");
        assert_se(cv == rv);
}

/* ── unit_file_preset_mode ────────────────────────────────────────────── */

static void test_unit_file_preset_mode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = unit_file_preset_mode_to_string(UNIT_FILE_PRESET_FULL);
        r_ret = rs_unit_file_preset_mode_to_string(UNIT_FILE_PRESET_FULL);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = unit_file_preset_mode_to_string(UNIT_FILE_PRESET_DISABLE_ONLY);
        r_ret = rs_unit_file_preset_mode_to_string(UNIT_FILE_PRESET_DISABLE_ONLY);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = unit_file_preset_mode_from_string("enable-only");
        rv = rs_unit_file_preset_mode_from_string("enable-only");
        assert_se(cv == rv);
}

/* ── boot_entry_type ──────────────────────────────────────────────────── */

static void test_boot_entry_type(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = boot_entry_type_to_string(BOOT_ENTRY_TYPE1);
        r_ret = rs_boot_entry_type_to_string(BOOT_ENTRY_TYPE1);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = boot_entry_type_to_string(BOOT_ENTRY_AUTO);
        r_ret = rs_boot_entry_type_to_string(BOOT_ENTRY_AUTO);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = boot_entry_type_from_string("loader");
        rv = rs_boot_entry_type_from_string("loader");
        assert_se(cv == rv);

        cv = boot_entry_type_from_string("bogus");
        rv = rs_boot_entry_type_from_string("bogus");
        assert_se(cv == rv);
}

/* ── boot_entry_type_description (to_string only) ─────────────────────── */

static void test_boot_entry_type_description(void) {
        const char *c_ret, *r_ret;

        c_ret = boot_entry_type_description_to_string(BOOT_ENTRY_TYPE1);
        r_ret = rs_boot_entry_type_description_to_string(BOOT_ENTRY_TYPE1);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = boot_entry_type_description_to_string(BOOT_ENTRY_AUTO);
        r_ret = rs_boot_entry_type_description_to_string(BOOT_ENTRY_AUTO);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

/* ── boot_entry_source (to_string only) ───────────────────────────────── */

static void test_boot_entry_source(void) {
        const char *c_ret, *r_ret;

        c_ret = boot_entry_source_to_string(BOOT_ENTRY_ESP);
        r_ret = rs_boot_entry_source_to_string(BOOT_ENTRY_ESP);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = boot_entry_source_to_string(BOOT_ENTRY_XBOOTLDR);
        r_ret = rs_boot_entry_source_to_string(BOOT_ENTRY_XBOOTLDR);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

/* ── boot_entry_source_description (to_string only) ───────────────────── */

static void test_boot_entry_source_description(void) {
        const char *c_ret, *r_ret;

        c_ret = boot_entry_source_description_to_string(BOOT_ENTRY_ESP);
        r_ret = rs_boot_entry_source_description_to_string(BOOT_ENTRY_ESP);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = boot_entry_source_description_to_string(BOOT_ENTRY_XBOOTLDR);
        r_ret = rs_boot_entry_source_description_to_string(BOOT_ENTRY_XBOOTLDR);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

int main(int argc, char **argv) {
        test_dns_rcode();
        test_dns_protocol();
        test_dns_svc_param_key();
        test_dns_ede_rcode();
        test_dns_class();
        test_nfproto();
        test_nft_set_source();
        test_install_change_type();
        test_unit_file_preset_mode();
        test_boot_entry_type();
        test_boot_entry_type_description();
        test_boot_entry_source();
        test_boot_entry_source_description();
        return 0;
}
