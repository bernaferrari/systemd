/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: various header inline wrappers vs Rust */

#include <assert.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sysmacros.h>
#include "tests.h"
#include "in-addr-util.h"
#include "devnum-util.h"
#include "xattr-util.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "rust/misc_inline_abi.h"

/* Rust FFI — in_addr */
bool rs_in4_addr_is_set(const struct in_addr *a);
bool rs_in6_addr_is_set(const struct in6_addr *a);
bool rs_in_addr_is_set(int family, const union in_addr_union *u);
int rs_in_addr_data_is_null(const struct in_addr_data *a);
bool rs_in_addr_data_is_set(const struct in_addr_data *a);

/* ── in4_addr_is_set ──────────────────────────────────────────────────── */

static void test_in4_addr_is_set(void) {
        struct in_addr null_addr = { 0 };
        struct in_addr set_addr;
        set_addr.s_addr = 0x0100007f; /* 127.0.0.1 in network byte order */

        assert_se(in4_addr_is_set(&null_addr) == rs_in4_addr_is_set(&null_addr));
        assert_se(!in4_addr_is_set(&null_addr));
        assert_se(in4_addr_is_set(&set_addr) == rs_in4_addr_is_set(&set_addr));
        assert_se(in4_addr_is_set(&set_addr));
}

/* ── in6_addr_is_set ──────────────────────────────────────────────────── */

static void test_in6_addr_is_set(void) {
        struct in6_addr null_addr = { 0 };
        struct in6_addr set_addr = { .s6_addr = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };

        assert_se(in6_addr_is_set(&null_addr) == rs_in6_addr_is_set(&null_addr));
        assert_se(!in6_addr_is_set(&null_addr));
        assert_se(in6_addr_is_set(&set_addr) == rs_in6_addr_is_set(&set_addr));
}

/* ── in_addr_is_set ───────────────────────────────────────────────────── */

static void test_in_addr_is_set(void) {
        union in_addr_union u;

        memset(&u, 0, sizeof(u));
        u.in.s_addr = 0x0100007f;
        assert_se(in_addr_is_set(AF_INET, &u) == rs_in_addr_is_set(AF_INET, &u));

        memset(&u, 0, sizeof(u));
        assert_se(!in_addr_is_set(AF_INET, &u));
        assert_se(!rs_in_addr_is_set(AF_INET, &u));
}

/* ── in_addr_data_is_null / is_set ─────────────────────────────────────── */

static void test_in_addr_data_is_null(void) {
        struct in_addr_data d;
        memset(&d, 0, sizeof(d));

        /* Null address */
        d.family = AF_INET;
        assert_se(in_addr_data_is_null(&d) == rs_in_addr_data_is_null(&d));
        assert_se(in_addr_data_is_null(&d) != 0);

        /* Set address */
        d.address.in.s_addr = 0x0100007f;
        assert_se(in_addr_data_is_null(&d) == rs_in_addr_data_is_null(&d));
        assert_se(in_addr_data_is_null(&d) == 0);

        /* is_set returns in_addr_data_is_null (C quirk — matches C behavior) */
        assert_se(in_addr_data_is_set(&d) == rs_in_addr_data_is_set(&d));
}

/* ── devnum_is_zero ───────────────────────────────────────────────────── */

static void test_devnum_is_zero(void) {
        assert_se(devnum_is_zero(makedev(0, 0)) == rs_devnum_is_zero(makedev(0, 0)));
        assert_se(devnum_is_zero(makedev(0, 0)));
        assert_se(devnum_is_zero(makedev(1, 0)) == rs_devnum_is_zero(makedev(1, 0)));
        assert_se(!devnum_is_zero(makedev(1, 0)));
        assert_se(devnum_is_zero(makedev(0, 5)) == rs_devnum_is_zero(makedev(0, 5)));
}

/* ── devnum_set_and_equal ─────────────────────────────────────────────── */

static void test_devnum_set_and_equal(void) {
        dev_t a = makedev(7, 255);
        dev_t b = makedev(7, 255);
        dev_t c = makedev(0, 0);
        dev_t d = makedev(8, 0);

        assert_se(devnum_set_and_equal(a, b) == rs_devnum_set_and_equal(a, b));
        assert_se(devnum_set_and_equal(a, b));
        assert_se(devnum_set_and_equal(a, c) == rs_devnum_set_and_equal(a, c));
        assert_se(!devnum_set_and_equal(a, c));
        assert_se(devnum_set_and_equal(c, c) == rs_devnum_set_and_equal(c, c));
        assert_se(!devnum_set_and_equal(c, c)); /* both zero → false */
        assert_se(devnum_set_and_equal(a, d) == rs_devnum_set_and_equal(a, d));
}

/* ── xattr_is_acl ─────────────────────────────────────────────────────── */

static void test_xattr_is_acl(void) {
        assert_se(xattr_is_acl("system.posix_acl_access") == rs_xattr_is_acl("system.posix_acl_access"));
        assert_se(xattr_is_acl("system.posix_acl_default") == rs_xattr_is_acl("system.posix_acl_default"));
        assert_se(xattr_is_acl("security.selinux") == rs_xattr_is_acl("security.selinux"));
        assert_se(xattr_is_acl("user.foo") == rs_xattr_is_acl("user.foo"));
}

/* ── xattr_is_selinux ─────────────────────────────────────────────────── */

static void test_xattr_is_selinux(void) {
        assert_se(xattr_is_selinux("security.selinux") == rs_xattr_is_selinux("security.selinux"));
        assert_se(xattr_is_selinux("system.posix_acl_access") == rs_xattr_is_selinux("system.posix_acl_access"));
        assert_se(xattr_is_selinux("user.foo") == rs_xattr_is_selinux("user.foo"));
}

/* ── format_bytes ──────────────────────────────────────────────────────── */

static void test_format_bytes(void) {
        char c_buf[FORMAT_BYTES_MAX], rs_buf[FORMAT_BYTES_MAX];

        /* 500 bytes */
        assert_se(streq(format_bytes(c_buf, sizeof(c_buf), 500),
                           rs_format_bytes(rs_buf, sizeof(rs_buf), 500)));

        /* 1024 bytes = 1.0 KB */
        assert_se(streq(format_bytes(c_buf, sizeof(c_buf), 1024),
                           rs_format_bytes(rs_buf, sizeof(rs_buf), 1024)));

        /* 0 bytes */
        assert_se(streq(format_bytes(c_buf, sizeof(c_buf), 0),
                           rs_format_bytes(rs_buf, sizeof(rs_buf), 0)));

        /* 1500 bytes */
        assert_se(streq(format_bytes(c_buf, sizeof(c_buf), 1500),
                           rs_format_bytes(rs_buf, sizeof(rs_buf), 1500)));

        assert_se(format_bytes(c_buf, sizeof(c_buf), UINT64_MAX) == NULL);
        assert_se(rs_format_bytes(rs_buf, sizeof(rs_buf), UINT64_MAX) == NULL);
}

/* ── unhexmem ──────────────────────────────────────────────────────────── */

static void test_unhexmem(void) {
        void *c_data = NULL, *rs_data = NULL;
        size_t c_size = 0, rs_size = 0;
        int c_r, rs_r;

        c_r = unhexmem("48656c6c6f", &c_data, &c_size);
        rs_r = rs_unhexmem("48656c6c6f", &rs_data, &rs_size);
        assert_se(c_r == rs_r && c_r == 0);
        assert_se(c_size == rs_size && c_size == 5);
        assert_se(memcmp(c_data, rs_data, c_size) == 0);
        free(c_data); c_data = NULL;
        free(rs_data); rs_data = NULL;

        /* Invalid hex */
        c_r = unhexmem("ZZ", &c_data, &c_size);
        rs_r = rs_unhexmem("ZZ", &rs_data, &rs_size);
        assert_se(c_r == rs_r && c_r < 0);

        c_r = unhexmem("", &c_data, &c_size);
        rs_r = rs_unhexmem("", &rs_data, &rs_size);
        assert_se(c_r == rs_r && c_r == 0);
        assert_se(c_size == rs_size && c_size == 0);
        free(c_data); c_data = NULL;
        free(rs_data); rs_data = NULL;
}

/* ── base64mem ─────────────────────────────────────────────────────────── */

static void test_base64mem(void) {
        _cleanup_free_ char *c_out = NULL, *rs_out = NULL;
        ssize_t c_r, rs_r;
        const char *input = "Hello, World!";

        c_r = base64mem(input, strlen(input), &c_out);
        rs_r = rs_base64mem(input, strlen(input), &rs_out);
        assert_se(c_r == rs_r && c_r > 0);
        assert_se(streq(c_out, rs_out));

        free(c_out); c_out = NULL;
        free(rs_out); rs_out = NULL;
        c_r = base64mem(NULL, 0, &c_out);
        rs_r = rs_base64mem(NULL, 0, &rs_out);
        assert_se(c_r == rs_r && c_r == 0);
        assert_se(streq(c_out, rs_out));
}

/* ── unbase64mem ───────────────────────────────────────────────────────── */

static void test_unbase64mem(void) {
        void *c_data = NULL, *rs_data = NULL;
        size_t c_size = 0, rs_size = 0;
        int c_r, rs_r;

        c_r = unbase64mem("SGVsbG8sIFdvcmxkIQ==", &c_data, &c_size);
        rs_r = rs_unbase64mem("SGVsbG8sIFdvcmxkIQ==", &rs_data, &rs_size);
        assert_se(c_r == rs_r && c_r == 0);
        assert_se(c_size == rs_size && c_size == 13);
        assert_se(memcmp(c_data, rs_data, c_size) == 0);
        free(c_data); c_data = NULL;
        free(rs_data); rs_data = NULL;

        c_r = unbase64mem("YQ", &c_data, &c_size);
        rs_r = rs_unbase64mem("YQ", &rs_data, &rs_size);
        assert_se(c_r == rs_r && c_r < 0);
}

int main(int argc, char **argv) {
        test_in4_addr_is_set();
        test_in6_addr_is_set();
        test_in_addr_is_set();
        test_in_addr_data_is_null();
        test_devnum_is_zero();
        test_devnum_set_and_equal();
        test_xattr_is_acl();
        test_xattr_is_selinux();
        test_format_bytes();
        test_unhexmem();
        test_base64mem();
        test_unbase64mem();
        return 0;
}
