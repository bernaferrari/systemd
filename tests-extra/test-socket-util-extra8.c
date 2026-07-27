/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C vs Rust for sockaddr_ll_len, sockaddr_un_len, sockaddr_len,
 * sockaddr_un_set_path, socket_address_verify, socket_address_can_accept,
 * socket_address_get_path, socket_address_parse_unix, socket_address_parse_vsock,
 * socket_address_equal_unix */

#include <string.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/vm_sockets.h>

#include "tests.h"
#include "socket-util.h"
#include "rust/socket_util.h"

/* ── sockaddr_ll_len ─────────────────────────────────────────────────── */

static void test_sockaddr_ll_len_eth(void) {
        struct sockaddr_ll sa = {};

        sa.sll_family = AF_PACKET;
        sa.sll_hatype = htobe16(ARPHRD_ETHER);

        size_t cr = sockaddr_ll_len(&sa);
        size_t rr = rs_sockaddr_ll_len(&sa);
        assert_se(cr == rr);
}

static void test_sockaddr_ll_len_infiniband(void) {
        struct sockaddr_ll sa = {};

        sa.sll_family = AF_PACKET;
        sa.sll_hatype = htobe16(ARPHRD_INFINIBAND);

        size_t cr = sockaddr_ll_len(&sa);
        size_t rr = rs_sockaddr_ll_len(&sa);
        assert_se(cr == rr);
}

static void test_sockaddr_ll_len_default(void) {
        struct sockaddr_ll sa = {};

        sa.sll_family = AF_PACKET;
        sa.sll_hatype = htobe16(99); /* Unknown type */

        size_t cr = sockaddr_ll_len(&sa);
        size_t rr = rs_sockaddr_ll_len(&sa);
        assert_se(cr == rr);
}

/* ── sockaddr_un_len ─────────────────────────────────────────────────── */

static void test_sockaddr_un_len_filesystem(void) {
        struct sockaddr_un sa = {};

        sa.sun_family = AF_UNIX;
        strncpy(sa.sun_path, "/run/systemd/private", sizeof(sa.sun_path));

        size_t cr = sockaddr_un_len(&sa);
        size_t rr = rs_sockaddr_un_len(&sa);
        assert_se(cr == rr);
        assert_se(cr == offsetof(struct sockaddr_un, sun_path) + strlen("/run/systemd/private") + 1);
}

static void test_sockaddr_un_len_abstract(void) {
        struct sockaddr_un sa = {};

        sa.sun_family = AF_UNIX;
        sa.sun_path[0] = 0; /* Abstract */
        memcpy(sa.sun_path + 1, "test", 5); /* "test" without NUL */

        size_t cr = sockaddr_un_len(&sa);
        size_t rr = rs_sockaddr_un_len(&sa);
        assert_se(cr == rr);
        assert_se(cr == offsetof(struct sockaddr_un, sun_path) + 1 + 4); /* NUL + "test" */
}

static void test_sockaddr_un_len_abstract_nul(void) {
        struct sockaddr_un sa = {};

        sa.sun_family = AF_UNIX;
        sa.sun_path[0] = 0; /* Abstract */
        memcpy(sa.sun_path + 1, "test\0extra", 10); /* NUL-terminated within */

        size_t cr = sockaddr_un_len(&sa);
        size_t rr = rs_sockaddr_un_len(&sa);
        assert_se(cr == rr);
        assert_se(cr == offsetof(struct sockaddr_un, sun_path) + 1 + 4);
}

static void test_sockaddr_un_len_short(void) {
        struct sockaddr_un sa = {};

        sa.sun_family = AF_UNIX;
        sa.sun_path[0] = 'a';
        sa.sun_path[1] = 0;

        size_t cr = sockaddr_un_len(&sa);
        size_t rr = rs_sockaddr_un_len(&sa);
        assert_se(cr == rr);
        assert_se(cr == offsetof(struct sockaddr_un, sun_path) + 2);
}

/* ── sockaddr_len ────────────────────────────────────────────────────── */

static void test_sockaddr_len_inet(void) {
        union sockaddr_union sa = {};
        sa.in.sin_family = AF_INET;

        size_t cr = sockaddr_len(&sa);
        size_t rr = rs_sockaddr_len(&sa);
        assert_se(cr == rr);
}

static void test_sockaddr_len_inet6(void) {
        union sockaddr_union sa = {};
        sa.in6.sin6_family = AF_INET6;

        size_t cr = sockaddr_len(&sa);
        size_t rr = rs_sockaddr_len(&sa);
        assert_se(cr == rr);
}

static void test_sockaddr_len_unix(void) {
        union sockaddr_union sa = {};
        sa.un.sun_family = AF_UNIX;
        strncpy(sa.un.sun_path, "/tmp/test", sizeof(sa.un.sun_path));

        size_t cr = sockaddr_len(&sa);
        size_t rr = rs_sockaddr_len(&sa);
        assert_se(cr == rr);
}

static void test_sockaddr_len_netlink(void) {
        union sockaddr_union sa = {};
        sa.nl.nl_family = AF_NETLINK;

        size_t cr = sockaddr_len(&sa);
        size_t rr = rs_sockaddr_len(&sa);
        assert_se(cr == rr);
}

static void test_sockaddr_len_vsock(void) {
        union sockaddr_union sa = {};
        sa.vm.svm_family = AF_VSOCK;

        size_t cr = sockaddr_len(&sa);
        size_t rr = rs_sockaddr_len(&sa);
        assert_se(cr == rr);
}

/* ── sockaddr_un_set_path ────────────────────────────────────────────── */

static void test_sockaddr_un_set_path_filesystem(void) {
        struct sockaddr_un c_ret = {}, r_ret = {};
        int cr, rr;

        cr = sockaddr_un_set_path(&c_ret, "/run/systemd/private");
        rr = rs_sockaddr_un_set_path(&r_ret, "/run/systemd/private");
        assert_se(cr == rr);
        assert_se(cr > 0);
        assert_se(c_ret.sun_family == r_ret.sun_family);
        assert_se(strcmp(c_ret.sun_path, r_ret.sun_path) == 0);
}

static void test_sockaddr_un_set_path_abstract(void) {
        struct sockaddr_un c_ret = {}, r_ret = {};
        int cr, rr;

        cr = sockaddr_un_set_path(&c_ret, "@test_socket");
        rr = rs_sockaddr_un_set_path(&r_ret, "@test_socket");
        assert_se(cr == rr);
        assert_se(cr > 0);
        assert_se(c_ret.sun_family == r_ret.sun_family);
        assert_se(c_ret.sun_path[0] == 0); /* Abstract: NUL at start */
        assert_se(r_ret.sun_path[0] == 0);
        assert_se(memcmp(c_ret.sun_path, r_ret.sun_path, SUN_PATH_LEN) == 0);
}

static void test_sockaddr_un_set_path_too_short(void) {
        struct sockaddr_un ret = {};
        int rr;

        /* C has assert for path — only test Rust */
        rr = rs_sockaddr_un_set_path(&ret, "/");
        assert_se(rr < 0);
}

static void test_sockaddr_un_set_path_bad_prefix(void) {
        struct sockaddr_un ret = {};
        int rr;

        rr = rs_sockaddr_un_set_path(&ret, "relative/path");
        assert_se(rr < 0);

        rr = rs_sockaddr_un_set_path(&ret, "a");
        assert_se(rr < 0);
}

static void test_sockaddr_un_set_path_null(void) {
        struct sockaddr_un ret = {};
        /* C has assert(ret) and assert(path) — only test Rust */
        assert_se(rs_sockaddr_un_set_path(NULL, "/test") < 0);
        assert_se(rs_sockaddr_un_set_path(&ret, NULL) < 0);
}

/* ── socket_address_verify ───────────────────────────────────────────── */

static void test_socket_address_verify_inet_valid(void) {
        SocketAddress c_a = {}, r_a = {};

        c_a.sockaddr.in.sin_family = AF_INET;
        c_a.sockaddr.in.sin_port = htobe16(8080);
        c_a.size = sizeof(struct sockaddr_in);
        c_a.type = SOCK_STREAM;

        memcpy(&r_a, &c_a, sizeof(c_a));

        int cr = socket_address_verify(&c_a, false);
        int rr = rs_socket_address_verify(&r_a, false);
        assert_se(cr == rr);
}

static void test_socket_address_verify_inet_zero_port(void) {
        SocketAddress a = {};

        a.sockaddr.in.sin_family = AF_INET;
        a.sockaddr.in.sin_port = 0;
        a.size = sizeof(struct sockaddr_in);

        int cr = socket_address_verify(&a, false);
        int rr = rs_socket_address_verify(&a, false);
        assert_se(cr == rr);
}

static void test_socket_address_verify_inet_wrong_size(void) {
        SocketAddress a = {};

        a.sockaddr.in.sin_family = AF_INET;
        a.sockaddr.in.sin_port = htobe16(80);
        a.size = 99;

        int cr = socket_address_verify(&a, false);
        int rr = rs_socket_address_verify(&a, false);
        assert_se(cr == rr);
}

static void test_socket_address_verify_inet6_valid(void) {
        SocketAddress c_a = {}, r_a = {};

        c_a.sockaddr.in6.sin6_family = AF_INET6;
        c_a.sockaddr.in6.sin6_port = htobe16(443);
        c_a.size = sizeof(struct sockaddr_in6);
        c_a.type = SOCK_DGRAM;

        memcpy(&r_a, &c_a, sizeof(c_a));

        int cr = socket_address_verify(&c_a, false);
        int rr = rs_socket_address_verify(&r_a, false);
        assert_se(cr == rr);
}

static void test_socket_address_verify_unix_valid(void) {
        SocketAddress c_a = {}, r_a = {};

        c_a.sockaddr.un.sun_family = AF_UNIX;
        strncpy(c_a.sockaddr.un.sun_path, "/run/test", sizeof(c_a.sockaddr.un.sun_path));
        c_a.size = offsetof(struct sockaddr_un, sun_path) + 9; /* strlen("/run/test") + 1 */
        c_a.type = SOCK_STREAM;

        memcpy(&r_a, &c_a, sizeof(c_a));

        int cr = socket_address_verify(&c_a, false);
        int rr = rs_socket_address_verify(&r_a, false);
        assert_se(cr == rr);
}

static void test_socket_address_verify_unix_strict(void) {
        SocketAddress a = {};

        a.sockaddr.un.sun_family = AF_UNIX;
        strncpy(a.sockaddr.un.sun_path, "/run/test", sizeof(a.sockaddr.un.sun_path));
        a.size = offsetof(struct sockaddr_un, sun_path) + 9;
        a.type = SOCK_STREAM;

        int cr = socket_address_verify(&a, true);
        int rr = rs_socket_address_verify(&a, true);
        assert_se(cr == rr);
}

static void test_socket_address_verify_unix_too_large_strict(void) {
        SocketAddress a = {};

        a.sockaddr.un.sun_family = AF_UNIX;
        a.size = sizeof(struct sockaddr_un) + 2; /* Too large */
        a.type = SOCK_STREAM;

        int cr = socket_address_verify(&a, true);
        int rr = rs_socket_address_verify(&a, true);
        assert_se(cr == rr);
}

static void test_socket_address_verify_unix_ok_nonstrict_extra(void) {
        SocketAddress a = {};

        a.sockaddr.un.sun_family = AF_UNIX;
        a.size = sizeof(struct sockaddr_un) + 1; /* Allowed in non-strict */
        a.type = SOCK_STREAM;

        int cr = socket_address_verify(&a, false);
        int rr = rs_socket_address_verify(&a, false);
        assert_se(cr == rr);
}

static void test_socket_address_verify_netlink_valid(void) {
        SocketAddress c_a = {}, r_a = {};

        c_a.sockaddr.nl.nl_family = AF_NETLINK;
        c_a.size = sizeof(struct sockaddr_nl);
        c_a.type = SOCK_RAW;

        memcpy(&r_a, &c_a, sizeof(c_a));

        int cr = socket_address_verify(&c_a, false);
        int rr = rs_socket_address_verify(&r_a, false);
        assert_se(cr == rr);
}

static void test_socket_address_verify_vsock_valid(void) {
        SocketAddress c_a = {}, r_a = {};

        c_a.sockaddr.vm.svm_family = AF_VSOCK;
        c_a.sockaddr.vm.svm_cid = 3;
        c_a.sockaddr.vm.svm_port = 1234;
        c_a.size = sizeof(struct sockaddr_vm);
        c_a.type = SOCK_STREAM;

        memcpy(&r_a, &c_a, sizeof(c_a));

        int cr = socket_address_verify(&c_a, false);
        int rr = rs_socket_address_verify(&r_a, false);
        assert_se(cr == rr);
}

static void test_socket_address_verify_unsupported(void) {
        SocketAddress a = {};
        a.sockaddr.sa.sa_family = 99;

        int cr = socket_address_verify(&a, false);
        int rr = rs_socket_address_verify(&a, false);
        assert_se(cr == rr);
}

static void test_socket_address_verify_null(void) {
        /* C has assert(a) — only test Rust */
        assert_se(rs_socket_address_verify(NULL, false) < 0);
}

/* ── socket_address_can_accept ───────────────────────────────────────── */

static void test_socket_address_can_accept(void) {
        SocketAddress a = {};

        a.type = SOCK_STREAM;
        bool cr = socket_address_can_accept(&a);
        bool rr = rs_socket_address_can_accept(&a);
        assert_se(cr == rr);
        assert_se(cr == true);

        a.type = SOCK_SEQPACKET;
        cr = socket_address_can_accept(&a);
        rr = rs_socket_address_can_accept(&a);
        assert_se(cr == rr);
        assert_se(cr == true);

        a.type = SOCK_DGRAM;
        cr = socket_address_can_accept(&a);
        rr = rs_socket_address_can_accept(&a);
        assert_se(cr == rr);
        assert_se(cr == false);

        a.type = 0;
        cr = socket_address_can_accept(&a);
        rr = rs_socket_address_can_accept(&a);
        assert_se(cr == rr);
        assert_se(cr == false);
}

/* ── socket_address_get_path ─────────────────────────────────────────── */

static void test_socket_address_get_path_unix(void) {
        SocketAddress a = {};

        a.sockaddr.un.sun_family = AF_UNIX;
        strncpy(a.sockaddr.un.sun_path, "/run/test.sock", sizeof(a.sockaddr.un.sun_path));

        const char *cr = socket_address_get_path(&a);
        const char *rr = rs_socket_address_get_path(&a);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(strcmp(cr, rr) == 0);
}

static void test_socket_address_get_path_abstract(void) {
        SocketAddress a = {};

        a.sockaddr.un.sun_family = AF_UNIX;
        a.sockaddr.un.sun_path[0] = 0; /* Abstract */

        const char *cr = socket_address_get_path(&a);
        const char *rr = rs_socket_address_get_path(&a);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

static void test_socket_address_get_path_inet(void) {
        SocketAddress a = {};
        a.sockaddr.in.sin_family = AF_INET;

        const char *cr = socket_address_get_path(&a);
        const char *rr = rs_socket_address_get_path(&a);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

static void test_socket_address_get_path_null(void) {
        /* C has assert(a) — only test Rust */
        assert_se(rs_socket_address_get_path(NULL) == NULL);
}

/* ── socket_address_parse_unix ───────────────────────────────────────── */

static void test_socket_address_parse_unix_filesystem(void) {
        SocketAddress c_a = {}, r_a = {};
        int cr, rr;

        cr = socket_address_parse_unix(&c_a, "/run/systemd/private");
        rr = rs_socket_address_parse_unix(&r_a, "/run/systemd/private");
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(c_a.size == r_a.size);
        assert_se(c_a.sockaddr.un.sun_family == r_a.sockaddr.un.sun_family);
        assert_se(strcmp(c_a.sockaddr.un.sun_path, r_a.sockaddr.un.sun_path) == 0);
}

static void test_socket_address_parse_unix_abstract(void) {
        SocketAddress c_a = {}, r_a = {};
        int cr, rr;

        cr = socket_address_parse_unix(&c_a, "@abstract_socket");
        rr = rs_socket_address_parse_unix(&r_a, "@abstract_socket");
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(c_a.size == r_a.size);
        assert_se(memcmp(&c_a.sockaddr.un, &r_a.sockaddr.un, sizeof(struct sockaddr_un)) == 0);
}

static void test_socket_address_parse_unix_bad_prefix(void) {
        SocketAddress a = {};
        int cr, rr;

        cr = socket_address_parse_unix(&a, "relative");
        rr = rs_socket_address_parse_unix(&a, "relative");
        assert_se(cr == rr);
        assert_se(cr < 0);
}

static void test_socket_address_parse_unix_null(void) {
        SocketAddress a = {};
        /* C has assert — only test Rust */
        assert_se(rs_socket_address_parse_unix(NULL, "/test") < 0);
        assert_se(rs_socket_address_parse_unix(&a, NULL) < 0);
}

/* ── socket_address_parse_vsock ──────────────────────────────────────── */

static void test_socket_address_parse_vsock_basic(void) {
        SocketAddress c_a = {}, r_a = {};
        int cr, rr;

        cr = socket_address_parse_vsock(&c_a, "vsock:3:1234");
        rr = rs_socket_address_parse_vsock(&r_a, "vsock:3:1234");
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(c_a.size == r_a.size);
        assert_se(c_a.type == r_a.type);
        assert_se(c_a.sockaddr.vm.svm_family == r_a.sockaddr.vm.svm_family);
        assert_se(c_a.sockaddr.vm.svm_cid == r_a.sockaddr.vm.svm_cid);
        assert_se(c_a.sockaddr.vm.svm_port == r_a.sockaddr.vm.svm_port);
}

static void test_socket_address_parse_vsock_dgram(void) {
        SocketAddress c_a = {}, r_a = {};
        int cr, rr;

        cr = socket_address_parse_vsock(&c_a, "vsock-dgram:host:8080");
        rr = rs_socket_address_parse_vsock(&r_a, "vsock-dgram:host:8080");
        assert_se(cr == rr);
        assert_se(c_a.size == r_a.size);
        assert_se(c_a.type == r_a.type);
        assert_se(c_a.sockaddr.vm.svm_cid == r_a.sockaddr.vm.svm_cid);
        assert_se(c_a.sockaddr.vm.svm_port == r_a.sockaddr.vm.svm_port);
}

static void test_socket_address_parse_vsock_seqpacket(void) {
        SocketAddress c_a = {}, r_a = {};
        int cr, rr;

        cr = socket_address_parse_vsock(&c_a, "vsock-seqpacket:2:9999");
        rr = rs_socket_address_parse_vsock(&r_a, "vsock-seqpacket:2:9999");
        assert_se(cr == rr);
        assert_se(c_a.type == r_a.type);
}

static void test_socket_address_parse_vsock_stream(void) {
        SocketAddress c_a = {}, r_a = {};
        int cr, rr;

        cr = socket_address_parse_vsock(&c_a, "vsock-stream:local:22");
        rr = rs_socket_address_parse_vsock(&r_a, "vsock-stream:local:22");
        assert_se(cr == rr);
        assert_se(c_a.type == r_a.type);
        assert_se(c_a.sockaddr.vm.svm_cid == r_a.sockaddr.vm.svm_cid);
}

static void test_socket_address_parse_vsock_any_cid(void) {
        SocketAddress c_a = {}, r_a = {};
        int cr, rr;

        cr = socket_address_parse_vsock(&c_a, "vsock::1234");
        rr = rs_socket_address_parse_vsock(&r_a, "vsock::1234");
        assert_se(cr == rr);
        assert_se(c_a.sockaddr.vm.svm_cid == r_a.sockaddr.vm.svm_cid);
        assert_se(c_a.sockaddr.vm.svm_port == r_a.sockaddr.vm.svm_port);
}

static void test_socket_address_parse_vsock_bad_prefix(void) {
        SocketAddress a = {};
        int cr, rr;

        cr = socket_address_parse_vsock(&a, "tcp:1:2");
        rr = rs_socket_address_parse_vsock(&a, "tcp:1:2");
        assert_se(cr == rr);
        assert_se(cr < 0);
}

static void test_socket_address_parse_vsock_no_colon(void) {
        SocketAddress a = {};
        int cr, rr;

        cr = socket_address_parse_vsock(&a, "vsock:1234");
        rr = rs_socket_address_parse_vsock(&a, "vsock:1234");
        assert_se(cr == rr);
        assert_se(cr < 0);
}

static void test_socket_address_parse_vsock_null(void) {
        SocketAddress a = {};
        /* C has assert — only test Rust */
        assert_se(rs_socket_address_parse_vsock(NULL, "vsock:1:2") < 0);
        assert_se(rs_socket_address_parse_vsock(&a, NULL) < 0);
}

/* ── socket_address_equal_unix ───────────────────────────────────────── */
/* Note: sockaddr_equal() returns false for AF_UNIX, so socket_address_equal_unix()
 * always returns 0 (false) for any two unix socket paths. This is a known
 * limitation — the union-level comparison doesn't handle AF_UNIX. */

static void test_socket_address_equal_unix_same_fs(void) {
        int cr, rr;

        cr = socket_address_equal_unix("/run/test.sock", "/run/test.sock");
        rr = rs_socket_address_equal_unix("/run/test.sock", "/run/test.sock");
        assert_se(cr == rr);
}

static void test_socket_address_equal_unix_different_fs(void) {
        int cr, rr;

        cr = socket_address_equal_unix("/run/a.sock", "/run/b.sock");
        rr = rs_socket_address_equal_unix("/run/a.sock", "/run/b.sock");
        assert_se(cr == rr);
}

static void test_socket_address_equal_unix_same_abstract(void) {
        int cr, rr;

        cr = socket_address_equal_unix("@test", "@test");
        rr = rs_socket_address_equal_unix("@test", "@test");
        assert_se(cr == rr);
}

static void test_socket_address_equal_unix_diff_abstract(void) {
        int cr, rr;

        cr = socket_address_equal_unix("@test1", "@test2");
        rr = rs_socket_address_equal_unix("@test1", "@test2");
        assert_se(cr == rr);
}

static void test_socket_address_equal_unix_fs_vs_abstract(void) {
        int cr, rr;

        cr = socket_address_equal_unix("/test", "@test");
        rr = rs_socket_address_equal_unix("/test", "@test");
        assert_se(cr == rr);
}

static void test_socket_address_equal_unix_null(void) {
        /* C has assert — only test Rust */
        assert_se(rs_socket_address_equal_unix(NULL, "/test") < 0);
        assert_se(rs_socket_address_equal_unix("/test", NULL) < 0);
}

int main(int argc, char **argv) {
        test_sockaddr_ll_len_eth();
        test_sockaddr_ll_len_infiniband();
        test_sockaddr_ll_len_default();
        test_sockaddr_un_len_filesystem();
        test_sockaddr_un_len_abstract();
        test_sockaddr_un_len_abstract_nul();
        test_sockaddr_un_len_short();
        test_sockaddr_len_inet();
        test_sockaddr_len_inet6();
        test_sockaddr_len_unix();
        test_sockaddr_len_netlink();
        test_sockaddr_len_vsock();
        test_sockaddr_un_set_path_filesystem();
        test_sockaddr_un_set_path_abstract();
        test_sockaddr_un_set_path_too_short();
        test_sockaddr_un_set_path_bad_prefix();
        test_sockaddr_un_set_path_null();
        test_socket_address_verify_inet_valid();
        test_socket_address_verify_inet_zero_port();
        test_socket_address_verify_inet_wrong_size();
        test_socket_address_verify_inet6_valid();
        test_socket_address_verify_unix_valid();
        test_socket_address_verify_unix_strict();
        test_socket_address_verify_unix_too_large_strict();
        test_socket_address_verify_unix_ok_nonstrict_extra();
        test_socket_address_verify_netlink_valid();
        test_socket_address_verify_vsock_valid();
        test_socket_address_verify_unsupported();
        test_socket_address_verify_null();
        test_socket_address_can_accept();
        test_socket_address_get_path_unix();
        test_socket_address_get_path_abstract();
        test_socket_address_get_path_inet();
        test_socket_address_get_path_null();
        test_socket_address_parse_unix_filesystem();
        test_socket_address_parse_unix_abstract();
        test_socket_address_parse_unix_bad_prefix();
        test_socket_address_parse_unix_null();
        test_socket_address_parse_vsock_basic();
        test_socket_address_parse_vsock_dgram();
        test_socket_address_parse_vsock_seqpacket();
        test_socket_address_parse_vsock_stream();
        test_socket_address_parse_vsock_any_cid();
        test_socket_address_parse_vsock_bad_prefix();
        test_socket_address_parse_vsock_no_colon();
        test_socket_address_parse_vsock_null();
        test_socket_address_equal_unix_same_fs();
        test_socket_address_equal_unix_different_fs();
        test_socket_address_equal_unix_same_abstract();
        test_socket_address_equal_unix_diff_abstract();
        test_socket_address_equal_unix_fs_vs_abstract();
        test_socket_address_equal_unix_null();

        return 0;
}
