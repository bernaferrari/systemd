/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "tests.h"
#include "ether-addr-util.h"

/* Rust FFI */
#include "rust/ether_addr_util.h"

/* Helpers: copy C ether_addr to Rust format */
static void ether_to_rs(const struct ether_addr *c, struct rs_ether_addr *r) {
        memcpy(r->octet, c->ether_addr_octet, 6);
}

static void ether_from_rs(const struct rs_ether_addr *r, struct ether_addr *c) {
        memcpy(c->ether_addr_octet, r->octet, 6);
}

/* Helpers: copy C hw_addr_data to Rust format */
static void hw_to_rs(const struct hw_addr_data *c, struct rs_hw_addr_data *r) {
        r->length = c->length;
        memcpy(r->bytes, c->bytes, c->length);
}

/* RUST-CONTRACT: hw-addr-format */
/* ── hw_addr_to_string_full ──────────────────────────────────────────── */

TEST(hw_addr_to_string_colon) {
        struct hw_addr_data c_addr = {
                .length = 6,
                .bytes = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
        };
        struct rs_hw_addr_data r_addr;
        hw_to_rs(&c_addr, &r_addr);

        char c_buf[3 * 32], r_buf[3 * 32];
        char *c_s = hw_addr_to_string_full(&c_addr, 0, c_buf);
        char *r_s = rs_hw_addr_to_string_full(&r_addr, 0, r_buf);

        assert_se(streq(c_s, r_s));
}

TEST(hw_addr_to_string_no_colon) {
        struct hw_addr_data c_addr = {
                .length = 6,
                .bytes = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
        };
        struct rs_hw_addr_data r_addr;
        hw_to_rs(&c_addr, &r_addr);

        char c_buf[3 * 32], r_buf[3 * 32];
        char *c_s = hw_addr_to_string_full(&c_addr, 1 << 0, c_buf);
        char *r_s = rs_hw_addr_to_string_full(&r_addr, 1 << 0, r_buf);

        assert_se(streq(c_s, r_s));
}

TEST(hw_addr_to_string_empty) {
        struct hw_addr_data c_addr = { .length = 0 };
        struct rs_hw_addr_data r_addr;
        hw_to_rs(&c_addr, &r_addr);

        char c_buf[3 * 32], r_buf[3 * 32];
        char *c_s = hw_addr_to_string_full(&c_addr, 0, c_buf);
        char *r_s = rs_hw_addr_to_string_full(&r_addr, 0, r_buf);

        assert_se(streq(c_s, r_s));
}

TEST(hw_addr_to_string_infiniband) {
        /* 20 bytes = INFINIBAND_ALEN */
        struct hw_addr_data c_addr = { .length = 20 };
        struct rs_hw_addr_data r_addr;
        for (int i = 0; i < 20; i++) {
                c_addr.bytes[i] = (uint8_t)(i * 0x11);
                r_addr.bytes[i] = (uint8_t)(i * 0x11);
        }
        r_addr.length = 20;

        char c_buf[3 * 32], r_buf[3 * 32];
        char *c_s = hw_addr_to_string_full(&c_addr, 0, c_buf);
        char *r_s = rs_hw_addr_to_string_full(&r_addr, 0, r_buf);

        assert_se(streq(c_s, r_s));
}

/* RUST-CONTRACT: ether-addr-format */
/* ── ether_addr_to_string ────────────────────────────────────────────── */

TEST(ether_addr_to_string_basic) {
        struct ether_addr c_addr = {
                .ether_addr_octet = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
        };
        struct rs_ether_addr r_addr;
        ether_to_rs(&c_addr, &r_addr);

        char c_buf[18], r_buf[18];
        char *c_s = ether_addr_to_string(&c_addr, c_buf);
        char *r_s = rs_ether_addr_to_string(&r_addr, r_buf);

        assert_se(streq(c_s, r_s));
}

TEST(ether_addr_to_string_zero) {
        struct ether_addr c_addr = {0};
        struct rs_ether_addr r_addr = {0};

        char c_buf[18], r_buf[18];
        char *c_s = ether_addr_to_string(&c_addr, c_buf);
        char *r_s = rs_ether_addr_to_string(&r_addr, r_buf);

        assert_se(streq(c_s, r_s));
}

TEST(ether_addr_to_string_broadcast) {
        struct ether_addr c_addr;
        memset(&c_addr, 0xff, sizeof(c_addr));
        struct rs_ether_addr r_addr;
        memset(&r_addr, 0xff, sizeof(r_addr));

        char c_buf[18], r_buf[18];
        char *c_s = ether_addr_to_string(&c_addr, c_buf);
        char *r_s = rs_ether_addr_to_string(&r_addr, r_buf);

        assert_se(streq(c_s, r_s));
}

/* RUST-CONTRACT: hw-addr-compare */
/* ── hw_addr_compare ─────────────────────────────────────────────────── */

TEST(hw_addr_compare_equal) {
        struct hw_addr_data ca = { .length = 6, .bytes = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66} };
        struct hw_addr_data cb = { .length = 6, .bytes = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66} };
        struct rs_hw_addr_data ra, rb;
        hw_to_rs(&ca, &ra);
        hw_to_rs(&cb, &rb);

        assert_se(hw_addr_compare(&ca, &cb) == rs_hw_addr_compare(&ra, &rb));
        assert_se(hw_addr_compare(&ca, &cb) == 0);
}

TEST(hw_addr_compare_less) {
        struct hw_addr_data ca = { .length = 6, .bytes = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66} };
        struct hw_addr_data cb = { .length = 6, .bytes = {0x22, 0x22, 0x33, 0x44, 0x55, 0x66} };
        struct rs_hw_addr_data ra, rb;
        hw_to_rs(&ca, &ra);
        hw_to_rs(&cb, &rb);

        int cr = hw_addr_compare(&ca, &cb);
        int rr = rs_hw_addr_compare(&ra, &rb);
        assert_se((cr < 0) == (rr < 0));
}

TEST(hw_addr_compare_length) {
        struct hw_addr_data ca = { .length = 4, .bytes = {0x11, 0x22, 0x33, 0x44} };
        struct hw_addr_data cb = { .length = 6, .bytes = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66} };
        struct rs_hw_addr_data ra, rb;
        hw_to_rs(&ca, &ra);
        hw_to_rs(&cb, &rb);

        int cr = hw_addr_compare(&ca, &cb);
        int rr = rs_hw_addr_compare(&ra, &rb);
        assert_se((cr < 0) == (rr < 0));
}

/* RUST-CONTRACT: ether-addr-compare */
/* ── ether_addr_compare ──────────────────────────────────────────────── */

TEST(ether_addr_compare_equal) {
        struct ether_addr ca = { .ether_addr_octet = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01} };
        struct ether_addr cb = { .ether_addr_octet = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01} };
        struct rs_ether_addr ra, rb;
        ether_to_rs(&ca, &ra);
        ether_to_rs(&cb, &rb);

        assert_se(ether_addr_compare(&ca, &cb) == rs_ether_addr_compare(&ra, &rb));
        assert_se(ether_addr_compare(&ca, &cb) == 0);
}

TEST(ether_addr_compare_different) {
        struct ether_addr ca = { .ether_addr_octet = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01} };
        struct ether_addr cb = { .ether_addr_octet = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02} };
        struct rs_ether_addr ra, rb;
        ether_to_rs(&ca, &ra);
        ether_to_rs(&cb, &rb);

        int cr = ether_addr_compare(&ca, &cb);
        int rr = rs_ether_addr_compare(&ra, &rb);
        assert_se((cr < 0) == (rr < 0));
}

/* RUST-CONTRACT: hw-addr-null */
/* ── hw_addr_is_null ─────────────────────────────────────────────────── */

TEST(hw_addr_is_null_empty) {
        struct hw_addr_data c = { .length = 0 };
        struct rs_hw_addr_data r = { .length = 0 };

        assert_se(hw_addr_is_null(&c) == rs_hw_addr_is_null(&r));
        assert_se(hw_addr_is_null(&c));
}

TEST(hw_addr_is_null_zeros) {
        struct hw_addr_data c = { .length = 6 };
        memset(c.bytes, 0, 6);
        struct rs_hw_addr_data r = { .length = 6 };
        memset(r.bytes, 0, 6);

        assert_se(hw_addr_is_null(&c) == rs_hw_addr_is_null(&r));
        assert_se(hw_addr_is_null(&c));
}

TEST(hw_addr_is_null_nonzero) {
        struct hw_addr_data c = { .length = 6, .bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01} };
        struct rs_hw_addr_data r = { .length = 6, .bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01} };

        assert_se(hw_addr_is_null(&c) == rs_hw_addr_is_null(&r));
        assert_se(!hw_addr_is_null(&c));
}

/* RUST-CONTRACT: ether-addr-broadcast */
/* ── ether_addr_is_broadcast ─────────────────────────────────────────── */

TEST(ether_addr_is_broadcast_yes) {
        struct ether_addr c;
        memset(&c, 0xff, sizeof(c));
        struct rs_ether_addr r;
        memset(&r, 0xff, sizeof(r));

        assert_se(ether_addr_is_broadcast(&c) == rs_ether_addr_is_broadcast(&r));
        assert_se(ether_addr_is_broadcast(&c));
}

TEST(ether_addr_is_broadcast_no) {
        struct ether_addr c = { .ether_addr_octet = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01} };
        struct rs_ether_addr r = { .octet = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01} };

        assert_se(ether_addr_is_broadcast(&c) == rs_ether_addr_is_broadcast(&r));
        assert_se(!ether_addr_is_broadcast(&c));
}

/* RUST-CONTRACT: ether-addr-randomize */
/* ── ether_addr_mark_random ──────────────────────────────────────────── */

TEST(ether_addr_mark_random_basic) {
        struct ether_addr c = { .ether_addr_octet = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01} };
        struct rs_ether_addr r = { .octet = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01} };

        ether_addr_mark_random(&c);
        rs_ether_addr_mark_random(&r);

        assert_se(c.ether_addr_octet[0] == r.octet[0]);
        /* First byte: clear multicast bit, set local bit */
        assert_se((c.ether_addr_octet[0] & 0x01) == 0);
        assert_se((c.ether_addr_octet[0] & 0x02) != 0);
        assert_se((r.octet[0] & 0x01) == 0);
        assert_se((r.octet[0] & 0x02) != 0);

        /* Rest unchanged */
        for (int i = 1; i < 6; i++)
                assert_se(c.ether_addr_octet[i] == r.octet[i]);
}

TEST(ether_addr_mark_random_already_local) {
        struct ether_addr c = { .ether_addr_octet = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee} };
        struct rs_ether_addr r = { .octet = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee} };

        ether_addr_mark_random(&c);
        rs_ether_addr_mark_random(&r);

        assert_se(c.ether_addr_octet[0] == r.octet[0]);
}

/* RUST-CONTRACT: hw-addr-set */
/* ── hw_addr_set ─────────────────────────────────────────────────────── */

TEST(hw_addr_set_basic) {
        uint8_t data[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

        struct hw_addr_data c;
        memset(&c, 0, sizeof(c));
        struct rs_hw_addr_data r;
        memset(&r, 0, sizeof(r));

        hw_addr_set(&c, data, 6);
        rs_hw_addr_set(&r, data, 6);

        assert_se(c.length == r.length);
        assert_se(c.length == 6);
        assert_se(memcmp(c.bytes, r.bytes, 6) == 0);
}

TEST(hw_addr_set_empty) {
        struct hw_addr_data c;
        memset(&c, 0xff, sizeof(c));
        struct rs_hw_addr_data r;
        memset(&r, 0xff, sizeof(r));

        hw_addr_set(&c, NULL, 0);
        rs_hw_addr_set(&r, NULL, 0);

        assert_se(c.length == 0);
        assert_se(r.length == 0);
}

/* RUST-CONTRACT: address-parsers */
/* ── parse_ether_addr ────────────────────────────────────────────────── */

TEST(parse_ether_addr_colon) {
        const char *s = "de:ad:be:ef:00:01";
        struct ether_addr c_ret;
        struct rs_ether_addr r_ret;

        int cr = parse_ether_addr(s, &c_ret);
        int rr = rs_parse_ether_addr(s, &r_ret);

        assert_se(cr == rr);
        assert_se(cr >= 0);
        assert_se(memcmp(c_ret.ether_addr_octet, r_ret.octet, 6) == 0);
        assert_se(c_ret.ether_addr_octet[0] == 0xde);
        assert_se(c_ret.ether_addr_octet[5] == 0x01);
}

TEST(parse_ether_addr_hyphen) {
        const char *s = "DE-AD-BE-EF-00-01";
        struct ether_addr c_ret;
        struct rs_ether_addr r_ret;

        int cr = parse_ether_addr(s, &c_ret);
        int rr = rs_parse_ether_addr(s, &r_ret);

        assert_se(cr == rr);
        assert_se(cr >= 0);
        assert_se(memcmp(c_ret.ether_addr_octet, r_ret.octet, 6) == 0);
}

TEST(parse_ether_addr_dot) {
        const char *s = "dead.beef.0001";
        struct ether_addr c_ret;
        struct rs_ether_addr r_ret;

        int cr = parse_ether_addr(s, &c_ret);
        int rr = rs_parse_ether_addr(s, &r_ret);

        assert_se(cr == rr);
        assert_se(cr >= 0);
        assert_se(memcmp(c_ret.ether_addr_octet, r_ret.octet, 6) == 0);
}

TEST(parse_ether_addr_invalid) {
        /* Wrong number of bytes */
        const char *s = "de:ad:be:ef";
        struct ether_addr c_ret;
        struct rs_ether_addr r_ret;

        int cr = parse_ether_addr(s, &c_ret);
        int rr = rs_parse_ether_addr(s, &r_ret);

        assert_se(cr == rr);
        assert_se(cr < 0);
}

TEST(parse_address_non_utf8_keeps_outputs) {
        static const char invalid[] = { (char) 0xff, 0 };
        struct ether_addr c_ether = { .ether_addr_octet = { 1, 2, 3, 4, 5, 6 } };
        struct rs_ether_addr r_ether = { .octet = { 1, 2, 3, 4, 5, 6 } };
        struct hw_addr_data c_hw = { .length = 6, .bytes = { 1, 2, 3, 4, 5, 6 } };
        struct rs_hw_addr_data r_hw = { .length = 6, .bytes = { 1, 2, 3, 4, 5, 6 } };

        assert_se(parse_ether_addr(invalid, &c_ether) == rs_parse_ether_addr(invalid, &r_ether));
        assert_se(memcmp(c_ether.ether_addr_octet, r_ether.octet, 6) == 0);
        assert_se(parse_hw_addr_full(invalid, 0, &c_hw) == rs_parse_hw_addr_full(invalid, 0, &r_hw));
        assert_se(c_hw.length == r_hw.length && memcmp(c_hw.bytes, r_hw.bytes, c_hw.length) == 0);
}

/* ── parse_hw_addr_full ──────────────────────────────────────────────── */

TEST(parse_hw_addr_full_auto_colon) {
        const char *s = "de:ad:be:ef:00:01";
        struct hw_addr_data c_ret;
        struct rs_hw_addr_data r_ret;

        int cr = parse_hw_addr_full(s, 0, &c_ret);
        int rr = rs_parse_hw_addr_full(s, 0, &r_ret);

        assert_se(cr == rr);
        assert_se(cr >= 0);
        assert_se(c_ret.length == r_ret.length);
        assert_se(c_ret.length == 6);
        assert_se(memcmp(c_ret.bytes, r_ret.bytes, 6) == 0);
}

TEST(parse_hw_addr_full_auto_ipv4) {
        const char *s = "192.168.1.1";
        struct hw_addr_data c_ret;
        struct rs_hw_addr_data r_ret;

        int cr = parse_hw_addr_full(s, 0, &c_ret);
        int rr = rs_parse_hw_addr_full(s, 0, &r_ret);

        assert_se(cr == rr);
        assert_se(cr >= 0);
        assert_se(c_ret.length == r_ret.length);
        assert_se(c_ret.length == 4);
        assert_se(memcmp(c_ret.bytes, r_ret.bytes, 4) == 0);
}

TEST(parse_hw_addr_full_expected_len) {
        const char *s = "de:ad:be:ef:00:01";
        struct hw_addr_data c_ret;
        struct rs_hw_addr_data r_ret;

        int cr = parse_hw_addr_full(s, 6, &c_ret);
        int rr = rs_parse_hw_addr_full(s, 6, &r_ret);

        assert_se(cr == rr);
        assert_se(cr >= 0);
        assert_se(c_ret.length == 6);
}

TEST(parse_hw_addr_full_wrong_len) {
        const char *s = "de:ad:be:ef:00:01";
        struct hw_addr_data c_ret;
        struct rs_hw_addr_data r_ret;

        int cr = parse_hw_addr_full(s, 4, &c_ret);
        int rr = rs_parse_hw_addr_full(s, 4, &r_ret);

        assert_se(cr == rr);
        assert_se(cr < 0);
}

TEST(parse_hw_addr_full_dot_format) {
        const char *s = "dead.beef.0001";
        struct hw_addr_data c_ret;
        struct rs_hw_addr_data r_ret;

        int cr = parse_hw_addr_full(s, 0, &c_ret);
        int rr = rs_parse_hw_addr_full(s, 0, &r_ret);

        assert_se(cr == rr);
        assert_se(cr >= 0);
        assert_se(c_ret.length == 6);
        assert_se(memcmp(c_ret.bytes, r_ret.bytes, 6) == 0);
}

TEST(parse_hw_addr_full_invalid_sep) {
        const char *s = "de/ad/be/ef/00/01";
        struct hw_addr_data c_ret;
        struct rs_hw_addr_data r_ret;

        int cr = parse_hw_addr_full(s, 0, &c_ret);
        int rr = rs_parse_hw_addr_full(s, 0, &r_ret);

        assert_se(cr == rr);
        assert_se(cr < 0);
}

/* RUST-CONTRACT: ether-addr-equality-and-null */
/* ── ether_addr_equal ─────────────────────────────────────────────────── */

TEST(ether_addr_equal_same) {
        struct ether_addr ca = { .ether_addr_octet = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01} };
        struct ether_addr cb = { .ether_addr_octet = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01} };
        struct rs_ether_addr ra, rb;
        ether_to_rs(&ca, &ra);
        ether_to_rs(&cb, &rb);

        assert_se(ether_addr_equal(&ca, &cb) == rs_ether_addr_equal(&ra, &rb));
        assert_se(ether_addr_equal(&ca, &cb));
}

TEST(ether_addr_equal_different) {
        struct ether_addr ca = { .ether_addr_octet = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01} };
        struct ether_addr cb = { .ether_addr_octet = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x02} };
        struct rs_ether_addr ra, rb;
        ether_to_rs(&ca, &ra);
        ether_to_rs(&cb, &rb);

        assert_se(ether_addr_equal(&ca, &cb) == rs_ether_addr_equal(&ra, &rb));
        assert_se(!ether_addr_equal(&ca, &cb));
}

/* ── ether_addr_is_null ──────────────────────────────────────────────── */

TEST(ether_addr_is_null_yes) {
        struct ether_addr c = {0};
        struct rs_ether_addr r = {0};

        assert_se(ether_addr_is_null(&c) == rs_ether_addr_is_null(&r));
        assert_se(ether_addr_is_null(&c));
}

TEST(ether_addr_is_null_no) {
        struct ether_addr c = { .ether_addr_octet = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01} };
        struct rs_ether_addr r = { .octet = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01} };

        assert_se(ether_addr_is_null(&c) == rs_ether_addr_is_null(&r));
        assert_se(!ether_addr_is_null(&c));
}

/* RUST-CONTRACT: ether-addr-multicast */
/* ── ether_addr_is_multicast / is_unicast ────────────────────────────── */

TEST(ether_addr_is_multicast_yes) {
        /* 01:00:5e:00:00:01 — multicast */
        struct ether_addr c = { .ether_addr_octet = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x01} };
        struct rs_ether_addr r = { .octet = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x01} };
        struct ether_addr cr;

        assert_se(ether_addr_is_multicast(&c) == rs_ether_addr_is_multicast(&r));
        assert_se(ether_addr_is_multicast(&c));
        assert_se(!ether_addr_is_unicast(&c));
        ether_from_rs(&r, &cr);
        assert_se(!ether_addr_is_unicast(&cr));
}

TEST(ether_addr_is_multicast_no) {
        /* fe:ff:ff:ff:ff:ff — not multicast */
        struct ether_addr c = { .ether_addr_octet = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff} };
        struct rs_ether_addr r = { .octet = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff} };
        struct ether_addr cr;

        assert_se(ether_addr_is_multicast(&c) == rs_ether_addr_is_multicast(&r));
        assert_se(!ether_addr_is_multicast(&c));
        assert_se(ether_addr_is_unicast(&c));
        ether_from_rs(&r, &cr);
        assert_se(ether_addr_is_unicast(&cr));
        assert_se(rs_ether_addr_is_unicast(&r));
}

/* RUST-CONTRACT: ether-addr-locality */
/* ── ether_addr_is_local / is_global ─────────────────────────────────── */

TEST(ether_addr_is_local_yes) {
        /* 02:aa:bb:cc:dd:ee — locally assigned */
        struct ether_addr c = { .ether_addr_octet = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee} };
        struct rs_ether_addr r = { .octet = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee} };

        assert_se(ether_addr_is_local(&c) == rs_ether_addr_is_local(&r));
        assert_se(ether_addr_is_local(&c));
        assert_se(!ether_addr_is_global(&c));
        assert_se(!rs_ether_addr_is_global(&r));
}

TEST(ether_addr_is_local_no) {
        /* 00:aa:bb:cc:dd:ee — globally assigned */
        struct ether_addr c = { .ether_addr_octet = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee} };
        struct rs_ether_addr r = { .octet = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee} };

        assert_se(ether_addr_is_local(&c) == rs_ether_addr_is_local(&r));
        assert_se(!ether_addr_is_local(&c));
        assert_se(ether_addr_is_global(&c));
        assert_se(rs_ether_addr_is_global(&r));
}

TEST(ether_addr_both_local_and_multicast) {
        /* 03:xx:xx:xx:xx:xx — both local and multicast */
        struct ether_addr c = { .ether_addr_octet = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00} };
        struct rs_ether_addr r = { .octet = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00} };

        assert_se(ether_addr_is_multicast(&c));
        assert_se(rs_ether_addr_is_multicast(&r));
        assert_se(ether_addr_is_local(&c));
        assert_se(rs_ether_addr_is_local(&r));
}

/* ── main ────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
