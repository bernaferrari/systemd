/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "devnum-util.h"
#include "tests.h"

/* Rust FFI */
#include "rust/devnum_util.h"

/* ── parse_devnum ───────────────────────────────────────────────────────── */

/* RUST-CONTRACT: parse-devnum */
TEST(parse_devnum_basic) {
        dev_t cr, rr;
        assert_se(parse_devnum("8:2", &cr) >= 0);
        assert_se(rs_parse_devnum("8:2", &rr) >= 0);
        assert_se(cr == rr);
        assert_se(major(cr) == 8);
        assert_se(minor(cr) == 2);
}

TEST(parse_devnum_zero) {
        dev_t cr, rr;
        assert_se(parse_devnum("0:0", &cr) >= 0);
        assert_se(rs_parse_devnum("0:0", &rr) >= 0);
        assert_se(cr == rr);
}

TEST(parse_devnum_large) {
        dev_t cr, rr;
        /* major 4095 = (1<<12)-1, minor 1048575 = (1<<20)-1 */
        assert_se(parse_devnum("4095:1048575", &cr) >= 0);
        assert_se(rs_parse_devnum("4095:1048575", &rr) >= 0);
        assert_se(cr == rr);
}

TEST(parse_devnum_base_zero) {
        static const char *const valid[] = {
                "010:010",                  /* octal major and minor */
                "8:0x10",                   /* C hexadecimal prefix */
                "8:0b10",                   /* Python binary prefix */
                "8:0o10",                   /* Python octal prefix */
                "8:0b 10",                  /* strtoul whitespace follows prefix mangling */
                "8:0b+10",                  /* strtoul sign follows prefix mangling */
                "8:0o\v10",                 /* full C-locale whitespace after prefix */
                "8:0b-0",                   /* negative zero remains zero */
                "8: 2",                     /* safe_atou() accepts leading whitespace */
                "000000000000000000001:0",  /* C permits DECIMAL_STR_MAX(dev_t) digits */
        };

        FOREACH_ELEMENT(input, valid) {
                dev_t cr, rr;
                int c = parse_devnum(*input, &cr);
                int r = rs_parse_devnum(*input, &rr);

                assert_se(c == r);
                assert_se(c == 0);
                assert_se(cr == rr);
        }

        dev_t cr, rr;
        assert_se(parse_devnum("08:02", &cr) == rs_parse_devnum("08:02", &rr));
        assert_se(parse_devnum("08:02", &cr) == -EINVAL);
        assert_se(parse_devnum("8:0b-1", &cr) == rs_parse_devnum("8:0b-1", &rr));
        assert_se(parse_devnum("8:0b-1", &cr) == -ERANGE);
}

TEST(parse_devnum_invalid) {
        dev_t cr, rr;
        assert_se(parse_devnum("abc", &cr) < 0);
        assert_se(rs_parse_devnum("abc", &rr) < 0);
}

TEST(parse_devnum_no_colon) {
        dev_t cr, rr;
        assert_se(parse_devnum("8", &cr) < 0);
        assert_se(rs_parse_devnum("8", &rr) < 0);
}

TEST(parse_devnum_empty) {
        dev_t cr, rr;
        assert_se(parse_devnum("", &cr) < 0);
        assert_se(rs_parse_devnum("", &rr) < 0);
}

TEST(parse_devnum_major_overflow) {
        dev_t cr, rr;
        assert_se(parse_devnum("4096:0", &cr) < 0);
        assert_se(rs_parse_devnum("4096:0", &rr) < 0);
}

TEST(parse_devnum_minor_overflow) {
        dev_t cr, rr;
        assert_se(parse_devnum("0:1048576", &cr) < 0);
        assert_se(rs_parse_devnum("0:1048576", &rr) < 0);
}

/* ── format_devnum ──────────────────────────────────────────────────────── */

/* RUST-CONTRACT: format-devnum */
TEST(format_devnum_basic) {
        char cb[DEVNUM_STR_MAX], rb[DEVNUM_STR_MAX];
        char *cr = format_devnum(makedev(8, 2), cb);
        char *rr = rs_format_devnum(makedev(8, 2), rb);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "8:2"));
}

TEST(format_devnum_zero) {
        char cb[DEVNUM_STR_MAX], rb[DEVNUM_STR_MAX];
        char *cr = format_devnum(makedev(0, 0), cb);
        char *rr = rs_format_devnum(makedev(0, 0), rb);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "0:0"));
}

TEST(format_devnum_max) {
        char cb[DEVNUM_STR_MAX], rb[DEVNUM_STR_MAX];
        char *cr = format_devnum(makedev(4095, 1048575), cb);
        char *rr = rs_format_devnum(makedev(4095, 1048575), rb);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "4095:1048575"));
}

TEST(format_devnum_full_encoded_dev_t) {
        char cb[DEVNUM_STR_MAX], rb[DEVNUM_STR_MAX];
        dev_t d = (dev_t) -1;
        char *cr = format_devnum(d, cb);
        char *rr = rs_format_devnum(d, rb);

        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));
}

/* RUST-CONTRACT: devnum-inline-predicates */
TEST(devnum_inline_predicates) {
        dev_t a = makedev(7, 255), zero = makedev(0, 0);

        assert_se(devnum_is_zero(zero) == rs_devnum_is_zero(zero));
        assert_se(devnum_is_zero(a) == rs_devnum_is_zero(a));
        assert_se(devnum_set_and_equal(a, a) == rs_devnum_set_and_equal(a, a));
        assert_se(devnum_set_and_equal(a, zero) == rs_devnum_set_and_equal(a, zero));
}

/* ── device_path_parse_major_minor ───────────────────────────────────────── */

/* RUST-CONTRACT: device-path-parse */
TEST(device_path_parse_block) {
        mode_t cm, rm;
        dev_t cd, rd;
        int cr, rr;

        cr = device_path_parse_major_minor("/dev/block/8:2", &cm, &cd);
        rr = rs_device_path_parse_major_minor("/dev/block/8:2", &rm, &rd);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cm == rm);
        assert_se(cd == rd);
        assert_se(major(cd) == 8);
        assert_se(minor(cd) == 2);
}

TEST(device_path_parse_char) {
        mode_t cm, rm;
        dev_t cd, rd;
        int cr, rr;

        cr = device_path_parse_major_minor("/dev/char/8:2", &cm, &cd);
        rr = rs_device_path_parse_major_minor("/dev/char/8:2", &rm, &rd);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cm == rm);
        assert_se(cd == rd);
}

TEST(device_path_parse_normalized_components) {
        static const char *const paths[] = {
                "/dev//block/8:2",
                "/dev/./block/8:2",
                "/dev/block/./8:2",
                "/dev/block/010:010",
        };

        FOREACH_ELEMENT(path, paths) {
                mode_t cm, rm;
                dev_t cd, rd;
                int c = device_path_parse_major_minor(*path, &cm, &cd);
                int r = rs_device_path_parse_major_minor(*path, &rm, &rd);

                assert_se(c == r);
                assert_se(c == 0);
                assert_se(cm == rm);
                assert_se(cd == rd);
        }
}

TEST(device_path_parse_invalid_utf8_non_device) {
        static const char path[] = "/home/\xff";
        mode_t cm, rm;
        dev_t cd, rd;

        assert_se(device_path_parse_major_minor(path, &cm, &cd) ==
                  rs_device_path_parse_major_minor(path, &rm, &rd));
        assert_se(device_path_parse_major_minor(path, &cm, &cd) == -ENODEV);
}

TEST(device_path_parse_inaccessible_chr) {
        mode_t cm, rm;
        dev_t cd, rd;
        int cr, rr;

        cr = device_path_parse_major_minor("/run/systemd/inaccessible/chr", &cm, &cd);
        rr = rs_device_path_parse_major_minor("/run/systemd/inaccessible/chr", &rm, &rd);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cm == rm);
        assert_se(cd == rd);
        assert_se(cd == 0);
}

TEST(device_path_parse_normalized_inaccessible) {
        const char *path = "/run//systemd/./inaccessible/chr/";
        mode_t cm, rm;
        dev_t cd, rd;
        int c = device_path_parse_major_minor(path, &cm, &cd);
        int r = rs_device_path_parse_major_minor(path, &rm, &rd);

        assert_se(c == r);
        assert_se(c == 0);
        assert_se(cm == rm);
        assert_se(cd == rd);
}

TEST(device_path_parse_inaccessible_blk) {
        mode_t cm, rm;
        dev_t cd, rd;
        int cr, rr;

        cr = device_path_parse_major_minor("/run/systemd/inaccessible/blk", &cm, &cd);
        rr = rs_device_path_parse_major_minor("/run/systemd/inaccessible/blk", &rm, &rd);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cd == rd);
}

TEST(device_path_parse_not_device_path) {
        mode_t cm, rm;
        dev_t cd, rd;
        int cr, rr;

        cr = device_path_parse_major_minor("/home/user/file", &cm, &cd);
        rr = rs_device_path_parse_major_minor("/home/user/file", &rm, &rd);
        assert_se(cr == rr);
        assert_se(cr == -ENODEV);
}

TEST(device_path_parse_null_ret) {
        int cr, rr;
        cr = device_path_parse_major_minor("/dev/block/8:2", NULL, NULL);
        rr = rs_device_path_parse_major_minor("/dev/block/8:2", NULL, NULL);
        assert_se(cr == rr);
        assert_se(cr == 0);
}

TEST(device_path_parse_invalid_devnum) {
        mode_t cm, rm;
        dev_t cd, rd;
        int cr, rr;

        cr = device_path_parse_major_minor("/dev/block/abc:def", &cm, &cd);
        rr = rs_device_path_parse_major_minor("/dev/block/abc:def", &rm, &rd);
        assert_se(cr == rr);
        assert_se(cr < 0);
}

/* ── device_path_make_major_minor ───────────────────────────────────────── */

/* RUST-CONTRACT: device-path-allocation */
TEST(device_path_make_block) {
        _cleanup_free_ char *cp = NULL, *rp = NULL;
        int cr, rr;

        cr = device_path_make_major_minor(S_IFBLK, makedev(8, 2), &cp);
        rr = rs_device_path_make_major_minor(S_IFBLK, makedev(8, 2), &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(cp, rp));
        assert_se(streq(cp, "/dev/block/8:2"));
}

TEST(device_path_make_char) {
        _cleanup_free_ char *cp = NULL, *rp = NULL;
        int cr, rr;

        cr = device_path_make_major_minor(S_IFCHR, makedev(0, 0), &cp);
        rr = rs_device_path_make_major_minor(S_IFCHR, makedev(0, 0), &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(cp, rp));
        assert_se(streq(cp, "/dev/char/0:0"));
}

TEST(device_path_make_full_encoded_dev_t) {
        _cleanup_free_ char *cp = NULL, *rp = NULL;
        dev_t d = (dev_t) -1;
        int cr, rr;

        cr = device_path_make_major_minor(S_IFBLK, d, &cp);
        rr = rs_device_path_make_major_minor(S_IFBLK, d, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(cp, rp));
}

TEST(device_path_make_invalid_mode) {
        char *cp = NULL, *rp = NULL;
        int cr, rr;

        cr = device_path_make_major_minor(S_IFREG, makedev(8, 2), &cp);
        rr = rs_device_path_make_major_minor(S_IFREG, makedev(8, 2), &rp);
        assert_se(cr == rr);
        assert_se(cr == -ENODEV);
}

/* ── device_path_make_inaccessible ──────────────────────────────────────── */

TEST(device_path_make_inaccessible_chr) {
        _cleanup_free_ char *cp = NULL, *rp = NULL;
        int cr, rr;

        cr = device_path_make_inaccessible(S_IFCHR, &cp);
        rr = rs_device_path_make_inaccessible(S_IFCHR, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(cp, rp));
        assert_se(streq(cp, "/run/systemd/inaccessible/chr"));
}

TEST(device_path_make_inaccessible_blk) {
        _cleanup_free_ char *cp = NULL, *rp = NULL;
        int cr, rr;

        cr = device_path_make_inaccessible(S_IFBLK, &cp);
        rr = rs_device_path_make_inaccessible(S_IFBLK, &rp);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(streq(cp, rp));
        assert_se(streq(cp, "/run/systemd/inaccessible/blk"));
}

TEST(device_path_make_inaccessible_invalid) {
        char *cp = NULL, *rp = NULL;
        int cr, rr;

        cr = device_path_make_inaccessible(S_IFREG, &cp);
        rr = rs_device_path_make_inaccessible(S_IFREG, &rp);
        assert_se(cr == rr);
        assert_se(cr == -ENODEV);
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
