/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C device-nodes vs Rust rs_device_nodes */

#include <limits.h>
#include <string.h>

#include "device-nodes.h"
#include "string-util.h"
#include "rust/device_nodes.h"

/* ── allow_listed_char_for_devnode ─────────────────────────────────────── */
/* RUST-CONTRACT: device-node-allowed-byte */

static void test_allow_listed_char(void) {
        static const char additional[] = { '!', '/', (char) 0x80, 0 };

        /* Match C across the complete char domain, including values that are
         * negative when char is signed and a high-bit byte in `additional`. */
        for (unsigned c = 0; c <= UCHAR_MAX; c++) {
                assert_se(!!allow_listed_char_for_devnode((char) c, NULL) ==
                          !!rs_allow_listed_char_for_devnode((char) c, NULL));
                assert_se(!!allow_listed_char_for_devnode((char) c, additional) ==
                          !!rs_allow_listed_char_for_devnode((char) c, additional));
        }

        /* Digits */
        for (char c = '0'; c <= '9'; c++) {
                assert_se(allow_listed_char_for_devnode(c, NULL) == 1);
                assert_se(rs_allow_listed_char_for_devnode(c, NULL) == 1);
        }

        /* Letters */
        for (char c = 'a'; c <= 'z'; c++) {
                assert_se(allow_listed_char_for_devnode(c, NULL) == 1);
                assert_se(rs_allow_listed_char_for_devnode(c, NULL) == 1);
        }
        for (char c = 'A'; c <= 'Z'; c++) {
                assert_se(allow_listed_char_for_devnode(c, NULL) == 1);
                assert_se(rs_allow_listed_char_for_devnode(c, NULL) == 1);
        }

        /* Special allowed chars */
        const char *special = "#+-.:=@_";
        for (const char *p = special; *p; p++) {
                assert_se(allow_listed_char_for_devnode(*p, NULL) == 1);
                assert_se(rs_allow_listed_char_for_devnode(*p, NULL) == 1);
        }

        /* Not allowed */
        assert_se(allow_listed_char_for_devnode('!', NULL) == 0);
        assert_se(rs_allow_listed_char_for_devnode('!', NULL) == 0);
        assert_se(allow_listed_char_for_devnode(' ', NULL) == 0);
        assert_se(rs_allow_listed_char_for_devnode(' ', NULL) == 0);
        assert_se(allow_listed_char_for_devnode('/', NULL) == 0);
        assert_se(rs_allow_listed_char_for_devnode('/', NULL) == 0);

        /* Additional chars */
        assert_se(allow_listed_char_for_devnode('/', "/") == 1);
        assert_se(rs_allow_listed_char_for_devnode('/', "/") == 1);
        assert_se(allow_listed_char_for_devnode('!', "!@#") == 1);
        assert_se(rs_allow_listed_char_for_devnode('!', "!@#") == 1);
        assert_se(allow_listed_char_for_devnode('$', "!@#") == 0);
        assert_se(rs_allow_listed_char_for_devnode('$', "!@#") == 0);

        /* NULL additional */
        assert_se(allow_listed_char_for_devnode('!', NULL) == 0);
        assert_se(rs_allow_listed_char_for_devnode('!', NULL) == 0);
}

/* ── encode_devnode_name ──────────────────────────────────────────────── */
/* RUST-CONTRACT: device-node-name-encoding */

static void test_encode_devnode_name(void) {
        char c_buf[256], r_buf[256];
        int c_ret, r_ret;

        /* Simple ASCII string */
        c_ret = encode_devnode_name("sda1", c_buf, sizeof(c_buf));
        r_ret = rs_encode_devnode_name("sda1", r_buf, sizeof(r_buf));
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(streq(c_buf, r_buf));
        assert_se(streq(c_buf, "sda1"));

        /* String with space (should be escaped) */
        c_ret = encode_devnode_name("my disk", c_buf, sizeof(c_buf));
        r_ret = rs_encode_devnode_name("my disk", r_buf, sizeof(r_buf));
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(streq(c_buf, r_buf));
        assert_se(streq(c_buf, "my\\x20disk"));

        /* Backslash should be escaped */
        c_ret = encode_devnode_name("a\\b", c_buf, sizeof(c_buf));
        r_ret = rs_encode_devnode_name("a\\b", r_buf, sizeof(r_buf));
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(streq(c_buf, r_buf));
        assert_se(streq(c_buf, "a\\x5cb"));

        /* Empty string */
        c_ret = encode_devnode_name("", c_buf, sizeof(c_buf));
        r_ret = rs_encode_devnode_name("", r_buf, sizeof(r_buf));
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(streq(c_buf, r_buf));
        assert_se(streq(c_buf, ""));

        /* UTF-8 multi-byte: é = 0xC3 0xA9 */
        char utf8[] = { 0xC3, 0xA9, 0 };
        c_ret = encode_devnode_name(utf8, c_buf, sizeof(c_buf));
        r_ret = rs_encode_devnode_name(utf8, r_buf, sizeof(r_buf));
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(streq(c_buf, r_buf));
        assert_se(strlen(c_buf) == 2); /* UTF-8 passes through */

        /* Buffer too small */
        c_ret = encode_devnode_name("sda1", c_buf, 3);
        r_ret = rs_encode_devnode_name("sda1", r_buf, 3);
        assert_se(c_ret == -EINVAL);
        assert_se(r_ret == -EINVAL);

        /* NULL input */
        c_ret = encode_devnode_name(NULL, c_buf, sizeof(c_buf));
        r_ret = rs_encode_devnode_name(NULL, r_buf, sizeof(r_buf));
        assert_se(c_ret == -EINVAL);
        assert_se(r_ret == -EINVAL);
        c_ret = encode_devnode_name("test", NULL, sizeof(c_buf));
        r_ret = rs_encode_devnode_name("test", NULL, sizeof(r_buf));
        assert_se(c_ret == -EINVAL);
        assert_se(r_ret == -EINVAL);

        /* All special chars need escaping */
        c_ret = encode_devnode_name("a b!c", c_buf, sizeof(c_buf));
        r_ret = rs_encode_devnode_name("a b!c", r_buf, sizeof(r_buf));
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(streq(c_buf, r_buf));
}

static void test_encode_devnode_name_boundaries(void) {
        static const char truncated[] = { (char) 0xc2, 'A', 0 };
        static const char overlong[] = { (char) 0xc0, (char) 0x80, 0 };
        static const char surrogate[] = { (char) 0xed, (char) 0xa0, (char) 0x80, 0 };
        static const char noncharacter[] = { (char) 0xef, (char) 0xb7, (char) 0x90, 0 };
        static const char out_of_range[] = {
                (char) 0xf4, (char) 0x90, (char) 0x80, (char) 0x80, 0
        };
        static const char invalid_lead[] = { (char) 0xff, 0 };
        static const char *const cases[] = {
                "", "abc", "systemd sucks", "valíd\\ųtf8", truncated,
                overlong, surrogate, noncharacter, out_of_range, invalid_lead,
        };

        for (size_t input = 0; input < ELEMENTSOF(cases); input++)
                for (size_t len = 0; len <= 32; len++) {
                        char c_output[32], rust_output[32];

                        memset(c_output, 0xa5, sizeof(c_output));
                        memset(rust_output, 0xa5, sizeof(rust_output));

                        assert_se(encode_devnode_name(cases[input], c_output, len) ==
                                  rs_encode_devnode_name(cases[input], rust_output, len));
                        /* This includes C snprintf's temporary NUL after a
                         * completed escape before a later capacity failure. */
                        assert_se(memcmp(c_output, rust_output, sizeof(c_output)) == 0);
                }
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_allow_listed_char();
        test_encode_devnode_name();
        test_encode_devnode_name_boundaries();

        return 0;
}
