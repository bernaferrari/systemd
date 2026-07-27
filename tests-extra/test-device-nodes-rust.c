/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C device-nodes vs Rust rs_device_nodes */

#include <string.h>

#include "device-nodes.h"
#include "string-util.h"
#include "rust/device_nodes.h"

/* ── allow_listed_char_for_devnode ─────────────────────────────────────── */

static void test_allow_listed_char(void) {
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

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_allow_listed_char();
        test_encode_devnode_name();

        return 0;
}
