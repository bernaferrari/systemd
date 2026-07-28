/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C hostname-setup vs Rust rs_shorten_overlong */
/* RUST-CONTRACT: hostname-setup-shorten-overlong */

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "string-util.h"

/* C header */
#include "hostname-setup.h"

/* Rust FFI */
#include "rust/hostname_setup.h"

static void test_shorten_overlong(void) {
        _cleanup_free_ char *c_ret = NULL, *r_ret = NULL;
        int cr, rr;

        /* Already valid short hostname */
        cr = shorten_overlong("myhost", &c_ret);
        rr = rs_shorten_overlong("myhost", &r_ret);
        assert_se(cr == rr);
        assert_se(streq(c_ret, r_ret));
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        /* Maximum length valid hostname (63 chars) */
        cr = shorten_overlong(
                        "abcdefghijklmnopqrstuvwxyz0123456789"
                        "abcdefghijklmnopqrstuvwxyab", &c_ret);
        rr = rs_shorten_overlong(
                        "abcdefghijklmnopqrstuvwxyz0123456789"
                        "abcdefghijklmnopqrstuvwxyab", &r_ret);
        assert_se(cr == rr);
        assert_se(streq(c_ret, r_ret));
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        /* FQDN */
        cr = shorten_overlong("myhost.example.com", &c_ret);
        rr = rs_shorten_overlong("myhost.example.com", &r_ret);
        assert_se(cr == rr);
        assert_se(streq(c_ret, r_ret));
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        /* Overlong with dot after 63 chars: should truncate */
        cr = shorten_overlong(
                        "abcdefghijklmnopqrstuvwxyz0123456789"
                        "abcdefghijklmnopqrstuvwxyz01234.example.com", &c_ret);
        rr = rs_shorten_overlong(
                        "abcdefghijklmnopqrstuvwxyz0123456789"
                        "abcdefghijklmnopqrstuvwxyz01234.example.com", &r_ret);
        assert_se(cr == rr);
        if (cr >= 0) {
                assert_se(streq(c_ret, r_ret));
        }
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        /* Dot early in an overlong string */
        cr = shorten_overlong("foo.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &c_ret);
        rr = rs_shorten_overlong("foo.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &r_ret);
        assert_se(cr == rr);
        if (cr >= 0) {
                assert_se(streq(c_ret, r_ret));
        }
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        /* Overlong with no dot */
        cr = shorten_overlong(
                        "abcdefghijklmnopqrstuvwxyz0123456789"
                        "abcdefghijklmnopqrstuvwxyz01234X", &c_ret);
        rr = rs_shorten_overlong(
                        "abcdefghijklmnopqrstuvwxyz0123456789"
                        "abcdefghijklmnopqrstuvwxyz01234X", &r_ret);
        assert_se(cr == rr);
        if (cr >= 0) {
                assert_se(streq(c_ret, r_ret));
        }
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        /* Completely invalid characters */
        cr = shorten_overlong("---!!!###$$$", &c_ret);
        rr = rs_shorten_overlong("---!!!###$$$", &r_ret);
        assert_se(cr == rr);
        assert_se(cr == -EDOM);
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        /* Empty string */
        cr = shorten_overlong("", &c_ret);
        rr = rs_shorten_overlong("", &r_ret);
        assert_se(cr == rr);
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        /* Single character */
        cr = shorten_overlong("a", &c_ret);
        rr = rs_shorten_overlong("a", &r_ret);
        assert_se(cr == rr);
        if (cr >= 0) {
                assert_se(streq(c_ret, r_ret));
        }
        c_ret = mfree(c_ret);
        r_ret = mfree(r_ret);

        /* Just a dot */
        cr = shorten_overlong(".", &c_ret);
        rr = rs_shorten_overlong(".", &r_ret);
        assert_se(cr == rr);

        /* C validates raw ASCII hostname bytes before publishing an output. */
        {
                static const char invalid_bytes[] = { 'a', (char) 0xff, 0 };
                char *unchanged = (char*) 1;

                cr = shorten_overlong(invalid_bytes, &c_ret);
                rr = rs_shorten_overlong(invalid_bytes, &unchanged);
                assert_se(cr == rr);
                assert_se(cr == -EDOM);
                assert_se(unchanged == (char*) 1);
        }
}

static void test_shorten_overlong_null_rust_only(void) {
        _cleanup_free_ char *r_ret = NULL;

        /* C asserts on NULL — Rust returns -EINVAL */
        assert_se(rs_shorten_overlong(NULL, &r_ret) == -EINVAL);
        assert_se(rs_shorten_overlong("foo", NULL) == -EINVAL);
}

int main(int argc, char **argv) {
        test_shorten_overlong();
        test_shorten_overlong_null_rust_only();

        return 0;
}
