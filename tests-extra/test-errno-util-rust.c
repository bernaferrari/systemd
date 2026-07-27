/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C errno-util vs Rust rs_errno_util */

#include <string.h>
#include <errno.h>
#include <limits.h>

#include "errno-util.h"
#include "errno-list.h"
#include "rust/errno_util.h"
#include "string-util.h"

/* ── strerror_or_eof with error ───────────────────────────────────────── */

static void test_strerror_or_eof_with_error(void) {
        char c_buf[1024];
        char r_buf[1024];

        const char *c_result = strerror_or_eof(EINVAL, c_buf, sizeof(c_buf));
        const char *r_result = rs_strerror_or_eof(EINVAL, r_buf, sizeof(r_buf));

        assert_se(c_result != NULL);
        assert_se(r_result != NULL);
        assert_se(streq(c_result, r_result));
}

/* ── strerror_or_eof with EOF (0) ────────────────────────────────────── */

static void test_strerror_or_eof_eof(void) {
        char c_buf[1024];
        char r_buf[1024];

        const char *c_result = strerror_or_eof(0, c_buf, sizeof(c_buf));
        const char *r_result = rs_strerror_or_eof(0, r_buf, sizeof(r_buf));

        assert_se(c_result != NULL);
        assert_se(r_result != NULL);
        assert_se(streq(c_result, "Unexpected EOF"));
        assert_se(streq(r_result, "Unexpected EOF"));
        assert_se(streq(rs_strerror_or_eof(0, NULL, 0), "Unexpected EOF"));
}

/* ── strerror_or_eof with negative error ─────────────────────────────── */

static void test_strerror_or_eof_negative(void) {
        char c_buf[1024];
        char r_buf[1024];

        const char *c_result = strerror_or_eof(-ENOENT, c_buf, sizeof(c_buf));
        const char *r_result = rs_strerror_or_eof(-ENOENT, r_buf, sizeof(r_buf));

        assert_se(c_result != NULL);
        assert_se(r_result != NULL);
        assert_se(streq(c_result, r_result));

        /* C's ABS(INT_MIN) is undefined; Rust must fail closed, not panic or
         * pass an overflowing value through the C ABI. */
        assert_se(rs_strerror_or_eof(INT_MIN, r_buf, sizeof(r_buf)) == NULL);
}

/* ── errno_from_name ─────────────────────────────────────────────────── */

static void test_errno_from_name(void) {
        int cr, rr;

        /* Standard errno names */
        cr = errno_from_name("EINVAL");
        rr = rs_errno_from_name("EINVAL");
        assert_se(cr == rr);
        assert_se(cr == EINVAL);

        cr = errno_from_name("ENOENT");
        rr = rs_errno_from_name("ENOENT");
        assert_se(cr == rr);
        assert_se(cr == ENOENT);

        cr = errno_from_name("ENOMEM");
        rr = rs_errno_from_name("ENOMEM");
        assert_se(cr == rr);
        assert_se(cr == ENOMEM);

        /* Aliases: EAGAIN == EWOULDBLOCK */
        cr = errno_from_name("EAGAIN");
        rr = rs_errno_from_name("EAGAIN");
        assert_se(cr == rr);
        assert_se(cr == EAGAIN);

        cr = errno_from_name("EWOULDBLOCK");
        rr = rs_errno_from_name("EWOULDBLOCK");
        assert_se(cr == rr);
        assert_se(cr == EWOULDBLOCK);

        /* Aliases: EDEADLK == EDEADLOCK */
        cr = errno_from_name("EDEADLK");
        rr = rs_errno_from_name("EDEADLK");
        assert_se(cr == rr);

        cr = errno_from_name("EDEADLOCK");
        rr = rs_errno_from_name("EDEADLOCK");
        assert_se(cr == rr);

        /* Aliases: ENOTSUP == EOPNOTSUPP */
        cr = errno_from_name("ENOTSUP");
        rr = rs_errno_from_name("ENOTSUP");
        assert_se(cr == rr);

        cr = errno_from_name("EOPNOTSUPP");
        rr = rs_errno_from_name("EOPNOTSUPP");
        assert_se(cr == rr);

        /* Unknown name */
        cr = errno_from_name("NOTAREALERRNO");
        rr = rs_errno_from_name("NOTAREALERRNO");
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* Empty */
        cr = errno_from_name("");
        rr = rs_errno_from_name("");
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* NULL — C asserts, skip shadow test */
        rr = rs_errno_from_name(NULL);
        assert_se(rr < 0);

        const char non_utf8[] = { (char) 0xff, 0 };
        assert_se(rs_errno_from_name(non_utf8) == -EINVAL);
}

/* ── errno_name_no_fallback ──────────────────────────────────────────── */

static void test_errno_name_no_fallback(void) {
        const char *cr, *rr;

        /* Standard errno values */
        cr = errno_name_no_fallback(EINVAL);
        rr = rs_errno_name_no_fallback(EINVAL);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        cr = errno_name_no_fallback(ENOENT);
        rr = rs_errno_name_no_fallback(ENOENT);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        cr = errno_name_no_fallback(ENOMEM);
        rr = rs_errno_name_no_fallback(ENOMEM);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        /* Zero */
        cr = errno_name_no_fallback(0);
        rr = rs_errno_name_no_fallback(0);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Negative */
        cr = errno_name_no_fallback(-EINVAL);
        rr = rs_errno_name_no_fallback(-EINVAL);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        /* Out of range */
        cr = errno_name_no_fallback(9999);
        rr = rs_errno_name_no_fallback(9999);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Large valid errno */
        cr = errno_name_no_fallback(EHWPOISON);
        rr = rs_errno_name_no_fallback(EHWPOISON);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        /* Gap in errno values (41 is unused on Linux) */
        cr = errno_name_no_fallback(41);
        rr = rs_errno_name_no_fallback(41);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* C's ABS(INT_MIN) is undefined; Rust's boundary is explicitly total. */
        assert_se(rs_errno_name_no_fallback(INT_MIN) == NULL);
}

static void test_errno_name_no_fallback_exhaustive(void) {
        for (int i = 0; i <= 4095; i++) {
                const char *cr = errno_name_no_fallback(i);
                const char *rr = rs_errno_name_no_fallback(i);

                assert_se((cr == NULL) == (rr == NULL));
                if (cr)
                        assert_se(streq(cr, rr));
        }
}

/* ── Main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_strerror_or_eof_with_error();
        test_strerror_or_eof_eof();
        test_strerror_or_eof_negative();
        test_errno_from_name();
        test_errno_name_no_fallback();
        test_errno_name_no_fallback_exhaustive();

        return 0;
}
