/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C fs-util.h at_flags_normalize vs Rust */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include "fs-util.h"
#include "rust/at_flags_util.h"
#include "tests.h"

static void test_at_flags_normalize_nofollow(void) {
        int cv, rv;

        /* No flags set → adds NOFOLLOW */
        cv = at_flags_normalize_nofollow(0);
        rv = rs_at_flags_normalize_nofollow(0);
        assert_se(cv == rv);
        assert_se(FLAGS_SET(cv, AT_SYMLINK_NOFOLLOW));
        assert_se(!FLAGS_SET(cv, AT_SYMLINK_FOLLOW));

        /* FOLLOW set → clears it */
        cv = at_flags_normalize_nofollow(AT_SYMLINK_FOLLOW);
        rv = rs_at_flags_normalize_nofollow(AT_SYMLINK_FOLLOW);
        assert_se(cv == rv);
        assert_se(!FLAGS_SET(cv, AT_SYMLINK_FOLLOW));
        assert_se(!FLAGS_SET(cv, AT_SYMLINK_NOFOLLOW));

        /* NOFOLLOW already set → no change */
        cv = at_flags_normalize_nofollow(AT_SYMLINK_NOFOLLOW);
        rv = rs_at_flags_normalize_nofollow(AT_SYMLINK_NOFOLLOW);
        assert_se(cv == rv);
        assert_se(FLAGS_SET(cv, AT_SYMLINK_NOFOLLOW));

        /* With O_RDONLY */
        cv = at_flags_normalize_nofollow(O_RDONLY);
        rv = rs_at_flags_normalize_nofollow(O_RDONLY);
        assert_se(cv == rv);

        /* FOLLOW + O_RDONLY → clears FOLLOW */
        cv = at_flags_normalize_nofollow(O_RDONLY | AT_SYMLINK_FOLLOW);
        rv = rs_at_flags_normalize_nofollow(O_RDONLY | AT_SYMLINK_FOLLOW);
        assert_se(cv == rv);
}

static void test_at_flags_normalize_follow(void) {
        int cv, rv;

        /* No flags set → adds FOLLOW */
        cv = at_flags_normalize_follow(0);
        rv = rs_at_flags_normalize_follow(0);
        assert_se(cv == rv);
        assert_se(FLAGS_SET(cv, AT_SYMLINK_FOLLOW));
        assert_se(!FLAGS_SET(cv, AT_SYMLINK_NOFOLLOW));

        /* NOFOLLOW set → clears it */
        cv = at_flags_normalize_follow(AT_SYMLINK_NOFOLLOW);
        rv = rs_at_flags_normalize_follow(AT_SYMLINK_NOFOLLOW);
        assert_se(cv == rv);
        assert_se(!FLAGS_SET(cv, AT_SYMLINK_NOFOLLOW));
        assert_se(!FLAGS_SET(cv, AT_SYMLINK_FOLLOW));

        /* FOLLOW already set → no change */
        cv = at_flags_normalize_follow(AT_SYMLINK_FOLLOW);
        rv = rs_at_flags_normalize_follow(AT_SYMLINK_FOLLOW);
        assert_se(cv == rv);
        assert_se(FLAGS_SET(cv, AT_SYMLINK_FOLLOW));

        /* With O_RDONLY */
        cv = at_flags_normalize_follow(O_RDONLY);
        rv = rs_at_flags_normalize_follow(O_RDONLY);
        assert_se(cv == rv);

        /* NOFOLLOW + O_RDONLY → clears NOFOLLOW */
        cv = at_flags_normalize_follow(O_RDONLY | AT_SYMLINK_NOFOLLOW);
        rv = rs_at_flags_normalize_follow(O_RDONLY | AT_SYMLINK_NOFOLLOW);
        assert_se(cv == rv);
}

static void test_contradictory_flags_fail_closed(void) {
        int flags = AT_SYMLINK_FOLLOW | AT_SYMLINK_NOFOLLOW;

        /* C asserts on this invalid caller state. The Rust ABI must never
         * unwind across C, so it exposes the contradiction as -EINVAL. */
        assert_se(rs_at_flags_normalize_nofollow(flags) == -EINVAL);
        assert_se(rs_at_flags_normalize_follow(flags) == -EINVAL);
}

int main(int argc, char **argv) {
        test_at_flags_normalize_nofollow();
        test_at_flags_normalize_follow();
        test_contradictory_flags_fail_closed();
        return 0;
}
