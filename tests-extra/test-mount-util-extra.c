/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "mount-util.h"
#include "string-util.h"
#include "tests.h"

TEST(mount_flags_to_string) {
        _cleanup_free_ char *s = NULL;
        int r;

        /* No flags → just "0" */
        r = mount_flags_to_string(0, &s);
        assert_se(r == 0);
        assert_se(streq(s, "0"));

        /* Single flag */
        s = mfree(s);
        r = mount_flags_to_string(MS_RDONLY, &s);
        assert_se(r == 0);
        assert_se(streq(s, "MS_RDONLY"));

        /* Multiple known flags */
        s = mfree(s);
        r = mount_flags_to_string(MS_RDONLY | MS_NOSUID | MS_NODEV, &s);
        assert_se(r == 0);
        assert_se(string_contains_word(s, "|", "MS_RDONLY"));
        assert_se(string_contains_word(s, "|", "MS_NOSUID"));
        assert_se(string_contains_word(s, "|", "MS_NODEV"));

        /* Unknown flag bits (e.g., a high bit not in the map) */
        s = mfree(s);
        r = mount_flags_to_string(1UL << 31, &s);
        assert_se(r == 0);
        /* Should contain the hex representation of the unknown bits */
        assert_se(endswith(s, "80000000"));

        /* MS_BIND */
        s = mfree(s);
        r = mount_flags_to_string(MS_BIND, &s);
        assert_se(r == 0);
        assert_se(streq(s, "MS_BIND"));

        /* MS_REC|MS_BIND */
        s = mfree(s);
        r = mount_flags_to_string(MS_REC | MS_BIND, &s);
        assert_se(r == 0);
        assert_se(string_contains_word(s, "|", "MS_REC"));
        assert_se(string_contains_word(s, "|", "MS_BIND"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
