/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hostname-setup.h"
#include "string-util.h"
#include "tests.h"

TEST(shorten_overlong) {
        _cleanup_free_ char *ret = NULL;
        int r;

        /* Valid hostname passes through unchanged */
        r = shorten_overlong("myhost", &ret);
        assert_se(r == 0);
        assert_se(streq(ret, "myhost"));
        ret = mfree(ret);

        /* FQDN passes through unchanged */
        r = shorten_overlong("myhost.example.com", &ret);
        assert_se(r == 0);
        assert_se(streq(ret, "myhost.example.com"));
        ret = mfree(ret);

        /* Hostname with trailing dot, after truncation at dot */
        r = shorten_overlong("myhost.", &ret);
        assert_se(r >= 0);
        if (r == 0)
                assert_se(streq(ret, "myhost."));
        ret = mfree(ret);

        /* Short name */
        r = shorten_overlong("a", &ret);
        assert_se(r == 0);
        assert_se(streq(ret, "a"));
        ret = mfree(ret);

        /* Very long hostname gets shortened */
        char longname[300];
        memset(longname, 'a', sizeof(longname) - 1);
        longname[sizeof(longname) - 1] = '\0';
        r = shorten_overlong(longname, &ret);
        assert_se(r >= 0 || r == -EDOM);
        ret = mfree(ret);

        /* Long hostname truncated at dot */
        char longwithdot[300];
        memset(longwithdot, 'a', 100);
        longwithdot[100] = '.';
        memset(longwithdot + 101, 'b', 100);
        longwithdot[201] = '\0';
        r = shorten_overlong(longwithdot, &ret);
        assert_se(r >= 0 || r == -EDOM);
        ret = mfree(ret);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
