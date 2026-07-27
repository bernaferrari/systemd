/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "fs-util.h"
#include "string-util.h"
#include "tests.h"

TEST(at_flags_normalize_nofollow_basic) {
        /* No flags → should add AT_SYMLINK_NOFOLLOW */
        int f = at_flags_normalize_nofollow(0);
        assert_se(f & AT_SYMLINK_NOFOLLOW);
        assert_se(!(f & AT_SYMLINK_FOLLOW));

        /* Already has AT_SYMLINK_NOFOLLOW → keep it */
        f = at_flags_normalize_nofollow(AT_SYMLINK_NOFOLLOW);
        assert_se(f & AT_SYMLINK_NOFOLLOW);
        assert_se(!(f & AT_SYMLINK_FOLLOW));

        /* Has AT_SYMLINK_FOLLOW → remove it (no NOFOLLOW added) */
        f = at_flags_normalize_nofollow(AT_SYMLINK_FOLLOW);
        assert_se(!(f & AT_SYMLINK_FOLLOW));
        /* Note: NOFOLLOW is NOT set in this case — function just clears FOLLOW */
}

TEST(at_flags_normalize_follow_basic) {
        /* No flags → should add AT_SYMLINK_FOLLOW */
        int f = at_flags_normalize_follow(0);
        assert_se(f & AT_SYMLINK_FOLLOW);
        assert_se(!(f & AT_SYMLINK_NOFOLLOW));

        /* Already has AT_SYMLINK_FOLLOW → keep it */
        f = at_flags_normalize_follow(AT_SYMLINK_FOLLOW);
        assert_se(f & AT_SYMLINK_FOLLOW);
        assert_se(!(f & AT_SYMLINK_NOFOLLOW));

        /* Has AT_SYMLINK_NOFOLLOW → remove it (no FOLLOW added) */
        f = at_flags_normalize_follow(AT_SYMLINK_NOFOLLOW);
        assert_se(!(f & AT_SYMLINK_NOFOLLOW));
        /* Note: FOLLOW is NOT set in this case — function just clears NOFOLLOW */
}

TEST(parse_cifs_service_basic) {
        _cleanup_free_ char *host = NULL, *service = NULL, *path = NULL;
        int r;

        r = parse_cifs_service("//server/share/path", &host, &service, &path);
        assert_se(r >= 0);
        assert_se(streq(host, "server"));
        assert_se(streq(service, "share"));
        assert_se(path && streq(path, "path"));
        host = mfree(host);
        service = mfree(service);
        path = mfree(path);

        r = parse_cifs_service("\\\\server\\share", &host, &service, &path);
        assert_se(r >= 0);
        assert_se(streq(host, "server"));
        assert_se(streq(service, "share"));
        host = mfree(host);
        service = mfree(service);
        path = mfree(path);

        /* No path component */
        r = parse_cifs_service("//myhost/myshare", &host, &service, &path);
        assert_se(r >= 0);
        assert_se(streq(host, "myhost"));
        assert_se(streq(service, "myshare"));
        host = mfree(host);
        service = mfree(service);
        path = mfree(path);

        /* Invalid: missing share */
        r = parse_cifs_service("//server", &host, &service, &path);
        assert_se(r < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
