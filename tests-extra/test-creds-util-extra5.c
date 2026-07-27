/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "creds-util.h"
#include "string-util.h"
#include "tests.h"

TEST(credentials_varlink_error_by_id) {
        /* Known error IDs */
        const CredentialsVarlinkError *e;

        e = credentials_varlink_error_by_id("io.systemd.Credentials.BadFormat");
        assert_se(e != NULL);
        assert_se(streq(e->id, "io.systemd.Credentials.BadFormat"));
        assert_se(e->errnum == EBADMSG);

        e = credentials_varlink_error_by_id("io.systemd.Credentials.TimeMismatch");
        assert_se(e != NULL);
        assert_se(e->errnum == ESTALE);

        e = credentials_varlink_error_by_id("io.systemd.Credentials.NoSuchUser");
        assert_se(e != NULL);
        assert_se(e->errnum == ESRCH);

        /* Unknown ID */
        e = credentials_varlink_error_by_id("io.systemd.Credentials.Nonexistent");
        assert_se(e == NULL);
}

TEST(credentials_varlink_error_by_errno) {
        const CredentialsVarlinkError *e;

        e = credentials_varlink_error_by_errno(EBADMSG);
        assert_se(e != NULL);
        assert_se(streq(e->id, "io.systemd.Credentials.BadFormat"));

        e = credentials_varlink_error_by_errno(ESRCH);
        assert_se(e != NULL);
        assert_se(streq(e->id, "io.systemd.Credentials.NoSuchUser"));

        /* Negative errno works too (ABS is applied) */
        e = credentials_varlink_error_by_errno(-ESTALE);
        assert_se(e != NULL);
        assert_se(streq(e->id, "io.systemd.Credentials.TimeMismatch"));

        /* Unknown errno */
        e = credentials_varlink_error_by_errno(999999);
        assert_se(e == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
