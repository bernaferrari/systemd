/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "group-record.h"
#include "string-util.h"
#include "tests.h"
#include "user-util.h"

TEST(group_record_disposition) {
        /* Use stack-allocated struct to avoid free() issues */
        GroupRecord g = {};

        /* From explicit disposition */
        g.disposition = USER_INTRINSIC;
        assert_se(group_record_disposition(&g) == USER_INTRINSIC);

        g.disposition = USER_SYSTEM;
        assert_se(group_record_disposition(&g) == USER_SYSTEM);

        /* Derived from GID when disposition is _INVALID */
        g.disposition = _USER_DISPOSITION_INVALID;

        /* GID 0 → INTRINSIC */
        g.gid = 0;
        assert_se(group_record_disposition(&g) == USER_INTRINSIC);

        /* GID_NOBODY → INTRINSIC */
        g.gid = GID_NOBODY;
        assert_se(group_record_disposition(&g) == USER_INTRINSIC);

        /* System GID */
        g.gid = 100;
        assert_se(group_record_disposition(&g) == USER_SYSTEM);

        /* Invalid GID → _INVALID */
        g.gid = GID_INVALID;
        assert_se(group_record_disposition(&g) == _USER_DISPOSITION_INVALID);

        /* Regular user GID */
        g.gid = 1000;
        assert_se(group_record_disposition(&g) == USER_REGULAR);
}

TEST(group_record_is_root) {
        /* Use stack-allocated struct to avoid free() on string literals */
        GroupRecord g = {};

        /* GID 0 is root */
        g.gid = 0;
        assert_se(group_record_is_root(&g));

        /* group_name "root" is root */
        g.gid = GID_INVALID;
        g.group_name = (char*) "root";
        assert_se(group_record_is_root(&g));

        /* Neither */
        g.gid = 100;
        g.group_name = (char*) "users";
        assert_se(!group_record_is_root(&g));

        /* Both conditions */
        g.gid = 0;
        g.group_name = (char*) "root";
        assert_se(group_record_is_root(&g));
}

TEST(group_record_is_nobody) {
        GroupRecord g = {};

        /* GID_NOBODY */
        g.gid = GID_NOBODY;
        assert_se(group_record_is_nobody(&g));

        /* NOBODY_GROUP_NAME */
        g.gid = GID_INVALID;
        g.group_name = (char*) NOBODY_GROUP_NAME;
        assert_se(group_record_is_nobody(&g));

        /* "nobody" */
        g.group_name = (char*) "nobody";
        assert_se(group_record_is_nobody(&g));

        /* Not nobody */
        g.gid = 100;
        g.group_name = (char*) "users";
        assert_se(!group_record_is_nobody(&g));
}

TEST(group_record_group_name_and_realm) {
        GroupRecord g = {};

        /* No realm → returns group_name */
        g.group_name = (char*) "mygroup";
        g.group_name_and_realm_auto = NULL;
        g.realm = NULL;
        assert_se(streq(group_record_group_name_and_realm(&g), "mygroup"));

        /* With auto string → returns that */
        g.group_name_and_realm_auto = (char*) "mygroup@realm";
        assert_se(streq(group_record_group_name_and_realm(&g), "mygroup@realm"));
}

TEST(group_record_matches_group_name) {
        GroupRecord g = {};

        g.group_name = (char*) "mygroup";

        /* Exact match */
        assert_se(group_record_matches_group_name(&g, "mygroup"));

        /* No match */
        assert_se(!group_record_matches_group_name(&g, "other"));

        /* NULL group name in record */
        g.group_name = NULL;
        assert_se(!group_record_matches_group_name(&g, "mygroup"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
