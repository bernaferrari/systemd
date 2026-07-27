/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "group-record.h"
#include "tests.h"

TEST(group_record_new_free) {
        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;

        g = group_record_new();
        assert_se(g);
        assert_se(g->n_ref == 1);
        assert_se(g->gid == GID_INVALID);
        assert_se(g->disposition == _USER_DISPOSITION_INVALID);
        assert_se(g->last_change_usec == UINT64_MAX);
        assert_se(g->group_name == NULL);
        assert_se(g->members == NULL);
}

TEST(group_record_ref_unref) {
        GroupRecord *g = group_record_new();
        assert_se(g);

        GroupRecord *g2 = group_record_ref(g);
        assert_se(g2 == g);
        assert_se(g->n_ref == 2);

        group_record_unref(g);
        /* Still alive with 1 ref */
        assert_se(g->n_ref == 1);

        group_record_unref(g);
}

TEST(group_record_unref_null) {
        group_record_unref(NULL);
        /* Should not crash */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
