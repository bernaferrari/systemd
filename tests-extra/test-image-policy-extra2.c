/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "image-policy.h"
#include "string-util.h"
#include "tests.h"

TEST(partition_policy_flags_extend) {
        PartitionPolicyFlags flags;

        /* No protection flag set → OPEN is added */
        flags = partition_policy_flags_extend(0);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_OPEN));
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_UNPROTECTED));
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_UNUSED));
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_ABSENT));
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_VERITY));
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_SIGNED));

        /* PARTITION_POLICY_UNPROTECTED alone: extend fills in read-only and growfs */
        flags = partition_policy_flags_extend(PARTITION_POLICY_UNPROTECTED);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_UNPROTECTED));
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_READ_ONLY_ON));
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_READ_ONLY_OFF));
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_GROWFS_ON));
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_GROWFS_OFF));
}

TEST(partition_policy_flags_reduce) {
        PartitionPolicyFlags flags;

        /* Full use mask → reduced to 0 for use bits */
        flags = partition_policy_flags_reduce(PARTITION_POLICY_OPEN);
        assert_se((flags & _PARTITION_POLICY_USE_MASK) == 0);

        /* Full read-only mask → reduced */
        flags = PARTITION_POLICY_READ_ONLY_ON | PARTITION_POLICY_READ_ONLY_OFF;
        flags = partition_policy_flags_reduce(flags);
        assert_se((flags & _PARTITION_POLICY_READ_ONLY_MASK) == 0);

        /* Full growfs mask → reduced */
        flags = PARTITION_POLICY_GROWFS_ON | PARTITION_POLICY_GROWFS_OFF;
        flags = partition_policy_flags_reduce(flags);
        assert_se((flags & _PARTITION_POLICY_GROWFS_MASK) == 0);
}

TEST(partition_policy_flags_extend_reduce_roundtrip) {
        /* Extending then reducing flags that are fully specified should give back 0 */
        PartitionPolicyFlags flags = partition_policy_flags_extend(0);
        PartitionPolicyFlags reduced = partition_policy_flags_reduce(flags);
        assert_se(reduced == 0);
}

TEST(image_policy_default) {
        /* NULL policy → PARTITION_POLICY_OPEN */
        assert_se(image_policy_default(NULL) == PARTITION_POLICY_OPEN);
}

TEST(image_policy_n_entries) {
        /* NULL policy → 0 entries */
        assert_se(image_policy_n_entries(NULL) == 0);
}

TEST(image_policy_from_string_roundtrip) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        /* "*" = default policy accepting everything */
        r = image_policy_from_string("*", false, &p);
        assert_se(r >= 0);
        assert_se(p != NULL);
        assert_se(image_policy_default(p) == PARTITION_POLICY_OPEN);
        p = image_policy_free(p);

        /* "-" = deny all */
        r = image_policy_from_string("-", false, &p);
        assert_se(r >= 0);
        p = image_policy_free(p);

        /* "~" = ignore */
        r = image_policy_from_string("~", false, &p);
        assert_se(r >= 0);
        p = image_policy_free(p);

        /* Specific policy: root=verity */
        r = image_policy_from_string("root=verity", false, &p);
        assert_se(r >= 0);
        assert_se(image_policy_n_entries(p) == 1);

        r = image_policy_to_string(p, true, &s);
        assert_se(r >= 0);
        assert_se(s != NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
