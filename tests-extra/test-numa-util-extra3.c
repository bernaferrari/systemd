/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "numa-util.h"
#include "string-util.h"
#include "tests.h"

TEST(numa_policy_is_valid_default) {
        NUMAPolicy policy = {
                .type = MPOL_DEFAULT,
        };
        assert_se(numa_policy_is_valid(&policy));
}

TEST(numa_policy_is_valid_local) {
        NUMAPolicy policy = {
                .type = MPOL_LOCAL,
        };
        assert_se(numa_policy_is_valid(&policy));
}

TEST(numa_policy_is_valid_invalid_type) {
        NUMAPolicy policy = {
                .type = 99,
        };
        assert_se(!numa_policy_is_valid(&policy));
}

TEST(numa_policy_is_valid_preferred_no_nodes) {
        NUMAPolicy policy = {
                .type = MPOL_PREFERRED,
        };
        /* MPOL_PREFERRED with no nodes is valid (uses local allocation) */
        assert_se(numa_policy_is_valid(&policy));
}

TEST(numa_policy_is_valid_bind_no_nodes) {
        NUMAPolicy policy = {
                .type = MPOL_BIND,
        };
        /* MPOL_BIND requires nodes */
        assert_se(!numa_policy_is_valid(&policy));
}

TEST(numa_policy_is_valid_interleave_no_nodes) {
        NUMAPolicy policy = {
                .type = MPOL_INTERLEAVE,
        };
        /* MPOL_INTERLEAVE requires nodes */
        assert_se(!numa_policy_is_valid(&policy));
}

TEST(mpol_is_valid_basic) {
        assert_se(mpol_is_valid(MPOL_DEFAULT));
        assert_se(mpol_is_valid(MPOL_PREFERRED));
        assert_se(mpol_is_valid(MPOL_BIND));
        assert_se(mpol_is_valid(MPOL_INTERLEAVE));
        assert_se(mpol_is_valid(MPOL_LOCAL));
        assert_se(!mpol_is_valid(99));
        assert_se(!mpol_is_valid(-1));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
