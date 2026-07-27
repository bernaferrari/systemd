/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <seccomp.h>

#include "seccomp-util.h"
#include "tests.h"

TEST(secure_bits_from_string_basic) {
        assert_se(secure_bits_from_string("keep-caps") >= 0);
        assert_se(secure_bits_from_string("no-setuid-fixup") >= 0);
        assert_se(secure_bits_from_string("noroot") >= 0);
        assert_se(secure_bits_from_string("keep-caps-locked") >= 0);
        assert_se(secure_bits_from_string("no-setuid-fixup-locked") >= 0);
        assert_se(secure_bits_from_string("noroot-locked") >= 0);
        assert_se(secure_bits_from_string("invalid") < 0);
}

TEST(mpol_from_string_basic) {
        assert_se(mpol_from_string("default") == MPOL_DEFAULT);
        assert_se(mpol_from_string("preferred") == MPOL_PREFERRED);
        assert_se(mpol_from_string("bind") == MPOL_BIND);
        assert_se(mpol_from_string("interleave") == MPOL_INTERLEAVE);
        assert_se(mpol_from_string("local") == MPOL_LOCAL);
        assert_se(mpol_from_string("invalid") < 0);
}

TEST(mpol_roundtrip) {
        assert_se(mpol_from_string(mpol_to_string(MPOL_DEFAULT)) == MPOL_DEFAULT);
        assert_se(mpol_from_string(mpol_to_string(MPOL_BIND)) == MPOL_BIND);
        assert_se(mpol_from_string(mpol_to_string(MPOL_INTERLEAVE)) == MPOL_INTERLEAVE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
