/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "capsule-util.h"
#include "tests.h"

TEST(capsule_name_is_valid_basic) {
        ASSERT_TRUE(capsule_name_is_valid("my-capsule"));
}

TEST(capsule_name_is_valid_simple) {
        ASSERT_TRUE(capsule_name_is_valid("a"));
}

TEST(capsule_name_is_valid_with_digits) {
        ASSERT_TRUE(capsule_name_is_valid("capsule-123"));
}

TEST(capsule_name_is_valid_empty) {
        ASSERT_FALSE(capsule_name_is_valid(""));
}

TEST(capsule_name_is_valid_null) {
        /* NULL should return false (filename_is_valid returns false) */
        ASSERT_FALSE(capsule_name_is_valid(NULL));
}

TEST(capsule_name_is_valid_dot) {
        ASSERT_FALSE(capsule_name_is_valid("."));
        ASSERT_FALSE(capsule_name_is_valid(".."));
}

TEST(capsule_name_is_valid_slash) {
        ASSERT_FALSE(capsule_name_is_valid("foo/bar"));
}

TEST(capsule_name_is_valid_leading_dot) {
        ASSERT_FALSE(capsule_name_is_valid(".hidden"));
}

TEST(capsule_name_is_valid_trailing_dot) {
        /* filename_is_valid rejects trailing dots */
        ASSERT_FALSE(capsule_name_is_valid("foo."));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
