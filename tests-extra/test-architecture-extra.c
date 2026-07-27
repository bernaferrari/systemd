/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "architecture.h"
#include "tests.h"

TEST(architecture) {
        ASSERT_STREQ(architecture_to_string(ARCHITECTURE_X86_64), "x86-64");
        ASSERT_STREQ(architecture_to_string(ARCHITECTURE_X86), "x86");
        ASSERT_STREQ(architecture_to_string(ARCHITECTURE_ARM64), "arm64");
        ASSERT_STREQ(architecture_to_string(ARCHITECTURE_ARM), "arm");
        ASSERT_STREQ(architecture_to_string(ARCHITECTURE_RISCV64), "riscv64");
        ASSERT_STREQ(architecture_to_string(ARCHITECTURE_PPC64), "ppc64");
        ASSERT_STREQ(architecture_to_string(ARCHITECTURE_S390X), "s390x");
        ASSERT_EQ(architecture_from_string("x86-64"), ARCHITECTURE_X86_64);
        ASSERT_EQ(architecture_from_string("arm64"), ARCHITECTURE_ARM64);
        ASSERT_EQ(architecture_from_string("invalid"), _ARCHITECTURE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
