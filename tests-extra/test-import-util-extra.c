/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "import-util.h"
#include "tests.h"

TEST(import_type_to_string) {
        ASSERT_STREQ(import_type_to_string(IMPORT_RAW), "raw");
        ASSERT_STREQ(import_type_to_string(IMPORT_TAR), "tar");
        ASSERT_STREQ(import_type_to_string(IMPORT_OCI), "oci");
}

TEST(import_type_from_string) {
        ASSERT_EQ(import_type_from_string("raw"), IMPORT_RAW);
        ASSERT_EQ(import_type_from_string("tar"), IMPORT_TAR);
        ASSERT_EQ(import_type_from_string("oci"), IMPORT_OCI);
        ASSERT_EQ(import_type_from_string("invalid"), _IMPORT_TYPE_INVALID);
}

TEST(import_verify_to_string) {
        ASSERT_STREQ(import_verify_to_string(IMPORT_VERIFY_NO), "no");
        ASSERT_STREQ(import_verify_to_string(IMPORT_VERIFY_CHECKSUM), "checksum");
        ASSERT_STREQ(import_verify_to_string(IMPORT_VERIFY_SIGNATURE), "signature");
}

TEST(import_verify_from_string) {
        ASSERT_EQ(import_verify_from_string("no"), IMPORT_VERIFY_NO);
        ASSERT_EQ(import_verify_from_string("checksum"), IMPORT_VERIFY_CHECKSUM);
        ASSERT_EQ(import_verify_from_string("signature"), IMPORT_VERIFY_SIGNATURE);
        ASSERT_EQ(import_verify_from_string("invalid"), _IMPORT_VERIFY_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
