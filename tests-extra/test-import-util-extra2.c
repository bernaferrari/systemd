/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "import-util.h"
#include "tests.h"

TEST(import_type_to_from_string) {
        assert_se(streq(import_type_to_string(IMPORT_RAW), "raw"));
        assert_se(streq(import_type_to_string(IMPORT_TAR), "tar"));
        assert_se(streq(import_type_to_string(IMPORT_OCI), "oci"));

        assert_se(import_type_from_string("raw") == IMPORT_RAW);
        assert_se(import_type_from_string("tar") == IMPORT_TAR);
        assert_se(import_type_from_string("oci") == IMPORT_OCI);
        assert_se(import_type_from_string("invalid") < 0);
}

TEST(import_verify_to_from_string) {
        assert_se(streq(import_verify_to_string(IMPORT_VERIFY_NO), "no"));
        assert_se(streq(import_verify_to_string(IMPORT_VERIFY_CHECKSUM), "checksum"));
        assert_se(streq(import_verify_to_string(IMPORT_VERIFY_SIGNATURE), "signature"));

        assert_se(import_verify_from_string("no") == IMPORT_VERIFY_NO);
        assert_se(import_verify_from_string("checksum") == IMPORT_VERIFY_CHECKSUM);
        assert_se(import_verify_from_string("signature") == IMPORT_VERIFY_SIGNATURE);
        assert_se(import_verify_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
