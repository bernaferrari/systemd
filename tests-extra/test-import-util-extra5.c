/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "import-util.h"
#include "string-util.h"
#include "tests.h"

TEST(import_type_roundtrip) {
        assert_se(streq(import_type_to_string(IMPORT_RAW), "raw"));
        assert_se(streq(import_type_to_string(IMPORT_TAR), "tar"));
        assert_se(streq(import_type_to_string(IMPORT_OCI), "oci"));

        assert_se(import_type_from_string("raw") == IMPORT_RAW);
        assert_se(import_type_from_string("tar") == IMPORT_TAR);
        assert_se(import_type_from_string("oci") == IMPORT_OCI);

        /* Invalid */
        assert_se(import_type_from_string("invalid") == _IMPORT_TYPE_INVALID);
        assert_se(import_type_from_string("") == _IMPORT_TYPE_INVALID);
}

TEST(import_verify_roundtrip) {
        assert_se(streq(import_verify_to_string(IMPORT_VERIFY_NO), "no"));
        assert_se(streq(import_verify_to_string(IMPORT_VERIFY_CHECKSUM), "checksum"));
        assert_se(streq(import_verify_to_string(IMPORT_VERIFY_SIGNATURE), "signature"));

        assert_se(import_verify_from_string("no") == IMPORT_VERIFY_NO);
        assert_se(import_verify_from_string("checksum") == IMPORT_VERIFY_CHECKSUM);
        assert_se(import_verify_from_string("signature") == IMPORT_VERIFY_SIGNATURE);

        /* Invalid */
        assert_se(import_verify_from_string("invalid") == _IMPORT_VERIFY_INVALID);
        assert_se(import_verify_from_string("") == _IMPORT_VERIFY_INVALID);
}

TEST(tar_strip_suffixes) {
        _cleanup_free_ char *result = NULL;

        assert_se(tar_strip_suffixes("image.tar", &result) == 0);
        assert_se(streq(result, "image"));

        result = mfree(result);
        assert_se(tar_strip_suffixes("image.tar.xz", &result) == 0);
        assert_se(streq(result, "image"));

        result = mfree(result);
        assert_se(tar_strip_suffixes("image.tar.gz", &result) == 0);
        assert_se(streq(result, "image"));

        result = mfree(result);
        assert_se(tar_strip_suffixes("image.tar.bz2", &result) == 0);
        assert_se(streq(result, "image"));

        result = mfree(result);
        assert_se(tar_strip_suffixes("image.tar.zst", &result) == 0);
        assert_se(streq(result, "image"));

        result = mfree(result);
        assert_se(tar_strip_suffixes("image.tgz", &result) == 0);
        assert_se(streq(result, "image"));
}

TEST(raw_strip_suffixes) {
        _cleanup_free_ char *result = NULL;

        assert_se(raw_strip_suffixes("image.raw", &result) == 0);
        assert_se(streq(result, "image"));

        result = mfree(result);
        assert_se(raw_strip_suffixes("image.raw.xz", &result) == 0);
        assert_se(streq(result, "image"));

        result = mfree(result);
        assert_se(raw_strip_suffixes("image.raw.gz", &result) == 0);
        assert_se(streq(result, "image"));

        result = mfree(result);
        assert_se(raw_strip_suffixes("image.raw.bz2", &result) == 0);
        assert_se(streq(result, "image"));

        result = mfree(result);
        assert_se(raw_strip_suffixes("image.raw.zst", &result) == 0);
        assert_se(streq(result, "image"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
