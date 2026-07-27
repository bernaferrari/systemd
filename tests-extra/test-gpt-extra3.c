/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "gpt.h"
#include "sd-id128.h"
#include "string-util.h"
#include "tests.h"

TEST(partition_designator_is_versioned) {
        assert_se(partition_designator_is_versioned(PARTITION_ROOT));
        assert_se(partition_designator_is_versioned(PARTITION_USR));
        assert_se(partition_designator_is_versioned(PARTITION_ROOT_VERITY));
        assert_se(partition_designator_is_versioned(PARTITION_USR_VERITY));
        assert_se(partition_designator_is_versioned(PARTITION_ROOT_VERITY_SIG));
        assert_se(partition_designator_is_versioned(PARTITION_USR_VERITY_SIG));

        assert_se(!partition_designator_is_versioned(PARTITION_HOME));
        assert_se(!partition_designator_is_versioned(PARTITION_SRV));
        assert_se(!partition_designator_is_versioned(PARTITION_ESP));
        assert_se(!partition_designator_is_versioned(PARTITION_XBOOTLDR));
        assert_se(!partition_designator_is_versioned(PARTITION_SWAP));
        assert_se(!partition_designator_is_versioned(PARTITION_TMP));
        assert_se(!partition_designator_is_versioned(PARTITION_VAR));
}

TEST(partition_verity_hash_of) {
        assert_se(partition_verity_hash_of(PARTITION_ROOT) == PARTITION_ROOT_VERITY);
        assert_se(partition_verity_hash_of(PARTITION_USR) == PARTITION_USR_VERITY);
        assert_se(partition_verity_hash_of(PARTITION_HOME) == _PARTITION_DESIGNATOR_INVALID);
        assert_se(partition_verity_hash_of(PARTITION_SWAP) == _PARTITION_DESIGNATOR_INVALID);
}

TEST(partition_verity_sig_of) {
        assert_se(partition_verity_sig_of(PARTITION_ROOT) == PARTITION_ROOT_VERITY_SIG);
        assert_se(partition_verity_sig_of(PARTITION_USR) == PARTITION_USR_VERITY_SIG);
        assert_se(partition_verity_sig_of(PARTITION_HOME) == _PARTITION_DESIGNATOR_INVALID);
}

TEST(partition_verity_hash_to_data) {
        assert_se(partition_verity_hash_to_data(PARTITION_ROOT_VERITY) == PARTITION_ROOT);
        assert_se(partition_verity_hash_to_data(PARTITION_USR_VERITY) == PARTITION_USR);
        assert_se(partition_verity_hash_to_data(PARTITION_ROOT) == _PARTITION_DESIGNATOR_INVALID);
}

TEST(partition_verity_sig_to_data) {
        assert_se(partition_verity_sig_to_data(PARTITION_ROOT_VERITY_SIG) == PARTITION_ROOT);
        assert_se(partition_verity_sig_to_data(PARTITION_USR_VERITY_SIG) == PARTITION_USR);
        assert_se(partition_verity_sig_to_data(PARTITION_ROOT) == _PARTITION_DESIGNATOR_INVALID);
}

TEST(partition_verity_to_data) {
        assert_se(partition_verity_to_data(PARTITION_ROOT_VERITY) == PARTITION_ROOT);
        assert_se(partition_verity_to_data(PARTITION_USR_VERITY) == PARTITION_USR);
        assert_se(partition_verity_to_data(PARTITION_ROOT_VERITY_SIG) == PARTITION_ROOT);
        assert_se(partition_verity_to_data(PARTITION_USR_VERITY_SIG) == PARTITION_USR);
}

TEST(partition_designator_is_verity_hash) {
        assert_se(partition_designator_is_verity_hash(PARTITION_ROOT_VERITY));
        assert_se(partition_designator_is_verity_hash(PARTITION_USR_VERITY));
        assert_se(!partition_designator_is_verity_hash(PARTITION_ROOT));
        assert_se(!partition_designator_is_verity_hash(PARTITION_HOME));
}

TEST(partition_designator_is_verity_sig) {
        assert_se(partition_designator_is_verity_sig(PARTITION_ROOT_VERITY_SIG));
        assert_se(partition_designator_is_verity_sig(PARTITION_USR_VERITY_SIG));
        assert_se(!partition_designator_is_verity_sig(PARTITION_ROOT));
}

TEST(partition_mountpoint_to_string_basic) {
        const char *s;

        /* mountpoint is nulstr format (null-separated strings) */
        s = partition_mountpoint_to_string(PARTITION_ROOT);
        assert_se(s && streq(s, "/"));

        s = partition_mountpoint_to_string(PARTITION_HOME);
        assert_se(s && streq(s, "/home"));

        s = partition_mountpoint_to_string(PARTITION_ESP);
        assert_se(s && streq(s, "/efi"));

        s = partition_mountpoint_to_string(PARTITION_XBOOTLDR);
        assert_se(s && streq(s, "/boot"));

        s = partition_mountpoint_to_string(PARTITION_SRV);
        assert_se(s && streq(s, "/srv"));

        s = partition_mountpoint_to_string(PARTITION_TMP);
        assert_se(s && streq(s, "/var/tmp"));

        s = partition_mountpoint_to_string(PARTITION_VAR);
        assert_se(s && streq(s, "/var"));

        /* Some designators have no mountpoint */
        assert_se(partition_mountpoint_to_string(PARTITION_SWAP) == NULL);
        assert_se(partition_mountpoint_to_string(PARTITION_ROOT_VERITY) == NULL);
}

TEST(partition_designator_roundtrip) {
        for (int i = 0; i < _PARTITION_DESIGNATOR_MAX; i++) {
                const char *s = partition_designator_to_string(i);
                if (s) {
                        int v = partition_designator_from_string(s);
                        assert_se(v == i);
                }
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
