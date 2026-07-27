/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "gpt.h"
#include "string-util.h"
#include "tests.h"

TEST(partition_designator_to_from_string) {
        assert_se(streq(partition_designator_to_string(PARTITION_ROOT), "root"));
        assert_se(streq(partition_designator_to_string(PARTITION_USR), "usr"));
        assert_se(streq(partition_designator_to_string(PARTITION_HOME), "home"));
        assert_se(streq(partition_designator_to_string(PARTITION_SRV), "srv"));
        assert_se(streq(partition_designator_to_string(PARTITION_ESP), "esp"));
        assert_se(streq(partition_designator_to_string(PARTITION_XBOOTLDR), "xbootldr"));
        assert_se(streq(partition_designator_to_string(PARTITION_SWAP), "swap"));
        assert_se(streq(partition_designator_to_string(PARTITION_ROOT_VERITY), "root-verity"));
        assert_se(streq(partition_designator_to_string(PARTITION_USR_VERITY), "usr-verity"));
        assert_se(streq(partition_designator_to_string(PARTITION_ROOT_VERITY_SIG), "root-verity-sig"));
        assert_se(streq(partition_designator_to_string(PARTITION_USR_VERITY_SIG), "usr-verity-sig"));
        assert_se(streq(partition_designator_to_string(PARTITION_TMP), "tmp"));
        assert_se(streq(partition_designator_to_string(PARTITION_VAR), "var"));

        assert_se(partition_designator_from_string("root") == PARTITION_ROOT);
        assert_se(partition_designator_from_string("usr") == PARTITION_USR);
        assert_se(partition_designator_from_string("home") == PARTITION_HOME);
        assert_se(partition_designator_from_string("esp") == PARTITION_ESP);
        assert_se(partition_designator_from_string("swap") == PARTITION_SWAP);
        assert_se(partition_designator_from_string("invalid") < 0);
}

TEST(partition_mountpoint_to_string) {
        assert_se(streq(partition_mountpoint_to_string(PARTITION_ROOT), "/"));
        assert_se(streq(partition_mountpoint_to_string(PARTITION_USR), "/usr"));
        assert_se(streq(partition_mountpoint_to_string(PARTITION_HOME), "/home"));
        assert_se(streq(partition_mountpoint_to_string(PARTITION_SRV), "/srv"));
        assert_se(streq(partition_mountpoint_to_string(PARTITION_XBOOTLDR), "/boot"));
        assert_se(streq(partition_mountpoint_to_string(PARTITION_TMP), "/var/tmp"));
        assert_se(streq(partition_mountpoint_to_string(PARTITION_VAR), "/var"));
        /* ESP has multiple mountpoints, returns first */
        assert_se(partition_mountpoint_to_string(PARTITION_ESP) != NULL);
        /* No mountpoint for swap */
        assert_se(partition_mountpoint_to_string(PARTITION_SWAP) == NULL);
}

TEST(partition_designator_is_versioned) {
        assert_se(partition_designator_is_versioned(PARTITION_ROOT));
        assert_se(partition_designator_is_versioned(PARTITION_USR));
        assert_se(partition_designator_is_versioned(PARTITION_ROOT_VERITY));
        assert_se(partition_designator_is_versioned(PARTITION_USR_VERITY));
        assert_se(partition_designator_is_versioned(PARTITION_ROOT_VERITY_SIG));
        assert_se(partition_designator_is_versioned(PARTITION_USR_VERITY_SIG));

        assert_se(!partition_designator_is_versioned(PARTITION_HOME));
        assert_se(!partition_designator_is_versioned(PARTITION_ESP));
        assert_se(!partition_designator_is_versioned(PARTITION_SWAP));
}

TEST(partition_verity_functions) {
        assert_se(partition_verity_hash_of(PARTITION_ROOT) == PARTITION_ROOT_VERITY);
        assert_se(partition_verity_hash_of(PARTITION_USR) == PARTITION_USR_VERITY);
        assert_se(partition_verity_hash_of(PARTITION_HOME) == _PARTITION_DESIGNATOR_INVALID);

        assert_se(partition_verity_sig_of(PARTITION_ROOT) == PARTITION_ROOT_VERITY_SIG);
        assert_se(partition_verity_sig_of(PARTITION_USR) == PARTITION_USR_VERITY_SIG);
        assert_se(partition_verity_sig_of(PARTITION_HOME) == _PARTITION_DESIGNATOR_INVALID);

        assert_se(partition_verity_hash_to_data(PARTITION_ROOT_VERITY) == PARTITION_ROOT);
        assert_se(partition_verity_hash_to_data(PARTITION_USR_VERITY) == PARTITION_USR);
        assert_se(partition_verity_hash_to_data(PARTITION_HOME) == _PARTITION_DESIGNATOR_INVALID);

        assert_se(partition_verity_sig_to_data(PARTITION_ROOT_VERITY_SIG) == PARTITION_ROOT);
        assert_se(partition_verity_sig_to_data(PARTITION_USR_VERITY_SIG) == PARTITION_USR);
        assert_se(partition_verity_sig_to_data(PARTITION_HOME) == _PARTITION_DESIGNATOR_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
