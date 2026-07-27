/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "install.h"
#include "string-util.h"
#include "tests.h"

TEST(unit_file_state_roundtrip) {
        assert_se(streq(unit_file_state_to_string(UNIT_FILE_ENABLED), "enabled"));
        assert_se(streq(unit_file_state_to_string(UNIT_FILE_DISABLED), "disabled"));
        assert_se(streq(unit_file_state_to_string(UNIT_FILE_MASKED), "masked"));

        assert_se(unit_file_state_from_string("enabled") == UNIT_FILE_ENABLED);
        assert_se(unit_file_state_from_string("disabled") == UNIT_FILE_DISABLED);
        assert_se(unit_file_state_from_string("masked") == UNIT_FILE_MASKED);
        assert_se(unit_file_state_from_string("invalid") == _UNIT_FILE_STATE_INVALID);
}

TEST(install_change_type_roundtrip) {
        assert_se(streq(install_change_type_to_string(INSTALL_CHANGE_SYMLINK), "symlink"));
        assert_se(streq(install_change_type_to_string(INSTALL_CHANGE_UNLINK), "unlink"));
        assert_se(streq(install_change_type_to_string(INSTALL_CHANGE_IS_MASKED), "masked"));

        assert_se(install_change_type_from_string("symlink") == INSTALL_CHANGE_SYMLINK);
        assert_se(install_change_type_from_string("unlink") == INSTALL_CHANGE_UNLINK);
}

TEST(unit_file_preset_mode_roundtrip) {
        assert_se(streq(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_FULL), "full"));
        assert_se(streq(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_ENABLE_ONLY), "enable-only"));
        assert_se(streq(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_DISABLE_ONLY), "disable-only"));

        assert_se(unit_file_preset_mode_from_string("full") == UNIT_FILE_PRESET_FULL);
        assert_se(unit_file_preset_mode_from_string("enable-only") == UNIT_FILE_PRESET_ENABLE_ONLY);
        assert_se(unit_file_preset_mode_from_string("disable-only") == UNIT_FILE_PRESET_DISABLE_ONLY);
}

TEST(preset_action_past_tense_to_string) {
        assert_se(preset_action_past_tense_to_string(PRESET_ENABLE) != NULL);
        assert_se(preset_action_past_tense_to_string(PRESET_DISABLE) != NULL);
        assert_se(preset_action_past_tense_to_string(PRESET_IGNORE) != NULL);
}

TEST(install_change_type_valid) {
        assert_se(INSTALL_CHANGE_TYPE_VALID(INSTALL_CHANGE_SYMLINK));
        assert_se(INSTALL_CHANGE_TYPE_VALID(INSTALL_CHANGE_UNLINK));
        assert_se(!INSTALL_CHANGE_TYPE_VALID(_INSTALL_CHANGE_TYPE_MAX));
        /* _INSTALL_CHANGE_INVALID = -EINVAL, which is within the valid range */
        assert_se(INSTALL_CHANGE_TYPE_VALID(_INSTALL_CHANGE_INVALID));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
