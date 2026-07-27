/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "install.h"
#include "tests.h"

TEST(unit_file_state) {
        ASSERT_STREQ(unit_file_state_to_string(UNIT_FILE_ENABLED), "enabled");
        ASSERT_STREQ(unit_file_state_to_string(UNIT_FILE_ENABLED_RUNTIME), "enabled-runtime");
        ASSERT_STREQ(unit_file_state_to_string(UNIT_FILE_LINKED), "linked");
        ASSERT_STREQ(unit_file_state_to_string(UNIT_FILE_MASKED), "masked");
        ASSERT_STREQ(unit_file_state_to_string(UNIT_FILE_STATIC), "static");
        ASSERT_STREQ(unit_file_state_to_string(UNIT_FILE_DISABLED), "disabled");
        ASSERT_STREQ(unit_file_state_to_string(UNIT_FILE_BAD), "bad");
        ASSERT_EQ(unit_file_state_from_string("enabled"), UNIT_FILE_ENABLED);
        ASSERT_EQ(unit_file_state_from_string("masked"), UNIT_FILE_MASKED);
        ASSERT_EQ(unit_file_state_from_string("disabled"), UNIT_FILE_DISABLED);
        ASSERT_EQ(unit_file_state_from_string("invalid"), _UNIT_FILE_STATE_INVALID);
}

TEST(install_change_type) {
        ASSERT_STREQ(install_change_type_to_string(INSTALL_CHANGE_SYMLINK), "symlink");
        ASSERT_STREQ(install_change_type_to_string(INSTALL_CHANGE_UNLINK), "unlink");
        ASSERT_STREQ(install_change_type_to_string(INSTALL_CHANGE_IS_MASKED), "masked");
        ASSERT_STREQ(install_change_type_to_string(INSTALL_CHANGE_IS_DANGLING), "dangling");
        ASSERT_EQ(install_change_type_from_string("symlink"), INSTALL_CHANGE_SYMLINK);
        ASSERT_EQ(install_change_type_from_string("masked"), INSTALL_CHANGE_IS_MASKED);
        ASSERT_EQ(install_change_type_from_string("invalid"), _INSTALL_CHANGE_INVALID);
}

TEST(unit_file_preset_mode) {
        ASSERT_STREQ(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_FULL), "full");
        ASSERT_STREQ(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_ENABLE_ONLY), "enable-only");
        ASSERT_STREQ(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_DISABLE_ONLY), "disable-only");
        ASSERT_EQ(unit_file_preset_mode_from_string("full"), UNIT_FILE_PRESET_FULL);
        ASSERT_EQ(unit_file_preset_mode_from_string("invalid"), _UNIT_FILE_PRESET_MODE_INVALID);
}

/* preset_action_past_tense uses TO_STRING only */
TEST(preset_action_past_tense) {
        ASSERT_STREQ(preset_action_past_tense_to_string(PRESET_UNKNOWN), "unknown");
        ASSERT_STREQ(preset_action_past_tense_to_string(PRESET_ENABLE), "enabled");
        ASSERT_STREQ(preset_action_past_tense_to_string(PRESET_DISABLE), "disabled");
        ASSERT_STREQ(preset_action_past_tense_to_string(PRESET_IGNORE), "ignored");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
