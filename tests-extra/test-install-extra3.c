/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "install.h"

TEST(unit_file_state_to_from_string) {
        assert_se(streq(unit_file_state_to_string(UNIT_FILE_ENABLED), "enabled"));
        assert_se(streq(unit_file_state_to_string(UNIT_FILE_DISABLED), "disabled"));
        assert_se(streq(unit_file_state_to_string(UNIT_FILE_MASKED), "masked"));
        assert_se(streq(unit_file_state_to_string(UNIT_FILE_STATIC), "static"));
        assert_se(streq(unit_file_state_to_string(UNIT_FILE_INDIRECT), "indirect"));
        assert_se(streq(unit_file_state_to_string(UNIT_FILE_GENERATED), "generated"));
        assert_se(streq(unit_file_state_to_string(UNIT_FILE_TRANSIENT), "transient"));

        assert_se(unit_file_state_from_string("enabled") == UNIT_FILE_ENABLED);
        assert_se(unit_file_state_from_string("disabled") == UNIT_FILE_DISABLED);
        assert_se(unit_file_state_from_string("masked") == UNIT_FILE_MASKED);
        assert_se(unit_file_state_from_string("static") == UNIT_FILE_STATIC);
        assert_se(unit_file_state_from_string("invalid") < 0);
}

TEST(install_change_type_to_from_string) {
        assert_se(streq(install_change_type_to_string(INSTALL_CHANGE_SYMLINK), "symlink"));
        assert_se(streq(install_change_type_to_string(INSTALL_CHANGE_UNLINK), "unlink"));
        assert_se(streq(install_change_type_to_string(INSTALL_CHANGE_IS_MASKED), "masked"));
        assert_se(streq(install_change_type_to_string(INSTALL_CHANGE_IS_DANGLING), "dangling"));

        assert_se(install_change_type_from_string("symlink") == INSTALL_CHANGE_SYMLINK);
        assert_se(install_change_type_from_string("unlink") == INSTALL_CHANGE_UNLINK);
        assert_se(install_change_type_from_string("masked") == INSTALL_CHANGE_IS_MASKED);
        assert_se(install_change_type_from_string("dangling") == INSTALL_CHANGE_IS_DANGLING);
        assert_se(install_change_type_from_string("invalid") < 0);
}

TEST(unit_file_preset_mode_to_from_string) {
        assert_se(streq(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_FULL), "full"));
        assert_se(streq(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_ENABLE_ONLY), "enable-only"));
        assert_se(streq(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_DISABLE_ONLY), "disable-only"));

        assert_se(unit_file_preset_mode_from_string("full") == UNIT_FILE_PRESET_FULL);
        assert_se(unit_file_preset_mode_from_string("enable-only") == UNIT_FILE_PRESET_ENABLE_ONLY);
        assert_se(unit_file_preset_mode_from_string("disable-only") == UNIT_FILE_PRESET_DISABLE_ONLY);
        assert_se(unit_file_preset_mode_from_string("invalid") < 0);
}

TEST(preset_action_past_tense_to_string) {
        /* TO_STRING only */
        assert_se(preset_action_past_tense_to_string(PRESET_ENABLE) != NULL);
        assert_se(streq(preset_action_past_tense_to_string(PRESET_ENABLE), "enabled"));
        assert_se(streq(preset_action_past_tense_to_string(PRESET_DISABLE), "disabled"));
        assert_se(streq(preset_action_past_tense_to_string(PRESET_IGNORE), "ignored"));
        assert_se(streq(preset_action_past_tense_to_string(PRESET_UNKNOWN), "unknown"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
