/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "install.h"
#include "tests.h"

TEST(unit_file_state_to_from_string) {
        ASSERT_STREQ(unit_file_state_to_string(UNIT_FILE_ENABLED), "enabled");
        ASSERT_STREQ(unit_file_state_to_string(UNIT_FILE_DISABLED), "disabled");
        ASSERT_STREQ(unit_file_state_to_string(UNIT_FILE_MASKED), "masked");
        ASSERT_STREQ(unit_file_state_to_string(UNIT_FILE_STATIC), "static");

        ASSERT_EQ(unit_file_state_from_string("enabled"), UNIT_FILE_ENABLED);
        ASSERT_EQ(unit_file_state_from_string("disabled"), UNIT_FILE_DISABLED);
        ASSERT_EQ(unit_file_state_from_string("masked"), UNIT_FILE_MASKED);
        ASSERT_EQ(unit_file_state_from_string("static"), UNIT_FILE_STATIC);
        ASSERT_LT(unit_file_state_from_string("invalid"), 0);
}

TEST(install_change_type_to_from_string) {
        ASSERT_STREQ(install_change_type_to_string(INSTALL_CHANGE_SYMLINK), "symlink");
        ASSERT_STREQ(install_change_type_to_string(INSTALL_CHANGE_UNLINK), "unlink");

        ASSERT_EQ(install_change_type_from_string("symlink"), INSTALL_CHANGE_SYMLINK);
        ASSERT_EQ(install_change_type_from_string("unlink"), INSTALL_CHANGE_UNLINK);
        ASSERT_LT(install_change_type_from_string("invalid"), 0);
}

TEST(unit_file_preset_mode_to_from_string) {
        ASSERT_STREQ(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_FULL), "full");
        ASSERT_STREQ(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_ENABLE_ONLY), "enable-only");
        ASSERT_STREQ(unit_file_preset_mode_to_string(UNIT_FILE_PRESET_DISABLE_ONLY), "disable-only");

        ASSERT_EQ(unit_file_preset_mode_from_string("full"), UNIT_FILE_PRESET_FULL);
        ASSERT_EQ(unit_file_preset_mode_from_string("enable-only"), UNIT_FILE_PRESET_ENABLE_ONLY);
        ASSERT_EQ(unit_file_preset_mode_from_string("disable-only"), UNIT_FILE_PRESET_DISABLE_ONLY);
        ASSERT_LT(unit_file_preset_mode_from_string("invalid"), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
