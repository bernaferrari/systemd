/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootspec.h"
#include "string-util.h"
#include "tests.h"

TEST(boot_filename_extract_tries_basic) {
        _cleanup_free_ char *stripped = NULL;
        unsigned tries_left = 0, tries_done = 0;
        int r;

        /* Filename with tries: name+3.efi → stripped=name.efi, left=3 */
        r = boot_filename_extract_tries("name+3.efi", &stripped, &tries_left, &tries_done);
        assert_se(r >= 0);
        assert_se(streq(stripped, "name.efi"));
        assert_se(tries_left == 3);
        assert_se(tries_done == UINT_MAX);
}

TEST(boot_filename_extract_tries_with_done) {
        _cleanup_free_ char *stripped = NULL;
        unsigned tries_left = 0, tries_done = 0;
        int r;

        /* Filename with both tries: name+3-1.efi → left=3, done=1 */
        r = boot_filename_extract_tries("name+3-1.efi", &stripped, &tries_left, &tries_done);
        assert_se(r >= 0);
        assert_se(streq(stripped, "name.efi"));
        assert_se(tries_left == 3);
        assert_se(tries_done == 1);
}

TEST(boot_filename_extract_tries_no_tries) {
        _cleanup_free_ char *stripped = NULL;
        unsigned tries_left = 99, tries_done = 99;
        int r;

        /* No tries marker → stripped = original, tries = UINT_MAX */
        r = boot_filename_extract_tries("simple.conf", &stripped, &tries_left, &tries_done);
        assert_se(r >= 0);
        assert_se(streq(stripped, "simple.conf"));
        assert_se(tries_left == UINT_MAX);
        assert_se(tries_done == UINT_MAX);
}

TEST(boot_filename_extract_tries_no_suffix) {
        _cleanup_free_ char *stripped = NULL;
        unsigned tries_left = 99, tries_done = 99;
        int r;

        /* No dot suffix → goes to nothing */
        r = boot_filename_extract_tries("nosuffix", &stripped, &tries_left, &tries_done);
        assert_se(r >= 0);
        assert_se(streq(stripped, "nosuffix"));
        assert_se(tries_left == UINT_MAX);
        assert_se(tries_done == UINT_MAX);
}

TEST(boot_filename_extract_tries_complex_name) {
        _cleanup_free_ char *stripped = NULL;
        unsigned tries_left = 0, tries_done = 0;
        int r;

        /* Complex name with path-like components */
        r = boot_filename_extract_tries("my-kernel+5.conf", &stripped, &tries_left, &tries_done);
        assert_se(r >= 0);
        assert_se(streq(stripped, "my-kernel.conf"));
        assert_se(tries_left == 5);
}

TEST(boot_entry_type_roundtrip) {
        for (int i = 0; i < _BOOT_ENTRY_TYPE_MAX; i++) {
                const char *s = boot_entry_type_to_string(i);
                assert_se(s);
                BootEntryType v = boot_entry_type_from_string(s);
                assert_se(v == i);
        }
}

TEST(boot_entry_type_from_string_invalid) {
        assert_se(boot_entry_type_from_string("nonsense") == _BOOT_ENTRY_TYPE_INVALID);
        assert_se(boot_entry_type_from_string("") == _BOOT_ENTRY_TYPE_INVALID);
}

TEST(boot_entry_type_description) {
        for (int i = 0; i < _BOOT_ENTRY_TYPE_MAX; i++) {
                const char *s = boot_entry_type_description_to_string(i);
                assert_se(s);
                assert_se(!isempty(s));
        }
}

TEST(boot_entry_source_description) {
        for (int i = 0; i < _BOOT_ENTRY_SOURCE_MAX; i++) {
                const char *s = boot_entry_source_description_to_string(i);
                assert_se(s);
                assert_se(!isempty(s));
        }
}

TEST(boot_entry_source_to_string) {
        for (int i = 0; i < _BOOT_ENTRY_SOURCE_MAX; i++) {
                const char *s = boot_entry_source_to_string(i);
                assert_se(s);
                assert_se(!isempty(s));
        }
}

TEST(boot_config_find_entry_empty) {
        BootConfig config = BOOT_CONFIG_NULL;
        /* Empty config → no entries → NULL */
        assert_se(boot_config_find_entry(&config, "test") == NULL);
}

TEST(boot_entry_title_macro) {
        BootEntry entry = {
                .id = (char*) "test-id",
                .title = NULL,
                .show_title = NULL,
        };
        /* No title or show_title → falls back to id */
        assert_se(streq(boot_entry_title(&entry), "test-id"));

        entry.title = (char*) "my-title";
        /* title set → uses title */
        assert_se(streq(boot_entry_title(&entry), "my-title"));

        entry.show_title = (char*) "show-this";
        /* show_title takes precedence */
        assert_se(streq(boot_entry_title(&entry), "show-this"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
