/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C shared/ string tables batch 2 vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "boot-entry.h"
#include "import-util.h"
#include "volatile-util.h"
#include "install.h"
#include "discover-image.h"
#include "kernel-image.h"
#include "open-file.h"

/* Rust FFI */
#include "rust/netdev_str_tables.h"

/* ── boot_entry_token_type ────────────────────────────────────────────── */

static void test_boot_entry_token_type(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_MACHINE_ID);
        r_ret = rs_boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_MACHINE_ID);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_AUTO);
        r_ret = rs_boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_AUTO);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = boot_entry_token_type_from_string("literal");
        rv = rs_boot_entry_token_type_from_string("literal");
        assert_se((int)cv == rv);

        cv = boot_entry_token_type_from_string("bogus");
        rv = rs_boot_entry_token_type_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── import_type ──────────────────────────────────────────────────────── */

static void test_import_type(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = import_type_to_string(IMPORT_RAW);
        r_ret = rs_import_type_to_string(IMPORT_RAW);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = import_type_to_string(IMPORT_OCI);
        r_ret = rs_import_type_to_string(IMPORT_OCI);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = import_type_from_string("tar");
        rv = rs_import_type_from_string("tar");
        assert_se((int)cv == rv);
}

/* ── import_verify ────────────────────────────────────────────────────── */

static void test_import_verify(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = import_verify_to_string(IMPORT_VERIFY_NO);
        r_ret = rs_import_verify_to_string(IMPORT_VERIFY_NO);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = import_verify_to_string(IMPORT_VERIFY_SIGNATURE);
        r_ret = rs_import_verify_to_string(IMPORT_VERIFY_SIGNATURE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = import_verify_from_string("checksum");
        rv = rs_import_verify_from_string("checksum");
        assert_se((int)cv == rv);
}

/* ── volatile_mode ────────────────────────────────────────────────────── */

static void test_volatile_mode(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = volatile_mode_to_string(VOLATILE_NO);
        r_ret = rs_volatile_mode_to_string(VOLATILE_NO);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = volatile_mode_to_string(VOLATILE_OVERLAY);
        r_ret = rs_volatile_mode_to_string(VOLATILE_OVERLAY);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = volatile_mode_from_string("state");
        rv = rs_volatile_mode_from_string("state");
        assert_se((int)cv == rv);
}

/* ── unit_file_state ──────────────────────────────────────────────────── */

static void test_unit_file_state(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = unit_file_state_to_string(UNIT_FILE_ENABLED);
        r_ret = rs_unit_file_state_to_string(UNIT_FILE_ENABLED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = unit_file_state_to_string(UNIT_FILE_BAD);
        r_ret = rs_unit_file_state_to_string(UNIT_FILE_BAD);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = unit_file_state_from_string("disabled");
        rv = rs_unit_file_state_from_string("disabled");
        assert_se((int)cv == rv);

        cv = unit_file_state_from_string("bogus");
        rv = rs_unit_file_state_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── preset_action_past_tense (to_string only) ───────────────────────── */

static void test_preset_action_past_tense(void) {
        const char *c_ret, *r_ret;

        c_ret = preset_action_past_tense_to_string(PRESET_ENABLE);
        r_ret = rs_preset_action_past_tense_to_string(PRESET_ENABLE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = preset_action_past_tense_to_string(PRESET_IGNORE);
        r_ret = rs_preset_action_past_tense_to_string(PRESET_IGNORE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

/* ── image_type ───────────────────────────────────────────────────────── */

static void test_image_type(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = image_type_to_string(IMAGE_DIRECTORY);
        r_ret = rs_image_type_to_string(IMAGE_DIRECTORY);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = image_type_to_string(IMAGE_MSTACK);
        r_ret = rs_image_type_to_string(IMAGE_MSTACK);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = image_type_from_string("raw");
        rv = rs_image_type_from_string("raw");
        assert_se((int)cv == rv);
}

/* ── kernel_image_type (to_string only) ──────────────────────────────── */

static void test_kernel_image_type(void) {
        const char *c_ret, *r_ret;

        c_ret = kernel_image_type_to_string(KERNEL_IMAGE_TYPE_UKI);
        r_ret = rs_kernel_image_type_to_string(KERNEL_IMAGE_TYPE_UKI);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = kernel_image_type_to_string(KERNEL_IMAGE_TYPE_PE);
        r_ret = rs_kernel_image_type_to_string(KERNEL_IMAGE_TYPE_PE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

/* ── open_file_flags (bit flags: 1,2,4,8) ────────────────────────────── */

static void test_open_file_flags(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = open_file_flags_to_string(OPENFILE_READ_ONLY);
        r_ret = rs_open_file_flags_to_string(OPENFILE_READ_ONLY);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = open_file_flags_to_string(OPENFILE_GRACEFUL);
        r_ret = rs_open_file_flags_to_string(OPENFILE_GRACEFUL);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = open_file_flags_from_string("append");
        rv = rs_open_file_flags_from_string("append");
        assert_se((int)cv == rv);
}

int main(int argc, char **argv) {
        test_boot_entry_token_type();
        test_import_type();
        test_import_verify();
        test_volatile_mode();
        test_unit_file_state();
        test_preset_action_past_tense();
        test_image_type();
        test_kernel_image_type();
        test_open_file_flags();
        return 0;
}
