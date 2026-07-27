/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C vs Rust for securebits (from_string/to_string/strv), ioprio, vlan, condition */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "strv.h"
#include "securebits-util.h"
#include "ioprio-util.h"
#include "vlan-util.h"
#include "kbd-util.h"
#include "condition.h"
#include "rust/shared_facades/policy.h"

/* The condition helper remains a separate partial surface. */
bool rs_condition_takes_path(int t);

/* -- securebits from_string / to_string / strv ------------------------------ */

static void test_secure_bits_from_string(void) {
        assert_se(rs_secure_bits_from_string("") == 0);
        assert_se(rs_secure_bits_from_string("noroot") == (1 << SECURE_NOROOT));
        assert_se(rs_secure_bits_from_string("keep-caps") == (1 << SECURE_KEEP_CAPS));
        assert_se(rs_secure_bits_from_string("noroot keep-caps") ==
                  ((1 << SECURE_NOROOT) | (1 << SECURE_KEEP_CAPS)));
        assert_se(rs_secure_bits_from_string("noroot no-setuid-fixup keep-caps") ==
                  ((1 << SECURE_NOROOT) | (1 << SECURE_NO_SETUID_FIXUP) | (1 << SECURE_KEEP_CAPS)));
        assert_se(rs_secure_bits_from_string("noroot-locked") == (1 << SECURE_NOROOT_LOCKED));
        assert_se(rs_secure_bits_from_string("no-setuid-fixup-locked") == (1 << SECURE_NO_SETUID_FIXUP_LOCKED));
        assert_se(rs_secure_bits_from_string("keep-caps-locked") == (1 << SECURE_KEEP_CAPS_LOCKED));
        assert_se(rs_secure_bits_from_string("unknown") == 0);
        assert_se(rs_secure_bits_from_string("noroot unknown keep-caps") ==
                  ((1 << SECURE_NOROOT) | (1 << SECURE_KEEP_CAPS)));
        assert_se(rs_secure_bits_from_string("'noroot' \"keep-caps\"") ==
                  ((1 << SECURE_NOROOT) | (1 << SECURE_KEEP_CAPS)));
}

static void test_secure_bits_to_string(void) {
        _cleanup_free_ char *c_str = NULL;
        _cleanup_free_ char *rs_str = NULL;
        int r;

        r = secure_bits_to_string_alloc(0, &c_str);
        assert_se(r == 0);
        r = rs_secure_bits_to_string_alloc(0, &rs_str);
        assert_se(r == 0);
        assert_se(streq_ptr(c_str, rs_str));
        assert_se(streq(c_str, ""));

        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        int bits = (1 << SECURE_NOROOT) | (1 << SECURE_KEEP_CAPS);
        r = secure_bits_to_string_alloc(bits, &c_str);
        assert_se(r == 0);
        r = rs_secure_bits_to_string_alloc(bits, &rs_str);
        assert_se(r == 0);
        assert_se(streq(c_str, rs_str));

        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        /* Unknown bits are ignored by both implementations. */
        bits = 1 << 30;
        assert_se(secure_bits_to_string_alloc(bits, &c_str) == 0);
        assert_se(rs_secure_bits_to_string_alloc(bits, &rs_str) == 0);
        assert_se(streq(c_str, rs_str));

        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        bits = (1 << SECURE_NOROOT) | (1 << SECURE_NO_SETUID_FIXUP) | (1 << SECURE_KEEP_CAPS);
        r = secure_bits_to_string_alloc(bits, &c_str);
        assert_se(r == 0);
        r = rs_secure_bits_to_string_alloc(bits, &rs_str);
        assert_se(r == 0);
        assert_se(streq(c_str, rs_str));
}

static void test_secure_bits_to_strv(void) {
        _cleanup_strv_free_ char **c_sv = NULL;
        _cleanup_strv_free_ char **rs_sv = NULL;
        int r;
        int bits;

        bits = 0;
        r = secure_bits_to_strv(bits, &c_sv);
        assert_se(r == 0);
        r = rs_secure_bits_to_strv(bits, &rs_sv);
        assert_se(r == 0);
        assert_se(strv_isempty(c_sv));
        assert_se(strv_isempty(rs_sv));

        c_sv = strv_free(c_sv);
        rs_sv = strv_free(rs_sv);

        bits = (1 << SECURE_NOROOT);
        r = secure_bits_to_strv(bits, &c_sv);
        assert_se(r == 0);
        r = rs_secure_bits_to_strv(bits, &rs_sv);
        assert_se(r == 0);
        assert_se(strv_length(c_sv) == 1);
        assert_se(strv_length(rs_sv) == 1);
        assert_se(streq(c_sv[0], rs_sv[0]));

        c_sv = strv_free(c_sv);
        rs_sv = strv_free(rs_sv);

        bits = (1 << SECURE_NOROOT) | (1 << SECURE_NO_SETUID_FIXUP) | (1 << SECURE_KEEP_CAPS);
        r = secure_bits_to_strv(bits, &c_sv);
        assert_se(r == 0);
        r = rs_secure_bits_to_strv(bits, &rs_sv);
        assert_se(r == 0);
        assert_se(strv_length(c_sv) == 3);
        assert_se(strv_length(rs_sv) == 3);
        for (int i = 0; i < 3; i++) {
                assert_se(streq(c_sv[i], rs_sv[i]));
        }
}

/* -- ioprio (class_is_valid, priority_is_valid, parse_priority) ------------- */

static void test_ioprio_class(void) {
        assert_se(rs_ioprio_class_is_valid(IOPRIO_CLASS_NONE) == ioprio_class_is_valid(IOPRIO_CLASS_NONE));
        assert_se(rs_ioprio_class_is_valid(IOPRIO_CLASS_RT) == ioprio_class_is_valid(IOPRIO_CLASS_RT));
        assert_se(rs_ioprio_class_is_valid(IOPRIO_CLASS_BE) == ioprio_class_is_valid(IOPRIO_CLASS_BE));
        assert_se(rs_ioprio_class_is_valid(IOPRIO_CLASS_IDLE) == ioprio_class_is_valid(IOPRIO_CLASS_IDLE));
        assert_se(rs_ioprio_class_is_valid(4) == false);
}

static void test_ioprio_priority(void) {
        assert_se(rs_ioprio_priority_is_valid(0) == ioprio_priority_is_valid(0));
        assert_se(rs_ioprio_priority_is_valid(0) == true);
        assert_se(rs_ioprio_priority_is_valid(7) == ioprio_priority_is_valid(7));
        assert_se(rs_ioprio_priority_is_valid(7) == true);
        assert_se(rs_ioprio_priority_is_valid(8) == ioprio_priority_is_valid(8));
        assert_se(rs_ioprio_priority_is_valid(8) == false);

        int c_val, rs_val;
        assert_se(ioprio_parse_priority("4", &c_val) >= 0);
        assert_se(rs_ioprio_parse_priority("4", &rs_val) >= 0);
        assert_se(c_val == rs_val);
        assert_se(c_val == 4);

        assert_se(ioprio_parse_priority("0", &c_val) >= 0);
        assert_se(rs_ioprio_parse_priority("0", &rs_val) >= 0);
        assert_se(c_val == rs_val);

        assert_se(ioprio_parse_priority("-1", &c_val) < 0);
        rs_val = 4711;
        assert_se(rs_ioprio_parse_priority("-1", &rs_val) < 0);
        assert_se(rs_val == 4711);

        assert_se(ioprio_parse_priority("8", &c_val) < 0);
        rs_val = 4711;
        assert_se(rs_ioprio_parse_priority("8", &rs_val) < 0);
        assert_se(rs_val == 4711);
}

/* -- vlan (vlanid_is_valid, parse_vid_range) ------------------------------- */
/* NOTE: parse_vlanid is already tested in test-gpt-util-rust.c */

static void test_vlanid(void) {
        assert_se(rs_vlanid_is_valid(0) == vlanid_is_valid(0));
        assert_se(rs_vlanid_is_valid(0) == true);
        assert_se(rs_vlanid_is_valid(4094) == vlanid_is_valid(4094));
        assert_se(rs_vlanid_is_valid(4094) == true);
        assert_se(rs_vlanid_is_valid(4095) == vlanid_is_valid(4095));
        assert_se(rs_vlanid_is_valid(4095) == false);
}

static void test_parse_vid_range(void) {
        uint16_t c_vid, c_vid_end, rs_vid, rs_vid_end;
        int r;

        r = parse_vid_range("100-200", &c_vid, &c_vid_end);
        assert_se(r >= 0);
        r = rs_parse_vid_range("100-200", &rs_vid, &rs_vid_end);
        assert_se(r >= 0);
        assert_se(c_vid == rs_vid && c_vid_end == rs_vid_end);

        r = parse_vid_range("0", &c_vid, &c_vid_end);
        assert_se(r >= 0);
        r = rs_parse_vid_range("0", &rs_vid, &rs_vid_end);
        assert_se(r >= 0);
        assert_se(c_vid == rs_vid && c_vid_end == rs_vid_end);

        r = parse_vid_range("5000-6000", &c_vid, &c_vid_end);
        assert_se(r < 0);
        rs_vid = 47;
        rs_vid_end = 11;
        r = rs_parse_vid_range("5000-6000", &rs_vid, &rs_vid_end);
        assert_se(r < 0);
        assert_se(rs_vid == 47 && rs_vid_end == 11);

        r = parse_vid_range("200-100", &c_vid, &c_vid_end);
        assert_se(r < 0);
        rs_vid = 47;
        rs_vid_end = 11;
        r = rs_parse_vid_range("200-100", &rs_vid, &rs_vid_end);
        assert_se(r < 0);
        assert_se(rs_vid == 47 && rs_vid_end == 11);
}

/* -- condition ------------------------------------------------------------- */

static void test_condition_takes_path(void) {
        assert_se(rs_condition_takes_path(CONDITION_PATH_EXISTS) == condition_takes_path(CONDITION_PATH_EXISTS));
        assert_se(rs_condition_takes_path(CONDITION_PATH_EXISTS) == true);
        assert_se(rs_condition_takes_path(CONDITION_PATH_IS_DIRECTORY) == condition_takes_path(CONDITION_PATH_IS_DIRECTORY));
        assert_se(rs_condition_takes_path(CONDITION_PATH_IS_DIRECTORY) == true);
        assert_se(rs_condition_takes_path(CONDITION_NEEDS_UPDATE) == condition_takes_path(CONDITION_NEEDS_UPDATE));
        assert_se(rs_condition_takes_path(CONDITION_NEEDS_UPDATE) == true);
        assert_se(rs_condition_takes_path(CONDITION_FILE_NOT_EMPTY) == condition_takes_path(CONDITION_FILE_NOT_EMPTY));
        assert_se(rs_condition_takes_path(CONDITION_FILE_NOT_EMPTY) == true);
        assert_se(rs_condition_takes_path(CONDITION_ARCHITECTURE) == condition_takes_path(CONDITION_ARCHITECTURE));
        assert_se(rs_condition_takes_path(CONDITION_ARCHITECTURE) == false);
        assert_se(rs_condition_takes_path(CONDITION_VIRTUALIZATION) == condition_takes_path(CONDITION_VIRTUALIZATION));
        assert_se(rs_condition_takes_path(CONDITION_VIRTUALIZATION) == false);
}

/* -- keymap ---------------------------------------------------------------- */

static void test_keymap_is_valid(void) {
        assert_se(rs_keymap_is_valid("us") == keymap_is_valid("us"));
        assert_se(rs_keymap_is_valid("us") == true);
        assert_se(rs_keymap_is_valid("us-dvorak") == keymap_is_valid("us-dvorak"));
        assert_se(rs_keymap_is_valid("us-dvorak") == true);
        assert_se(rs_keymap_is_valid("") == keymap_is_valid(""));
        assert_se(rs_keymap_is_valid("") == false);
        assert_se(rs_keymap_is_valid("a/b") == keymap_is_valid("a/b"));
        assert_se(rs_keymap_is_valid("a/b") == false); /* slash not allowed by filename_is_valid */
        assert_se(rs_keymap_is_valid("us\001") == keymap_is_valid("us\001"));
        assert_se(rs_keymap_is_valid("us\001") == false); /* control char */
        assert_se(rs_keymap_is_valid("us\"x") == keymap_is_valid("us\"x"));
        assert_se(rs_keymap_is_valid("us\"x") == false); /* quote not safe */
        assert_se(rs_keymap_is_valid("us*") == keymap_is_valid("us*"));
        assert_se(rs_keymap_is_valid("us*") == false); /* glob not safe */
        assert_se(rs_keymap_is_valid("café") == keymap_is_valid("café"));
        assert_se(rs_keymap_is_valid("café") == true);
}

int main(int argc, char **argv) {
        test_secure_bits_from_string();
        test_secure_bits_to_string();
        test_secure_bits_to_strv();
        test_ioprio_class();
        test_ioprio_priority();
        test_vlanid();
        test_parse_vid_range();
        test_condition_takes_path();
        test_keymap_is_valid();
        return 0;
}
