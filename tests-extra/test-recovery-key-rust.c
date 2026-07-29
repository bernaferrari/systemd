/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "recovery-key.h"
#include "tests.h"
#include "rust/recovery_key.h"

/* Recovery key: 32 bytes = 64 modhex chars (no dashes) or 71 chars (with dashes) */

static void assert_normalize_parity(const char *input) {
        _cleanup_free_ char *c_result = NULL;
        _cleanup_free_ char *r_result = NULL;
        int c, r;

        c = normalize_recovery_key(input, &c_result);
        r = rs_normalize_recovery_key(input, &r_result);
        assert_se(c == r);
        if (c >= 0)
                ASSERT_STREQ(c_result, r_result);
        else {
                assert_se(c_result == NULL);
                assert_se(r_result == NULL);
        }
}

/* ── decode_modhex_char ────────────────────────────────────────────────── */

static void test_decode_modhex_char_lowercase(void) {
        /* RUST-CONTRACT: recovery-key-decode */
        assert_se(rs_decode_modhex_char('c') == 0);
        assert_se(rs_decode_modhex_char('b') == 1);
        assert_se(rs_decode_modhex_char('d') == 2);
        assert_se(rs_decode_modhex_char('e') == 3);
        assert_se(rs_decode_modhex_char('f') == 4);
        assert_se(rs_decode_modhex_char('g') == 5);
        assert_se(rs_decode_modhex_char('h') == 6);
        assert_se(rs_decode_modhex_char('i') == 7);
        assert_se(rs_decode_modhex_char('j') == 8);
        assert_se(rs_decode_modhex_char('k') == 9);
        assert_se(rs_decode_modhex_char('l') == 10);
        assert_se(rs_decode_modhex_char('n') == 11);
        assert_se(rs_decode_modhex_char('r') == 12);
        assert_se(rs_decode_modhex_char('t') == 13);
        assert_se(rs_decode_modhex_char('u') == 14);
        assert_se(rs_decode_modhex_char('v') == 15);
}

static void test_decode_modhex_char_uppercase(void) {
        assert_se(rs_decode_modhex_char('C') == 0);
        assert_se(rs_decode_modhex_char('B') == 1);
        assert_se(rs_decode_modhex_char('D') == 2);
        assert_se(rs_decode_modhex_char('V') == 15);
        assert_se(rs_decode_modhex_char('T') == 13);
}

static void test_decode_modhex_char_invalid(void) {
        assert_se(rs_decode_modhex_char('x') < 0);
        assert_se(rs_decode_modhex_char('z') < 0);
        assert_se(rs_decode_modhex_char('a') < 0);
        assert_se(rs_decode_modhex_char('0') < 0);
        assert_se(rs_decode_modhex_char(' ') < 0);
        assert_se(rs_decode_modhex_char('-') < 0);
}

static void test_decode_modhex_char_c_parity(void) {
        static const char inputs[] = "cbdefghijklnrtuvCBDEFGHIJKLNRTUVxza0 -";

        for (size_t i = 0; i < STRLEN(inputs); i++)
                assert_se(decode_modhex_char(inputs[i]) == rs_decode_modhex_char(inputs[i]));
}

/* ── normalize_recovery_key ────────────────────────────────────────────── */

static void test_normalize_null_args(void) {
        char *ret = NULL;
        assert_se(rs_normalize_recovery_key(NULL, &ret) < 0);
        assert_se(rs_normalize_recovery_key("cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd", NULL) < 0);
}

static void test_normalize_wrong_length(void) {
        char *ret = NULL;
        assert_se(rs_normalize_recovery_key("short", &ret) < 0);
        /* 70 chars instead of 71 (one char short) */
        assert_se(rs_normalize_recovery_key("cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbc", &ret) < 0);
}

static void test_normalize_invalid_char(void) {
        char *ret = NULL;
        /* 64 invalid modhex characters exercises validation after allocation. */
        assert_se(rs_normalize_recovery_key("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", &ret) == -EINVAL);
        assert_se(ret == NULL);
}

static void test_normalize_error_does_not_publish_output(void) {
        char sentinel[] = "unchanged";
        char *ret = sentinel;

        assert_se(rs_normalize_recovery_key("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", &ret) == -EINVAL);
        assert_se(ret == sentinel);
}

static void test_normalize_valid_with_dashes(void) {
        char *ret = NULL;
        /* 71 chars: 8 groups of 8 chars separated by 7 dashes */
        assert_se(rs_normalize_recovery_key("cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd", &ret) == 0);
        assert_se(ret);
        assert_se(streq(ret, "cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd"));
        free(ret);
}

static void test_normalize_valid_without_dashes(void) {
        char *ret = NULL;
        /* 64 chars: no dashes */
        assert_se(rs_normalize_recovery_key("cbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcd", &ret) == 0);
        assert_se(ret);
        assert_se(streq(ret, "cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd"));
        free(ret);
}

static void test_normalize_uppercase(void) {
        char *ret = NULL;
        assert_se(rs_normalize_recovery_key("CBCDCBCD-CBCDCBCD-CBCDCBCD-CBCDCBCD-CBCDCBCD-CBCDCBCD-CBCDCBCD-CBCDCBCD", &ret) == 0);
        assert_se(ret);
        assert_se(streq(ret, "cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd"));
        free(ret);
}

static void test_normalize_mixed_case(void) {
        char *ret = NULL;
        assert_se(rs_normalize_recovery_key("CbCdCbCd-CbCdCbCd-CbCdCbCd-CbCdCbCd-CbCdCbCd-CbCdCbCd-CbCdCbCd-CbCdCbCd", &ret) == 0);
        assert_se(ret);
        assert_se(streq(ret, "cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd"));
        free(ret);
}

static void test_normalize_missing_dash(void) {
        char *ret = NULL;
        /* 70 chars: missing a dash (has 6 dashes instead of 7) */
        assert_se(rs_normalize_recovery_key("cbcdcbcdcbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd-cbcdcbcd", &ret) < 0);
}

static void test_normalize_all_zeros(void) {
        char *ret = NULL;
        /* 64 chars of 'c' (modhex 0) */
        assert_se(rs_normalize_recovery_key("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", &ret) == 0);
        assert_se(ret);
        assert_se(streq(ret, "cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc"));
        free(ret);
}

static void test_normalize_all_fs(void) {
        char *ret = NULL;
        /* 64 chars of 'v' (modhex 15) */
        assert_se(rs_normalize_recovery_key("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv", &ret) == 0);
        assert_se(ret);
        assert_se(streq(ret, "vvvvvvvv-vvvvvvvv-vvvvvvvv-vvvvvvvv-vvvvvvvv-vvvvvvvv-vvvvvvvv-vvvvvvvv"));
        free(ret);
}

static void test_normalize_c_parity(void) {
        char c_sentinel[] = "unchanged", r_sentinel[] = "unchanged";
        char *c_result = c_sentinel, *r_result = r_sentinel;

        /* RUST-CONTRACT: recovery-key-normalize */
        assert_normalize_parity("cbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcd");
        assert_normalize_parity("CBCDCBCD-CBCDCBCD-CBCDCBCD-CBCDCBCD-CBCDCBCD-CBCDCBCD-CBCDCBCD-CBCDCBCD");
        assert_normalize_parity("short");
        assert_normalize_parity("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

        assert_se(normalize_recovery_key("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", &c_result) == -EINVAL);
        assert_se(rs_normalize_recovery_key("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", &r_result) == -EINVAL);
        assert_se(c_result == c_sentinel);
        assert_se(r_result == r_sentinel);
}

int main(int argc, char *argv[]) {
        test_decode_modhex_char_lowercase();
        test_decode_modhex_char_uppercase();
        test_decode_modhex_char_invalid();
        test_decode_modhex_char_c_parity();
        test_normalize_null_args();
        test_normalize_wrong_length();
        test_normalize_invalid_char();
        test_normalize_error_does_not_publish_output();
        test_normalize_valid_with_dashes();
        test_normalize_valid_without_dashes();
        test_normalize_uppercase();
        test_normalize_mixed_case();
        test_normalize_missing_dash();
        test_normalize_all_zeros();
        test_normalize_all_fs();
        test_normalize_c_parity();

        return 0;
}
