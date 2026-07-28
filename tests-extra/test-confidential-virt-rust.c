/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: confidential-virt-to-string */
/* RUST-CONTRACT: confidential-virt-from-string */

#include <assert.h>
#include <string.h>

#include "tests.h"
#include "confidential-virt.h"
#include "rust/confidential_virt.h"

/* ── confidential_virtualization_to_string ─────────────────────────────── */

static void test_confidential_virt_to_string_all(void) {
        static const struct {
                int v;
                const char *expected;
        } table[] = {
                { CONFIDENTIAL_VIRTUALIZATION_NONE,     "none" },
                { CONFIDENTIAL_VIRTUALIZATION_SEV,      "sev" },
                { CONFIDENTIAL_VIRTUALIZATION_SEV_ES,   "sev-es" },
                { CONFIDENTIAL_VIRTUALIZATION_SEV_SNP,  "sev-snp" },
                { CONFIDENTIAL_VIRTUALIZATION_TDX,      "tdx" },
                { CONFIDENTIAL_VIRTUALIZATION_PROTVIRT, "protvirt" },
                { CONFIDENTIAL_VIRTUALIZATION_CCA,      "cca" },
        };

        for (int i = 0; i < (int)ELEMENTSOF(table); i++) {
                const char *r_c = confidential_virtualization_to_string(table[i].v);
                const char *r_r = rs_confidential_virtualization_to_string(table[i].v);
                assert_se(r_c && r_r);
                assert_se(streq(r_c, r_r));
                assert_se(streq(r_c, table[i].expected));
        }
}

static void test_confidential_virt_to_string_invalid(void) {
        const char *r_c = confidential_virtualization_to_string(-1);
        const char *r_r = rs_confidential_virtualization_to_string(-1);
        assert_se(!r_c && !r_r);

        r_c = confidential_virtualization_to_string(99);
        r_r = rs_confidential_virtualization_to_string(99);
        assert_se(!r_c && !r_r);
}

/* ── confidential_virtualization_from_string ───────────────────────────── */

static void test_confidential_virt_from_string_all(void) {
        static const struct {
                const char *name;
                int expected;
        } table[] = {
                { "none",     CONFIDENTIAL_VIRTUALIZATION_NONE },
                { "sev",      CONFIDENTIAL_VIRTUALIZATION_SEV },
                { "sev-es",   CONFIDENTIAL_VIRTUALIZATION_SEV_ES },
                { "sev-snp",  CONFIDENTIAL_VIRTUALIZATION_SEV_SNP },
                { "tdx",      CONFIDENTIAL_VIRTUALIZATION_TDX },
                { "protvirt", CONFIDENTIAL_VIRTUALIZATION_PROTVIRT },
                { "cca",      CONFIDENTIAL_VIRTUALIZATION_CCA },
        };

        for (int i = 0; i < (int)ELEMENTSOF(table); i++) {
                int r_c = confidential_virtualization_from_string(table[i].name);
                int r_r = rs_confidential_virtualization_from_string(table[i].name);
                assert_se(r_c == r_r);
                assert_se(r_c >= 0);
                assert_se(r_c == table[i].expected);
        }
}

static void test_confidential_virt_from_string_invalid(void) {
        int r_c = confidential_virtualization_from_string("foobar");
        int r_r = rs_confidential_virtualization_from_string("foobar");
        assert_se(r_c == r_r);
        assert_se(r_c < 0);

        r_c = confidential_virtualization_from_string("SEV");
        r_r = rs_confidential_virtualization_from_string("SEV");
        assert_se(r_c == r_r);
        assert_se(r_c < 0);

        r_c = confidential_virtualization_from_string(NULL);
        r_r = rs_confidential_virtualization_from_string(NULL);
        assert_se(r_c == r_r);
        assert_se(r_c == -EINVAL);

        static const char non_utf8[] = { 's', 'e', 'v', (char) 0xff, 0 };
        r_c = confidential_virtualization_from_string(non_utf8);
        r_r = rs_confidential_virtualization_from_string(non_utf8);
        assert_se(r_c == r_r);
        assert_se(r_c == -EINVAL);
}

/* ── roundtrip ─────────────────────────────────────────────────────────── */

static void test_confidential_virt_roundtrip(void) {
        for (int v = 0; v <= 6; v++) {
                const char *s_c = confidential_virtualization_to_string(v);
                const char *s_r = rs_confidential_virtualization_to_string(v);
                assert_se(s_c && s_r);
                assert_se(streq(s_c, s_r));

                int r_c = confidential_virtualization_from_string(s_c);
                int r_r = rs_confidential_virtualization_from_string(s_r);
                assert_se(r_c == r_r);
                assert_se(r_c == v);
        }
}

int main(int argc, char *argv[]) {
        test_confidential_virt_to_string_all();
        test_confidential_virt_to_string_invalid();
        test_confidential_virt_from_string_all();
        test_confidential_virt_from_string_invalid();
        test_confidential_virt_roundtrip();

        return 0;
}
