/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C architecture vs Rust rs_architecture */

#include <string.h>

#include "architecture.h"
#include "string-util.h"
#include "rust/architecture.h"

/* ── architecture_to_string ────────────────────────────────────────────── */

static void test_architecture_to_string(void) {
        /* Valid architectures */
        assert_se(streq(architecture_to_string(ARCHITECTURE_ALPHA), "alpha"));
        assert_se(streq(rs_architecture_to_string(ARCHITECTURE_ALPHA), "alpha"));

        assert_se(streq(architecture_to_string(ARCHITECTURE_X86_64), "x86-64"));
        assert_se(streq(rs_architecture_to_string(ARCHITECTURE_X86_64), "x86-64"));

        assert_se(streq(architecture_to_string(ARCHITECTURE_ARM64), "arm64"));
        assert_se(streq(rs_architecture_to_string(ARCHITECTURE_ARM64), "arm64"));

        assert_se(streq(architecture_to_string(ARCHITECTURE_MIPS64_LE), "mips64-le"));
        assert_se(streq(rs_architecture_to_string(ARCHITECTURE_MIPS64_LE), "mips64-le"));

        assert_se(streq(architecture_to_string(ARCHITECTURE_PPC64_LE), "ppc64-le"));
        assert_se(streq(rs_architecture_to_string(ARCHITECTURE_PPC64_LE), "ppc64-le"));

        assert_se(streq(architecture_to_string(ARCHITECTURE_RISCV64), "riscv64"));
        assert_se(streq(rs_architecture_to_string(ARCHITECTURE_RISCV64), "riscv64"));

        /* Invalid value */
        assert_se(architecture_to_string(-1) == NULL);
        assert_se(rs_architecture_to_string(-1) == NULL);

        assert_se(architecture_to_string(_ARCHITECTURE_MAX) == NULL);
        assert_se(rs_architecture_to_string(_ARCHITECTURE_MAX) == NULL);

        assert_se(architecture_to_string(999) == NULL);
        assert_se(rs_architecture_to_string(999) == NULL);

        /* Spot-check all entries */
        for (int i = 0; i < _ARCHITECTURE_MAX; i++) {
                const char *c_str = architecture_to_string(i);
                const char *r_str = rs_architecture_to_string(i);
                assert_se(c_str != NULL);
                assert_se(r_str != NULL);
                assert_se(streq(c_str, r_str));
        }
}

/* ── architecture_from_string ──────────────────────────────────────────── */

static void test_architecture_from_string(void) {
        int c_ret, r_ret;

        /* Valid strings */
        c_ret = architecture_from_string("x86-64");
        r_ret = rs_architecture_from_string("x86-64");
        assert_se(c_ret == ARCHITECTURE_X86_64);
        assert_se(c_ret == r_ret);

        c_ret = architecture_from_string("arm64");
        r_ret = rs_architecture_from_string("arm64");
        assert_se(c_ret == ARCHITECTURE_ARM64);
        assert_se(c_ret == r_ret);

        c_ret = architecture_from_string("alpha");
        r_ret = rs_architecture_from_string("alpha");
        assert_se(c_ret == ARCHITECTURE_ALPHA);
        assert_se(c_ret == r_ret);

        /* Case sensitive (DEFINE_STRING_TABLE_LOOKUP uses streq_ptr) */
        c_ret = architecture_from_string("X86-64");
        r_ret = rs_architecture_from_string("X86-64");
        assert_se(c_ret < 0); /* case mismatch → not found */
        assert_se(c_ret == r_ret);

        c_ret = architecture_from_string("ARM64");
        r_ret = rs_architecture_from_string("ARM64");
        assert_se(c_ret < 0);
        assert_se(c_ret == r_ret);

        /* Invalid string */
        c_ret = architecture_from_string("nonexistent");
        r_ret = rs_architecture_from_string("nonexistent");
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* NULL */
        c_ret = architecture_from_string(NULL);
        r_ret = rs_architecture_from_string(NULL);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Round-trip: to_string → from_string */
        for (int i = 0; i < _ARCHITECTURE_MAX; i++) {
                const char *s = architecture_to_string(i);
                assert_se(s != NULL);
                c_ret = architecture_from_string(s);
                r_ret = rs_architecture_from_string(s);
                assert_se(c_ret == i);
                assert_se(r_ret == i);
        }
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_architecture_to_string();
        test_architecture_from_string();

        return 0;
}
