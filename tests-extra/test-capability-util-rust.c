/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: capability-util.h inline functions vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "capability-util.h"
#include "rust/capability_util.h"

/* ── capability_is_set ─────────────────────────────────────────────────── */

/* RUST-CONTRACT: capability-is-set */
static void test_capability_is_set(void) {
        /* UNSET (UINT64_MAX) means "not set" */
        assert_se(capability_is_set(UINT64_MAX) == rs_capability_is_set(UINT64_MAX));
        assert_se(!capability_is_set(UINT64_MAX));

        /* Any other value means "set" */
        assert_se(capability_is_set(0) == rs_capability_is_set(0));
        assert_se(capability_is_set(0));
        assert_se(capability_is_set(1) == rs_capability_is_set(1));
        assert_se(capability_is_set(1));
        assert_se(capability_is_set(UINT64_MAX - 1) == rs_capability_is_set(UINT64_MAX - 1));
        assert_se(capability_is_set(UINT64_MAX - 1));
}

/* ── capability_quintet_is_set ─────────────────────────────────────────── */

/* RUST-CONTRACT: capability-quintet-is-set */
static void test_capability_quintet_is_set(void) {
        struct CapabilityQuintet q;
        uint64_t *fields[] = {
                &q.effective,
                &q.bounding,
                &q.inheritable,
                &q.permitted,
                &q.ambient,
        };

        /* All unset → not set */
        memset(&q, 0xFF, sizeof(q));
        assert_se(capability_quintet_is_set(&q) == rs_capability_quintet_is_set(&q));
        assert_se(!capability_quintet_is_set(&q));

        /* One field set → set */
        memset(&q, 0xFF, sizeof(q));
        q.effective = 0;
        assert_se(capability_quintet_is_set(&q) == rs_capability_quintet_is_set(&q));
        assert_se(capability_quintet_is_set(&q));

        /* Every individual field participates in the aggregate predicate. */
        for (size_t i = 0; i < ELEMENTSOF(fields); i++) {
                memset(&q, 0xFF, sizeof(q));
                *fields[i] = UINT64_C(1) << i;
                assert_se(capability_quintet_is_set(&q) == rs_capability_quintet_is_set(&q));
                assert_se(capability_quintet_is_set(&q));
        }

        /* All fields set → set */
        memset(&q, 0, sizeof(q));
        assert_se(capability_quintet_is_set(&q) == rs_capability_quintet_is_set(&q));
        assert_se(capability_quintet_is_set(&q));

        /* NULL → not set */
        assert_se(!rs_capability_quintet_is_set(NULL));
}

/* ── capability_quintet_is_fully_set ───────────────────────────────────── */

/* RUST-CONTRACT: capability-quintet-is-fully-set */
static void test_capability_quintet_is_fully_set(void) {
        struct CapabilityQuintet q;
        uint64_t *fields[] = {
                &q.effective,
                &q.bounding,
                &q.inheritable,
                &q.permitted,
                &q.ambient,
        };

        /* All unset → not fully set */
        memset(&q, 0xFF, sizeof(q));
        assert_se(capability_quintet_is_fully_set(&q) == rs_capability_quintet_is_fully_set(&q));
        assert_se(!capability_quintet_is_fully_set(&q));

        /* Any individual unset field makes the complete predicate false. */
        for (size_t i = 0; i < ELEMENTSOF(fields); i++) {
                memset(&q, 0, sizeof(q));
                *fields[i] = UINT64_MAX;
                assert_se(capability_quintet_is_fully_set(&q) == rs_capability_quintet_is_fully_set(&q));
                assert_se(!capability_quintet_is_fully_set(&q));
        }

        /* One field unset → not fully set */
        memset(&q, 0, sizeof(q));
        q.effective = UINT64_MAX;
        assert_se(capability_quintet_is_fully_set(&q) == rs_capability_quintet_is_fully_set(&q));
        assert_se(!capability_quintet_is_fully_set(&q));

        /* All fields set → fully set */
        memset(&q, 0, sizeof(q));
        assert_se(capability_quintet_is_fully_set(&q) == rs_capability_quintet_is_fully_set(&q));
        assert_se(capability_quintet_is_fully_set(&q));

        /* NULL → not fully set */
        assert_se(!rs_capability_quintet_is_fully_set(NULL));
}

/* ── capability_quintet_equal ──────────────────────────────────────────── */

/* RUST-CONTRACT: capability-quintet-equal */
static void test_capability_quintet_equal(void) {
        struct CapabilityQuintet a, b;
        uint64_t *a_fields[] = {
                &a.effective,
                &a.bounding,
                &a.inheritable,
                &a.permitted,
                &a.ambient,
        };

        /* Equal quintets */
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        assert_se(capability_quintet_equal(&a, &b) == rs_capability_quintet_equal(&a, &b));
        assert_se(capability_quintet_equal(&a, &b));

        /* Different quintets */
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        b.effective = 1;
        assert_se(capability_quintet_equal(&a, &b) == rs_capability_quintet_equal(&a, &b));
        assert_se(!capability_quintet_equal(&a, &b));

        /* Equality compares every field, not only the effective set. */
        for (size_t i = 0; i < ELEMENTSOF(a_fields); i++) {
                memset(&a, 0, sizeof(a));
                memset(&b, 0, sizeof(b));
                *a_fields[i] = UINT64_C(1) << i;
                assert_se(capability_quintet_equal(&a, &b) == rs_capability_quintet_equal(&a, &b));
                assert_se(!capability_quintet_equal(&a, &b));
        }

        /* All unset — equal */
        memset(&a, 0xFF, sizeof(a));
        memset(&b, 0xFF, sizeof(b));
        assert_se(capability_quintet_equal(&a, &b) == rs_capability_quintet_equal(&a, &b));
        assert_se(capability_quintet_equal(&a, &b));

        /* NULL, NULL — equal */
        assert_se(rs_capability_quintet_equal(NULL, NULL));

        /* One NULL — not equal */
        memset(&a, 0, sizeof(a));
        assert_se(!rs_capability_quintet_equal(&a, NULL));
        assert_se(!rs_capability_quintet_equal(NULL, &a));
}

int main(int argc, char **argv) {
        test_capability_is_set();
        test_capability_quintet_is_set();
        test_capability_quintet_is_fully_set();
        test_capability_quintet_equal();
        return 0;
}
