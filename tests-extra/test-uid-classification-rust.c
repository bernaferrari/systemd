/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C uid-classification inline functions vs Rust */

#include <assert.h>
#include <stdint.h>
#include "tests.h"
#include "uid-classification.h"
#include "rust/uid_classification.h"

static void test_uid_is_greeter(void) {
        uid_t min = GREETER_UID_MIN, max = GREETER_UID_MAX;

        assert_se(uid_is_greeter(min) == rs_uid_is_greeter(min));
        assert_se(uid_is_greeter(max) == rs_uid_is_greeter(max));
        if (min > 0)
                assert_se(uid_is_greeter(min - 1) == rs_uid_is_greeter(min - 1));
        if (max < UINT32_MAX)
                assert_se(uid_is_greeter(max + 1) == rs_uid_is_greeter(max + 1));
        assert_se(uid_is_greeter(0) == rs_uid_is_greeter(0));
        assert_se(uid_is_greeter(UINT32_MAX) == rs_uid_is_greeter(UINT32_MAX));
}

static void test_uid_is_dynamic(void) {
        uid_t min = DYNAMIC_UID_MIN, max = DYNAMIC_UID_MAX;

        assert_se(uid_is_dynamic(min) == rs_uid_is_dynamic(min));
        assert_se(uid_is_dynamic(max) == rs_uid_is_dynamic(max));
        if (min > 0)
                assert_se(uid_is_dynamic(min - 1) == rs_uid_is_dynamic(min - 1));
        if (max < UINT32_MAX)
                assert_se(uid_is_dynamic(max + 1) == rs_uid_is_dynamic(max + 1));
        assert_se(uid_is_dynamic(0) == rs_uid_is_dynamic(0));
        assert_se(gid_is_dynamic(min) == rs_gid_is_dynamic(min));
        assert_se(gid_is_dynamic(max) == rs_gid_is_dynamic(max));
        assert_se(gid_is_dynamic(0) == rs_gid_is_dynamic(0));
        if (min > 0)
                assert_se(gid_is_dynamic(min - 1) == rs_gid_is_dynamic(min - 1));
        if (max < UINT32_MAX)
                assert_se(gid_is_dynamic(max + 1) == rs_gid_is_dynamic(max + 1));
        assert_se(gid_is_dynamic(UINT32_MAX) == rs_gid_is_dynamic(UINT32_MAX));
}

static void test_uid_is_container(void) {
        uid_t min = CONTAINER_UID_MIN, max = CONTAINER_UID_MAX;

        assert_se(uid_is_container(min) == rs_uid_is_container(min));
        assert_se(uid_is_container(max) == rs_uid_is_container(max));
        if (min > 0)
                assert_se(uid_is_container(min - 1) == rs_uid_is_container(min - 1));
        if (max < UINT32_MAX)
                assert_se(uid_is_container(max + 1) == rs_uid_is_container(max + 1));
        assert_se(uid_is_container(0) == rs_uid_is_container(0));
        assert_se(gid_is_container(min) == rs_gid_is_container(min));
        assert_se(gid_is_container(max) == rs_gid_is_container(max));
        assert_se(gid_is_container(0) == rs_gid_is_container(0));
        if (min > 0)
                assert_se(gid_is_container(min - 1) == rs_gid_is_container(min - 1));
        if (max < UINT32_MAX)
                assert_se(gid_is_container(max + 1) == rs_gid_is_container(max + 1));
        assert_se(gid_is_container(UINT32_MAX) == rs_gid_is_container(UINT32_MAX));
}

static void test_uid_is_foreign(void) {
        uid_t min = FOREIGN_UID_MIN, max = FOREIGN_UID_MAX;

        assert_se(uid_is_foreign(min) == rs_uid_is_foreign(min));
        assert_se(uid_is_foreign(max) == rs_uid_is_foreign(max));
        if (min > 0)
                assert_se(uid_is_foreign(min - 1) == rs_uid_is_foreign(min - 1));
        if (max < UINT32_MAX)
                assert_se(uid_is_foreign(max + 1) == rs_uid_is_foreign(max + 1));
        assert_se(uid_is_foreign(0) == rs_uid_is_foreign(0));
        assert_se(gid_is_foreign(min) == rs_gid_is_foreign(min));
        assert_se(gid_is_foreign(max) == rs_gid_is_foreign(max));
        assert_se(gid_is_foreign(0) == rs_gid_is_foreign(0));
        if (min > 0)
                assert_se(gid_is_foreign(min - 1) == rs_gid_is_foreign(min - 1));
        if (max < UINT32_MAX)
                assert_se(gid_is_foreign(max + 1) == rs_gid_is_foreign(max + 1));
        assert_se(gid_is_foreign(UINT32_MAX) == rs_gid_is_foreign(UINT32_MAX));
}

static void test_uid_is_transient(void) {
        assert_se(uid_is_transient(DYNAMIC_UID_MIN) == rs_uid_is_transient(DYNAMIC_UID_MIN));
        assert_se(uid_is_transient(CONTAINER_UID_MIN) == rs_uid_is_transient(CONTAINER_UID_MIN));
        assert_se(uid_is_transient(0) == rs_uid_is_transient(0));
        assert_se(uid_is_transient(UINT32_MAX) == rs_uid_is_transient(UINT32_MAX));
        assert_se(gid_is_transient(DYNAMIC_UID_MIN) == rs_gid_is_transient(DYNAMIC_UID_MIN));
        assert_se(gid_is_transient(CONTAINER_UID_MIN) == rs_gid_is_transient(CONTAINER_UID_MIN));
        assert_se(gid_is_transient(0) == rs_gid_is_transient(0));
        assert_se(gid_is_transient(GREETER_UID_MIN) == rs_gid_is_transient(GREETER_UID_MIN));
        assert_se(gid_is_transient(UINT32_MAX) == rs_gid_is_transient(UINT32_MAX));
}

int main(int argc, char **argv) {
        test_uid_is_greeter();
        test_uid_is_dynamic();
        test_uid_is_container();
        test_uid_is_foreign();
        test_uid_is_transient();
        return 0;
}
