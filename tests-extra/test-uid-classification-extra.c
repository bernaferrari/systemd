/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "uid-classification.h"
#include "tests.h"

TEST(uid_is_greeter) {
        ASSERT_TRUE(uid_is_greeter(GREETER_UID_MIN));
        ASSERT_TRUE(uid_is_greeter((GREETER_UID_MIN + GREETER_UID_MAX) / 2));
        ASSERT_TRUE(uid_is_greeter(GREETER_UID_MAX));
        ASSERT_FALSE(uid_is_greeter(GREETER_UID_MIN - 1));
        ASSERT_FALSE(uid_is_greeter(GREETER_UID_MAX + 1));
        ASSERT_FALSE(uid_is_greeter(0));
        ASSERT_FALSE(uid_is_greeter(1000));
}

TEST(uid_is_dynamic) {
        ASSERT_TRUE(uid_is_dynamic(DYNAMIC_UID_MIN));
        ASSERT_TRUE(uid_is_dynamic((DYNAMIC_UID_MIN + DYNAMIC_UID_MAX) / 2));
        ASSERT_TRUE(uid_is_dynamic(DYNAMIC_UID_MAX));
        ASSERT_FALSE(uid_is_dynamic(DYNAMIC_UID_MIN - 1));
        ASSERT_FALSE(uid_is_dynamic(DYNAMIC_UID_MAX + 1));
        ASSERT_FALSE(uid_is_dynamic(0));
        ASSERT_FALSE(uid_is_dynamic(1000));
}

TEST(gid_is_dynamic) {
        ASSERT_TRUE(gid_is_dynamic(DYNAMIC_UID_MIN));
        ASSERT_TRUE(gid_is_dynamic(DYNAMIC_UID_MAX));
        ASSERT_FALSE(gid_is_dynamic(0));
        ASSERT_FALSE(gid_is_dynamic(1000));
}

TEST(uid_is_container) {
        ASSERT_TRUE(uid_is_container(CONTAINER_UID_MIN));
        ASSERT_TRUE(uid_is_container((CONTAINER_UID_MIN + CONTAINER_UID_MAX) / 2));
        ASSERT_TRUE(uid_is_container(CONTAINER_UID_MAX));
        ASSERT_FALSE(uid_is_container(CONTAINER_UID_MIN - 1));
        ASSERT_FALSE(uid_is_container(CONTAINER_UID_MAX + 1));
        ASSERT_FALSE(uid_is_container(0));
        ASSERT_FALSE(uid_is_container(1000));
}

TEST(gid_is_container) {
        ASSERT_TRUE(gid_is_container(CONTAINER_UID_MIN));
        ASSERT_TRUE(gid_is_container(CONTAINER_UID_MAX));
        ASSERT_FALSE(gid_is_container(0));
}

TEST(uid_is_foreign) {
        ASSERT_TRUE(uid_is_foreign(FOREIGN_UID_MIN));
        ASSERT_TRUE(uid_is_foreign((FOREIGN_UID_MIN + FOREIGN_UID_MAX) / 2));
        ASSERT_TRUE(uid_is_foreign(FOREIGN_UID_MAX));
        ASSERT_FALSE(uid_is_foreign(FOREIGN_UID_MIN - 1));
        ASSERT_FALSE(uid_is_foreign(FOREIGN_UID_MAX + 1));
        ASSERT_FALSE(uid_is_foreign(0));
        ASSERT_FALSE(uid_is_foreign(1000));
}

TEST(gid_is_foreign) {
        ASSERT_TRUE(gid_is_foreign(FOREIGN_UID_MIN));
        ASSERT_TRUE(gid_is_foreign(FOREIGN_UID_MAX));
        ASSERT_FALSE(gid_is_foreign(0));
}

TEST(uid_is_transient) {
        /* Transient = container OR dynamic */
        ASSERT_TRUE(uid_is_transient(DYNAMIC_UID_MIN));
        ASSERT_TRUE(uid_is_transient(DYNAMIC_UID_MAX));
        ASSERT_TRUE(uid_is_transient(CONTAINER_UID_MIN));
        ASSERT_TRUE(uid_is_transient((CONTAINER_UID_MIN + CONTAINER_UID_MAX) / 2));
        ASSERT_FALSE(uid_is_transient(0));
        ASSERT_FALSE(uid_is_transient(1000));
        ASSERT_FALSE(uid_is_transient(GREETER_UID_MIN)); /* greeter is not transient */
}

TEST(gid_is_transient) {
        ASSERT_TRUE(gid_is_transient(DYNAMIC_UID_MIN));
        ASSERT_TRUE(gid_is_transient(CONTAINER_UID_MIN));
        ASSERT_FALSE(gid_is_transient(0));
        ASSERT_FALSE(gid_is_transient(1000));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
