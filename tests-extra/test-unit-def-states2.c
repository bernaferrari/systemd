/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "unit-def.h"
#include "tests.h"

TEST(mount_state) {
        ASSERT_STREQ(mount_state_to_string(MOUNT_DEAD), "dead");
        ASSERT_STREQ(mount_state_to_string(MOUNT_MOUNTING), "mounting");
        ASSERT_STREQ(mount_state_to_string(MOUNT_MOUNTED), "mounted");
        ASSERT_STREQ(mount_state_to_string(MOUNT_REMOUNTING), "remounting");
        ASSERT_STREQ(mount_state_to_string(MOUNT_UNMOUNTING), "unmounting");
        ASSERT_STREQ(mount_state_to_string(MOUNT_FAILED), "failed");
        ASSERT_EQ(mount_state_from_string("mounted"), MOUNT_MOUNTED);
        ASSERT_EQ(mount_state_from_string("invalid"), _MOUNT_STATE_INVALID);
}

TEST(path_state) {
        ASSERT_STREQ(path_state_to_string(PATH_DEAD), "dead");
        ASSERT_STREQ(path_state_to_string(PATH_WAITING), "waiting");
        ASSERT_STREQ(path_state_to_string(PATH_RUNNING), "running");
        ASSERT_STREQ(path_state_to_string(PATH_FAILED), "failed");
        ASSERT_EQ(path_state_from_string("running"), PATH_RUNNING);
        ASSERT_EQ(path_state_from_string("invalid"), _PATH_STATE_INVALID);
}

TEST(scope_state) {
        ASSERT_STREQ(scope_state_to_string(SCOPE_DEAD), "dead");
        ASSERT_STREQ(scope_state_to_string(SCOPE_RUNNING), "running");
        ASSERT_STREQ(scope_state_to_string(SCOPE_ABANDONED), "abandoned");
        ASSERT_STREQ(scope_state_to_string(SCOPE_FAILED), "failed");
        ASSERT_EQ(scope_state_from_string("running"), SCOPE_RUNNING);
        ASSERT_EQ(scope_state_from_string("invalid"), _SCOPE_STATE_INVALID);
}

TEST(service_state) {
        ASSERT_STREQ(service_state_to_string(SERVICE_DEAD), "dead");
        ASSERT_STREQ(service_state_to_string(SERVICE_RUNNING), "running");
        ASSERT_STREQ(service_state_to_string(SERVICE_EXITED), "exited");
        ASSERT_STREQ(service_state_to_string(SERVICE_FAILED), "failed");
        ASSERT_STREQ(service_state_to_string(SERVICE_AUTO_RESTART), "auto-restart");
        ASSERT_EQ(service_state_from_string("running"), SERVICE_RUNNING);
        ASSERT_EQ(service_state_from_string("failed"), SERVICE_FAILED);
        ASSERT_EQ(service_state_from_string("invalid"), _SERVICE_STATE_INVALID);
}

TEST(slice_state) {
        ASSERT_STREQ(slice_state_to_string(SLICE_DEAD), "dead");
        ASSERT_STREQ(slice_state_to_string(SLICE_ACTIVE), "active");
        ASSERT_EQ(slice_state_from_string("active"), SLICE_ACTIVE);
        ASSERT_EQ(slice_state_from_string("invalid"), _SLICE_STATE_INVALID);
}

TEST(socket_state) {
        ASSERT_STREQ(socket_state_to_string(SOCKET_DEAD), "dead");
        ASSERT_STREQ(socket_state_to_string(SOCKET_LISTENING), "listening");
        ASSERT_STREQ(socket_state_to_string(SOCKET_RUNNING), "running");
        ASSERT_STREQ(socket_state_to_string(SOCKET_FAILED), "failed");
        ASSERT_EQ(socket_state_from_string("listening"), SOCKET_LISTENING);
        ASSERT_EQ(socket_state_from_string("invalid"), _SOCKET_STATE_INVALID);
}

TEST(swap_state) {
        ASSERT_STREQ(swap_state_to_string(SWAP_DEAD), "dead");
        ASSERT_STREQ(swap_state_to_string(SWAP_ACTIVE), "active");
        ASSERT_STREQ(swap_state_to_string(SWAP_FAILED), "failed");
        ASSERT_EQ(swap_state_from_string("active"), SWAP_ACTIVE);
        ASSERT_EQ(swap_state_from_string("invalid"), _SWAP_STATE_INVALID);
}

TEST(target_state) {
        ASSERT_STREQ(target_state_to_string(TARGET_DEAD), "dead");
        ASSERT_STREQ(target_state_to_string(TARGET_ACTIVE), "active");
        ASSERT_EQ(target_state_from_string("active"), TARGET_ACTIVE);
        ASSERT_EQ(target_state_from_string("invalid"), _TARGET_STATE_INVALID);
}

TEST(timer_state) {
        ASSERT_STREQ(timer_state_to_string(TIMER_DEAD), "dead");
        ASSERT_STREQ(timer_state_to_string(TIMER_WAITING), "waiting");
        ASSERT_STREQ(timer_state_to_string(TIMER_RUNNING), "running");
        ASSERT_STREQ(timer_state_to_string(TIMER_ELAPSED), "elapsed");
        ASSERT_STREQ(timer_state_to_string(TIMER_FAILED), "failed");
        ASSERT_EQ(timer_state_from_string("waiting"), TIMER_WAITING);
        ASSERT_EQ(timer_state_from_string("invalid"), _TIMER_STATE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
