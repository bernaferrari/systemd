/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>

#include "namespace-util.h"
#include "tests.h"

TEST(detach_mount_namespace_basic) {
        int r = detach_mount_namespace();
        log_debug("detach_mount_namespace: %d", r);
}

TEST(fd_is_namespace_basic) {
        int r = fd_is_namespace(STDIN_FILENO, NAMESPACE_MOUNT);
        log_debug("fd_is_namespace(stdin, MOUNT): %d", r);
}

TEST(is_our_namespace_basic) {
        int r = is_our_namespace(STDIN_FILENO, NAMESPACE_MOUNT);
        log_debug("is_our_namespace(stdin, MOUNT): %d", r);
}

TEST(clone_flag_to_namespace_type_basic) {
        NamespaceType t;

        t = clone_flag_to_namespace_type(CLONE_NEWNS);
        assert_se(t == NAMESPACE_MOUNT);

        t = clone_flag_to_namespace_type(CLONE_NEWPID);
        assert_se(t == NAMESPACE_PID);

        t = clone_flag_to_namespace_type(CLONE_NEWNET);
        assert_se(t == NAMESPACE_NET);

        t = clone_flag_to_namespace_type(CLONE_NEWUSER);
        assert_se(t == NAMESPACE_USER);

        t = clone_flag_to_namespace_type(CLONE_NEWCGROUP);
        assert_se(t == NAMESPACE_CGROUP);

        t = clone_flag_to_namespace_type(CLONE_NEWIPC);
        assert_se(t == NAMESPACE_IPC);

        t = clone_flag_to_namespace_type(CLONE_NEWUTS);
        assert_se(t == NAMESPACE_UTS);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
