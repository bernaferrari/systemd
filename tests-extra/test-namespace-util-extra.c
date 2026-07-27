/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>

#include "namespace-util.h"
#include "tests.h"

TEST(clone_flag_to_namespace_type) {
        /* Each CLONE_* flag should map to the correct NamespaceType */
        ASSERT_EQ(clone_flag_to_namespace_type(CLONE_NEWCGROUP), NAMESPACE_CGROUP);
        ASSERT_EQ(clone_flag_to_namespace_type(CLONE_NEWIPC), NAMESPACE_IPC);
        ASSERT_EQ(clone_flag_to_namespace_type(CLONE_NEWNET), NAMESPACE_NET);
        ASSERT_EQ(clone_flag_to_namespace_type(CLONE_NEWNS), NAMESPACE_MOUNT);
        ASSERT_EQ(clone_flag_to_namespace_type(CLONE_NEWPID), NAMESPACE_PID);
        ASSERT_EQ(clone_flag_to_namespace_type(CLONE_NEWUSER), NAMESPACE_USER);
        ASSERT_EQ(clone_flag_to_namespace_type(CLONE_NEWUTS), NAMESPACE_UTS);
        ASSERT_EQ(clone_flag_to_namespace_type(CLONE_NEWTIME), NAMESPACE_TIME);

        /* Invalid flag should return _NAMESPACE_TYPE_INVALID */
        ASSERT_EQ(clone_flag_to_namespace_type(0), _NAMESPACE_TYPE_INVALID);
        ASSERT_EQ(clone_flag_to_namespace_type(0xFFFFFFFF), _NAMESPACE_TYPE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
