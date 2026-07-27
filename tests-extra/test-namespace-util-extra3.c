/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>

#include "namespace-util.h"
#include "string-util.h"
#include "tests.h"

TEST(clone_flag_to_namespace_type) {
        assert_se(clone_flag_to_namespace_type(CLONE_NEWCGROUP) == NAMESPACE_CGROUP);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWIPC) == NAMESPACE_IPC);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWNET) == NAMESPACE_NET);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWNS) == NAMESPACE_MOUNT);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWPID) == NAMESPACE_PID);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWUSER) == NAMESPACE_USER);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWUTS) == NAMESPACE_UTS);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWTIME) == NAMESPACE_TIME);

        /* Invalid flag → _NAMESPACE_TYPE_INVALID */
        assert_se(clone_flag_to_namespace_type(0) == _NAMESPACE_TYPE_INVALID);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWNS|CLONE_NEWNET) == _NAMESPACE_TYPE_INVALID);
}

TEST(namespace_info_table) {
        /* Verify the namespace_info entries have correct names */
        assert_se(streq(namespace_info[NAMESPACE_CGROUP].proc_name, "cgroup"));
        assert_se(streq(namespace_info[NAMESPACE_IPC].proc_name, "ipc"));
        assert_se(streq(namespace_info[NAMESPACE_NET].proc_name, "net"));
        assert_se(streq(namespace_info[NAMESPACE_MOUNT].proc_name, "mnt"));
        assert_se(streq(namespace_info[NAMESPACE_PID].proc_name, "pid"));
        assert_se(streq(namespace_info[NAMESPACE_USER].proc_name, "user"));
        assert_se(streq(namespace_info[NAMESPACE_UTS].proc_name, "uts"));
        assert_se(streq(namespace_info[NAMESPACE_TIME].proc_name, "time"));

        /* proc_path should be ns/ prefix */
        assert_se(streq(namespace_info[NAMESPACE_IPC].proc_path, "ns/ipc"));
        assert_se(streq(namespace_info[NAMESPACE_MOUNT].proc_path, "ns/mnt"));

        /* clone flags should match */
        assert_se(namespace_info[NAMESPACE_IPC].clone_flag == CLONE_NEWIPC);
        assert_se(namespace_info[NAMESPACE_NET].clone_flag == CLONE_NEWNET);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
