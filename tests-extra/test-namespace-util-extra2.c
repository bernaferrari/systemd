/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>

#include "namespace-util.h"
#include "tests.h"

TEST(userns_shift_range_valid_basic) {
        /* Valid ranges */
        assert_se(userns_shift_range_valid(0, 1));
        assert_se(userns_shift_range_valid(0, 65536));
        assert_se(userns_shift_range_valid(1000, 1));
        assert_se(userns_shift_range_valid(65536, 65536));

        /* range <= 0 is invalid */
        assert_se(!userns_shift_range_valid(0, 0));
        assert_se(!userns_shift_range_valid(100, 0));

        /* Overflow: shift + range > UID_MAX */
        assert_se(!userns_shift_range_valid(UINT32_MAX, 1));
        assert_se(!userns_shift_range_valid(UINT32_MAX - 10, 11));
        /* Non-overflow at boundary */
        assert_se(userns_shift_range_valid(UINT32_MAX - 10, 10));
}

TEST(namespace_info_names) {
        /* namespace_info array has name strings for each type */
        assert_se(streq(namespace_info[NAMESPACE_MOUNT].proc_path, "ns/mnt"));
        assert_se(streq(namespace_info[NAMESPACE_CGROUP].proc_path, "ns/cgroup"));
        assert_se(streq(namespace_info[NAMESPACE_UTS].proc_path, "ns/uts"));
        assert_se(streq(namespace_info[NAMESPACE_IPC].proc_path, "ns/ipc"));
        assert_se(streq(namespace_info[NAMESPACE_NET].proc_path, "ns/net"));
        assert_se(streq(namespace_info[NAMESPACE_PID].proc_path, "ns/pid"));
        assert_se(streq(namespace_info[NAMESPACE_USER].proc_path, "ns/user"));
}

TEST(clone_flag_to_namespace_type_basic) {
        assert_se(clone_flag_to_namespace_type(CLONE_NEWNS) == NAMESPACE_MOUNT);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWCGROUP) == NAMESPACE_CGROUP);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWUTS) == NAMESPACE_UTS);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWIPC) == NAMESPACE_IPC);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWNET) == NAMESPACE_NET);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWPID) == NAMESPACE_PID);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWUSER) == NAMESPACE_USER);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
