/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>

#include "capability-util.h"
#include "namespace-util.h"
#include "string-util.h"
#include "tests.h"

TEST(clone_flag_to_namespace_type_basic) {
        assert_se(clone_flag_to_namespace_type(CLONE_NEWIPC) == NAMESPACE_IPC);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWNET) == NAMESPACE_NET);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWNS) == NAMESPACE_MOUNT);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWPID) == NAMESPACE_PID);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWUSER) == NAMESPACE_USER);
        assert_se(clone_flag_to_namespace_type(CLONE_NEWUTS) == NAMESPACE_UTS);
        assert_se(clone_flag_to_namespace_type(0) == _NAMESPACE_TYPE_INVALID);
}

TEST(namespace_info_table) {
        /* Verify the proc_name fields are populated */
        assert_se(streq(namespace_info[NAMESPACE_CGROUP].proc_name, "cgroup"));
        assert_se(streq(namespace_info[NAMESPACE_IPC].proc_name, "ipc"));
        assert_se(streq(namespace_info[NAMESPACE_NET].proc_name, "net"));
        assert_se(streq(namespace_info[NAMESPACE_MOUNT].proc_name, "mnt"));
        assert_se(streq(namespace_info[NAMESPACE_PID].proc_name, "pid"));
        assert_se(streq(namespace_info[NAMESPACE_USER].proc_name, "user"));
        assert_se(streq(namespace_info[NAMESPACE_UTS].proc_name, "uts"));
        assert_se(streq(namespace_info[NAMESPACE_TIME].proc_name, "time"));

        /* Verify clone flags */
        assert_se(FLAGS_SET(namespace_info[NAMESPACE_IPC].clone_flag, CLONE_NEWIPC));
        assert_se(FLAGS_SET(namespace_info[NAMESPACE_NET].clone_flag, CLONE_NEWNET));
        assert_se(FLAGS_SET(namespace_info[NAMESPACE_MOUNT].clone_flag, CLONE_NEWNS));
        assert_se(FLAGS_SET(namespace_info[NAMESPACE_PID].clone_flag, CLONE_NEWPID));
        assert_se(FLAGS_SET(namespace_info[NAMESPACE_USER].clone_flag, CLONE_NEWUSER));
        assert_se(FLAGS_SET(namespace_info[NAMESPACE_UTS].clone_flag, CLONE_NEWUTS));
}

TEST(capability_quintet_basics) {
        CapabilityQuintet q = CAPABILITY_QUINTET_NULL;

        /* All unset → not set */
        assert_se(!capability_quintet_is_set(&q));
        assert_se(!capability_quintet_is_fully_set(&q));

        /* Set one field → is_set but not fully_set */
        q.effective = 0;
        assert_se(capability_quintet_is_set(&q));
        assert_se(!capability_quintet_is_fully_set(&q));

        /* All set → both true */
        q = (CapabilityQuintet) {
                .effective = 0,
                .bounding = 0,
                .inheritable = 0,
                .permitted = 0,
                .ambient = 0,
        };
        assert_se(capability_quintet_is_set(&q));
        assert_se(capability_quintet_is_fully_set(&q));
}

TEST(capability_quintet_equal) {
        CapabilityQuintet a = {
                .effective = 1,
                .bounding = 2,
                .inheritable = 3,
                .permitted = 4,
                .ambient = 5,
        };
        CapabilityQuintet b = a;
        assert_se(capability_quintet_equal(&a, &b));

        b.effective = 99;
        assert_se(!capability_quintet_equal(&a, &b));
}

TEST(capability_is_set_basic) {
        assert_se(!capability_is_set(CAP_MASK_UNSET));
        assert_se(capability_is_set(0));
        assert_se(capability_is_set(1));
        assert_se(capability_is_set(UINT64_C(0x7fffffffffffffff)));
}

TEST(userns_shift_range_valid_basic) {
        /* Valid */
        assert_se(userns_shift_range_valid(0, 1));
        assert_se(userns_shift_range_valid(1000, 65536));
        assert_se(userns_shift_range_valid(0, (uid_t) -1));

        /* Invalid: range==0 */
        assert_se(!userns_shift_range_valid(0, 0));
        assert_se(!userns_shift_range_valid(100, 0));

        /* Invalid: overflow */
        assert_se(!userns_shift_range_valid(1, (uid_t) -1));
        assert_se(!userns_shift_range_valid((uid_t) -1, 1));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
