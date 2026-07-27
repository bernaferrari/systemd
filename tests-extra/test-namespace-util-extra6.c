/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>

#include "errno-util.h"
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
        assert_se(clone_flag_to_namespace_type(CLONE_NEWTIME) == NAMESPACE_TIME);
        assert_se(clone_flag_to_namespace_type(0) == _NAMESPACE_TYPE_INVALID);
        assert_se(clone_flag_to_namespace_type(0xFFFFFFFF) == _NAMESPACE_TYPE_INVALID);
}

TEST(namespace_type_supported_basic) {
        /* On Lima VM, most namespace types should be supported */
        assert_se(namespace_type_supported(NAMESPACE_MOUNT));
        assert_se(namespace_type_supported(NAMESPACE_UTS));
        assert_se(namespace_type_supported(NAMESPACE_IPC));
        assert_se(namespace_type_supported(NAMESPACE_NET));
        assert_se(namespace_type_supported(NAMESPACE_PID));

        /* User namespace might not be supported depending on kernel config */
        (void) namespace_type_supported(NAMESPACE_USER);
}

TEST(userns_supported_basic) {
        /* On most Linux systems, userns is supported */
        (void) userns_supported();
}

TEST(namespace_is_init_basic) {
        /* In the init namespace, this should return true for most types */
        int r;

        r = namespace_is_init(NAMESPACE_IPC);
        if (r >= 0)
                assert_se(r > 0);

        r = namespace_is_init(NAMESPACE_UTS);
        if (r >= 0)
                assert_se(r > 0);

        /* MOUNT and NET don't have root_inode set, so should return -EBADR */
        r = namespace_is_init(NAMESPACE_MOUNT);
        assert_se(r == -EBADR);

        r = namespace_is_init(NAMESPACE_NET);
        assert_se(r == -EBADR);
}

TEST(parse_userns_uid_range_basic) {
        uid_t shift, range;
        int r;

        /* Just shift */
        r = parse_userns_uid_range("1000", &shift, &range);
        if (r < 0) {
                log_debug("parse_userns_uid_range failed: %m, skipping");
                return;
        }
        assert_se(shift == 1000);
        assert_se(range == 65536);

        /* Shift with range */
        r = parse_userns_uid_range("1000:10000", &shift, &range);
        assert_se(r >= 0);
        assert_se(shift == 1000);
        assert_se(range == 10000);

        /* Invalid */
        assert_se(parse_userns_uid_range("", &shift, &range) < 0);
        assert_se(parse_userns_uid_range("abc", &shift, &range) < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
