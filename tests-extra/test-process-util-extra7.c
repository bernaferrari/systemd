/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>

#include "alloc-util.h"
#include "pidref.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"

TEST(sched_policy_supported_basic) {
        /* Standard policies should be supported */
        assert_se(sched_policy_supported(SCHED_OTHER));
        assert_se(sched_policy_supported(SCHED_FIFO));
        assert_se(sched_policy_supported(SCHED_RR));

        /* Invalid policy */
        assert_se(!sched_policy_supported(-1));
}

TEST(sched_get_priority_min_safe_basic) {
        int r;

        r = sched_get_priority_min_safe(SCHED_FIFO);
        assert_se(r >= 0);

        r = sched_get_priority_min_safe(SCHED_OTHER);
        assert_se(r == 0);

        /* Invalid policy — safe variant returns 0 as fallback */
        r = sched_get_priority_min_safe(-1);
        assert_se(r >= 0);
}

TEST(sched_get_priority_max_safe_basic) {
        int r;

        r = sched_get_priority_max_safe(SCHED_FIFO);
        assert_se(r >= 0);

        r = sched_get_priority_max_safe(SCHED_OTHER);
        assert_se(r == 0);

        /* Invalid policy — safe variant returns 0 as fallback */
        r = sched_get_priority_max_safe(-1);
        assert_se(r >= 0);
}

TEST(pidref_self_basic) {
        pid_t my_pid = getpid_cached();
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        assert_se(pidref_set_pid(&pidref, my_pid) >= 0);

        assert_se(pidref.pid == my_pid);
        assert_se(pidref.fd >= 0);
}

TEST(pidref_get_comm_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        assert_se(pidref_set_pid(&pidref, getpid_cached()) >= 0);

        _cleanup_free_ char *comm = NULL;
        int r = pidref_get_comm(&pidref, &comm);
        if (r >= 0) {
                assert_se(!isempty(comm));
                log_debug("self comm: %s", comm);
        }
}

TEST(pidref_get_uid_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        assert_se(pidref_set_pid(&pidref, getpid_cached()) >= 0);

        uid_t uid;
        int r = pidref_get_uid(&pidref, &uid);
        if (r >= 0)
                assert_se(uid == getuid());
}

TEST(pidref_get_ppid_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        assert_se(pidref_set_pid(&pidref, getpid_cached()) >= 0);

        pid_t ppid;
        int r = pidref_get_ppid(&pidref, &ppid);
        if (r >= 0)
                assert_se(ppid > 0);
}

TEST(pidref_is_alive_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        assert_se(pidref_set_pid(&pidref, getpid_cached()) >= 0);

        assert_se(pidref_is_alive(&pidref) > 0);
}

TEST(get_process_threads_self) {
        int r = get_process_threads(getpid_cached());
        if (r >= 0)
                assert_se(r >= 1);
}

TEST(is_reaper_process_basic) {
        /* Just verify no crash — result depends on environment */
        (void) is_reaper_process();
}

TEST(getpid_cached_basic) {
        pid_t a = getpid_cached();
        pid_t b = getpid_cached();
        assert_se(a == b);
        assert_se(a > 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
