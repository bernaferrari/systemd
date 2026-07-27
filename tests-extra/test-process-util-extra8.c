/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/personality.h>
#include <sys/wait.h>

#include "alloc-util.h"
#include "architecture.h"
#include "pidref.h"
#include "process-util.h"
#include "strv.h"
#include "string-util.h"
#include "tests.h"

TEST(pidref_get_cmdline_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        assert_se(pidref_set_pid(&pidref, getpid_cached()) >= 0);

        _cleanup_free_ char *cmdline = NULL;
        int r = pidref_get_cmdline(&pidref, SIZE_MAX, 0, &cmdline);
        if (r >= 0)
                assert_se(!isempty(cmdline));
}

TEST(pidref_get_cmdline_strv_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        assert_se(pidref_set_pid(&pidref, getpid_cached()) >= 0);

        _cleanup_strv_free_ char **cmdline = NULL;
        int r = pidref_get_cmdline_strv(&pidref, 0, &cmdline);
        if (r >= 0)
                assert_se(cmdline && !isempty(cmdline[0]));
}

TEST(pidref_is_kernel_thread_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        assert_se(pidref_set_pid(&pidref, getpid_cached()) >= 0);

        int r = pidref_is_kernel_thread(&pidref);
        if (r >= 0)
                assert_se(r == 0); /* We are not a kernel thread */
}

TEST(pidref_get_uid_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        assert_se(pidref_set_pid(&pidref, getpid_cached()) >= 0);

        uid_t uid;
        int r = pidref_get_uid(&pidref, &uid);
        if (r >= 0)
                assert_se(uid == getuid());
}

TEST(pid_get_uid_self) {
        uid_t uid;
        int r = pid_get_uid(getpid_cached(), &uid);
        if (r >= 0)
                assert_se(uid == getuid());
}

TEST(get_process_gid_self) {
        gid_t gid;
        int r = get_process_gid(getpid_cached(), &gid);
        if (r >= 0)
                assert_se(gid == getgid());
}

TEST(get_process_cwd_self) {
        _cleanup_free_ char *cwd = NULL;
        int r = get_process_cwd(getpid_cached(), &cwd);
        if (r >= 0)
                assert_se(!isempty(cwd));
}

TEST(get_process_exe_self) {
        _cleanup_free_ char *exe = NULL;
        int r = get_process_exe(getpid_cached(), &exe);
        if (r >= 0)
                assert_se(!isempty(exe));
}

TEST(pid_get_start_time_self) {
        usec_t start_time;
        int r = pid_get_start_time(getpid_cached(), &start_time);
        if (r >= 0)
                assert_se(start_time > 0);
}

TEST(pidref_get_start_time_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        assert_se(pidref_set_pid(&pidref, getpid_cached()) >= 0);

        usec_t start_time;
        int r = pidref_get_start_time(&pidref, &start_time);
        if (r >= 0)
                assert_se(start_time > 0);
}

TEST(getpid_cached_values) {
        pid_t p = getpid_cached();
        assert_se(p > 0);
        assert_se(getpid_cached() == p);
}

TEST(pid_is_kernel_thread_self) {
        int r = pid_is_kernel_thread(getpid_cached());
        if (r >= 0)
                assert_se(r == 0);
}

TEST(pid_is_alive_self) {
        assert_se(pid_is_alive(getpid_cached()) > 0);
}

TEST(pid_is_unwaited_self) {
        assert_se(pid_is_unwaited(getpid_cached()) > 0);
}

TEST(personality_to_string_basic) {
        const char *s = personality_to_string(PER_LINUX);
        assert_se(!isempty(s));
        log_debug("personality_to_string(PER_LINUX): %s", s);
}

TEST(personality_from_string_basic) {
        /* personality_from_string returns unsigned long directly */
        const char *arch = architecture_to_string(native_architecture());
        unsigned long p = personality_from_string(arch);
        assert_se(p != PERSONALITY_INVALID);
        log_debug("personality_from_string(%s): %lu", arch, p);

        /* Invalid */
        assert_se(personality_from_string("invalid_arch") == PERSONALITY_INVALID);
        assert_se(personality_from_string(NULL) == PERSONALITY_INVALID);
}

TEST(opinionated_personality_basic) {
        unsigned long p;
        int r = opinionated_personality(&p);
        if (r >= 0) {
                assert_se(IN_SET(p, PER_LINUX, PER_LINUX32));
                log_debug("opinionated_personality: %lu", p);
        }
}

TEST(get_process_threads_self) {
        int r = get_process_threads(getpid_cached());
        if (r >= 0)
                assert_se(r >= 1);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
