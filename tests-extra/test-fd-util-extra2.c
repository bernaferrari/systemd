/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "fd-util.h"
#include "string-util.h"
#include "tests.h"

TEST(fdname_is_valid_basic) {
        assert_se(fdname_is_valid("stdin"));
        assert_se(fdname_is_valid("0"));
        assert_se(fdname_is_valid("my-fd"));
        assert_se(fdname_is_valid("a"));
        assert_se(fdname_is_valid(""));
        assert_se(!fdname_is_valid(NULL));
}

TEST(format_proc_fd_path_basic) {
        char buf[PROC_FD_PATH_MAX];

        char *p = format_proc_fd_path(buf, 0);
        assert_se(p);
        assert_se(startswith(p, "/proc/"));
        assert_se(endswith(p, "/fd/0"));

        p = format_proc_fd_path(buf, 42);
        assert_se(p);
        assert_se(endswith(p, "/fd/42"));
}

TEST(format_proc_pid_fd_path_basic) {
        char buf[PROC_PID_FD_PATH_MAX];

        char *p = format_proc_pid_fd_path(buf, 1, 3);
        assert_se(p);
        assert_se(streq(p, "/proc/1/fd/3"));

        p = format_proc_pid_fd_path(buf, 1234, 0);
        assert_se(p);
        assert_se(streq(p, "/proc/1234/fd/0"));
}

TEST(accmode_to_string_basic) {
        assert_se(streq(accmode_to_string(O_RDONLY), "ro"));
        assert_se(streq(accmode_to_string(O_WRONLY), "wo"));
        assert_se(streq(accmode_to_string(O_RDWR), "rw"));
}

TEST(fd_validate_basic) {
        /* stdin should be valid */
        assert_se(fd_validate(STDIN_FILENO) >= 0);

        /* negative fd should fail */
        assert_se(fd_validate(-1) < 0);
}

TEST(same_fd_basic) {
        /* Same fd should be same */
        assert_se(same_fd(STDIN_FILENO, STDIN_FILENO));
        assert_se(same_fd(STDOUT_FILENO, STDOUT_FILENO));

        /* Different fds should be different */
        assert_se(!same_fd(STDIN_FILENO, STDOUT_FILENO));
}

TEST(fd_cloexec_basic) {
        /* Create a pipe to test cloexec */
        int p[2];
        assert_se(pipe2(p, O_CLOEXEC) >= 0);

        /* Already has cloexec */
        assert_se(fd_cloexec(p[0], true) >= 0);
        assert_se(fd_cloexec(p[0], false) >= 0);

        safe_close_pair(p);
}

TEST(fd_nonblock_basic) {
        int p[2];
        assert_se(pipe(p) >= 0);

        /* Set nonblocking */
        assert_se(fd_nonblock(p[0], true) >= 0);
        assert_se(fd_nonblock(p[0], false) >= 0);

        safe_close_pair(p);
}

TEST(close_many_basic) {
        int p[2];
        assert_se(pipe(p) >= 0);

        /* close_many should close both fds */
        close_many(p, 2);
        /* Just verify no crash */
}

TEST(read_nr_open_basic) {
        unsigned nr = read_nr_open();
        assert_se(nr > 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
