/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <unistd.h>

#include "copy.h"
#include "fd-util.h"
#include "string-util.h"
#include "tests.h"

TEST(copy_bytes_full_pipe) {
        int pipefd[2];
        int r;

        r = pipe2(pipefd, O_CLOEXEC);
        assert_se(r >= 0);

        /* Write some data to the pipe */
        const char *data = "hello world";
        size_t data_len = strlen(data);
        assert_se(write(pipefd[1], data, data_len) == (ssize_t) data_len);
        pipefd[1] = safe_close(pipefd[1]); /* close write end to signal EOF */

        /* Read data from pipe to a new pipe */
        int pipefd2[2];
        r = pipe2(pipefd2, O_CLOEXEC);
        assert_se(r >= 0);

        r = copy_bytes(pipefd[0], pipefd2[1], UINT64_MAX, 0);
        assert_se(r >= 0);
        pipefd2[1] = safe_close(pipefd2[1]);

        /* Read back and verify */
        char buf[64] = {};
        ssize_t n = read(pipefd2[0], buf, sizeof(buf) - 1);
        assert_se(n >= 0);
        buf[n] = '\0';
        assert_se(streq(buf, data));

        pipefd[0] = safe_close(pipefd[0]);
        pipefd2[0] = safe_close(pipefd2[0]);
}

TEST(copy_bytes_max_bytes) {
        int pipefd[2];
        int r;

        r = pipe2(pipefd, O_CLOEXEC);
        assert_se(r >= 0);

        const char *data = "0123456789";
        assert_se(write(pipefd[1], data, 10) == 10);
        pipefd[1] = safe_close(pipefd[1]);

        int pipefd2[2];
        r = pipe2(pipefd2, O_CLOEXEC);
        assert_se(r >= 0);

        /* Copy only 5 bytes */
        r = copy_bytes(pipefd[0], pipefd2[1], 5, 0);
        assert_se(r >= 0);
        pipefd2[1] = safe_close(pipefd2[1]);

        char buf[64] = {};
        ssize_t n = read(pipefd2[0], buf, sizeof(buf) - 1);
        assert_se(n == 5);
        buf[n] = '\0';
        assert_se(streq(buf, "01234"));

        pipefd[0] = safe_close(pipefd[0]);
        pipefd2[0] = safe_close(pipefd2[0]);
}

TEST(copy_bytes_empty) {
        int pipefd[2];
        int r;

        r = pipe2(pipefd, O_CLOEXEC);
        assert_se(r >= 0);

        /* Close write end immediately → EOF */
        pipefd[1] = safe_close(pipefd[1]);

        int pipefd2[2];
        r = pipe2(pipefd2, O_CLOEXEC);
        assert_se(r >= 0);

        r = copy_bytes(pipefd[0], pipefd2[1], UINT64_MAX, 0);
        assert_se(r >= 0);
        pipefd2[1] = safe_close(pipefd2[1]);

        /* Nothing to read */
        char buf[64];
        ssize_t n = read(pipefd2[0], buf, sizeof(buf));
        assert_se(n == 0);

        pipefd[0] = safe_close(pipefd[0]);
        pipefd2[0] = safe_close(pipefd2[0]);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
