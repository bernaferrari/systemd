/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: libsystemd sd-daemon helper checks vs Rust */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mqueue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "fd-util.h"
#include "rm-rf.h"
#include "socket-util.h"
#include "sd-daemon.h"
#include "strv.h"
#include "tests.h"

/* Rust FFI exports */
int rs_libsystemd_sd_is_fifo(int fd, const char *path);
int rs_libsystemd_sd_is_special(int fd, const char *path);
int rs_libsystemd_sd_is_socket(int fd, int family, int type, int listening);
int rs_libsystemd_sd_is_socket_inet(int fd, int family, int type, int listening, uint16_t port);
int rs_libsystemd_sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length);
int rs_libsystemd_sd_booted(void);
int rs_libsystemd_sd_watchdog_enabled(int unset_environment, uint64_t *usec);
int rs_libsystemd_sd_pidfd_get_inode_id(int pidfd, uint64_t *ret);
int rs_libsystemd_sd_listen_fds(int unset_environment);
int rs_libsystemd_sd_listen_fds_with_names(int unset_environment, char ***ret_names);
int rs_libsystemd_sd_pid_notify_with_fds(pid_t pid, int unset_environment, const char *state, const int *fds, unsigned n_fds);
int rs_libsystemd_sd_pid_notify(pid_t pid, int unset_environment, const char *state);
int rs_libsystemd_sd_notify(int unset_environment, const char *state);
int rs_libsystemd_sd_pid_notify_barrier(pid_t pid, int unset_environment, uint64_t timeout);
int rs_libsystemd_sd_notify_barrier(int unset_environment, uint64_t timeout);
int rs_libsystemd_sd_is_socket_sockaddr(int fd, int type, const struct sockaddr *addr, unsigned addr_len, int listening);
int rs_libsystemd_sd_is_mq(int fd, const char *path);

typedef struct Fd3State {
        int saved_fd3;
        int staging_fd;
} Fd3State;

static void fd3_state_done(Fd3State *s) {
        assert(s);

        s->staging_fd = safe_close(s->staging_fd);

        if (s->saved_fd3 >= 0) {
                assert_se(dup2(s->saved_fd3, 3) >= 0);
                s->saved_fd3 = safe_close(s->saved_fd3);
        } else
                (void) close(3);
}

static int fd3_state_prepare(Fd3State *s) {
        int saved;

        assert(s);
        *s = (Fd3State) {
                .saved_fd3 = -1,
                .staging_fd = -1,
        };

        saved = fcntl(3, F_DUPFD_CLOEXEC, 10);
        if (saved < 0 && errno != EBADF)
                return -errno;

        s->saved_fd3 = saved;
        s->staging_fd = open("/dev/null", O_RDONLY|O_CLOEXEC);
        if (s->staging_fd < 0)
                return -errno;

        if (dup2(s->staging_fd, 3) < 0)
                return -errno;

        return 0;
}

TEST(sd_is_invalid_fd) {
        ASSERT_EQ(sd_is_fifo(-1, NULL), rs_libsystemd_sd_is_fifo(-1, NULL));
        ASSERT_EQ(sd_is_fifo(-1, NULL), -EBADF);

        ASSERT_EQ(sd_is_special(-1, NULL), rs_libsystemd_sd_is_special(-1, NULL));
        ASSERT_EQ(sd_is_special(-1, NULL), -EBADF);

        ASSERT_EQ(sd_is_socket(-1, AF_INET, SOCK_STREAM, 1), rs_libsystemd_sd_is_socket(-1, AF_INET, SOCK_STREAM, 1));
        ASSERT_EQ(sd_is_socket(-1, AF_INET, SOCK_STREAM, 1), -EBADF);

        ASSERT_EQ(sd_is_socket_inet(-1, AF_INET, SOCK_STREAM, 1, 0), rs_libsystemd_sd_is_socket_inet(-1, AF_INET, SOCK_STREAM, 1, 0));
        ASSERT_EQ(sd_is_socket_inet(-1, AF_INET, SOCK_STREAM, 1, 0), -EBADF);

        ASSERT_EQ(sd_is_socket_unix(-1, SOCK_STREAM, 1, NULL, 0), rs_libsystemd_sd_is_socket_unix(-1, SOCK_STREAM, 1, NULL, 0));
        ASSERT_EQ(sd_is_socket_unix(-1, SOCK_STREAM, 1, NULL, 0), -EBADF);

        ASSERT_EQ(sd_pidfd_get_inode_id(-1, NULL), rs_libsystemd_sd_pidfd_get_inode_id(-1, NULL));
        ASSERT_EQ(sd_pidfd_get_inode_id(-1, NULL), -EBADF);
}

TEST(sd_is_fifo) {
        _cleanup_free_ char *dir = strdup("/tmp/systemd-sd-daemon-fifo-XXXXXX");
        _cleanup_close_pair_ int pipefd[2] = { -1, -1 };
        _cleanup_close_ int regular_fd = -1;
        _cleanup_close_ int fifo_fd = -1;

        char fifo_path[PATH_MAX];
        char regular_path[PATH_MAX];

        int len;

        if (!dir) {
                log_debug("failed to allocate temporary dir path");
                return;
        }

        if (!mkdtemp(dir)) {
                log_debug("mkdtemp(%s): %m", dir);
                return;
        }

        len = snprintf(fifo_path, sizeof fifo_path, "%s/fifo", dir);
        ASSERT_TRUE(len > 0 && (size_t) len < sizeof(fifo_path));

        len = snprintf(regular_path, sizeof regular_path, "%s/regular", dir);
        ASSERT_TRUE(len > 0 && (size_t) len < sizeof(regular_path));

        ASSERT_EQ(mkfifo(fifo_path, 0600), 0);

        fifo_fd = open(fifo_path, O_RDONLY|O_NONBLOCK|O_CLOEXEC);
        ASSERT_GE(fifo_fd, 0);

        regular_fd = open(regular_path, O_CREAT|O_RDWR|O_CLOEXEC|O_TRUNC, 0600);
        ASSERT_GE(regular_fd, 0);

        ASSERT_EQ(sd_is_fifo(fifo_fd, fifo_path), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_fifo(fifo_fd, fifo_path), 1);
        ASSERT_EQ(sd_is_fifo(fifo_fd, regular_path), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_fifo(fifo_fd, regular_path), 0);
        ASSERT_EQ(sd_is_fifo(fifo_fd, NULL), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_fifo(fifo_fd, NULL), 1);

        ASSERT_EQ(pipe(pipefd), 0);
        ASSERT_EQ(sd_is_fifo(pipefd[0], NULL), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_fifo(pipefd[0], NULL), 1);
        ASSERT_EQ(sd_is_fifo(pipefd[0], fifo_path), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_fifo(pipefd[0], fifo_path), 0);

        (void) unlink(fifo_path);
        (void) unlink(regular_path);
        ASSERT_OK(rm_rf(dir, REMOVE_ROOT));
}

TEST(sd_is_special) {
        _cleanup_free_ char *dir = strdup("/tmp/systemd-sd-daemon-special-XXXXXX");
        _cleanup_close_ int file_fd = -1;
        _cleanup_close_ int path_other_fd = -1;
        char path_file[PATH_MAX];
        char path_other[PATH_MAX];
        int len;

        if (!dir) {
                log_debug("failed to allocate temporary dir path");
                return;
        }

        if (!mkdtemp(dir)) {
                log_debug("mkdtemp(%s): %m", dir);
                return;
        }

        len = snprintf(path_file, sizeof path_file, "%s/special", dir);
        ASSERT_TRUE(len > 0 && (size_t) len < sizeof(path_file));

        len = snprintf(path_other, sizeof path_other, "%s/mismatch", dir);
        ASSERT_TRUE(len > 0 && (size_t) len < sizeof(path_other));

        file_fd = open(path_file, O_CREAT|O_RDWR|O_CLOEXEC|O_TRUNC, 0600);
        ASSERT_GE(file_fd, 0);
        path_other_fd = open(path_other, O_CREAT|O_RDWR|O_CLOEXEC|O_TRUNC, 0600);
        ASSERT_GE(path_other_fd, 0);

        ASSERT_EQ(sd_is_special(file_fd, path_file), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_special(file_fd, path_file), 1);
        ASSERT_EQ(sd_is_special(file_fd, path_other), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_special(file_fd, path_other), 0);
        ASSERT_EQ(sd_is_special(file_fd, NULL), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_special(file_fd, NULL), 1);

        ASSERT_OK(rm_rf(dir, REMOVE_ROOT));
}

TEST(sd_is_inet_socket) {
        _cleanup_close_ int sock = -1;
        struct sockaddr_in addr = {
                .sin_family = AF_INET,
                .sin_addr = {
                        .s_addr = htonl(INADDR_LOOPBACK),
                },
                .sin_port = 0,
        };
        unsigned port;
        int r;
        uint16_t mismatch_port;

        sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        ASSERT_GE(sock, 0);

        ASSERT_EQ(bind(sock, (const struct sockaddr*) &addr, sizeof(addr)), 0);
        ASSERT_EQ(listen(sock, 1), 0);

        socklen_t len = sizeof(addr);
        r = getsockname(sock, (struct sockaddr*) &addr, &len);
        ASSERT_EQ(r, 0);
        ASSERT_GE(len, sizeof(addr));

        r = sockaddr_port((struct sockaddr*) &addr, &port);
        ASSERT_EQ(r, 0);
        ASSERT_NE(port, 0U);

        ASSERT_EQ(sd_is_socket_inet(sock, AF_INET, SOCK_STREAM, 1, 0), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_inet(sock, AF_INET, SOCK_STREAM, 1, 0), 1);
        ASSERT_EQ(sd_is_socket_inet(sock, AF_INET6, SOCK_STREAM, 1, 0), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_inet(sock, AF_INET6, SOCK_STREAM, 1, 0), 0);
        ASSERT_EQ(sd_is_socket_inet(sock, AF_INET, SOCK_DGRAM, 1, 0), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_inet(sock, AF_INET, SOCK_DGRAM, 1, 0), 0);
        ASSERT_EQ(sd_is_socket_inet(sock, AF_INET, SOCK_STREAM, 0, 0), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_inet(sock, AF_INET, SOCK_STREAM, 0, 0), 0);
        mismatch_port = (uint16_t) (port == UINT16_MAX ? UINT16_MAX - 1 : port + 1);
        ASSERT_EQ(sd_is_socket_inet(sock, AF_INET, SOCK_STREAM, 1, mismatch_port), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_inet(sock, AF_INET, SOCK_STREAM, 1, mismatch_port), 0);

        ASSERT_EQ(sd_is_socket(sock, AF_INET, SOCK_STREAM, 1), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_socket(sock, AF_INET, SOCK_STREAM, 1), 1);
        ASSERT_EQ(sd_is_socket(sock, AF_INET, SOCK_DGRAM, 1), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_socket(sock, AF_INET, SOCK_DGRAM, 1), 0);
        ASSERT_EQ(sd_is_socket(sock, AF_INET6, 0, -1), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_socket(sock, AF_INET6, 0, -1), 0);

        ASSERT_EQ(sd_is_socket_sockaddr(sock, SOCK_STREAM, (const struct sockaddr*) &addr, sizeof(addr), 1), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_sockaddr(sock, SOCK_STREAM, (const struct sockaddr*) &addr, sizeof(addr), 1), 1);

        struct sockaddr_in addr_mismatch = addr;
        addr_mismatch.sin_port = htons((uint16_t) (ntohs(addr.sin_port) == UINT16_MAX ? UINT16_MAX - 1 : ntohs(addr.sin_port) + 1));
        ASSERT_EQ(sd_is_socket_sockaddr(sock, SOCK_STREAM, (const struct sockaddr*) &addr_mismatch, sizeof(addr_mismatch), 1), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_sockaddr(sock, SOCK_STREAM, (const struct sockaddr*) &addr_mismatch, sizeof(addr_mismatch), 1), 0);
}

TEST(sd_is_unix_socket) {
        _cleanup_free_ char *dir = strdup("/tmp/systemd-sd-daemon-unix-XXXXXX");
        _cleanup_close_ int path_sock = -1;
        _cleanup_close_ int abstract_sock = -1;
        struct sockaddr_un sa = {};
        char path[PATH_MAX];
        int len;

        if (!dir) {
                log_debug("failed to allocate temporary dir path");
                return;
        }

        if (!mkdtemp(dir)) {
                log_debug("mkdtemp(%s): %m", dir);
                return;
        }

        len = snprintf(path, sizeof path, "%s/unix.sock", dir);
        ASSERT_TRUE(len > 0 && (size_t) len < sizeof(path));

        path_sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        ASSERT_GE(path_sock, 0);

        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        ASSERT_TRUE(snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path) > 0);

        len = offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;
        ASSERT_EQ(bind(path_sock, (const struct sockaddr*) &sa, len), 0);

        ASSERT_EQ(sd_is_socket_unix(path_sock, SOCK_STREAM, -1, path, 0), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_unix(path_sock, SOCK_STREAM, -1, path, 0), 1);

        char mismatch_path[PATH_MAX];
        len = snprintf(mismatch_path, sizeof mismatch_path, "%s/other.sock", dir);
        ASSERT_TRUE(len > 0 && (size_t) len < sizeof(mismatch_path));

        ASSERT_EQ(sd_is_socket_unix(path_sock, SOCK_STREAM, -1, mismatch_path, 0), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_unix(path_sock, SOCK_STREAM, -1, mismatch_path, 0), 0);

        ASSERT_EQ(sd_is_socket_unix(path_sock, SOCK_DGRAM, -1, path, 0), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_unix(path_sock, SOCK_DGRAM, -1, path, 0), 0);

        ASSERT_EQ(sd_is_socket_unix(path_sock, SOCK_STREAM, 0, path, 0), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_unix(path_sock, SOCK_STREAM, 0, path, 0), 1);

        ASSERT_EQ(sd_is_socket_unix(path_sock, SOCK_STREAM, 1, path, 0), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_unix(path_sock, SOCK_STREAM, 1, path, 0), 0);

        ASSERT_EQ(sd_is_socket_unix(path_sock, SOCK_STREAM, -1, NULL, 0), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_unix(path_sock, SOCK_STREAM, -1, NULL, 0), 1);

        (void) unlink(path);

#ifdef __linux__
        size_t abstract_name_len;
        size_t abstract_mismatch_len;

        struct {
                char name[sizeof(sa.sun_path)];
        } abstract = {};

        abstract_sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        ASSERT_GE(abstract_sock, 0);

        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        sa.sun_path[0] = 0;
        memcpy(sa.sun_path + 1, "systemd-test", sizeof("systemd-test") - 1);

        abstract_name_len = sizeof("systemd-test") - 1;
        len = offsetof(struct sockaddr_un, sun_path) + 1 + (int) abstract_name_len;
        ASSERT_EQ(bind(abstract_sock, (const struct sockaddr*) &sa, len), 0);

        memcpy(abstract.name, "\0systemd-test", abstract_name_len + 1);
        ASSERT_EQ(sd_is_socket_unix(abstract_sock, SOCK_STREAM, -1, abstract.name, abstract_name_len + 1), 1);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_unix(abstract_sock, SOCK_STREAM, -1, abstract.name, abstract_name_len + 1), 1);

        struct {
                char name[sizeof(sa.sun_path)];
        } abstract_mismatch = {};
        abstract_mismatch.name[0] = 0;
        abstract_mismatch_len = sizeof("systemd-mismatch") - 1;
        memcpy(abstract_mismatch.name + 1, "systemd-mismatch", abstract_mismatch_len);

        ASSERT_EQ(sd_is_socket_unix(abstract_sock, SOCK_STREAM, -1, abstract_mismatch.name, abstract_mismatch_len + 1), 0);
        ASSERT_EQ(rs_libsystemd_sd_is_socket_unix(abstract_sock, SOCK_STREAM, -1, abstract_mismatch.name, abstract_mismatch_len + 1), 0);
#endif

        ASSERT_OK(rm_rf(dir, REMOVE_ROOT));
}

TEST(sd_booted) {
        ASSERT_EQ(sd_booted(), rs_libsystemd_sd_booted());
}

TEST(sd_watchdog_enabled) {
        _cleanup_free_ char *old_usec = NULL;
        _cleanup_free_ char *old_pid = NULL;
        uint64_t c_usec = UINT64_MAX, r_usec = UINT64_MAX;
        pid_t self;
        char pid_buf[32];
        int c, r;

        old_usec = getenv("WATCHDOG_USEC") ? strdup(getenv("WATCHDOG_USEC")) : NULL;
        old_pid = getenv("WATCHDOG_PID") ? strdup(getenv("WATCHDOG_PID")) : NULL;

        if (getenv("WATCHDOG_USEC"))
                assert_se(old_usec);
        if (getenv("WATCHDOG_PID"))
                assert_se(old_pid);

        assert_se(unsetenv("WATCHDOG_USEC") >= 0);
        assert_se(unsetenv("WATCHDOG_PID") >= 0);
        c = sd_watchdog_enabled(false, &c_usec);
        r = rs_libsystemd_sd_watchdog_enabled(false, &r_usec);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 0);

        assert_se(setenv("WATCHDOG_USEC", "1000000", 1) >= 0);
        assert_se(unsetenv("WATCHDOG_PID") >= 0);
        c = sd_watchdog_enabled(false, &c_usec);
        r = rs_libsystemd_sd_watchdog_enabled(false, &r_usec);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 1);
        ASSERT_EQ(c_usec, r_usec);

        self = getpid();
        assert_se(snprintf(pid_buf, sizeof(pid_buf), "%ld", (long) self) > 0);
        assert_se(setenv("WATCHDOG_USEC", "2500000", 1) >= 0);
        assert_se(setenv("WATCHDOG_PID", pid_buf, 1) >= 0);
        c = sd_watchdog_enabled(false, &c_usec);
        r = rs_libsystemd_sd_watchdog_enabled(false, &r_usec);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 1);
        ASSERT_EQ(c_usec, r_usec);

        assert_se(setenv("WATCHDOG_USEC", "2500000", 1) >= 0);
        assert_se(setenv("WATCHDOG_PID", "1", 1) >= 0);
        c = sd_watchdog_enabled(false, &c_usec);
        r = rs_libsystemd_sd_watchdog_enabled(false, &r_usec);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 0);

        assert_se(setenv("WATCHDOG_USEC", "0", 1) >= 0);
        assert_se(unsetenv("WATCHDOG_PID") >= 0);
        c = sd_watchdog_enabled(false, &c_usec);
        r = rs_libsystemd_sd_watchdog_enabled(false, &r_usec);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, -EINVAL);

        assert_se(setenv("WATCHDOG_USEC", "1234", 1) >= 0);
        assert_se(setenv("WATCHDOG_PID", "not-a-pid", 1) >= 0);
        c = sd_watchdog_enabled(false, &c_usec);
        r = rs_libsystemd_sd_watchdog_enabled(false, &r_usec);
        ASSERT_EQ(c, r);
        ASSERT_LT(c, 0);

        assert_se(setenv("WATCHDOG_USEC", "5678", 1) >= 0);
        assert_se(setenv("WATCHDOG_PID", pid_buf, 1) >= 0);
        c = sd_watchdog_enabled(true, &c_usec);
        r = rs_libsystemd_sd_watchdog_enabled(true, &r_usec);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 1);
        ASSERT_NULL(getenv("WATCHDOG_USEC"));
        ASSERT_NULL(getenv("WATCHDOG_PID"));

        if (old_usec)
                assert_se(setenv("WATCHDOG_USEC", old_usec, 1) >= 0);
        else
                assert_se(unsetenv("WATCHDOG_USEC") >= 0);

        if (old_pid)
                assert_se(setenv("WATCHDOG_PID", old_pid, 1) >= 0);
        else
                assert_se(unsetenv("WATCHDOG_PID") >= 0);
}

TEST(sd_listen_fds_env_paths) {
        _cleanup_free_ char *old_pid = NULL;
        _cleanup_free_ char *old_pidfdid = NULL;
        _cleanup_free_ char *old_fds = NULL;
        _cleanup_free_ char *old_fdnames = NULL;
        char pid_buf[32];
        int c, r;
        _cleanup_strv_free_ char **c_names = NULL;
        _cleanup_strv_free_ char **r_names = NULL;
        _cleanup_(fd3_state_done) Fd3State fd3 = {};

        old_pid = getenv("LISTEN_PID") ? strdup(getenv("LISTEN_PID")) : NULL;
        old_pidfdid = getenv("LISTEN_PIDFDID") ? strdup(getenv("LISTEN_PIDFDID")) : NULL;
        old_fds = getenv("LISTEN_FDS") ? strdup(getenv("LISTEN_FDS")) : NULL;
        old_fdnames = getenv("LISTEN_FDNAMES") ? strdup(getenv("LISTEN_FDNAMES")) : NULL;

        ASSERT_OK(fd3_state_prepare(&fd3));

        assert_se(unsetenv("LISTEN_PID") >= 0);
        assert_se(unsetenv("LISTEN_PIDFDID") >= 0);
        assert_se(unsetenv("LISTEN_FDS") >= 0);
        assert_se(unsetenv("LISTEN_FDNAMES") >= 0);

        c = sd_listen_fds(false);
        r = rs_libsystemd_sd_listen_fds(false);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 0);

        assert_se(setenv("LISTEN_PID", "not-a-pid", 1) >= 0);
        assert_se(setenv("LISTEN_FDS", "1", 1) >= 0);
        c = sd_listen_fds(false);
        r = rs_libsystemd_sd_listen_fds(false);
        ASSERT_EQ(c, r);
        ASSERT_LT(c, 0);

        assert_se(setenv("LISTEN_PID", "1", 1) >= 0);
        assert_se(setenv("LISTEN_FDS", "1", 1) >= 0);
        assert_se(unsetenv("LISTEN_PIDFDID") >= 0);
        c = sd_listen_fds(false);
        r = rs_libsystemd_sd_listen_fds(false);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 0);

        assert_se(snprintf(pid_buf, sizeof(pid_buf), "%ld", (long) getpid()) > 0);
        assert_se(setenv("LISTEN_PID", pid_buf, 1) >= 0);
        assert_se(setenv("LISTEN_FDS", "0", 1) >= 0);
        assert_se(unsetenv("LISTEN_PIDFDID") >= 0);
        c = sd_listen_fds(false);
        r = rs_libsystemd_sd_listen_fds(false);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, -EINVAL);

        assert_se(setenv("LISTEN_PID", pid_buf, 1) >= 0);
        assert_se(setenv("LISTEN_FDS", "not-a-number", 1) >= 0);
        c = sd_listen_fds(false);
        r = rs_libsystemd_sd_listen_fds(false);
        ASSERT_EQ(c, r);
        ASSERT_LT(c, 0);

        assert_se(setenv("LISTEN_PID", "not-a-pid", 1) >= 0);
        assert_se(setenv("LISTEN_FDS", "1", 1) >= 0);
        assert_se(setenv("LISTEN_PIDFDID", "123", 1) >= 0);
        assert_se(setenv("LISTEN_FDNAMES", "dummy", 1) >= 0);
        c = sd_listen_fds(true);
        r = rs_libsystemd_sd_listen_fds(true);
        ASSERT_EQ(c, r);
        ASSERT_LT(c, 0);
        ASSERT_NULL(getenv("LISTEN_PID"));
        ASSERT_NULL(getenv("LISTEN_PIDFDID"));
        ASSERT_NULL(getenv("LISTEN_FDS"));
        ASSERT_NULL(getenv("LISTEN_FDNAMES"));

        assert_se(setenv("LISTEN_PID", pid_buf, 1) >= 0);
        assert_se(setenv("LISTEN_FDS", "1", 1) >= 0);
        assert_se(setenv("LISTEN_FDNAMES", "alpha", 1) >= 0);
        c = sd_listen_fds_with_names(false, &c_names);
        r = rs_libsystemd_sd_listen_fds_with_names(false, &r_names);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 1);
        ASSERT_STREQ(c_names[0], "alpha");
        ASSERT_STREQ(r_names[0], "alpha");
        ASSERT_NULL(c_names[1]);
        ASSERT_NULL(r_names[1]);
        c_names = strv_free(c_names);
        r_names = strv_free(r_names);

        assert_se(setenv("LISTEN_PID", pid_buf, 1) >= 0);
        assert_se(setenv("LISTEN_FDS", "1", 1) >= 0);
        assert_se(unsetenv("LISTEN_FDNAMES") >= 0);
        c = sd_listen_fds_with_names(false, &c_names);
        r = rs_libsystemd_sd_listen_fds_with_names(false, &r_names);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 1);
        ASSERT_STREQ(c_names[0], "unknown");
        ASSERT_STREQ(r_names[0], "unknown");
        ASSERT_NULL(c_names[1]);
        ASSERT_NULL(r_names[1]);
        c_names = strv_free(c_names);
        r_names = strv_free(r_names);

        assert_se(setenv("LISTEN_PID", pid_buf, 1) >= 0);
        assert_se(setenv("LISTEN_FDS", "1", 1) >= 0);
        assert_se(setenv("LISTEN_FDNAMES", "a:b", 1) >= 0);
        c = sd_listen_fds_with_names(false, &c_names);
        r = rs_libsystemd_sd_listen_fds_with_names(false, &r_names);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, -EINVAL);
        ASSERT_NULL(c_names);
        ASSERT_NULL(r_names);

        if (old_pid)
                assert_se(setenv("LISTEN_PID", old_pid, 1) >= 0);
        else
                assert_se(unsetenv("LISTEN_PID") >= 0);

        if (old_pidfdid)
                assert_se(setenv("LISTEN_PIDFDID", old_pidfdid, 1) >= 0);
        else
                assert_se(unsetenv("LISTEN_PIDFDID") >= 0);

        if (old_fds)
                assert_se(setenv("LISTEN_FDS", old_fds, 1) >= 0);
        else
                assert_se(unsetenv("LISTEN_FDS") >= 0);

        if (old_fdnames)
                assert_se(setenv("LISTEN_FDNAMES", old_fdnames, 1) >= 0);
        else
                assert_se(unsetenv("LISTEN_FDNAMES") >= 0);
}

TEST(sd_is_mq_basic) {
        _cleanup_close_ int fd = -1;
        _cleanup_close_ int mqfd = -1;
        char name[96];
        struct mq_attr attr = {
                .mq_maxmsg = 4,
                .mq_msgsize = 16,
        };
        int c, r;

        fd = open("/dev/null", O_RDONLY|O_CLOEXEC);
        ASSERT_GE(fd, 0);
        ASSERT_EQ(sd_is_mq(fd, NULL), rs_libsystemd_sd_is_mq(fd, NULL));
        ASSERT_EQ(sd_is_mq(fd, NULL), 0);

        for (unsigned i = 0; i < 16; i++) {
                assert_se(snprintf(name, sizeof(name), "/systemd-rs-mq-%ld-%u", (long) getpid(), i) > 0);
                mqfd = mq_open(name, O_CREAT|O_EXCL|O_RDONLY|O_CLOEXEC, 0600, &attr);
                if (mqfd >= 0)
                        break;
                if (errno != EEXIST)
                        break;
        }

        if (mqfd < 0) {
                log_debug("mq_open failed (%m), skipping mq positive checks");
                return;
        }

        c = sd_is_mq(mqfd, NULL);
        r = rs_libsystemd_sd_is_mq(mqfd, NULL);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 1);

        c = sd_is_mq(mqfd, "not-absolute");
        r = rs_libsystemd_sd_is_mq(mqfd, "not-absolute");
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, -EINVAL);

        c = sd_is_mq(mqfd, name);
        r = rs_libsystemd_sd_is_mq(mqfd, name);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 1);

        assert_se(mq_unlink(name) >= 0 || errno == ENOENT);
}

TEST(sd_notify_wrappers_basic) {
        _cleanup_free_ char *old_notify = NULL;
        int c, r;

        old_notify = getenv("NOTIFY_SOCKET") ? strdup(getenv("NOTIFY_SOCKET")) : NULL;
        if (getenv("NOTIFY_SOCKET"))
                assert_se(old_notify);

        assert_se(unsetenv("NOTIFY_SOCKET") >= 0);

        c = sd_pid_notify_with_fds(0, false, "READY=1", NULL, 0);
        r = rs_libsystemd_sd_pid_notify_with_fds(0, false, "READY=1", NULL, 0);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 0);

        c = sd_pid_notify(0, false, "READY=1");
        r = rs_libsystemd_sd_pid_notify(0, false, "READY=1");
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 0);

        c = sd_notify(false, "READY=1");
        r = rs_libsystemd_sd_notify(false, "READY=1");
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 0);

        c = sd_pid_notify_barrier(0, false, 1);
        r = rs_libsystemd_sd_pid_notify_barrier(0, false, 1);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 0);

        c = sd_notify_barrier(false, 1);
        r = rs_libsystemd_sd_notify_barrier(false, 1);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, 0);

        assert_se(setenv("NOTIFY_SOCKET", "invalid-notify-address", 1) >= 0);
        c = sd_notify(false, "READY=1");
        r = rs_libsystemd_sd_notify(false, "READY=1");
        ASSERT_EQ(c, r);
        ASSERT_LT(c, 0);
        ASSERT_STREQ(getenv("NOTIFY_SOCKET"), "invalid-notify-address");

        c = sd_notify(true, "READY=1");
        r = rs_libsystemd_sd_notify(true, "READY=1");
        ASSERT_EQ(c, r);
        ASSERT_LT(c, 0);
        ASSERT_NULL(getenv("NOTIFY_SOCKET"));

        assert_se(setenv("NOTIFY_SOCKET", "invalid-notify-address", 1) >= 0);
        c = sd_pid_notify_with_fds(0, true, NULL, NULL, 0);
        r = rs_libsystemd_sd_pid_notify_with_fds(0, true, NULL, NULL, 0);
        ASSERT_EQ(c, r);
        ASSERT_EQ(c, -EINVAL);
        ASSERT_NULL(getenv("NOTIFY_SOCKET"));

        if (old_notify)
                assert_se(setenv("NOTIFY_SOCKET", old_notify, 1) >= 0);
        else
                assert_se(unsetenv("NOTIFY_SOCKET") >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
