/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C vs Rust for stat verify functions and device path validators */

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/stat.h>
#include "tests.h"
#include "stat-util.h"
#include "path-util.h"
#include "rust/path_util.h"
#include "rust/stat_util.h"

/* -- stat_verify_regular --------------------------------------------------- */

static void test_stat_verify_regular(void) {
        struct stat st;

        memset(&st, 0, sizeof(st));
        st.st_mode = S_IFREG | 0644;
        assert_se(stat_verify_regular(&st) == rs_stat_verify_regular(&st));
        assert_se(stat_verify_regular(&st) == 0);

        st.st_mode = S_IFDIR | 0755;
        assert_se(stat_verify_regular(&st) == rs_stat_verify_regular(&st));
        assert_se(stat_verify_regular(&st) == -EISDIR);

        st.st_mode = S_IFLNK | 0777;
        assert_se(stat_verify_regular(&st) == rs_stat_verify_regular(&st));
        assert_se(stat_verify_regular(&st) == -ELOOP);

        st.st_mode = S_IFCHR | 0600;
        assert_se(stat_verify_regular(&st) == rs_stat_verify_regular(&st));
        assert_se(stat_verify_regular(&st) == -EBADFD);
}

static void test_statx_verify_regular(void) {
        struct statx stx;

        memset(&stx, 0, sizeof(stx));
        stx.stx_mask = STATX_TYPE;
        stx.stx_mode = S_IFREG;
        assert_se(statx_verify_regular(&stx) == rs_statx_verify_regular(&stx));
        assert_se(statx_verify_regular(&stx) == 0);

        stx.stx_mode = S_IFDIR;
        assert_se(statx_verify_regular(&stx) == rs_statx_verify_regular(&stx));
        assert_se(statx_verify_regular(&stx) == -EISDIR);

        /* Without STATX_TYPE */
        stx.stx_mask = 0;
        stx.stx_mode = S_IFREG;
        assert_se(statx_verify_regular(&stx) == rs_statx_verify_regular(&stx));
        assert_se(statx_verify_regular(&stx) == -ENODATA);
}

/* -- stat_verify_directory ------------------------------------------------- */

static void test_stat_verify_directory(void) {
        struct stat st;

        memset(&st, 0, sizeof(st));
        st.st_mode = S_IFDIR | 0755;
        assert_se(stat_verify_directory(&st) == rs_stat_verify_directory(&st));
        assert_se(stat_verify_directory(&st) == 0);

        st.st_mode = S_IFREG | 0644;
        assert_se(stat_verify_directory(&st) == rs_stat_verify_directory(&st));
        assert_se(stat_verify_directory(&st) == -ENOTDIR);

        st.st_mode = S_IFLNK | 0777;
        assert_se(stat_verify_directory(&st) == rs_stat_verify_directory(&st));
        assert_se(stat_verify_directory(&st) == -ELOOP);
}

static void test_statx_verify_directory(void) {
        struct statx stx;

        memset(&stx, 0, sizeof(stx));
        stx.stx_mask = STATX_TYPE;
        stx.stx_mode = S_IFDIR;
        assert_se(statx_verify_directory(&stx) == rs_statx_verify_directory(&stx));
        assert_se(statx_verify_directory(&stx) == 0);

        stx.stx_mask = 0;
        assert_se(statx_verify_directory(&stx) == rs_statx_verify_directory(&stx));
        assert_se(statx_verify_directory(&stx) == -ENODATA);
}

/* -- stat_verify_symlink --------------------------------------------------- */

static void test_stat_verify_symlink(void) {
        struct stat st;

        memset(&st, 0, sizeof(st));
        st.st_mode = S_IFLNK | 0777;
        assert_se(stat_verify_symlink(&st) == rs_stat_verify_symlink(&st));
        assert_se(stat_verify_symlink(&st) == 0);

        st.st_mode = S_IFDIR | 0755;
        assert_se(stat_verify_symlink(&st) == rs_stat_verify_symlink(&st));
        assert_se(stat_verify_symlink(&st) == -EISDIR);

        st.st_mode = S_IFREG | 0644;
        assert_se(stat_verify_symlink(&st) == rs_stat_verify_symlink(&st));
        assert_se(stat_verify_symlink(&st) == -ENOLINK);
}

/* -- stat_verify_socket --------------------------------------------------- */

static void test_stat_verify_socket(void) {
        struct stat st;

        memset(&st, 0, sizeof(st));
        st.st_mode = S_IFSOCK | 0600;
        assert_se(stat_verify_socket(&st) == rs_stat_verify_socket(&st));
        assert_se(stat_verify_socket(&st) == 0);

        st.st_mode = S_IFDIR | 0755;
        assert_se(stat_verify_socket(&st) == rs_stat_verify_socket(&st));
        assert_se(stat_verify_socket(&st) == -EISDIR);

        st.st_mode = S_IFREG | 0644;
        assert_se(stat_verify_socket(&st) == rs_stat_verify_socket(&st));
        assert_se(stat_verify_socket(&st) == -ENOTSOCK);
}

static void test_statx_verify_socket(void) {
        struct statx stx;

        memset(&stx, 0, sizeof(stx));
        stx.stx_mode = S_IFSOCK;
        assert_se(statx_verify_socket(&stx) == rs_statx_verify_socket(&stx));
        assert_se(statx_verify_socket(&stx) == 0);

        stx.stx_mode = S_IFREG;
        assert_se(statx_verify_socket(&stx) == rs_statx_verify_socket(&stx));
        assert_se(statx_verify_socket(&stx) == -ENOTSOCK);
}

/* -- stat_verify_linked ---------------------------------------------------- */

static void test_stat_verify_linked(void) {
        struct stat st;

        memset(&st, 0, sizeof(st));
        st.st_nlink = 1;
        assert_se(stat_verify_linked(&st) == rs_stat_verify_linked(&st));
        assert_se(stat_verify_linked(&st) == 0);

        st.st_nlink = (nlink_t) INT32_MAX + 1U;
        assert_se(stat_verify_linked(&st) == rs_stat_verify_linked(&st));
        assert_se(stat_verify_linked(&st) == 0);

        st.st_nlink = 0;
        assert_se(stat_verify_linked(&st) == rs_stat_verify_linked(&st));
        assert_se(stat_verify_linked(&st) == -EIDRM);
}

/* -- stat_verify_block ----------------------------------------------------- */

static void test_stat_verify_block(void) {
        struct stat st = {};

        st.st_mode = S_IFBLK | 0600;
        assert_se(stat_verify_block(&st) == rs_stat_verify_block(&st));
        assert_se(stat_verify_block(&st) == 0);

        st.st_mode = S_IFDIR | 0755;
        assert_se(stat_verify_block(&st) == rs_stat_verify_block(&st));
        assert_se(stat_verify_block(&st) == -EISDIR);

        st.st_mode = S_IFLNK | 0777;
        assert_se(stat_verify_block(&st) == rs_stat_verify_block(&st));
        assert_se(stat_verify_block(&st) == -ELOOP);

        st.st_mode = S_IFCHR | 0600;
        assert_se(stat_verify_block(&st) == rs_stat_verify_block(&st));
        assert_se(stat_verify_block(&st) == -ENOTBLK);

        assert_se(rs_stat_verify_block(NULL) == -EINVAL);
}

/* -- stat_verify_char ------------------------------------------------------ */

static void test_stat_verify_char(void) {
        struct stat st = {};

        st.st_mode = S_IFCHR | 0600;
        assert_se(stat_verify_char(&st) == rs_stat_verify_char(&st));
        assert_se(stat_verify_char(&st) == 0);

        st.st_mode = S_IFDIR | 0755;
        assert_se(stat_verify_char(&st) == rs_stat_verify_char(&st));
        assert_se(stat_verify_char(&st) == -EISDIR);

        st.st_mode = S_IFLNK | 0777;
        assert_se(stat_verify_char(&st) == rs_stat_verify_char(&st));
        assert_se(stat_verify_char(&st) == -ELOOP);

        st.st_mode = S_IFBLK | 0600;
        assert_se(stat_verify_char(&st) == rs_stat_verify_char(&st));
        assert_se(stat_verify_char(&st) == -EBADFD);

        assert_se(rs_stat_verify_char(NULL) == -EINVAL);
}

/* -- stat_verify_regular_or_block ----------------------------------------- */

static void test_stat_verify_regular_or_block(void) {
        struct stat st = {};

        st.st_mode = S_IFREG | 0644;
        assert_se(stat_verify_regular_or_block(&st) == rs_stat_verify_regular_or_block(&st));
        assert_se(stat_verify_regular_or_block(&st) == 0);

        st.st_mode = S_IFBLK | 0600;
        assert_se(stat_verify_regular_or_block(&st) == rs_stat_verify_regular_or_block(&st));
        assert_se(stat_verify_regular_or_block(&st) == 0);

        st.st_mode = S_IFDIR | 0755;
        assert_se(stat_verify_regular_or_block(&st) == rs_stat_verify_regular_or_block(&st));
        assert_se(stat_verify_regular_or_block(&st) == -EISDIR);

        st.st_mode = S_IFLNK | 0777;
        assert_se(stat_verify_regular_or_block(&st) == rs_stat_verify_regular_or_block(&st));
        assert_se(stat_verify_regular_or_block(&st) == -ELOOP);

        st.st_mode = S_IFCHR | 0600;
        assert_se(stat_verify_regular_or_block(&st) == rs_stat_verify_regular_or_block(&st));
        assert_se(stat_verify_regular_or_block(&st) == -EBADFD);

        assert_se(rs_stat_verify_regular_or_block(NULL) == -EINVAL);
}

/* -- stat_verify_device_node ---------------------------------------------- */

static void test_stat_verify_device_node(void) {
        struct stat st;

        memset(&st, 0, sizeof(st));
        st.st_mode = S_IFCHR | 0600;
        assert_se(stat_verify_device_node(&st) == rs_stat_verify_device_node(&st));
        assert_se(stat_verify_device_node(&st) == 0);

        st.st_mode = S_IFBLK | 0600;
        assert_se(stat_verify_device_node(&st) == rs_stat_verify_device_node(&st));
        assert_se(stat_verify_device_node(&st) == 0);

        st.st_mode = S_IFREG | 0644;
        assert_se(stat_verify_device_node(&st) == rs_stat_verify_device_node(&st));
        assert_se(stat_verify_device_node(&st) == -ENOTTY);

        st.st_mode = S_IFDIR | 0755;
        assert_se(stat_verify_device_node(&st) == rs_stat_verify_device_node(&st));
        assert_se(stat_verify_device_node(&st) == -EISDIR);

        st.st_mode = S_IFLNK | 0777;
        assert_se(stat_verify_device_node(&st) == rs_stat_verify_device_node(&st));
        assert_se(stat_verify_device_node(&st) == -ELOOP);
}

/* -- stat_may_be_dev_null ------------------------------------------------- */

static void test_stat_may_be_dev_null(void) {
        struct stat st;

        memset(&st, 0, sizeof(st));
        st.st_mode = S_IFCHR | 0600;
        assert_se(rs_stat_may_be_dev_null(&st) == stat_may_be_dev_null(&st));
        assert_se(rs_stat_may_be_dev_null(&st) == true);

        st.st_mode = S_IFREG | 0644;
        assert_se(rs_stat_may_be_dev_null(&st) == stat_may_be_dev_null(&st));
        assert_se(rs_stat_may_be_dev_null(&st) == false);

        st.st_mode = S_IFBLK | 0600;
        assert_se(rs_stat_may_be_dev_null(&st) == stat_may_be_dev_null(&st));
        assert_se(rs_stat_may_be_dev_null(&st) == false);
}

/* -- stat_is_empty --------------------------------------------------------- */

static void test_stat_is_empty(void) {
        struct stat st;

        memset(&st, 0, sizeof(st));
        st.st_mode = S_IFREG | 0644;
        st.st_size = 0;
        assert_se(rs_stat_is_empty(&st) == stat_is_empty(&st));
        assert_se(rs_stat_is_empty(&st) == true);

        st.st_size = 100;
        assert_se(rs_stat_is_empty(&st) == stat_is_empty(&st));
        assert_se(rs_stat_is_empty(&st) == false);

        st.st_size = -1;
        assert_se(rs_stat_is_empty(&st) == stat_is_empty(&st));
        assert_se(rs_stat_is_empty(&st) == true);

        st.st_mode = S_IFDIR | 0755;
        st.st_size = 0;
        assert_se(rs_stat_is_empty(&st) == stat_is_empty(&st));
        assert_se(rs_stat_is_empty(&st) == false);
}

/* -- is_device_path ------------------------------------------------------- */

static void test_is_device_path(void) {
        static const char non_utf8_device[] = "/dev/\xff";
        char overlong[STRLEN("/dev/") + NAME_MAX + 2];

        assert_se(rs_is_device_path("/dev/sda") == is_device_path("/dev/sda"));
        assert_se(rs_is_device_path("/dev/sda") == true);
        assert_se(rs_is_device_path("/dev/sda/foo") == is_device_path("/dev/sda/foo"));
        assert_se(rs_is_device_path("/dev/sda/foo") == true);
        assert_se(rs_is_device_path("/sys/class") == is_device_path("/sys/class"));
        assert_se(rs_is_device_path("/sys/class") == true);
        assert_se(rs_is_device_path("/dev/..") == is_device_path("/dev/.."));
        assert_se(rs_is_device_path("/dev/..") == true);
        assert_se(rs_is_device_path("/sys/..") == is_device_path("/sys/.."));
        assert_se(rs_is_device_path("/sys/..") == true);
        assert_se(rs_is_device_path("/dev") == is_device_path("/dev"));
        assert_se(rs_is_device_path("/dev") == false);
        assert_se(rs_is_device_path("/sys") == is_device_path("/sys"));
        assert_se(rs_is_device_path("/sys") == false);
        assert_se(rs_is_device_path("/usr/path") == is_device_path("/usr/path"));
        assert_se(rs_is_device_path("/usr/path") == false);
        assert_se(rs_is_device_path("/./dev/foo") == is_device_path("/./dev/foo"));
        assert_se(rs_is_device_path("/./dev/foo") == true);
        assert_se(rs_is_device_path("/../dev/sda") == is_device_path("/../dev/sda"));
        assert_se(rs_is_device_path("/../dev/sda") == false);
        assert_se(rs_is_device_path("/dev//./foo") == is_device_path("/dev//./foo"));
        assert_se(rs_is_device_path("/dev//./foo") == true);
        assert_se(rs_is_device_path("/dev/.") == is_device_path("/dev/."));
        assert_se(rs_is_device_path("/dev/.") == false);
        assert_se(rs_is_device_path(non_utf8_device) == is_device_path(non_utf8_device));
        assert_se(rs_is_device_path(non_utf8_device) == true);

        memcpy(overlong, "/dev/", STRLEN("/dev/"));
        memset(overlong + STRLEN("/dev/"), 'x', NAME_MAX + 1);
        overlong[sizeof(overlong) - 1] = 0;
        assert_se(rs_is_device_path(overlong) == is_device_path(overlong));
        assert_se(rs_is_device_path(overlong) == false);
}

static void test_inode_type_can_hardlink(void) {
        assert_se(inode_type_can_hardlink(S_IFSOCK) == rs_inode_type_can_hardlink(S_IFSOCK));
        assert_se(inode_type_can_hardlink(S_IFLNK) == rs_inode_type_can_hardlink(S_IFLNK));
        assert_se(inode_type_can_hardlink(S_IFREG) == rs_inode_type_can_hardlink(S_IFREG));
        assert_se(inode_type_can_hardlink(S_IFBLK) == rs_inode_type_can_hardlink(S_IFBLK));
        assert_se(inode_type_can_hardlink(S_IFCHR) == rs_inode_type_can_hardlink(S_IFCHR));
        assert_se(inode_type_can_hardlink(S_IFIFO) == rs_inode_type_can_hardlink(S_IFIFO));
        assert_se(inode_type_can_hardlink(S_IFDIR) == rs_inode_type_can_hardlink(S_IFDIR));
        assert_se(inode_type_can_hardlink(0) == rs_inode_type_can_hardlink(0));
        assert_se(inode_type_can_hardlink(S_IFMT) == rs_inode_type_can_hardlink(S_IFMT));
}

static void test_descriptor_verification(void) {
        int sockets[2];

        assert_se(verify_regular_at(AT_FDCWD, ".", false) ==
                  rs_verify_regular_at(AT_FDCWD, ".", false));
        assert_se(fd_verify_regular(STDIN_FILENO) == rs_fd_verify_regular(STDIN_FILENO));
        assert_se(fd_verify_regular(AT_FDCWD) == rs_fd_verify_regular(AT_FDCWD));

        assert_se(fd_verify_directory(AT_FDCWD) == rs_fd_verify_directory(AT_FDCWD));
        assert_se(is_dir_at(AT_FDCWD, ".", true) == rs_is_dir_at(AT_FDCWD, ".", true));
        assert_se(is_dir(".", true) == rs_is_dir(".", true));
        assert_se(is_dir("/dev/null", true) == rs_is_dir("/dev/null", true));

        assert_se(fd_verify_symlink(STDIN_FILENO) == rs_fd_verify_symlink(STDIN_FILENO));
        assert_se(is_symlink(".") == rs_is_symlink("."));

        assert_se(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) >= 0);
        assert_se(fd_verify_socket(sockets[0]) == rs_fd_verify_socket(sockets[0]));
        assert_se(close(sockets[0]) >= 0);
        assert_se(close(sockets[1]) >= 0);
        assert_se(is_socket(".") == rs_is_socket("."));

        assert_se(fd_verify_linked(STDIN_FILENO) == rs_fd_verify_linked(STDIN_FILENO));
        assert_se(fd_verify_block(STDIN_FILENO) == rs_fd_verify_block(STDIN_FILENO));
        assert_se(is_device_node("/dev/null") == rs_is_device_node("/dev/null"));
        assert_se(fd_verify_regular_or_block(STDIN_FILENO) ==
                  rs_fd_verify_regular_or_block(STDIN_FILENO));

        assert_se(rs_verify_regular_at(-1, NULL, false) == -EBADF);
        assert_se(rs_verify_regular_at(AT_FDCWD, NULL, true) == -EINVAL);
        assert_se(rs_is_dir(NULL, true) == -EINVAL);
        assert_se(rs_is_symlink(NULL) == -EINVAL);
        assert_se(rs_is_socket(NULL) == -EINVAL);
        assert_se(rs_is_device_node(NULL) == -EINVAL);
}

int main(int argc, char **argv) {
        test_stat_verify_regular();
        test_statx_verify_regular();
        test_stat_verify_directory();
        test_statx_verify_directory();
        test_stat_verify_symlink();
        test_stat_verify_socket();
        test_statx_verify_socket();
        test_stat_verify_linked();
        test_stat_verify_block();
        test_stat_verify_char();
        test_stat_verify_regular_or_block();
        test_stat_verify_device_node();
        test_stat_may_be_dev_null();
        test_stat_is_empty();
        test_is_device_path();
        test_inode_type_can_hardlink();
        test_descriptor_verification();
        return 0;
}
