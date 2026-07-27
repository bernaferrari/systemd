/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C stat-util functions vs Rust */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "chattr-util.h"
#include "siphash24.h"
#include "stat-util.h"
#include "tests.h"
#include "rust/stat_util.h"
#include "string-util.h"

/* -- inode_type_to_string ------------------------------------------------- */

static void test_inode_type_to_string(void) {
        assert_se(streq(inode_type_to_string(S_IFREG), rs_inode_type_to_string(S_IFREG)));
        assert_se(streq(inode_type_to_string(S_IFREG), "reg"));
        assert_se(streq(inode_type_to_string(S_IFDIR), rs_inode_type_to_string(S_IFDIR)));
        assert_se(streq(inode_type_to_string(S_IFDIR), "dir"));
        assert_se(streq(inode_type_to_string(S_IFLNK), rs_inode_type_to_string(S_IFLNK)));
        assert_se(streq(inode_type_to_string(S_IFLNK), "lnk"));
        assert_se(streq(inode_type_to_string(S_IFCHR), rs_inode_type_to_string(S_IFCHR)));
        assert_se(streq(inode_type_to_string(S_IFCHR), "chr"));
        assert_se(streq(inode_type_to_string(S_IFBLK), rs_inode_type_to_string(S_IFBLK)));
        assert_se(streq(inode_type_to_string(S_IFBLK), "blk"));
        assert_se(streq(inode_type_to_string(S_IFIFO), rs_inode_type_to_string(S_IFIFO)));
        assert_se(streq(inode_type_to_string(S_IFIFO), "fifo"));
        assert_se(streq(inode_type_to_string(S_IFSOCK), rs_inode_type_to_string(S_IFSOCK)));
        assert_se(streq(inode_type_to_string(S_IFSOCK), "sock"));
        assert_se(inode_type_to_string(0) == rs_inode_type_to_string(0));
        assert_se(inode_type_to_string(0) == NULL);
        assert_se(streq(inode_type_to_string(S_IFREG | 0755),
                        rs_inode_type_to_string(S_IFREG | 0755)));
        assert_se(streq(inode_type_to_string(S_IFREG | 0755), "reg"));
}

/* -- inode_type_from_string ----------------------------------------------- */

static void test_inode_type_from_string(void) {
        static const char non_utf8[] = "\xff";

        assert_se(inode_type_from_string("reg") == rs_inode_type_from_string("reg"));
        assert_se(inode_type_from_string("reg") == S_IFREG);
        assert_se(inode_type_from_string("dir") == rs_inode_type_from_string("dir"));
        assert_se(inode_type_from_string("lnk") == rs_inode_type_from_string("lnk"));
        assert_se(inode_type_from_string("chr") == rs_inode_type_from_string("chr"));
        assert_se(inode_type_from_string("blk") == rs_inode_type_from_string("blk"));
        assert_se(inode_type_from_string("fifo") == rs_inode_type_from_string("fifo"));
        assert_se(inode_type_from_string("sock") == rs_inode_type_from_string("sock"));
        assert_se(inode_type_from_string("invalid") == rs_inode_type_from_string("invalid"));
        assert_se(inode_type_from_string("invalid") == MODE_INVALID);
        assert_se(inode_type_from_string(non_utf8) == rs_inode_type_from_string(non_utf8));
        assert_se(inode_type_from_string(non_utf8) == MODE_INVALID);
        assert_se(inode_type_from_string(NULL) == rs_inode_type_from_string(NULL));
        assert_se(inode_type_from_string(NULL) == MODE_INVALID);
}

/* -- inode_compare_func -------------------------------------------------- */

static void test_inode_compare_func(void) {
        struct stat a = {}, b = {};

        a.st_dev = 1; a.st_ino = 100; a.st_mode = S_IFREG;
        b.st_dev = 1; b.st_ino = 100; b.st_mode = S_IFREG;

        assert_se(inode_compare_func(&a, &b) == rs_inode_compare_func(&a, &b));
        assert_se(inode_compare_func(&a, &b) == 0);

        /* Different device */
        b.st_dev = 2;
        assert_se(inode_compare_func(&a, &b) == rs_inode_compare_func(&a, &b));
        assert_se(inode_compare_func(&a, &b) == -1);
        assert_se(inode_compare_func(&b, &a) == rs_inode_compare_func(&b, &a));
        assert_se(inode_compare_func(&b, &a) == 1);

        /* Different inode */
        b.st_dev = 1; b.st_ino = 200;
        assert_se(inode_compare_func(&a, &b) == rs_inode_compare_func(&a, &b));
        assert_se(inode_compare_func(&a, &b) == -1);
        assert_se(inode_compare_func(&b, &a) == rs_inode_compare_func(&b, &a));
        assert_se(inode_compare_func(&b, &a) == 1);

        /* Different type */
        b.st_ino = 100; b.st_mode = S_IFDIR;
        assert_se(inode_compare_func(&a, &b) == rs_inode_compare_func(&a, &b));
        assert_se(inode_compare_func(&a, &b) == 1); /* S_IFREG > S_IFDIR */
        assert_se(inode_compare_func(&b, &a) == rs_inode_compare_func(&b, &a));
        assert_se(inode_compare_func(&b, &a) == -1);

        /* Preserve target dev_t width and signedness without narrowing. */
        a.st_dev = (dev_t) -1;
        b.st_dev = 1;
        b.st_mode = S_IFREG;
        assert_se(inode_compare_func(&a, &b) == rs_inode_compare_func(&a, &b));

        assert_se(rs_inode_compare_func(NULL, &b) == -EINVAL);
        assert_se(rs_inode_compare_func(&a, NULL) == -EINVAL);
}

/* -- inode_unmodified_compare_func ---------------------------------------- */

static void test_inode_unmodified_compare_func(void) {
        struct stat a = {}, b = {};

        a.st_dev = 1; a.st_ino = 100; a.st_mode = S_IFREG;
        a.st_mtim.tv_sec = 1000; a.st_size = 500;
        memcpy(&b, &a, sizeof(b));

        assert_se(inode_unmodified_compare_func(&a, &b) == rs_inode_unmodified_compare_func(&a, &b));
        assert_se(inode_unmodified_compare_func(&a, &b) == 0);

        /* Signed time_t ordering must not be narrowed or treated as unsigned. */
        a.st_mtim.tv_sec = -2;
        b.st_mtim.tv_sec = -1;
        assert_se(inode_unmodified_compare_func(&a, &b) == rs_inode_unmodified_compare_func(&a, &b));
        assert_se(inode_unmodified_compare_func(&a, &b) == -1);
        assert_se(inode_unmodified_compare_func(&b, &a) == rs_inode_unmodified_compare_func(&b, &a));
        assert_se(inode_unmodified_compare_func(&b, &a) == 1);

        /* tv_nsec has the target's native signed long width. */
        a.st_mtim.tv_sec = b.st_mtim.tv_sec = -1;
        a.st_mtim.tv_nsec = -2;
        b.st_mtim.tv_nsec = -1;
        assert_se(inode_unmodified_compare_func(&a, &b) == rs_inode_unmodified_compare_func(&a, &b));
        assert_se(inode_unmodified_compare_func(&a, &b) == -1);
        assert_se(inode_unmodified_compare_func(&b, &a) == rs_inode_unmodified_compare_func(&b, &a));
        assert_se(inode_unmodified_compare_func(&b, &a) == 1);

        /* Signed off_t ordering for regular files. */
        memcpy(&b, &a, sizeof(b));
        a.st_size = -2;
        b.st_size = -1;
        assert_se(inode_unmodified_compare_func(&a, &b) == rs_inode_unmodified_compare_func(&a, &b));
        assert_se(inode_unmodified_compare_func(&a, &b) == -1);
        assert_se(inode_unmodified_compare_func(&b, &a) == rs_inode_unmodified_compare_func(&b, &a));
        assert_se(inode_unmodified_compare_func(&b, &a) == 1);

        /* Preserve target dev_t width and signedness for device nodes. */
        a.st_mode = S_IFCHR; a.st_rdev = (dev_t) -1;
        b.st_mode = S_IFCHR; b.st_rdev = 1;
        assert_se(inode_unmodified_compare_func(&a, &b) == rs_inode_unmodified_compare_func(&a, &b));
        assert_se(inode_unmodified_compare_func(&b, &a) == rs_inode_unmodified_compare_func(&b, &a));

        assert_se(rs_inode_unmodified_compare_func(NULL, &b) == -EINVAL);
        assert_se(rs_inode_unmodified_compare_func(&a, NULL) == -EINVAL);
}

/* -- stat_inode_same ------------------------------------------------------ */

static void test_stat_inode_same(void) {
        struct stat a = {}, b = {};

        a.st_dev = 1; a.st_ino = 100; a.st_mode = S_IFREG | 0644;
        memcpy(&b, &a, sizeof(b));

        assert_se(stat_inode_same(&a, &b) == rs_stat_inode_same(&a, &b));
        assert_se(stat_inode_same(&a, &b) == true);

        /* Different device */
        b.st_dev = 2;
        assert_se(stat_inode_same(&a, &b) == rs_stat_inode_same(&a, &b));
        assert_se(stat_inode_same(&a, &b) == false);

        /* Different inode */
        b.st_dev = 1; b.st_ino = 200;
        assert_se(stat_inode_same(&a, &b) == rs_stat_inode_same(&a, &b));
        assert_se(stat_inode_same(&a, &b) == false);

        /* Different type */
        b.st_ino = 100; b.st_mode = S_IFDIR | 0755;
        assert_se(stat_inode_same(&a, &b) == rs_stat_inode_same(&a, &b));
        assert_se(stat_inode_same(&a, &b) == false);

        /* Zero device */
        a.st_dev = 0;
        assert_se(stat_inode_same(&a, &b) == rs_stat_inode_same(&a, &b));
        assert_se(stat_inode_same(&a, &b) == false);

        /* MODE_INVALID is the other stat_is_set() invalid marker. */
        a.st_dev = 1;
        a.st_ino = 100;
        a.st_mode = MODE_INVALID;
        memcpy(&b, &a, sizeof(b));
        assert_se(stat_inode_same(&a, &b) == rs_stat_inode_same(&a, &b));
        assert_se(stat_inode_same(&a, &b) == false);

        assert_se(!rs_stat_inode_same(NULL, NULL));
        assert_se(!rs_stat_inode_same(NULL, &b));
        assert_se(!rs_stat_inode_same(&a, NULL));
}

/* -- stat_inode_unmodified ----------------------------------------------- */

static void test_stat_inode_unmodified(void) {
        struct stat a = {}, b = {};

        a.st_dev = 1;
        a.st_ino = 100;
        a.st_mode = S_IFREG | 0644;
        a.st_mtim.tv_sec = -2;
        a.st_mtim.tv_nsec = 17;
        a.st_size = -3;
        memcpy(&b, &a, sizeof(b));

        assert_se(stat_inode_unmodified(&a, &b) == rs_stat_inode_unmodified(&a, &b));
        assert_se(stat_inode_unmodified(&a, &b));

        b.st_mtim.tv_sec = -1;
        assert_se(stat_inode_unmodified(&a, &b) == rs_stat_inode_unmodified(&a, &b));
        assert_se(!stat_inode_unmodified(&a, &b));

        memcpy(&b, &a, sizeof(b));
        b.st_mtim.tv_nsec++;
        assert_se(stat_inode_unmodified(&a, &b) == rs_stat_inode_unmodified(&a, &b));
        assert_se(!stat_inode_unmodified(&a, &b));

        memcpy(&b, &a, sizeof(b));
        b.st_size = -2;
        assert_se(stat_inode_unmodified(&a, &b) == rs_stat_inode_unmodified(&a, &b));
        assert_se(!stat_inode_unmodified(&a, &b));

        a.st_mode = b.st_mode = S_IFDIR | 0755;
        b.st_size = 1234;
        assert_se(stat_inode_unmodified(&a, &b) == rs_stat_inode_unmodified(&a, &b));
        assert_se(stat_inode_unmodified(&a, &b));

        a.st_mode = b.st_mode = S_IFCHR | 0600;
        a.st_rdev = (dev_t) -1;
        b.st_rdev = 1;
        assert_se(stat_inode_unmodified(&a, &b) == rs_stat_inode_unmodified(&a, &b));
        assert_se(!stat_inode_unmodified(&a, &b));

        assert_se(!rs_stat_inode_unmodified(NULL, &b));
        assert_se(!rs_stat_inode_unmodified(&a, NULL));
}

/* -- statx_inode_same ----------------------------------------------------- */

static void test_statx_inode_same(void) {
        struct statx a = {}, b = {};

        a.stx_mask = STATX_TYPE | STATX_INO;
        a.stx_mode = S_IFREG | 0644;
        a.stx_dev_major = 8;
        a.stx_dev_minor = 1;
        a.stx_ino = UINT64_MAX;
        memcpy(&b, &a, sizeof(b));

        assert_se(statx_inode_same(&a, &b) == rs_statx_inode_same(&a, &b));
        assert_se(statx_inode_same(&a, &b));

        b.stx_mode = S_IFREG | 0600;
        assert_se(statx_inode_same(&a, &b) == rs_statx_inode_same(&a, &b));
        assert_se(statx_inode_same(&a, &b));

        b.stx_mode = S_IFDIR | 0755;
        assert_se(statx_inode_same(&a, &b) == rs_statx_inode_same(&a, &b));
        assert_se(!statx_inode_same(&a, &b));

        memcpy(&b, &a, sizeof(b));
        b.stx_dev_major++;
        assert_se(statx_inode_same(&a, &b) == rs_statx_inode_same(&a, &b));
        assert_se(!statx_inode_same(&a, &b));

        memcpy(&b, &a, sizeof(b));
        b.stx_dev_minor++;
        assert_se(statx_inode_same(&a, &b) == rs_statx_inode_same(&a, &b));
        assert_se(!statx_inode_same(&a, &b));

        memcpy(&b, &a, sizeof(b));
        b.stx_ino--;
        assert_se(statx_inode_same(&a, &b) == rs_statx_inode_same(&a, &b));
        assert_se(!statx_inode_same(&a, &b));

        b.stx_mask = STATX_TYPE;
        assert_se(!rs_statx_inode_same(&a, &b));
        assert_se(!rs_statx_inode_same(NULL, &b));
        assert_se(!rs_statx_inode_same(&a, NULL));
}

/* -- statx_mount_same ----------------------------------------------------- */

static void test_statx_mount_same(void) {
        struct statx a = {}, b = {};

        assert_se(statx_mount_same(&a, &b) == rs_statx_mount_same(&a, &b));
        assert_se(statx_mount_same(&a, &b) == 0);

        a.stx_mask = b.stx_mask = STATX_MNT_ID;
        a.stx_mnt_id = b.stx_mnt_id = UINT64_MAX;
        assert_se(statx_mount_same(&a, &b) == rs_statx_mount_same(&a, &b));
        assert_se(statx_mount_same(&a, &b) == 1);

        b.stx_mnt_id--;
        assert_se(statx_mount_same(&a, &b) == rs_statx_mount_same(&a, &b));
        assert_se(statx_mount_same(&a, &b) == 0);

        a.stx_mask = b.stx_mask = STATX_MNT_ID_UNIQUE;
        a.stx_mnt_id = b.stx_mnt_id = 42;
        assert_se(statx_mount_same(&a, &b) == rs_statx_mount_same(&a, &b));
        assert_se(statx_mount_same(&a, &b) == 1);

        a.stx_mask = STATX_MNT_ID;
        b.stx_mask = STATX_MNT_ID_UNIQUE;
        assert_se(statx_mount_same(&a, &b) == rs_statx_mount_same(&a, &b));
        assert_se(statx_mount_same(&a, &b) == -ENODATA);

        assert_se(rs_statx_mount_same(NULL, &b) == 0);
        assert_se(rs_statx_mount_same(&a, NULL) == 0);
}

/* -- xstatx -------------------------------------------------------------- */

static void assert_statx_core_equal(const struct statx *a, const struct statx *b) {
        assert_se(a->stx_mask == b->stx_mask);
        assert_se(a->stx_attributes == b->stx_attributes);
        assert_se(a->stx_attributes_mask == b->stx_attributes_mask);
        assert_se(a->stx_mode == b->stx_mode);
        assert_se(a->stx_ino == b->stx_ino);
        assert_se(a->stx_size == b->stx_size);
        assert_se(a->stx_dev_major == b->stx_dev_major);
        assert_se(a->stx_dev_minor == b->stx_dev_minor);
        assert_se(a->stx_mnt_id == b->stx_mnt_id);
}

static void test_xstatx(void) {
        struct statx c_statx = {}, rust_statx = {}, sentinel;
        int c_result, fd, rust_result;

        c_result = xstatx(AT_FDCWD, ".", 0, STATX_BASIC_STATS, &c_statx);
        rust_result = rs_xstatx(AT_FDCWD, ".", 0, STATX_BASIC_STATS, &rust_statx);
        assert_se(c_result == rust_result);
        if (c_result >= 0)
                assert_statx_core_equal(&c_statx, &rust_statx);

        c_result = xstatx_full(AT_FDCWD, ".", 0, 0, STATX_BASIC_STATS, STATX_BTIME, 0, &c_statx);
        rust_result = rs_xstatx_full(AT_FDCWD, ".", 0, 0, STATX_BASIC_STATS, STATX_BTIME, 0, &rust_statx);
        assert_se(c_result == rust_result);
        if (c_result >= 0)
                assert_statx_core_equal(&c_statx, &rust_statx);

        c_result = xstatx_full(XAT_FDROOT, NULL, 0, XSTATX_MNT_ID_BEST, STATX_TYPE, 0, 0, &c_statx);
        rust_result = rs_xstatx_full(XAT_FDROOT, NULL, 0, XSTATX_MNT_ID_BEST, STATX_TYPE, 0, 0, &rust_statx);
        assert_se(c_result == rust_result);
        if (c_result >= 0) {
                assert_se(c_statx.stx_mask & (STATX_MNT_ID | STATX_MNT_ID_UNIQUE));
                assert_statx_core_equal(&c_statx, &rust_statx);
        }

        fd = open(".", O_PATH | O_CLOEXEC);
        assert_se(fd >= 0);
        c_result = xstatx(fd, NULL, 0, STATX_TYPE | STATX_INO, &c_statx);
        rust_result = rs_xstatx(fd, NULL, 0, STATX_TYPE | STATX_INO, &rust_statx);
        assert_se(c_result == rust_result);
        if (c_result >= 0)
                assert_statx_core_equal(&c_statx, &rust_statx);
        assert_se(close(fd) >= 0);

        memset(&c_statx, 0xa5, sizeof(c_statx));
        memset(&rust_statx, 0xa5, sizeof(rust_statx));
        memset(&sentinel, 0xa5, sizeof(sentinel));
        c_result = xstatx_full(AT_FDCWD, ".", 0, 0, STATX_TYPE, 0, UINT64_C(1) << 63, &c_statx);
        rust_result = rs_xstatx_full(AT_FDCWD, ".", 0, 0, STATX_TYPE, 0, UINT64_C(1) << 63, &rust_statx);
        assert_se(c_result == -EUNATCH);
        assert_se(c_result == rust_result);
        assert_se(memcmp(&c_statx, &sentinel, sizeof(c_statx)) == 0);
        assert_se(memcmp(&rust_statx, &sentinel, sizeof(rust_statx)) == 0);

        assert_se(rs_xstatx(AT_FDCWD, ".", 0, STATX_TYPE, NULL) == -EINVAL);
        assert_se(rs_xstatx_full(AT_FDCWD, ".", 0, 0, STATX_TYPE, STATX_TYPE, 0, &rust_statx) == -EINVAL);
        assert_se(rs_xstatx_full(-1, NULL, 0, 0, STATX_TYPE, 0, 0, &rust_statx) == -EBADF);
}

/* -- inode_same ---------------------------------------------------------- */

static void test_inode_same_helpers(void) {
        char directory[] = "/tmp/test-inode-same-rust.XXXXXX";
        int fd_a, fd_b;

        assert_se(mkdtemp(directory));
        const char *path_a = strjoina(directory, "/a");
        const char *path_b = strjoina(directory, "/b");

        fd_a = open(path_a, O_CREAT | O_CLOEXEC | O_RDWR, 0600);
        assert_se(fd_a >= 0);
        assert_se(link(path_a, path_b) >= 0);
        fd_b = open(path_b, O_CLOEXEC | O_PATH);
        assert_se(fd_b >= 0);

        assert_se(inode_same(path_a, path_b, 0) == rs_inode_same(path_a, path_b, 0));
        assert_se(inode_same(path_a, path_b, 0) == 1);
        assert_se(fd_inode_same(fd_a, fd_b) == rs_fd_inode_same(fd_a, fd_b));
        assert_se(fd_inode_same(fd_a, fd_b) == 1);
        assert_se(inode_same_at(fd_a, NULL, fd_a, NULL, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) ==
                  rs_inode_same_at(fd_a, NULL, fd_a, NULL, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW));
        assert_se(inode_same_at(AT_FDCWD, path_a, AT_FDCWD, path_b, AT_NO_AUTOMOUNT) ==
                  rs_inode_same_at(AT_FDCWD, path_a, AT_FDCWD, path_b, AT_NO_AUTOMOUNT));

        assert_se(unlink(path_b) >= 0);
        assert_se(close(fd_b) >= 0);
        fd_b = open(path_b, O_CREAT | O_CLOEXEC | O_RDWR, 0600);
        assert_se(fd_b >= 0);
        assert_se(inode_same(path_a, path_b, 0) == rs_inode_same(path_a, path_b, 0));
        assert_se(inode_same(path_a, path_b, 0) == 0);
        assert_se(fd_inode_same(fd_a, fd_b) == rs_fd_inode_same(fd_a, fd_b));
        assert_se(fd_inode_same(fd_a, fd_b) == 0);

        assert_se(rs_inode_same(NULL, path_b, 0) == -EINVAL);
        assert_se(rs_inode_same_at(-1, path_a, AT_FDCWD, path_b, 0) == -EBADF);
        assert_se(rs_inode_same_at(AT_FDCWD, path_a, AT_FDCWD, path_b, AT_REMOVEDIR) == -EINVAL);

        assert_se(close(fd_a) >= 0);
        assert_se(close(fd_b) >= 0);
        assert_se(unlink(path_a) >= 0);
        assert_se(unlink(path_b) >= 0);
        assert_se(rmdir(directory) >= 0);
}

/* -- inode hash functions ------------------------------------------------ */

static uint64_t finish_inode_hash(const struct stat *st, bool rust, bool unmodified) {
        static const uint8_t key[16] = {};
        struct siphash state;

        siphash24_init(&state, key);
        if (rust) {
                if (unmodified)
                        rs_inode_unmodified_hash_func(st, &state);
                else
                        rs_inode_hash_func(st, &state);
        } else {
                if (unmodified)
                        inode_unmodified_hash_func(st, &state);
                else
                        inode_hash_func(st, &state);
        }
        return siphash24_finalize(&state);
}

static void test_inode_hash_functions(void) {
        struct stat a = {
                .st_dev = (dev_t) -1,
                .st_ino = (ino_t) -1,
                .st_mode = S_IFREG | 0644,
                .st_mtim = { .tv_sec = -2, .tv_nsec = -3 },
                .st_size = -4,
                .st_rdev = (dev_t) -5,
        };
        struct stat b = a;

        assert_se(finish_inode_hash(&a, false, false) == finish_inode_hash(&a, true, false));
        assert_se(finish_inode_hash(&a, false, true) == finish_inode_hash(&a, true, true));

        /* Permissions are outside inode_compare_func and both hash domains. */
        b.st_mode = S_IFREG | 0600;
        assert_se(inode_compare_func(&a, &b) == 0);
        assert_se(finish_inode_hash(&a, true, false) == finish_inode_hash(&b, true, false));
        assert_se(inode_unmodified_compare_func(&a, &b) == 0);
        assert_se(finish_inode_hash(&a, true, true) == finish_inode_hash(&b, true, true));

        /* Non-regular sizes and non-device rdev values use typed sentinels. */
        a.st_mode = b.st_mode = S_IFDIR | 0755;
        b.st_size++;
        b.st_rdev++;
        assert_se(inode_unmodified_compare_func(&a, &b) == 0);
        assert_se(finish_inode_hash(&a, true, true) == finish_inode_hash(&b, true, true));

        /* Device rdev and regular size remain part of unmodified identity. */
        a.st_mode = b.st_mode = S_IFCHR | 0600;
        b.st_rdev = a.st_rdev + 1;
        assert_se(finish_inode_hash(&a, false, true) == finish_inode_hash(&a, true, true));
        assert_se(finish_inode_hash(&b, false, true) == finish_inode_hash(&b, true, true));

        a.st_mode = b.st_mode = S_IFREG | 0644;
        b.st_size = a.st_size + 1;
        assert_se(finish_inode_hash(&a, false, true) == finish_inode_hash(&a, true, true));
        assert_se(finish_inode_hash(&b, false, true) == finish_inode_hash(&b, true, true));
}

/* -- vfs_free_bytes ------------------------------------------------------- */

static void test_vfs_free_bytes(void) {
        uint64_t c_value = UINT64_C(0xfeedfacecafebeef);
        uint64_t rust_value = c_value;
        int c_result, rust_result;

        c_result = vfs_free_bytes(STDIN_FILENO, &c_value);
        rust_result = rs_vfs_free_bytes(STDIN_FILENO, &rust_value);
        assert_se(c_result == rust_result);
        assert_se(c_value == rust_value);

        rust_value = UINT64_C(0xfeedfacecafebeef);
        assert_se(rs_vfs_free_bytes(-1, &rust_value) == -EINVAL);
        assert_se(rust_value == UINT64_C(0xfeedfacecafebeef));
        assert_se(rs_vfs_free_bytes(0, NULL) == -EINVAL);
}

/* -- statfs descriptor/path queries -------------------------------------- */

static void test_statfs_queries(void) {
        struct statfs c_statfs = {}, rust_statfs = {}, synthetic = {};
        int c_result, rust_result;

        c_result = xstatfsat(AT_FDCWD, NULL, &c_statfs);
        rust_result = rs_xstatfsat(AT_FDCWD, NULL, &rust_statfs);
        assert_se(c_result == rust_result);
        assert_se(c_result < 0 ||
                  (c_statfs.f_type == rust_statfs.f_type &&
                   c_statfs.f_flags == rust_statfs.f_flags));

        if (c_result >= 0)
                assert_se(is_fs_type_at(AT_FDCWD, NULL, c_statfs.f_type) ==
                          rs_is_fs_type_at(AT_FDCWD, NULL, c_statfs.f_type));

        assert_se(fd_is_read_only_fs(AT_FDCWD) == rs_fd_is_read_only_fs(AT_FDCWD));
        assert_se(path_is_read_only_fs(".") == rs_path_is_read_only_fs("."));
        assert_se(fd_is_temporary_fs(AT_FDCWD) == rs_fd_is_temporary_fs(AT_FDCWD));
        assert_se(fd_is_network_fs(AT_FDCWD) == rs_fd_is_network_fs(AT_FDCWD));
        assert_se(path_is_temporary_fs(".") == rs_path_is_temporary_fs("."));
        assert_se(path_is_network_fs(".") == rs_path_is_network_fs("."));

        synthetic.f_type = TMPFS_MAGIC;
        assert_se(is_temporary_fs(&synthetic) == rs_is_temporary_fs(&synthetic));
        assert_se(is_network_fs(&synthetic) == rs_is_network_fs(&synthetic));

        synthetic.f_type = RAMFS_MAGIC;
        assert_se(is_temporary_fs(&synthetic) == rs_is_temporary_fs(&synthetic));

        synthetic.f_type = NFS_SUPER_MAGIC;
        assert_se(is_network_fs(&synthetic) == rs_is_network_fs(&synthetic));
        assert_se(is_temporary_fs(&synthetic) == rs_is_temporary_fs(&synthetic));

        assert_se(rs_xstatfsat(-1, NULL, &rust_statfs) == -EBADF);
        assert_se(rs_xstatfsat(AT_FDCWD, NULL, NULL) == -EINVAL);
        assert_se(rs_is_fs_type_at(-1, NULL, TMPFS_MAGIC) == -EBADF);
        assert_se(rs_fd_is_read_only_fs(-1) == -EBADF);
        assert_se(rs_path_is_read_only_fs(NULL) == -EINVAL);
        assert_se(!rs_is_temporary_fs(NULL));
        assert_se(!rs_is_network_fs(NULL));
        assert_se(rs_fd_is_temporary_fs(-1) == -EBADF);
        assert_se(rs_fd_is_network_fs(-1) == -EBADF);
        assert_se(rs_path_is_temporary_fs(NULL) == -EINVAL);
        assert_se(rs_path_is_network_fs(NULL) == -EINVAL);
}

/* -- moderate directory/null/proc helpers -------------------------------- */

static void test_moderate_stat_helpers(void) {
        char directory[] = "/tmp/test-stat-util-rust.XXXXXX";
        struct stat st = {};
        struct statfs fs = {};
        int fd;

        assert_se(mkdtemp(directory));
        assert_se(dir_is_empty(directory, false) == rs_dir_is_empty(directory, false));
        assert_se(dir_is_empty(directory, false) == 1);

        const char *hidden = strjoina(directory, "/.hidden");
        fd = open(hidden, O_CREAT | O_CLOEXEC | O_WRONLY, 0600);
        assert_se(fd >= 0);
        assert_se(close(fd) >= 0);
        assert_se(dir_is_empty(directory, false) == rs_dir_is_empty(directory, false));
        assert_se(dir_is_empty(directory, true) == rs_dir_is_empty(directory, true));
        assert_se(dir_is_empty(directory, true) == 1);

        const char *plain = strjoina(directory, "/plain");
        fd = open(plain, O_CREAT | O_CLOEXEC | O_WRONLY, 0600);
        assert_se(fd >= 0);
        assert_se(close(fd) >= 0);
        assert_se(dir_is_empty(directory, true) == rs_dir_is_empty(directory, true));
        assert_se(dir_is_empty(directory, true) == 0);

        fd = open(directory, O_CLOEXEC | O_DIRECTORY);
        assert_se(fd >= 0);
        assert_se(dir_is_empty_at(fd, NULL, true) == rs_dir_is_empty_at(fd, NULL, true));
        assert_se(close(fd) >= 0);

        st.st_mode = S_IFCHR | 0600;
        assert_se(null_or_empty(&st) == rs_null_or_empty(&st));
        st.st_mode = S_IFREG | 0644;
        st.st_size = 0;
        assert_se(null_or_empty(&st) == rs_null_or_empty(&st));
        st.st_size = 1;
        assert_se(null_or_empty(&st) == rs_null_or_empty(&st));

        assert_se(null_or_empty_path("/dev/null") == rs_null_or_empty_path("/dev/null"));
        assert_se(null_or_empty_path(plain) == rs_null_or_empty_path(plain));
        assert_se(null_or_empty_path_with_root("/dev/null", "/") ==
                  rs_null_or_empty_path_with_root("/dev/null", "/"));

        assert_se(xstatfsat(AT_FDCWD, NULL, &fs) >= 0);
        assert_se(fd_is_fs_type(AT_FDCWD, fs.f_type) ==
                  rs_fd_is_fs_type(AT_FDCWD, fs.f_type));
        assert_se(path_is_fs_type(".", fs.f_type) ==
                  rs_path_is_fs_type(".", fs.f_type));
        assert_se(path_is_fs_type(NULL, fs.f_type) ==
                  rs_path_is_fs_type(NULL, fs.f_type));

        errno = EUCLEAN;
        int c_result = proc_mounted();
        assert_se(errno == EUCLEAN);
        errno = EUCLEAN;
        int rust_result = rs_proc_mounted();
        assert_se(errno == EUCLEAN);
        assert_se(c_result == rust_result);

        assert_se(!rs_null_or_empty(NULL));
        assert_se(rs_null_or_empty_path(NULL) == -EINVAL);
        assert_se(rs_null_or_empty_path_with_root(NULL, NULL) == -EINVAL);
        assert_se(rs_dir_is_empty_at(-1, NULL, false) == -EBADF);

        assert_se(unlink(plain) >= 0);
        assert_se(unlink(hidden) >= 0);
        assert_se(rmdir(directory) >= 0);
}

/* -- inode_type_can_chattr ----------------------------------------------- */

static void test_inode_type_can_chattr(void) {
        bool cr, rr;

        cr = inode_type_can_chattr(S_IFREG);
        rr = rs_inode_type_can_chattr(S_IFREG);
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = inode_type_can_chattr(S_IFDIR);
        rr = rs_inode_type_can_chattr(S_IFDIR);
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = inode_type_can_chattr(S_IFREG | 0644);
        rr = rs_inode_type_can_chattr(S_IFREG | 0644);
        assert_se(cr == rr);
        assert_se(cr == true);

        cr = inode_type_can_chattr(S_IFDIR | 0755);
        rr = rs_inode_type_can_chattr(S_IFDIR | 0755);
        assert_se(cr == rr);
        assert_se(cr == true);

        /* Cannot chattr */
        cr = inode_type_can_chattr(S_IFLNK);
        rr = rs_inode_type_can_chattr(S_IFLNK);
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = inode_type_can_chattr(S_IFCHR);
        rr = rs_inode_type_can_chattr(S_IFCHR);
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = inode_type_can_chattr(S_IFBLK);
        rr = rs_inode_type_can_chattr(S_IFBLK);
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = inode_type_can_chattr(S_IFIFO);
        rr = rs_inode_type_can_chattr(S_IFIFO);
        assert_se(cr == rr);
        assert_se(cr == false);

        cr = inode_type_can_chattr(S_IFSOCK);
        rr = rs_inode_type_can_chattr(S_IFSOCK);
        assert_se(cr == rr);
        assert_se(cr == false);

        /* Zero mode */
        cr = inode_type_can_chattr(0);
        rr = rs_inode_type_can_chattr(0);
        assert_se(cr == rr);
        assert_se(cr == false);
}

int main(int argc, char **argv) {
        test_inode_type_to_string();
        test_inode_type_from_string();
        test_inode_compare_func();
        test_inode_unmodified_compare_func();
        test_stat_inode_same();
        test_stat_inode_unmodified();
        test_statx_inode_same();
        test_statx_mount_same();
        test_xstatx();
        test_inode_same_helpers();
        test_inode_hash_functions();
        test_vfs_free_bytes();
        test_statfs_queries();
        test_moderate_stat_helpers();
        test_inode_type_can_chattr();
        return 0;
}
