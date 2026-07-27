/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C errno-util.h / seccomp-util.h error classification vs Rust */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include "tests.h"
#include "errno-util.h"
#include "rust/errno_util.h"
#include "seccomp-util.h"

/* Helper: test a NEG function with its matching and non-matching errnos */
#define TEST_NEG(name, ...) do { \
        intmax_t _matches[] = { __VA_ARGS__ }; \
        for (size_t _i = 0; _i < sizeof(_matches)/sizeof(_matches[0]); _i++) { \
                assert_se(ERRNO_IS_NEG_##name(_matches[_i]) == rs_ERRNO_IS_NEG_##name(_matches[_i])); \
                assert_se(ERRNO_IS_NEG_##name(_matches[_i]) == true); \
                assert_se(ERRNO_IS_##name(-_matches[_i]) == rs_ERRNO_IS_##name(-_matches[_i])); \
                assert_se(ERRNO_IS_##name(-_matches[_i]) == true); \
                assert_se(ERRNO_IS_##name(_matches[_i]) == rs_ERRNO_IS_##name(_matches[_i])); \
                assert_se(ERRNO_IS_##name(_matches[_i]) == true); \
        } \
        /* Non-matches, including both domains of the absolute wrapper. */ \
        assert_se(ERRNO_IS_NEG_##name(0) == rs_ERRNO_IS_NEG_##name(0)); \
        assert_se(ERRNO_IS_NEG_##name(0) == false); \
        assert_se(ERRNO_IS_NEG_##name(1) == rs_ERRNO_IS_NEG_##name(1)); \
        assert_se(ERRNO_IS_NEG_##name(1) == false); \
        assert_se(ERRNO_IS_NEG_##name(-42) == rs_ERRNO_IS_NEG_##name(-42)); \
        assert_se(ERRNO_IS_NEG_##name(-42) == false); \
        assert_se(ERRNO_IS_##name(0) == rs_ERRNO_IS_##name(0)); \
        assert_se(ERRNO_IS_##name(0) == false); \
        assert_se(ERRNO_IS_##name(42) == rs_ERRNO_IS_##name(42)); \
        assert_se(ERRNO_IS_##name(42) == false); \
        assert_se(ERRNO_IS_##name(INTMAX_MIN) == rs_ERRNO_IS_##name(INTMAX_MIN)); \
        assert_se(ERRNO_IS_##name(INTMAX_MIN) == false); \
} while (0)

static void test_ERRNO_IS_NEG_TRANSIENT(void) {
        TEST_NEG(TRANSIENT, -EAGAIN, -EINTR);
}

static void test_ERRNO_IS_NEG_DISCONNECT(void) {
        TEST_NEG(DISCONNECT, -ECONNABORTED, -ECONNREFUSED, -ECONNRESET,
                  -EHOSTDOWN, -EHOSTUNREACH, -ENETDOWN, -ENETRESET, -ENETUNREACH,
                  -ENONET, -ENOPROTOOPT, -ENOTCONN, -EPIPE, -EPROTO,
                  -ESHUTDOWN, -ETIMEDOUT);
}

static void test_ERRNO_IS_NEG_ACCEPT_AGAIN(void) {
        TEST_NEG(ACCEPT_AGAIN, -ECONNABORTED, -EAGAIN, -EINTR, -EOPNOTSUPP);
}

static void test_ERRNO_IS_NEG_RESOURCE(void) {
        TEST_NEG(RESOURCE, -EMFILE, -ENFILE, -ENOMEM);
}

static void test_ERRNO_IS_NEG_NOT_SUPPORTED(void) {
        TEST_NEG(NOT_SUPPORTED, -EOPNOTSUPP, -ENOTTY, -ENOSYS,
                  -EAFNOSUPPORT, -EPFNOSUPPORT, -EPROTONOSUPPORT,
                  -ESOCKTNOSUPPORT, -ENOPROTOOPT);
}

static void test_ERRNO_IS_NEG_IOCTL_NOT_SUPPORTED(void) {
        TEST_NEG(IOCTL_NOT_SUPPORTED, -EOPNOTSUPP, -ENOTTY, -ENOSYS, -EINVAL);
}

static void test_ERRNO_IS_NEG_PRIVILEGE(void) {
        TEST_NEG(PRIVILEGE, -EACCES, -EPERM);
}

static void test_ERRNO_IS_NEG_FS_WRITE_REFUSED(void) {
        TEST_NEG(FS_WRITE_REFUSED, -EROFS, -EACCES, -EPERM);
}

static void test_ERRNO_IS_NEG_DISK_SPACE(void) {
        TEST_NEG(DISK_SPACE, -ENOSPC, -EDQUOT, -EFBIG);
}

static void test_ERRNO_IS_NEG_DEVICE_ABSENT(void) {
        TEST_NEG(DEVICE_ABSENT, -ENODEV, -ENXIO, -ENOENT);
}

static void test_ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY(void) {
        TEST_NEG(DEVICE_ABSENT_OR_EMPTY, -ENODEV, -ENXIO, -ENOENT, -ENOMEDIUM);
}

static void test_ERRNO_IS_NEG_XATTR_ABSENT(void) {
        TEST_NEG(XATTR_ABSENT, -ENODATA, -EOPNOTSUPP, -ENOTTY, -ENOSYS);
}

#if HAVE_SECCOMP
static void test_ERRNO_IS_NEG_SECCOMP_FATAL(void) {
        TEST_NEG(SECCOMP_FATAL, -EPERM, -EACCES, -ENOMEM, -EFAULT);
}
#endif

/* Test the positive (ABS wrapper) versions */
static void test_ABS_wrappers(void) {
        /* For each NEG function, verify the positive wrapper matches for a match and non-match */
        assert_se(ERRNO_IS_TRANSIENT(EAGAIN) == rs_ERRNO_IS_TRANSIENT(EAGAIN));
        assert_se(ERRNO_IS_TRANSIENT(EINTR) == rs_ERRNO_IS_TRANSIENT(EINTR));
        assert_se(ERRNO_IS_TRANSIENT(0) == rs_ERRNO_IS_TRANSIENT(0));
        assert_se(ERRNO_IS_TRANSIENT(EINVAL) == rs_ERRNO_IS_TRANSIENT(EINVAL));

        assert_se(ERRNO_IS_DISCONNECT(ECONNABORTED) == rs_ERRNO_IS_DISCONNECT(ECONNABORTED));
        assert_se(ERRNO_IS_DISCONNECT(EPIPE) == rs_ERRNO_IS_DISCONNECT(EPIPE));
        assert_se(ERRNO_IS_DISCONNECT(EINVAL) == rs_ERRNO_IS_DISCONNECT(EINVAL));

        assert_se(ERRNO_IS_RESOURCE(ENOMEM) == rs_ERRNO_IS_RESOURCE(ENOMEM));
        assert_se(ERRNO_IS_RESOURCE(EINVAL) == rs_ERRNO_IS_RESOURCE(EINVAL));

        assert_se(ERRNO_IS_PRIVILEGE(EACCES) == rs_ERRNO_IS_PRIVILEGE(EACCES));
        assert_se(ERRNO_IS_PRIVILEGE(EPERM) == rs_ERRNO_IS_PRIVILEGE(EPERM));
        assert_se(ERRNO_IS_PRIVILEGE(EINVAL) == rs_ERRNO_IS_PRIVILEGE(EINVAL));

        assert_se(ERRNO_IS_DISK_SPACE(ENOSPC) == rs_ERRNO_IS_DISK_SPACE(ENOSPC));
        assert_se(ERRNO_IS_DISK_SPACE(EINVAL) == rs_ERRNO_IS_DISK_SPACE(EINVAL));

        assert_se(ERRNO_IS_DEVICE_ABSENT(ENOENT) == rs_ERRNO_IS_DEVICE_ABSENT(ENOENT));
        assert_se(ERRNO_IS_DEVICE_ABSENT(EINVAL) == rs_ERRNO_IS_DEVICE_ABSENT(EINVAL));

        assert_se(ERRNO_IS_NOT_SUPPORTED(EOPNOTSUPP) == rs_ERRNO_IS_NOT_SUPPORTED(EOPNOTSUPP));
        assert_se(ERRNO_IS_NOT_SUPPORTED(EINVAL) == rs_ERRNO_IS_NOT_SUPPORTED(EINVAL));

#if HAVE_SECCOMP
        assert_se(ERRNO_IS_SECCOMP_FATAL(EPERM) == rs_ERRNO_IS_SECCOMP_FATAL(EPERM));
        assert_se(ERRNO_IS_SECCOMP_FATAL(EINVAL) == rs_ERRNO_IS_SECCOMP_FATAL(EINVAL));
#endif
}

/* Test INTMAX_MIN edge case */
static void test_INTMAX_MIN(void) {
        assert_se(ERRNO_IS_TRANSIENT(INTMAX_MIN) == rs_ERRNO_IS_TRANSIENT(INTMAX_MIN));
        assert_se(ERRNO_IS_DISCONNECT(INTMAX_MIN) == rs_ERRNO_IS_DISCONNECT(INTMAX_MIN));
        assert_se(ERRNO_IS_ACCEPT_AGAIN(INTMAX_MIN) == rs_ERRNO_IS_ACCEPT_AGAIN(INTMAX_MIN));
        assert_se(ERRNO_IS_RESOURCE(INTMAX_MIN) == rs_ERRNO_IS_RESOURCE(INTMAX_MIN));
        assert_se(ERRNO_IS_NOT_SUPPORTED(INTMAX_MIN) == rs_ERRNO_IS_NOT_SUPPORTED(INTMAX_MIN));
        assert_se(ERRNO_IS_IOCTL_NOT_SUPPORTED(INTMAX_MIN) == rs_ERRNO_IS_IOCTL_NOT_SUPPORTED(INTMAX_MIN));
        assert_se(ERRNO_IS_PRIVILEGE(INTMAX_MIN) == rs_ERRNO_IS_PRIVILEGE(INTMAX_MIN));
        assert_se(ERRNO_IS_FS_WRITE_REFUSED(INTMAX_MIN) == rs_ERRNO_IS_FS_WRITE_REFUSED(INTMAX_MIN));
        assert_se(ERRNO_IS_DISK_SPACE(INTMAX_MIN) == rs_ERRNO_IS_DISK_SPACE(INTMAX_MIN));
        assert_se(ERRNO_IS_DEVICE_ABSENT(INTMAX_MIN) == rs_ERRNO_IS_DEVICE_ABSENT(INTMAX_MIN));
        assert_se(ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(INTMAX_MIN) == rs_ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(INTMAX_MIN));
        assert_se(ERRNO_IS_XATTR_ABSENT(INTMAX_MIN) == rs_ERRNO_IS_XATTR_ABSENT(INTMAX_MIN));
#if HAVE_SECCOMP
        assert_se(ERRNO_IS_SECCOMP_FATAL(INTMAX_MIN) == rs_ERRNO_IS_SECCOMP_FATAL(INTMAX_MIN));
#endif
}

/* Keep every token-pasted NEG call visible to static ABI inventory too. */
static void test_NEG_export_surface(void) {
        assert_se(!rs_ERRNO_IS_NEG_TRANSIENT(0));
        assert_se(!rs_ERRNO_IS_NEG_DISCONNECT(0));
        assert_se(!rs_ERRNO_IS_NEG_ACCEPT_AGAIN(0));
        assert_se(!rs_ERRNO_IS_NEG_RESOURCE(0));
        assert_se(!rs_ERRNO_IS_NEG_NOT_SUPPORTED(0));
        assert_se(!rs_ERRNO_IS_NEG_IOCTL_NOT_SUPPORTED(0));
        assert_se(!rs_ERRNO_IS_NEG_PRIVILEGE(0));
        assert_se(!rs_ERRNO_IS_NEG_FS_WRITE_REFUSED(0));
        assert_se(!rs_ERRNO_IS_NEG_DISK_SPACE(0));
        assert_se(!rs_ERRNO_IS_NEG_DEVICE_ABSENT(0));
        assert_se(!rs_ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY(0));
        assert_se(!rs_ERRNO_IS_NEG_XATTR_ABSENT(0));
#if HAVE_SECCOMP
        assert_se(!rs_ERRNO_IS_NEG_SECCOMP_FATAL(0));
#endif
}

int main(int argc, char **argv) {
        test_ERRNO_IS_NEG_TRANSIENT();
        test_ERRNO_IS_NEG_DISCONNECT();
        test_ERRNO_IS_NEG_ACCEPT_AGAIN();
        test_ERRNO_IS_NEG_RESOURCE();
        test_ERRNO_IS_NEG_NOT_SUPPORTED();
        test_ERRNO_IS_NEG_IOCTL_NOT_SUPPORTED();
        test_ERRNO_IS_NEG_PRIVILEGE();
        test_ERRNO_IS_NEG_FS_WRITE_REFUSED();
        test_ERRNO_IS_NEG_DISK_SPACE();
        test_ERRNO_IS_NEG_DEVICE_ABSENT();
        test_ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY();
        test_ERRNO_IS_NEG_XATTR_ABSENT();
#if HAVE_SECCOMP
        test_ERRNO_IS_NEG_SECCOMP_FATAL();
#endif
        test_ABS_wrappers();
        test_INTMAX_MIN();
        test_NEG_export_surface();
        return 0;
}
