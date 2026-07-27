/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

const char *rs_strerror_or_eof(int errnum, char *buf, size_t buflen);
int rs_errno_from_name(const char *name);
const char *rs_errno_name_no_fallback(int id);
int rs_negative_errno(void);
int rs_RET_NERRNO(int ret);
int rs_errno_or_else(int fallback);

/* Exact C ABI façades for the ERRNO_IS_* static inline classifiers in
 * errno-util.h and seccomp-util.h. They accept the same intmax_t domain:
 * `NEG` variants only match a negative errno, while the other variants match
 * either sign and reject INTMAX_MIN like the C ABS wrapper. */
bool rs_ERRNO_IS_NEG_TRANSIENT(intmax_t r);
bool rs_ERRNO_IS_TRANSIENT(intmax_t r);
bool rs_ERRNO_IS_NEG_DISCONNECT(intmax_t r);
bool rs_ERRNO_IS_DISCONNECT(intmax_t r);
bool rs_ERRNO_IS_NEG_ACCEPT_AGAIN(intmax_t r);
bool rs_ERRNO_IS_ACCEPT_AGAIN(intmax_t r);
bool rs_ERRNO_IS_NEG_RESOURCE(intmax_t r);
bool rs_ERRNO_IS_RESOURCE(intmax_t r);
bool rs_ERRNO_IS_NEG_NOT_SUPPORTED(intmax_t r);
bool rs_ERRNO_IS_NOT_SUPPORTED(intmax_t r);
bool rs_ERRNO_IS_NEG_IOCTL_NOT_SUPPORTED(intmax_t r);
bool rs_ERRNO_IS_IOCTL_NOT_SUPPORTED(intmax_t r);
bool rs_ERRNO_IS_NEG_PRIVILEGE(intmax_t r);
bool rs_ERRNO_IS_PRIVILEGE(intmax_t r);
bool rs_ERRNO_IS_NEG_FS_WRITE_REFUSED(intmax_t r);
bool rs_ERRNO_IS_FS_WRITE_REFUSED(intmax_t r);
bool rs_ERRNO_IS_NEG_DISK_SPACE(intmax_t r);
bool rs_ERRNO_IS_DISK_SPACE(intmax_t r);
bool rs_ERRNO_IS_NEG_DEVICE_ABSENT(intmax_t r);
bool rs_ERRNO_IS_DEVICE_ABSENT(intmax_t r);
bool rs_ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY(intmax_t r);
bool rs_ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(intmax_t r);
bool rs_ERRNO_IS_NEG_XATTR_ABSENT(intmax_t r);
bool rs_ERRNO_IS_XATTR_ABSENT(intmax_t r);
bool rs_ERRNO_IS_NEG_SECCOMP_FATAL(intmax_t r);
bool rs_ERRNO_IS_SECCOMP_FATAL(intmax_t r);
