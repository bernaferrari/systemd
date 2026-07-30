/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.basic-validators; authority=src/basic/cgroup-util.h,src/basic/io-util.h,src/basic/audit-util.h,src/basic/errno-list.h,src/basic/alloc-util.h,src/basic/string-util.h,src/basic/socket-util.h,src/basic/process-util.h,src/basic/pidref.h,src/basic/pidref.c,src/basic/fileio.h */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "pidref.h"

bool rs_CGROUP_WEIGHT_IS_OK(uint64_t x);
uint64_t rs_BFQ_WEIGHT(uint64_t io_weight);

bool rs_FILE_SIZE_VALID(uint64_t l);
bool rs_FILE_SIZE_VALID_OR_INFINITY(uint64_t l);

bool rs_audit_session_is_valid(uint32_t id);
bool rs_errno_is_valid(int n);
bool rs_VSOCK_CID_IS_REGULAR(unsigned cid);
bool rs_SIGINFO_CODE_IS_DEAD(int code);

bool rs_pid_is_valid(pid_t pid);
bool rs_pid_is_automatic(pid_t pid);
bool rs_pidref_is_set(const PidRef *pidref);
bool rs_pidref_is_automatic(const PidRef *pidref);
bool rs_pidref_is_set_or_automatic(const PidRef *pidref);
bool rs_pidref_is_remote(const PidRef *pidref);

bool rs_size_multiply_overflow(size_t size, size_t need);
size_t rs_GREEDY_ALLOC_ROUND_UP(size_t l);
bool rs_file_offset_beyond_memory_size(off_t x);

const char *rs_strnull(const char *s);
const char *rs_strna(const char *s);
const char *rs_true_false(bool b);
const char *rs_plus_minus(bool b);
const char *rs_one_zero(bool b);
const char *rs_enable_disable(bool b);
const char *rs_enabled_disabled(bool b);
const char *rs_empty_to_na(const char *p);
const char *rs_empty_to_dash(const char *s);
bool rs_empty_or_dash(const char *s);
