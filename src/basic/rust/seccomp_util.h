/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

bool rs_seccomp_errno_or_action_is_valid(int n);
int rs_seccomp_parse_errno_or_action(const char *p);
/* Returned strings have static lifetime and must not be freed. */
const char *rs_seccomp_errno_or_action_to_string(int num);
const char *rs_seccomp_arch_to_string(uint32_t c);
int rs_seccomp_arch_from_string(const char *n, uint32_t *ret);
