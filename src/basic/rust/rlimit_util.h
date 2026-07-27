/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/resource.h>

const char *rs_rlimit_to_string(int resource);
int rs_rlimit_from_string(const char *s);
int rs_rlimit_from_string_harder(const char *s);
int rs_rlimit_parse_nice(const char *value, rlim_t *ret);
int rs_rlimit_parse_u64(const char *value, rlim_t *ret);
int rs_rlimit_parse_size(const char *value, rlim_t *ret);
int rs_rlimit_format(const struct rlimit *limit, char **ret);
