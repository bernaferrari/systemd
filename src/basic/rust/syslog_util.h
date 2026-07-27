/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

int rs_log_facility_unshifted_from_string(const char *name);
int rs_log_facility_unshifted_to_string_alloc(int value, char **ret);
bool rs_log_facility_unshifted_is_valid(int facility);

int rs_log_level_from_string(const char *name);
int rs_log_level_to_string_alloc(int value, char **ret);
bool rs_log_level_is_valid(int level);

int rs_syslog_parse_priority(const char **p, int *priority, bool with_facility);
