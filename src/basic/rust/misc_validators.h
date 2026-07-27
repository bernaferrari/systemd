/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

bool rs_bus_property_is_timestamp(const char *name);
bool rs_nft_identifier_valid(const char *s);
bool rs_nice_is_valid(int n);
bool rs_sched_policy_is_valid(int policy);
bool rs_oom_score_adjust_is_valid(int oa);
bool rs_valid_gecos(const char *d);
bool rs_log_namespace_name_valid(const char *s);
bool rs_valid_home(const char *p);
bool rs_valid_shell(const char *p);
bool rs_condition_takes_path(int t);
bool rs_image_name_is_valid(const char *s);
