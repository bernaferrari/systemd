/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/* PORT-SYNC: scope=shared.import-util; authority=src/shared/import-util.c,src/shared/import-util.h,src/shared/reboot-util.c,src/shared/reboot-util.h */

/* Successful string results are fresh malloc(3) allocations owned by the caller. */
int rs_import_url_last_component(const char *url, char **ret);
int rs_import_url_change_suffix(const char *url, size_t n_drop_components, const char *suffix, char **ret);
int rs_tar_strip_suffixes(const char *name, char **ret);
int rs_raw_strip_suffixes(const char *name, char **ret);
bool rs_reboot_parameter_is_valid(const char *parameter);
