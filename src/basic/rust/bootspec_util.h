/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

int rs_boot_filename_extract_tries(const char *fname, char **ret_stripped, unsigned *ret_tries_left, unsigned *ret_tries_done);
bool rs_bootspec_pick_name_version_sort_key(
                const char *os_pretty_name,
                const char *os_image_id,
                const char *os_name,
                const char *os_id,
                const char *os_image_version,
                const char *os_version,
                const char *os_version_id,
                const char *os_build_id,
                const char **ret_name,
                const char **ret_version,
                const char **ret_sort_key);
