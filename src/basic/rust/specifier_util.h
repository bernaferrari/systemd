/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.specifier-util; authority=src/shared/specifier.c,src/shared/specifier.h,src/shared/efi-loader.c,src/shared/efi-loader.h */

#include <stdbool.h>
#include <stddef.h>

/* Returned strings and strvs use the process C allocator and may be released with free()/strv_free(). */
char *rs_specifier_escape(const char *string);

/* l is borrowed and unmodified. ret is required; the Rust facade returns -EINVAL when it is NULL. */
int rs_specifier_escape_strv(char **l, char ***ret);

bool rs_efi_loader_entry_name_valid(const char *s);
