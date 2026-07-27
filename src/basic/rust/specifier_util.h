/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

char *rs_specifier_escape(const char *string);
int rs_specifier_escape_strv(char **l, char ***ret);
bool rs_efi_loader_entry_name_valid(const char *s);
