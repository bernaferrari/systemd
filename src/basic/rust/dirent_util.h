/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>

/* Forward-declare the opaque dirent pointer for Rust FFI */
struct dirent;
bool rs_dirent_is_file(const struct dirent *de);
bool rs_dirent_is_file_with_suffix(const struct dirent *de, const char *suffix);
