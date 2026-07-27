/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Rust FFI declarations for shadow testing credential validators */

#include <stdbool.h>

bool rs_credential_name_valid(const char *s);
bool rs_credential_glob_valid(const char *s);
