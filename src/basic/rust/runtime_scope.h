/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.runtime_scope; authority=src/basic/runtime-scope.c,src/basic/runtime-scope.h */

#include <stdint.h>

const char *rs_runtime_scope_to_string(int scope);
int rs_runtime_scope_from_string(const char *s);
const char *rs_runtime_scope_cmdline_option_to_string(int scope);
uint32_t rs_runtime_scope_to_socket_mode(int scope);
