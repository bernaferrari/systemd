/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

/* PORT-SYNC: scope=basic.device-nodes; authority=src/basic/device-nodes.c,src/basic/device-nodes.h
 * Rust FFI declarations for device_nodes module. */

int rs_allow_listed_char_for_devnode(char c, const char *additional);
int rs_encode_devnode_name(const char *str, char *str_enc, size_t len);
