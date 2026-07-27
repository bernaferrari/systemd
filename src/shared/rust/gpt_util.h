/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Rust FFI declarations for shadow testing GPT and VLAN utility functions */

#include <stdbool.h>

/* gpt.c */
bool rs_partition_designator_is_versioned(int d);
int rs_partition_verity_hash_of(int p);
int rs_partition_verity_sig_of(int p);
int rs_partition_verity_hash_to_data(int d);
int rs_partition_verity_sig_to_data(int d);
int rs_partition_verity_to_data(int d);
const char *rs_partition_mountpoint_to_string(int d);

/* vlan-util.c */
int rs_parse_vlanid(const char *p, unsigned short *ret);
