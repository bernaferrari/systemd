/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.gpt-abi; authority=src/shared/gpt.c,src/shared/gpt.h,src/shared/vlan-util.c,src/shared/vlan-util.h */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "gpt.h"

bool rs_gpt_header_has_signature(const uint8_t *p);
bool rs_partition_designator_is_versioned(int d);
int rs_partition_verity_hash_of(int p);
int rs_partition_verity_sig_of(int p);
int rs_partition_verity_hash_to_data(int d);
int rs_partition_verity_sig_to_data(int d);
int rs_partition_verity_to_data(int d);
const char *rs_partition_mountpoint_to_string(int d);
int rs_parse_vlanid(const char *p, uint16_t *ret);
int rs_gpt_partition_label_valid(const char *s);
bool rs_partition_designator_is_verity_hash(int d);
bool rs_partition_designator_is_verity_sig(int d);
bool rs_partition_designator_is_verity(int d);
bool rs_gpt_partition_type_knows_read_only(GptPartitionType type);
bool rs_gpt_partition_type_knows_growfs(GptPartitionType type);
bool rs_gpt_partition_type_knows_no_auto(GptPartitionType type);
bool rs_gpt_partition_type_has_filesystem(GptPartitionType type);
