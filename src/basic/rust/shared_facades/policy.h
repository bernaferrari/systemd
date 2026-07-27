/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: src/shared/securebits-util.c,src/shared/ioprio-util.h,src/shared/vlan-util.c,src/shared/condition.h,src/shared/kbd-util.c */
#pragma once

#include <stdbool.h>
#include <stdint.h>

int rs_secure_bits_from_string(const char *s);
int rs_secure_bits_to_string_alloc(int bits, char **ret);
int rs_secure_bits_to_strv(int bits, char ***ret);

bool rs_ioprio_class_is_valid(int value);
bool rs_ioprio_priority_is_valid(int value);
int rs_ioprio_parse_priority(const char *s, int *ret);

bool rs_vlanid_is_valid(uint16_t id);
int rs_parse_vid_range(const char *p, uint16_t *vid, uint16_t *vid_end);

bool rs_keymap_is_valid(const char *name);
