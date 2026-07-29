/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.uid-range; authority=src/basic/uid-range.c,src/basic/uid-range.h */
#pragma once

#include "uid-range.h"

UIDRange* rs_uid_range_free(UIDRange *range);
int rs_uid_range_add_internal(UIDRange **range, uid_t start, uid_t nr, bool coalesce);
bool rs_uid_range_covers(const UIDRange *range, uid_t start, uid_t nr);
bool rs_uid_range_contains(const UIDRange *range, uid_t uid);
bool rs_uid_range_overlaps(const UIDRange *range, uid_t start, uid_t nr);
unsigned rs_uid_range_size(const UIDRange *range);
bool rs_uid_range_is_empty(const UIDRange *range);
bool rs_uid_range_equal(const UIDRange *a, const UIDRange *b);
uid_t rs_uid_range_base(const UIDRange *range);
int rs_uid_range_next_lower(const UIDRange *range, uid_t *uid);
int rs_uid_range_clip(UIDRange *range, uid_t min, uid_t max);
int rs_uid_range_copy(const UIDRange *range, UIDRange **ret);
int rs_uid_range_translate(const UIDRange *outside, const UIDRange *inside, uid_t uid, uid_t *ret);
int rs_uid_range_remove(UIDRange *range, uid_t start, uid_t size);
int rs_uid_range_partition(UIDRange *range, uid_t size);
int rs_uid_range_add_str_full(UIDRange **range, const char *s, bool coalesce);
