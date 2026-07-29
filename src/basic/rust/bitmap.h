/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.bitmap; authority=src/shared/bitmap.c,src/shared/bitmap.h,src/basic/iterator.h */
#pragma once

/*
 * Rust FFI declarations for C-compatible Bitmap shadows. Bitmap objects and
 * their word arrays are libc-owned, layout-compatible with src/shared/bitmap.h,
 * and may be exchanged with the C implementation. Bitmap pointers returned by
 * rs_bitmap_new()/copy() must be released with rs_bitmap_free() or bitmap_free().
 */
#include <stdbool.h>
#include <stddef.h>

struct Bitmap;
struct Iterator;

/* Query (all input storage is borrowed). */
bool rs_bitmap_isset(const struct Bitmap *b, unsigned n);
bool rs_bitmap_isclear(const struct Bitmap *b);
bool rs_bitmap_equal(const struct Bitmap *a, const struct Bitmap *b);

/* Allocation and ownership. */
struct Bitmap *rs_bitmap_new(void);
struct Bitmap *rs_bitmap_copy(struct Bitmap *b);
struct Bitmap *rs_bitmap_free(struct Bitmap *b);
int rs_bitmap_ensure_allocated(struct Bitmap **b);

/* Mutation. */
int rs_bitmap_set(struct Bitmap *b, unsigned n);
void rs_bitmap_unset(struct Bitmap *b, unsigned n);
void rs_bitmap_clear(struct Bitmap *b);

/* Iteration; Iterator and n are writable C caller storage. */
bool rs_bitmap_iterate(const struct Bitmap *b, struct Iterator *i, unsigned *n);
