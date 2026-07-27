/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Rust FFI declarations for shadow testing bitmap.c */
#include <stdbool.h>
#include <stddef.h>

struct Bitmap;

/* Query */
bool rs_bitmap_isset(const struct Bitmap *b, unsigned n);
bool rs_bitmap_isclear(const struct Bitmap *b);
bool rs_bitmap_equal(const struct Bitmap *a, const struct Bitmap *b);

/* Allocation */
struct Bitmap *rs_bitmap_new(void);
struct Bitmap *rs_bitmap_copy(const struct Bitmap *b);
struct Bitmap *rs_bitmap_free(struct Bitmap *b);
int rs_bitmap_ensure_allocated(struct Bitmap **b);

/* Mutation */
int rs_bitmap_set(struct Bitmap *b, unsigned n);
void rs_bitmap_unset(struct Bitmap *b, unsigned n);
void rs_bitmap_clear(struct Bitmap *b);

/* Iteration */
bool rs_bitmap_iterate(const struct Bitmap *b, struct Iterator *i, unsigned *n);
