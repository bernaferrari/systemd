/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.iovec-util; authority=src/basic/iovec-util.c,src/basic/iovec-util.h,src/fundamental/iovec-util.h */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct rs_IoVec {
        void *iov_base;
        size_t iov_len;
};

/* Inline helpers (from src/fundamental/iovec-util.h) */
bool rs_iovec_is_set(const struct rs_IoVec *iovec);
bool rs_iovec_is_valid(const struct rs_IoVec *iovec);
void rs_iovec_done(struct rs_IoVec *iovec);
void rs_iovec_done_many_and_free(struct rs_IoVec *iovec, size_t n);

/* Functions from iovec-util.c */
int rs_iovec_alloc(size_t n, struct rs_IoVec *ret);
void rs_iovec_erase(struct rs_IoVec *iovec);
size_t rs_iovec_total_size(const struct rs_IoVec *iovec, size_t n);
bool rs_iovec_inc_many(struct rs_IoVec *iovec, size_t n, size_t k);
struct rs_IoVec* rs_iovec_make_string(struct rs_IoVec *iovec, const char *s);
int rs_iovec_memcmp(const struct rs_IoVec *a, const struct rs_IoVec *b);
struct rs_IoVec* rs_iovec_memdup(const struct rs_IoVec *source, struct rs_IoVec *ret);
int rs_iovec_done_and_memdup(struct rs_IoVec *iovec, const struct rs_IoVec *source);
