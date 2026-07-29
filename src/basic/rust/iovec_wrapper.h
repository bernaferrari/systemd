/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

/* PORT-SYNC: scope=basic.iovec-wrapper; authority=src/basic/alloc-util.c,src/basic/alloc-util.h,src/basic/iovec-util.c,src/basic/iovec-util.h,src/basic/iovec-wrapper.c,src/basic/iovec-wrapper.h */

/* The Rust iovec_wrapper struct has the same layout as the C version:
 *   struct iovec_wrapper { struct iovec *iovec; size_t count; };
 * We use the C struct iovec directly in the Rust wrapper. */

struct rs_IoVecWrapper {
        struct iovec *iovec;
        size_t count;
};

struct rs_IoVecWrapper *rs_iovw_free(struct rs_IoVecWrapper *iovw);
struct rs_IoVecWrapper *rs_iovw_free_free(struct rs_IoVecWrapper *iovw);
void rs_iovw_done(struct rs_IoVecWrapper *iovw);
void rs_iovw_done_free(struct rs_IoVecWrapper *iovw);
int rs_iovw_put(struct rs_IoVecWrapper *iovw, void *data, size_t len);
void rs_iovw_rebase(struct rs_IoVecWrapper *iovw, void *old, void *new);
size_t rs_iovw_size(const struct rs_IoVecWrapper *iovw);
bool rs_iovw_isempty(const struct rs_IoVecWrapper *iovw);
