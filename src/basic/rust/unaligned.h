/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

/* C ABI mirrors for the safe byte-oriented implementation in unaligned.rs.
 *
 * Each pointer must be non-NULL and cover the named number of consecutive
 * bytes; it need not be aligned. Read pointers must address initialized,
 * readable bytes. Write pointers must address writable bytes, and callers
 * must provide synchronization for concurrent access. */
uint16_t rs_unaligned_read_be16(const void *p);
uint32_t rs_unaligned_read_be32(const void *p);
uint64_t rs_unaligned_read_be64(const void *p);
void rs_unaligned_write_be16(void *p, uint16_t value);
void rs_unaligned_write_be32(void *p, uint32_t value);
void rs_unaligned_write_be64(void *p, uint64_t value);

uint16_t rs_unaligned_read_le16(const void *p);
uint32_t rs_unaligned_read_le32(const void *p);
uint64_t rs_unaligned_read_le64(const void *p);
void rs_unaligned_write_le16(void *p, uint16_t value);
void rs_unaligned_write_le32(void *p, uint32_t value);
void rs_unaligned_write_le64(void *p, uint64_t value);
