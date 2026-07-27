/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.ether-addr-util; authority=src/basic/ether-addr-util.c,src/basic/ether-addr-util.h */
#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Rust FFI declarations for ether_addr_util module. */

/* Formatting writes only to the caller-provided fixed buffer; this shadow ABI
 * neither allocates nor transfers ownership across the C/Rust boundary. */

struct rs_hw_addr_data {
        size_t length;
        uint8_t bytes[32]; /* HW_ADDR_MAX_SIZE */
};

struct rs_ether_addr {
        uint8_t octet[6]; /* ETH_ALEN */
};

char *rs_hw_addr_to_string_full(const struct rs_hw_addr_data *addr, unsigned flags, char buffer[]);
struct rs_hw_addr_data *rs_hw_addr_set(struct rs_hw_addr_data *addr, const uint8_t *bytes, size_t length);
int rs_hw_addr_compare(const struct rs_hw_addr_data *a, const struct rs_hw_addr_data *b);
bool rs_hw_addr_is_null(const struct rs_hw_addr_data *addr);
char *rs_ether_addr_to_string(const struct rs_ether_addr *addr, char buffer[]);
int rs_ether_addr_compare(const struct rs_ether_addr *a, const struct rs_ether_addr *b);
bool rs_ether_addr_is_broadcast(const struct rs_ether_addr *addr);
bool rs_ether_addr_equal(const struct rs_ether_addr *a, const struct rs_ether_addr *b);
bool rs_ether_addr_is_null(const struct rs_ether_addr *addr);
bool rs_ether_addr_is_multicast(const struct rs_ether_addr *addr);
bool rs_ether_addr_is_unicast(const struct rs_ether_addr *addr);
bool rs_ether_addr_is_local(const struct rs_ether_addr *addr);
bool rs_ether_addr_is_global(const struct rs_ether_addr *addr);
void rs_ether_addr_mark_random(struct rs_ether_addr *addr);
int rs_parse_hw_addr_full(const char *s, size_t expected_len, struct rs_hw_addr_data *ret);
int rs_parse_ether_addr(const char *s, struct rs_ether_addr *ret);
