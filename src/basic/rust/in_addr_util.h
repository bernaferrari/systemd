/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Rust FFI declarations for in_addr_util module.
 * PORT-SYNC: src/basic/in-addr-util.c (pure subset) */

struct rs_InAddr { uint32_t s_addr; };
struct rs_In6Addr {
        union {
                uint8_t u6_addr8[16];
                uint32_t u6_addr32[4];
        } __in6_u;
};
#define rs_s6_addr __in6_u.u6_addr8
#define rs_s6_addr32 __in6_u.u6_addr32
union rs_InAddrUnion {
        uint8_t bytes[16];
        struct rs_InAddr in4;
        struct rs_In6Addr in6;
};

/* Null checks */
bool rs_in4_addr_is_null(const struct rs_InAddr *a);
bool rs_in6_addr_is_null(const struct rs_In6Addr *a);
int rs_in_addr_is_null(int family, const union rs_InAddrUnion *u);
bool rs_in4_addr_is_set(const struct rs_InAddr *a);
bool rs_in6_addr_is_set(const struct rs_In6Addr *a);
bool rs_in_addr_is_set(int family, const union rs_InAddrUnion *u);

/* Link-local */
bool rs_in4_addr_is_link_local(const struct rs_InAddr *a);
bool rs_in4_addr_is_link_local_dynamic(const struct rs_InAddr *a);
bool rs_in6_addr_is_link_local(const struct rs_In6Addr *a);
int rs_in_addr_is_link_local(int family, const union rs_InAddrUnion *u);
bool rs_in6_addr_is_link_local_all_nodes(const struct rs_In6Addr *a);

/* Multicast */
bool rs_in4_addr_is_multicast(const struct rs_InAddr *a);
bool rs_in6_addr_is_multicast(const struct rs_In6Addr *a);
bool rs_in4_addr_is_local_multicast(const struct rs_InAddr *a);
int rs_in_addr_is_multicast(int family, const union rs_InAddrUnion *u);

/* Localhost */
bool rs_in4_addr_is_localhost(const struct rs_InAddr *a);
bool rs_in4_addr_is_non_local(const struct rs_InAddr *a);
int rs_in_addr_is_localhost(int family, const union rs_InAddrUnion *u);
int rs_in_addr_is_localhost_one(int family, const union rs_InAddrUnion *u);

/* Equality */
bool rs_in4_addr_equal(const struct rs_InAddr *a, const struct rs_InAddr *b);
bool rs_in6_addr_equal(const struct rs_In6Addr *a, const struct rs_In6Addr *b);
int rs_in_addr_equal(int family, const union rs_InAddrUnion *a, const union rs_InAddrUnion *b);
bool rs_in6_addr_is_ipv4_mapped_address(const struct rs_In6Addr *a);

/* Prefix intersection */
bool rs_in4_addr_prefix_intersect(const struct rs_InAddr *a, unsigned aprefixlen, const struct rs_InAddr *b, unsigned bprefixlen);
bool rs_in6_addr_prefix_intersect(const struct rs_In6Addr *a, unsigned aprefixlen, const struct rs_In6Addr *b, unsigned bprefixlen);
int rs_in_addr_prefix_intersect(int family, const union rs_InAddrUnion *a, unsigned aprefixlen, const union rs_InAddrUnion *b, unsigned bprefixlen);

/* Prefix nth */
int rs_in_addr_prefix_nth(int family, union rs_InAddrUnion *u, unsigned prefixlen, uint64_t nth);
int rs_in_addr_prefix_next(int family, union rs_InAddrUnion *u, unsigned prefixlen);

/* Netmask */
unsigned char rs_in4_addr_netmask_to_prefixlen(const struct rs_InAddr *addr);
struct rs_InAddr *rs_in4_addr_prefixlen_to_netmask(struct rs_InAddr *addr, unsigned char prefixlen);
struct rs_In6Addr *rs_in6_addr_prefixlen_to_netmask(struct rs_In6Addr *addr, unsigned char prefixlen);
int rs_in_addr_prefixlen_to_netmask(int family, union rs_InAddrUnion *addr, unsigned char prefixlen);

/* Default prefix length */
int rs_in4_addr_default_prefixlen(const struct rs_InAddr *addr, unsigned char *prefixlen);

/* Mask */
int rs_in4_addr_mask(struct rs_InAddr *addr, unsigned char prefixlen);
int rs_in6_addr_mask(struct rs_In6Addr *addr, unsigned char prefixlen);
int rs_in_addr_mask(int family, union rs_InAddrUnion *addr, unsigned char prefixlen);

/* Prefix covers */
bool rs_in4_addr_prefix_covers(const struct rs_InAddr *prefix, unsigned char prefixlen, const struct rs_InAddr *address);
bool rs_in6_addr_prefix_covers(const struct rs_In6Addr *prefix, unsigned char prefixlen, const struct rs_In6Addr *address);
int rs_in_addr_prefix_covers(int family, const union rs_InAddrUnion *prefix, unsigned char prefixlen, const union rs_InAddrUnion *address);
int rs_in4_addr_prefix_covers_full(const struct rs_InAddr *prefix, unsigned char prefixlen, const struct rs_InAddr *address, unsigned char address_prefixlen);
int rs_in6_addr_prefix_covers_full(const struct rs_In6Addr *prefix, unsigned char prefixlen, const struct rs_In6Addr *address, unsigned char address_prefixlen);
int rs_in_addr_prefix_covers_full(int family, const union rs_InAddrUnion *prefix, unsigned char prefixlen, const union rs_InAddrUnion *address, unsigned char address_prefixlen);

/* Prefix length parsing */
int rs_in_addr_parse_prefixlen(int family, const char *p, unsigned char *ret);

/* Default subnet mask */
int rs_in4_addr_default_subnet_mask(const struct rs_InAddr *addr, struct rs_InAddr *mask);

/* Pointer ↔ address conversion */
void rs_PTR_TO_IN4_ADDR(const void *p, struct rs_InAddr *ret);
void *rs_IN4_ADDR_TO_PTR(const struct rs_InAddr *a);

/* Address size by family */
size_t rs_FAMILY_ADDRESS_SIZE(int family);

/* String conversion */
int rs_in_addr_from_string(int family, const char *s, union rs_InAddrUnion *ret);
int rs_in_addr_from_string_auto(const char *s, int *ret_family, union rs_InAddrUnion *ret);
int rs_in_addr_to_string(int family, const union rs_InAddrUnion *u, char **ret);
int rs_in_addr_prefix_from_string(const char *p, int family, union rs_InAddrUnion *ret_prefix, unsigned char *ret_prefixlen);
int rs_in_addr_prefix_from_string_auto_full(const char *p, int mode, int *ret_family, union rs_InAddrUnion *ret_prefix, unsigned char *ret_prefixlen);

/* Prefix range */
int rs_in_addr_prefix_range(int family, const union rs_InAddrUnion *in, unsigned prefixlen, union rs_InAddrUnion *ret_start, union rs_InAddrUnion *ret_end);

/* Prefix to string */
int rs_in_addr_prefix_to_string(int family, const union rs_InAddrUnion *u, unsigned prefixlen, char *buf, size_t buf_len);

/* Compare functions */
int rs_in6_addr_compare_func(const struct rs_In6Addr *a, const struct rs_In6Addr *b);

/* in_addr_data */
struct rs_InAddrData { int family; union rs_InAddrUnion address; };
int rs_in_addr_data_is_null(const struct rs_InAddrData *a);
bool rs_in_addr_data_is_set(const struct rs_InAddrData *a);
int rs_in_addr_data_compare_func(const struct rs_InAddrData *x, const struct rs_InAddrData *y);
