/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: src/shared/condition.c,src/shared/resolve-util.c,src/shared/netif-util.c,src/basic/compress.c,src/basic/socket-util.c,src/shared/output-mode.c */
#pragma once

/* Rust FFI declarations for shadow testing condition_type, dns_server_address_valid,
   netif_has_carrier, compression_lowercase, socket_address_type, netlink_family, ip_tos,
   output_mode */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* All *_to_string() results borrow static storage and must not be freed.
 * *_to_string_alloc() stores a libc malloc() allocation in *ret on success;
 * the caller owns it and must free() it. All *_from_string() inputs must be
 * NUL-terminated byte strings; NULL and invalid input return -EINVAL
 * (numeric fallback is supported where the matching C API supports it).
 * The address validator returns false for NULL. */

/* condition.c */
const char *rs_condition_type_to_string(int t);
int rs_condition_type_from_string(const char *s);
const char *rs_assert_type_to_string(int t);
int rs_assert_type_from_string(const char *s);

/* resolve-util.c */
bool rs_dns_server_address_valid(int family, const void *sa);

/* netif-util.c */
bool rs_netif_has_carrier(uint8_t operstate, unsigned flags);

/* compress.c */
const char *rs_compression_lowercase_to_string(int c);
int rs_compression_lowercase_from_string(const char *s);

/* socket-util.c */
const char *rs_socket_address_type_to_string(int t);
int rs_socket_address_type_from_string(const char *s);
int rs_netlink_family_to_string_alloc(int f, char **ret);
int rs_netlink_family_from_string(const char *s);
int rs_ip_tos_to_string_alloc(int t, char **ret);
int rs_ip_tos_from_string(const char *s);

/* output-mode.c (to_string/from_string in netdev_str_tables.h) */
int64_t rs_output_mode_to_json_format_flags(int m);
