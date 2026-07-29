/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=shared.dns-label; authority=src/shared/dns-domain.c,src/shared/dns-domain.h */
#pragma once

/* Rust FFI declarations for shadow testing dns-domain.c label/name functions */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

int rs_dns_label_unescape(const char **name, char *dest, size_t sz, unsigned flags);
int rs_dns_label_escape(const char *p, size_t l, char *dest, size_t sz);
int rs_dns_name_parent(const char **name);
bool rs_dns_name_is_root(const char *name);
int rs_dns_name_equal(const char *x, const char *y);
int rs_dns_name_endswith(const char *name, const char *suffix);
int rs_dns_name_startswith(const char *name, const char *prefix);
int rs_dns_name_count_labels(const char *name);
bool rs_dns_name_is_single_label(const char *name);
bool rs_dns_name_dont_resolve(const char *name);
int rs_dns_name_dot_suffixed(const char *name);
int rs_dns_name_skip(const char *a, unsigned n_labels, const char **ret);
int rs_dns_name_suffix(const char *name, unsigned n_labels, const char **ret);
int rs_dns_name_equal_skip(const char *a, unsigned n_labels, const char *b);
int rs_dns_name_common_suffix(const char *a, const char *b, const char **ret);
int rs_dns_name_to_wire_format(const char *domain, uint8_t *buffer, size_t len, bool canonical);
int rs_dns_name_reverse(int family, const void *a, char **ret);
int rs_dns_name_address(const char *p, int *ret_family, void *ret);
int rs_dns_name_from_wire_format(const uint8_t **data, size_t *len, char **ret);
int rs_dns_label_unescape_suffix(const char *name, const char **label_terminal, char *dest, size_t sz);
int rs_dns_name_compare_func(const char *a, const char *b);
int rs_dns_name_between(const char *a, const char *b, const char *c);
int rs_dns_label_escape_new(const char *p, size_t l, char **ret);
int rs_dns_name_concat(const char *a, const char *b, unsigned flags, char **ret);
int rs_dns_name_change_suffix(const char *name, const char *old_suffix, const char *new_suffix, char **ret);
int rs_dns_name_normalize(const char *s, unsigned flags, char **ret);
int rs_dns_name_is_valid(const char *s);
int rs_dns_name_is_valid_ldh(const char *s);
int rs_dns_service_join(const char *name, const char *type, const char *domain, char **ret);
int rs_dns_service_split(const char *joined, char **ret_name, char **ret_type, char **ret_domain);
