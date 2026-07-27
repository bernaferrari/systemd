/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Shadow FFI — socket-util pure functions */
bool rs_ifname_valid_char(char a);
bool rs_ifname_valid_full(const char *p, int flags);
bool rs_ifname_valid(const char *p);
bool rs_address_label_valid(const char *p);
int rs_vsock_parse_port(const char *s, unsigned *ret);
int rs_vsock_parse_cid(const char *s, unsigned *ret);
int rs_sockaddr_port(const void *sa, unsigned *ret_port);
const void *rs_sockaddr_in_addr(const void *sa);
int rs_sockaddr_set_in_addr(void *u, int family, const void *a, uint16_t port);
bool rs_sockaddr_equal(const void *a, const void *b);
size_t rs_sockaddr_ll_len(const void *sa);
size_t rs_sockaddr_un_len(const void *sa);
size_t rs_sockaddr_len(const void *sa);
int rs_sockaddr_un_set_path(void *ret, const char *path);
int rs_socket_address_verify(const void *a, bool strict);
bool rs_socket_address_can_accept(const void *a);
const char *rs_socket_address_get_path(const void *a);
int rs_socket_address_parse_unix(void *ret_address, const char *s);
int rs_socket_address_parse_vsock(void *ret_address, const char *s);
int rs_socket_address_equal_unix(const char *a, const char *b);
