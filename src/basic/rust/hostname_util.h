/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.hostname-util-abi; authority=src/basic/hostname-util.c,src/basic/hostname-util.h,src/basic/user-util.c,src/basic/user-util.h,src/basic/string-util.c,src/basic/string-util.h,src/basic/utf8.c,src/basic/utf8.h */

#include <stdbool.h>

#include "forward.h"

bool rs_valid_ldh_char(char c);
bool rs_hostname_is_valid(const char *s, int flags);
char* rs_hostname_cleanup(char *s);
bool rs_is_localhost(const char *hostname);
bool rs_is_gateway_hostname(const char *hostname);
bool rs_is_outbound_hostname(const char *hostname);
bool rs_is_dns_stub_hostname(const char *hostname);
bool rs_is_dns_proxy_stub_hostname(const char *hostname);
int rs_split_user_at_host(const char *s, char **ret_user, char **ret_host);
int rs_machine_spec_valid(const char *s);
