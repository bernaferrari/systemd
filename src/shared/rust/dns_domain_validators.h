/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=shared.dns-domain-validators; authority=src/shared/dns-domain.c,src/shared/dns-domain.h */

/* Rust FFI declarations for shadow testing dns-domain.c validators */

bool rs_dns_service_name_is_valid(const char *name);
bool rs_dns_subtype_name_is_valid(const char *name);
bool rs_dns_srv_type_is_valid(const char *name);
bool rs_dnssd_srv_type_is_valid(const char *name);
