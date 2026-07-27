/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Rust FFI declarations for shadow testing dns-type.c predicates */

bool rs_dns_type_is_pseudo(uint16_t type);
bool rs_dns_class_is_pseudo(uint16_t class);
bool rs_dns_type_is_valid_query(uint16_t type);
bool rs_dns_type_is_zone_transfer(uint16_t type);
bool rs_dns_type_is_valid_rr(uint16_t type);
bool rs_dns_class_is_valid_rr(uint16_t class);
bool rs_dns_type_may_redirect(uint16_t type);
bool rs_dns_type_may_wildcard(uint16_t type);
bool rs_dns_type_apex_only(uint16_t type);
bool rs_dns_type_is_dnssec(uint16_t type);
bool rs_dns_type_is_obsolete(uint16_t type);
bool rs_dns_type_needs_authentication(uint16_t type);
int rs_dns_type_to_af(uint16_t type);

/* Borrowed static storage. These pointers are never NULL and must not be freed. */
const char *rs_tlsa_cert_usage_to_string(uint8_t cert_usage);
const char *rs_tlsa_selector_to_string(uint8_t selector);
const char *rs_tlsa_matching_type_to_string(uint8_t selector);
