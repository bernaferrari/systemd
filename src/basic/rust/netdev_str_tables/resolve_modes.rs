// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/resolve-util.c

use super::*;

static RESOLVE_SUPPORT_TABLE: &[(i32, &[u8])] = &[(0, b"no\0"), (2, b"yes\0"), (1, b"resolve\0")];
string_table_boolean!(
    rs_resolve_support_to_string,
    rs_resolve_support_from_string,
    RESOLVE_SUPPORT_TABLE,
    2
);

static DNSSEC_MODE_TABLE: &[(i32, &[u8])] =
    &[(0, b"no\0"), (1, b"allow-downgrade\0"), (2, b"yes\0")];
string_table_boolean!(
    rs_dnssec_mode_to_string,
    rs_dnssec_mode_from_string,
    DNSSEC_MODE_TABLE,
    2
);

static DNS_OVER_TLS_MODE_TABLE: &[(i32, &[u8])] =
    &[(0, b"no\0"), (1, b"opportunistic\0"), (2, b"yes\0")];
string_table_boolean!(
    rs_dns_over_tls_mode_to_string,
    rs_dns_over_tls_mode_from_string,
    DNS_OVER_TLS_MODE_TABLE,
    2
);

static DNS_CACHE_MODE_TABLE: &[(i32, &[u8])] =
    &[(1, b"yes\0"), (0, b"no\0"), (2, b"no-negative\0")];
string_table_boolean!(
    rs_dns_cache_mode_to_string,
    rs_dns_cache_mode_from_string,
    DNS_CACHE_MODE_TABLE,
    1
);
