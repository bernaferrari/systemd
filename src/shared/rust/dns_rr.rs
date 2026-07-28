// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dns-rr.c, src/shared/dns-rr.h
//
// The Rust API is intentionally presented from this stable facade while the
// implementation follows the C ownership boundaries: model/key, record
// operations, wire codec, and presentation.

pub const SOURCE_PATH: &str = "src/shared/dns-rr.c";
pub const SOURCE_TEXT: &str = include_str!("../dns-rr.c");

mod format;
mod key;
mod model;
mod record;
mod wire;

pub use format::{
    dnssec_algorithm_to_string, dnssec_digest_to_string, format_location, format_svc_param,
    format_svc_param_value, format_svc_params, format_timestamp_dns, format_txt, format_types,
    sshfp_algorithm_to_string, sshfp_key_type_to_string,
};
pub use key::DnsResourceKey;
pub use model::{
    AF_INET, AF_INET6, CAA_FLAG_CRITICAL, DNS_HOSTNAME_MAX, DNS_RESOURCE_KEY_STRING_MAX,
    DNSKEY_FLAG_REVOKE, DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE_KEY, DnsClass, DnsSvcParam,
    DnsSvcParamKey, DnsTxtItem, DnsType, DnssecAlgorithm, DnssecDigest, MDNS_RR_CACHE_FLUSH_OR_QU,
    Nsec3Algorithm, ParseError, Rdata, SshfpAlgorithm, SshfpKeyType,
};
pub use record::{
    DnsResourceRecord, dns_resource_key_compare_func, dns_resource_key_hash_func,
    dns_resource_record_compare_func, dns_resource_record_hash_func, dns_resource_record_payload,
    dns_svc_params_copy, dns_svc_params_equal, dns_txt_item_copy, dns_txt_item_equal,
    dns_txt_item_new_empty, dnssec_keytag,
};

#[cfg(test)]
use key::dns_name_count_labels;

#[cfg(test)]
#[path = "dns_rr/tests.rs"]
mod tests;
