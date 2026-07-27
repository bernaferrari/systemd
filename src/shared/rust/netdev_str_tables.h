/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Rust FFI declarations for shadow testing.
 * These mirror the C functions in various src/shared/ headers with rs_ prefix. */

/* bond-util string tables */
const char *rs_bond_mode_to_string(int i);
int rs_bond_mode_from_string(const char *s);
const char *rs_bond_xmit_hash_policy_to_string(int i);
int rs_bond_xmit_hash_policy_from_string(const char *s);
const char *rs_bond_lacp_rate_to_string(int i);
int rs_bond_lacp_rate_from_string(const char *s);
const char *rs_bond_ad_select_to_string(int i);
int rs_bond_ad_select_from_string(const char *s);
const char *rs_bond_fail_over_mac_to_string(int i);
int rs_bond_fail_over_mac_from_string(const char *s);
const char *rs_bond_arp_validate_to_string(int i);
int rs_bond_arp_validate_from_string(const char *s);
const char *rs_bond_arp_all_targets_to_string(int i);
int rs_bond_arp_all_targets_from_string(const char *s);
const char *rs_bond_primary_reselect_to_string(int i);
int rs_bond_primary_reselect_from_string(const char *s);

/* bridge-util string tables */
const char *rs_bridge_state_to_string(int i);
int rs_bridge_state_from_string(const char *s);

/* ethtool-util string tables */
const char *rs_duplex_to_string(int i);
int rs_duplex_from_string(const char *s);
const char *rs_port_to_string(int i);
int rs_port_from_string(const char *s);
const char *rs_mdi_to_string(int i);

/* coredump-util string tables */
const char *rs_coredump_filter_to_string(int i);
int rs_coredump_filter_from_string(const char *s);
int rs_coredump_filter_mask_from_string(const char *s, uint64_t *ret);

/* macvlan-util string tables */
const char *rs_macvlan_mode_to_string(int i);
int rs_macvlan_mode_from_string(const char *s);

/* ipvlan-util string tables */
const char *rs_ipvlan_mode_to_string(int i);
int rs_ipvlan_mode_from_string(const char *s);
const char *rs_ipvlan_flags_to_string(int i);
int rs_ipvlan_flags_from_string(const char *s);

/* geneve-util string tables */
const char *rs_geneve_df_to_string(int i);
int rs_geneve_df_from_string(const char *s);

/* sleep-config string tables */
const char *rs_sleep_operation_to_string(int i);
int rs_sleep_operation_from_string(const char *s);

/* factory-reset string tables */
const char *rs_factory_reset_mode_to_string(int i);
int rs_factory_reset_mode_from_string(const char *s);

/* hostname-setup string tables */
const char *rs_hostname_source_to_string(int i);
int rs_hostname_source_from_string(const char *s);

/* numa-util string tables */
const char *rs_mpol_to_string(int i);
int rs_mpol_from_string(const char *s);

/* output-mode string tables */
const char *rs_output_mode_to_string(int i);
int rs_output_mode_from_string(const char *s);

/* boot-entry string tables */
const char *rs_boot_entry_token_type_to_string(int i);
int rs_boot_entry_token_type_from_string(const char *s);

/* import-util string tables */
const char *rs_import_type_to_string(int i);
int rs_import_type_from_string(const char *s);
const char *rs_import_verify_to_string(int i);
int rs_import_verify_from_string(const char *s);

/* volatile-util string tables */
const char *rs_volatile_mode_to_string(int i);
int rs_volatile_mode_from_string(const char *s);

/* install (unit-file) string tables */
const char *rs_unit_file_state_to_string(int i);
int rs_unit_file_state_from_string(const char *s);
const char *rs_preset_action_past_tense_to_string(int i);

/* discover-image string tables */
const char *rs_image_type_to_string(int i);
int rs_image_type_from_string(const char *s);

/* kernel-image string tables */
const char *rs_kernel_image_type_to_string(int i);

/* open-file string tables */
const char *rs_open_file_flags_to_string(int i);
int rs_open_file_flags_from_string(const char *s);

/* socket-label string tables */
const char *rs_socket_address_bind_ipv6_only_to_string(int i);
int rs_socket_address_bind_ipv6_only_from_string(const char *s);

/* metrics string tables */
const char *rs_metric_family_type_to_string(int i);

/* mstack string tables */
const char *rs_mstack_mount_type_to_string(int i);

/* bus-util string tables */
const char *rs_bus_transport_to_string(int i);

/* user-record string tables */
const char *rs_user_storage_to_string(int i);
int rs_user_storage_from_string(const char *s);
const char *rs_user_disposition_to_string(int i);
int rs_user_disposition_from_string(const char *s);
const char *rs_auto_resize_mode_to_string(int i);
int rs_auto_resize_mode_from_string(const char *s);

/* gpt string tables */
const char *rs_partition_designator_to_string(int i);
int rs_partition_designator_from_string(const char *s);

/* netif-naming-scheme string tables */
const char *rs_name_policy_to_string(int i);
int rs_name_policy_from_string(const char *s);
const char *rs_alternative_names_policy_to_string(int i);
int rs_alternative_names_policy_from_string(const char *s);

/* condition string tables */
const char *rs_condition_result_to_string(int i);
int rs_condition_result_from_string(const char *s);

/* wifi-util string tables */
const char *rs_nl80211_iftype_to_string(int i);
int rs_nl80211_iftype_from_string(const char *s);

/* netif-sriov string tables */
const char *rs_sr_iov_attribute_to_string(int i);

/* resolve-util string tables */
const char *rs_resolve_support_to_string(int i);
int rs_resolve_support_from_string(const char *s);
const char *rs_dnssec_mode_to_string(int i);
int rs_dnssec_mode_from_string(const char *s);
const char *rs_dns_over_tls_mode_to_string(int i);
int rs_dns_over_tls_mode_from_string(const char *s);
const char *rs_dns_cache_mode_to_string(int i);
int rs_dns_cache_mode_from_string(const char *s);

/* dns-packet string tables */
const char *rs_dns_rcode_to_string(int i);
int rs_dns_rcode_from_string(const char *s);
const char *rs_dns_protocol_to_string(int i);
int rs_dns_protocol_from_string(const char *s);
const char *rs_dns_svc_param_key_to_string(int i);
const char *rs_dns_ede_rcode_to_string(int i);
bool rs_dns_ede_rcode_is_dnssec(int ede_rcode);

/* dns-type string tables */
const char *rs_dns_class_to_string(int i);
int rs_dns_class_from_string(const char *s);

/* firewall-util string tables */
const char *rs_nfproto_to_string(int i);
int rs_nfproto_from_string(const char *s);
const char *rs_nft_set_source_to_string(int i);
int rs_nft_set_source_from_string(const char *s);

/* install string tables */
const char *rs_install_change_type_to_string(int i);
int rs_install_change_type_from_string(const char *s);
const char *rs_unit_file_preset_mode_to_string(int i);
int rs_unit_file_preset_mode_from_string(const char *s);

/* bootspec string tables */
const char *rs_boot_entry_type_to_string(int i);
int rs_boot_entry_type_from_string(const char *s);
const char *rs_boot_entry_type_description_to_string(int i);
const char *rs_boot_entry_source_to_string(int i);
const char *rs_boot_entry_source_description_to_string(int i);

/* ioprio-util string tables (WITH_FALLBACK) */
int rs_ioprio_class_to_string_alloc(int i, char **ret);
int rs_ioprio_class_from_string(const char *s);

/* dns-rr string tables (WITH_FALLBACK) */
int rs_dnssec_algorithm_to_string_alloc(int i, char **ret);
int rs_dnssec_algorithm_from_string(const char *s);
int rs_dnssec_digest_to_string_alloc(int i, char **ret);
int rs_dnssec_digest_from_string(const char *s);
int rs_sshfp_algorithm_to_string_alloc(int i, char **ret);
int rs_sshfp_algorithm_from_string(const char *s);
int rs_sshfp_key_type_to_string_alloc(int i, char **ret);
int rs_sshfp_key_type_from_string(const char *s);

/* ethtool-util wol_options (bitfield-to-string) */
int rs_wol_options_to_string_alloc(uint32_t opts, char **ret);

/* bpf-program string tables */
const char *rs_bpf_cgroup_attach_type_to_string(int i);
int rs_bpf_cgroup_attach_type_from_string(const char *s);

/* tpm2-util string tables */
const char *rs_tpm2_userspace_event_type_to_string(int i);
int rs_tpm2_userspace_event_type_from_string(const char *s);
const char *rs_tpm2_pcr_index_to_string(int i);
int rs_tpm2_pcr_index_from_string(const char *s);
int rs_tpm2_hash_alg_to_size(unsigned short alg);
const char *rs_tpm2_hash_alg_to_string(unsigned short alg);
int rs_tpm2_hash_alg_from_string(const char *alg);
const char *rs_tpm2_asym_alg_to_string(unsigned short alg);
int rs_tpm2_asym_alg_from_string(const char *alg);
char *rs_tpm2_pcr_mask_to_string(uint32_t mask);
bool rs_tpm2_nvpcr_name_is_valid(const char *name);

/* wifi-util nl80211_cmd string tables (to_string only) */
const char *rs_nl80211_cmd_to_string(int i);
