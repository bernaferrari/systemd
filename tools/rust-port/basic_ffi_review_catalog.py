"""Reviewed basic-Rust ABI surface catalog.

Keep the intentionally narrow review scope in one place.  The executable gate
owns parsing and failure policy; this module owns only the immutable mapping of
reviewed header/source pairs, C authorities, and comparison tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BasicFfiReviewCatalog:
    """Paths and symbol sets used by the basic Rust ABI review gate."""

    surfaces: dict[str, tuple[Path, Path]]
    surface_extra_sources: dict[str, tuple[Path, ...]]
    partial_surfaces: dict[str, tuple[Path, Path, frozenset[str]]]
    partial_extra_sources: dict[str, tuple[Path, ...]]
    shadow_tests: dict[str, tuple[Path, ...]]
    partial_shadow_tests: dict[str, tuple[Path, ...]]
    ci_only_shadow_tests: tuple[Path, ...]
    c_authorities: dict[str, tuple[Path, ...]]
    partial_c_authorities: dict[str, tuple[Path, ...]]


def build_catalog(root: Path) -> BasicFfiReviewCatalog:
    """Build the reviewed surface catalog relative to the source root."""

    basic_rust = root / "src/basic/rust"
    shared_rust = root / "src/shared/rust"
    tests_extra = root / "tests-extra"
    surfaces = {
        "af_list": (basic_rust / "af_list.h", basic_rust / "af_list.rs"),
        "basic_validators": (basic_rust / "basic_validators.h", basic_rust / "basic_validators.rs"),
        "bus_type_util": (basic_rust / "bus_type_util.h", basic_rust / "bus_type_util.rs"),
        "capability_util": (basic_rust / "capability_util.h", basic_rust / "capability_util.rs"),
        "devnum_util": (basic_rust / "devnum_util.h", basic_rust / "devnum_util.rs"),
        "dns_type_predicates": (
            shared_rust / "dns_type_predicates.h",
            basic_rust / "dns_type_predicates.rs",
        ),
        "iovec_util": (basic_rust / "iovec_util.h", basic_rust / "iovec_util.rs"),
        "import_util": (basic_rust / "import_util.h", basic_rust / "import_util.rs"),
        "unit_name": (basic_rust / "unit_name.h", basic_rust / "unit_name.rs"),
        "errno_util": (basic_rust / "errno_util.h", basic_rust / "errno_util.rs"),
        "percent_util": (basic_rust / "percent_util.h", basic_rust / "percent_util.rs"),
        "procfs_util": (basic_rust / "procfs_util.h", basic_rust / "procfs_util.rs"),
        "rlimit_util": (basic_rust / "rlimit_util.h", basic_rust / "rlimit_util.rs"),
        "stat_util": (basic_rust / "stat_util.h", basic_rust / "stat_util.rs"),
        "safe_math": (basic_rust / "safe_math.h", basic_rust / "safe_math.rs"),
        "unaligned": (basic_rust / "unaligned.h", basic_rust / "unaligned.rs"),
        "user_util": (basic_rust / "user_util.h", basic_rust / "user_util.rs"),
        "virt": (basic_rust / "virt.h", basic_rust / "virt.rs"),
    }
    surface_extra_sources = {
        "stat_util": (
            basic_rust / "stat_util/verification.rs",
            basic_rust / "stat_util/inode.rs",
            basic_rust / "stat_util/filesystem.rs",
            basic_rust / "stat_util/descriptor.rs",
            basic_rust / "stat_util/moderate.rs",
            basic_rust / "stat_util/xstatx.rs",
            basic_rust / "stat_util/inode_same.rs",
            basic_rust / "stat_util/hash.rs",
        ),
    }
    partial_surfaces = {
        "address_label_valid": (
            basic_rust / "socket_util.h",
            basic_rust / "misc_validators.rs",
            frozenset({"rs_address_label_valid"}),
        ),
        "exit_status_securebits": (
            basic_rust / "exit_status.h",
            basic_rust / "exit_status.rs",
            frozenset({"rs_secure_bits_is_valid"}),
        ),
        "exit_status_lookup": (
            basic_rust / "exit_status.h",
            basic_rust / "exit_status.rs",
            frozenset(
                {
                    "rs_exit_status_to_string",
                    "rs_exit_status_class",
                    "rs_exit_status_from_string",
                    "rs_secure_bit_to_string",
                }
            ),
        ),
        "exit_status_sets": (
            basic_rust / "exit_status.h",
            basic_rust / "exit_status.rs",
            frozenset(
                {
                    "rs_is_clean_exit",
                    "rs_exit_status_set_free",
                    "rs_exit_status_set_is_empty",
                    "rs_exit_status_set_test",
                }
            ),
        ),
        "xml_tokenizer": (
            shared_rust / "xml_tokenizer.h",
            basic_rust / "xml_tokenizer.rs",
            frozenset({"rs_xml_tokenize"}),
        ),
        "parse_util": (
            basic_rust / "parse_util.h",
            basic_rust / "parse_util.rs",
            frozenset(
                {
                    "rs_parse_ip_port_range",
                    "rs_parse_oom_score_adjust",
                    "rs_safe_atou8",
                    "rs_safe_atou16",
                    "rs_safe_atoux16",
                    "rs_safe_atou32",
                    "rs_safe_atoi32",
                    "rs_safe_atolu",
                    "rs_safe_atoli",
                    "rs_safe_atozu",
                    "rs_parse_tristate",
                    "rs_parse_tristate_full",
                    "rs_parse_mtu",
                    "rs_parse_sector_size",
                    "rs_store_loadavg_fixed_point",
                    "rs_parse_loadavg_fixed_point",
                    "rs_parse_boolean",
                    "rs_safe_atou",
                    "rs_safe_atou_full",
                    "rs_safe_atou_bounded",
                    "rs_safe_atou8_full",
                    "rs_safe_atou16_full",
                    "rs_safe_atoi",
                    "rs_safe_atoi16",
                    "rs_safe_atolli",
                    "rs_safe_atollu",
                    "rs_safe_atollu_full",
                    "rs_safe_atolu_full",
                    "rs_safe_atou64",
                    "rs_safe_atoi64",
                    "rs_safe_atoux64",
                    "rs_parse_size",
                    "rs_parse_pid",
                    "rs_parse_mode",
                    "rs_parse_ifindex",
                    "rs_parse_fd",
                    "rs_parse_errno",
                    "rs_parse_nice",
                    "rs_parse_ip_port",
                    "rs_parse_range",
                }
            ),
        ),
        "utf8_abi": (
            basic_rust / "utf8.h",
            basic_rust / "utf8.rs",
            frozenset(
                {
                    "rs_unichar_is_valid",
                    "rs_utf8_is_valid_n",
                    "rs_ascii_is_valid_n",
                    "rs_utf8_to_ascii",
                    "rs_utf8_escape_invalid",
                    "rs_utf8_is_printable_newline",
                    "rs_utf8_escape_non_printable_full",
                    "rs_utf8_encode_unichar",
                    "rs_utf16_encode_unichar",
                    "rs_utf16_to_utf8",
                    "rs_utf8_to_utf16",
                    "rs_char16_strlen",
                    "rs_char16_strsize",
                    "rs_utf8_encoded_valid_unichar",
                    "rs_utf8_encoded_to_unichar",
                    "rs_utf8_n_codepoints",
                    "rs_utf8_char_console_width",
                    "rs_utf8_console_width",
                    "rs_utf8_last_length",
                }
            ),
        ),
        "syslog_util": (
            basic_rust / "syslog_util.h",
            basic_rust / "syslog_util.rs",
            frozenset(
                {
                    "rs_log_facility_unshifted_from_string",
                    "rs_log_facility_unshifted_to_string_alloc",
                    "rs_log_facility_unshifted_is_valid",
                    "rs_log_level_from_string",
                    "rs_log_level_to_string_alloc",
                    "rs_log_level_is_valid",
                    "rs_syslog_parse_priority",
                }
            ),
        ),
        "exec_util": (
            basic_rust / "exec_util.h",
            basic_rust / "exec_util.rs",
            frozenset(
                {
                    "rs_exec_command_flags_from_string",
                    "rs_exec_command_flags_to_string",
                    "rs_exec_command_flags_from_strv",
                    "rs_exec_command_flags_to_strv",
                    "rs_indent_embedded_newlines",
                }
            ),
        ),
        "unit_dbus": (
            basic_rust / "unit_def.h",
            basic_rust / "unit_def.rs",
            frozenset(
                {
                    "rs_unit_dbus_path_from_name",
                    "rs_unit_name_from_dbus_path",
                    "rs_unit_dbus_interface_from_type",
                    "rs_unit_dbus_interface_from_name",
                }
            ),
        ),
        "ratelimit": (
            basic_rust / "ratelimit.h",
            basic_rust / "ratelimit.rs",
            frozenset(
                {
                    "rs_ratelimit_below",
                    "rs_ratelimit_num_dropped",
                    "rs_ratelimit_end",
                    "rs_ratelimit_left",
                    "rs_ratelimit_reset",
                    "rs_ratelimit_configured",
                }
            ),
        ),
        "extract_word": (
            basic_rust / "extract_word.h",
            basic_rust / "extract_word.rs",
            frozenset({"rs_extract_first_word"}),
        ),
        "user_shell_util": (
            shared_rust / "user_shell_util.h",
            basic_rust / "user_shell_util.rs",
            frozenset(
                {
                    "rs_is_nologin_shell",
                    "rs_shell_is_placeholder",
                    "rs_parse_fractional_part_u",
                }
            ),
        ),
        "parse_util_fractional": (
            basic_rust / "parse_util.h",
            basic_rust / "user_shell_util.rs",
            frozenset({"rs_parse_fractional_part_u"}),
        ),
        "strbuf": (
            basic_rust / "strbuf.h",
            basic_rust / "strbuf.rs",
            frozenset(
                {
                    "rs_strbuf_new",
                    "rs_strbuf_add_string_full",
                    "rs_strbuf_complete",
                    "rs_strbuf_free",
                }
            ),
        ),
        "mempool": (
            basic_rust / "mempool.h",
            basic_rust / "mempool.rs",
            frozenset(
                {
                    "rs_mempool_alloc_tile",
                    "rs_mempool_alloc0_tile",
                    "rs_mempool_free_tile",
                }
            ),
        ),
        "pe_binary": (
            basic_rust / "pe_binary.h",
            basic_rust / "pe_binary.rs",
            frozenset(
                {
                    "rs_pe_header_is_64bit",
                    "rs_pe_section_table_find",
                    "rs_pe_header_find_section",
                    "rs_pe_is_uki",
                    "rs_pe_is_addon",
                    "rs_pe_is_native",
                    "rs_pe_header_get_data_directory",
                }
            ),
        ),
        "sha1": (
            basic_rust / "sha1.h",
            basic_rust / "sha1.rs",
            frozenset(
                {
                    "rs_sha1_init_ctx",
                    "rs_sha1_process_bytes",
                    "rs_sha1_finish_ctx",
                }
            ),
        ),
        "sha256_hmac": (
            basic_rust / "sha256_hmac.h",
            basic_rust / "sha256_hmac.rs",
            frozenset(
                {
                    "rs_sha256_is_valid",
                    "rs_parse_sha256",
                    "rs_hmac_sha256",
                }
            ),
        ),
        "siphash24": (
            basic_rust / "siphash24.h",
            basic_rust / "siphash24.rs",
            frozenset(
                {
                    "rs_siphash24_init",
                    "rs_siphash24_compress",
                    "rs_siphash24_compress_string",
                    "rs_siphash24_finalize",
                    "rs_siphash24",
                    "rs_siphash24_string",
                }
            ),
        ),
        "dns_domain_validators": (
            shared_rust / "dns_domain_validators.h",
            basic_rust / "dns_domain_validators.rs",
            frozenset(
                {
                    "rs_dns_service_name_is_valid",
                    "rs_dns_subtype_name_is_valid",
                    "rs_dns_srv_type_is_valid",
                    "rs_dnssd_srv_type_is_valid",
                }
            ),
        ),
        # dns_label.h predates the dedicated validator header and retains the
        # same two declarations for existing consumers. The single exported
        # facade is deliberately checked against both advertised headers.
        "dns_label_srv_type_abi": (
            shared_rust / "dns_label.h",
            basic_rust / "dns_domain_validators.rs",
            frozenset(
                {
                    "rs_dns_srv_type_is_valid",
                    "rs_dnssd_srv_type_is_valid",
                }
            ),
        ),
        "dns_label_abi": (
            shared_rust / "dns_label.h",
            basic_rust / "dns_label.rs",
            frozenset(
                {
                    "rs_dns_label_unescape",
                    "rs_dns_label_escape",
                    "rs_dns_name_parent",
                    "rs_dns_name_is_root",
                    "rs_dns_name_equal",
                    "rs_dns_name_endswith",
                    "rs_dns_name_startswith",
                    "rs_dns_name_count_labels",
                    "rs_dns_name_is_single_label",
                    "rs_dns_name_dont_resolve",
                    "rs_dns_name_dot_suffixed",
                    "rs_dns_name_skip",
                    "rs_dns_name_suffix",
                    "rs_dns_name_equal_skip",
                    "rs_dns_name_common_suffix",
                    "rs_dns_name_to_wire_format",
                    "rs_dns_name_reverse",
                    "rs_dns_name_address",
                    "rs_dns_name_from_wire_format",
                    "rs_dns_label_unescape_suffix",
                    "rs_dns_name_compare_func",
                    "rs_dns_name_between",
                    "rs_dns_label_escape_new",
                    "rs_dns_name_concat",
                    "rs_dns_name_change_suffix",
                    "rs_dns_name_normalize",
                    "rs_dns_name_is_valid",
                    "rs_dns_name_is_valid_ldh",
                    "rs_dns_service_join",
                    "rs_dns_service_split",
                }
            ),
        ),
        "bitmap": (
            basic_rust / "bitmap.h",
            basic_rust / "bitmap.rs",
            frozenset(
                {
                    "rs_bitmap_isset",
                    "rs_bitmap_isclear",
                    "rs_bitmap_equal",
                    "rs_bitmap_new",
                    "rs_bitmap_copy",
                    "rs_bitmap_free",
                    "rs_bitmap_ensure_allocated",
                    "rs_bitmap_set",
                    "rs_bitmap_unset",
                    "rs_bitmap_clear",
                    "rs_bitmap_iterate",
                }
            ),
        ),
        "iovec_wrapper": (
            basic_rust / "iovec_wrapper.h",
            basic_rust / "iovec_wrapper.rs",
            frozenset(
                {
                    "rs_iovw_done",
                    "rs_iovw_done_free",
                    "rs_iovw_free",
                    "rs_iovw_free_free",
                    "rs_iovw_put",
                    "rs_iovw_rebase",
                    "rs_iovw_size",
                    "rs_iovw_isempty",
                }
            ),
        ),
        "prioq": (
            basic_rust / "prioq.h",
            basic_rust / "prioq.rs",
            frozenset(
                {
                    "rs_prioq_new",
                    "rs_prioq_free",
                    "rs_prioq_put",
                    "rs_prioq_remove",
                    "rs_prioq_reshuffle",
                    "rs_prioq_peek_by_index",
                    "rs_prioq_pop",
                    "rs_prioq_size",
                    "rs_prioq_isempty",
                }
            ),
        ),
        "image_policy_util": (
            basic_rust / "image_policy_util.h",
            basic_rust / "image_policy_util.rs",
            frozenset(
                {
                    "rs_partition_policy_flags_extend",
                    "rs_partition_policy_flags_reduce",
                    "rs_partition_policy_flags_from_string",
                    "rs_partition_policy_flags_to_string",
                    "rs_image_policy_free",
                    "rs_image_policy_get",
                    "rs_image_policy_get_exhaustively",
                    "rs_image_policy_equal",
                    "rs_image_policy_equivalent",
                    "rs_image_policy_equiv_ignore",
                    "rs_image_policy_equiv_allow",
                    "rs_image_policy_equiv_deny",
                    "rs_image_policy_from_string",
                    "rs_image_policy_to_string",
                    "rs_image_policy_intersect",
                    "rs_image_policy_union",
                    "rs_partition_policy_determine_fstype",
                }
            ),
        ),
        "socket_util": (
            basic_rust / "socket_util.h",
            basic_rust / "socket_util.rs",
            frozenset(
                {
                    "rs_ifname_valid_char",
                    "rs_ifname_valid_full",
                    "rs_ifname_valid",
                    "rs_vsock_parse_port",
                    "rs_vsock_parse_cid",
                    "rs_sockaddr_port",
                    "rs_sockaddr_in_addr",
                    "rs_sockaddr_set_in_addr",
                    "rs_sockaddr_equal",
                    "rs_sockaddr_ll_len",
                    "rs_sockaddr_un_len",
                    "rs_sockaddr_len",
                    "rs_sockaddr_un_set_path",
                    "rs_socket_address_verify",
                    "rs_socket_address_can_accept",
                    "rs_socket_address_get_path",
                    "rs_socket_address_parse_unix",
                    "rs_socket_address_parse_vsock",
                    "rs_socket_address_equal_unix",
                }
            ),
        ),
        "sort_util": (
            basic_rust / "sort_util.h",
            basic_rust / "sort_util.rs",
            frozenset(
                {
                    "rs_xbsearch_r",
                    "rs_qsort_safe",
                    "rs_qsort_r_safe",
                    "rs_bsearch_safe_internal",
                    "rs_cmp_int",
                    "rs_cmp_uint16",
                }
            ),
        ),
        "time_util_conversion": (
            basic_rust / "time_util.h",
            basic_rust / "time_util/conversion.rs",
            frozenset(
                {
                    "rs_map_clock_usec_raw",
                    "rs_timespec_load",
                    "rs_timespec_load_nsec",
                    "rs_timespec_store",
                    "rs_timespec_store_nsec",
                    "rs_timeval_load",
                    "rs_timeval_store",
                    "rs_triple_timestamp_by_clock",
                }
            ),
        ),
        "time_util_formatting": (
            basic_rust / "time_util.h",
            basic_rust / "time_util/formatting.rs",
            frozenset(
                {
                    "rs_parse_gmtoff",
                    "rs_format_timespan",
                    "rs_timestamp_style_to_string",
                    "rs_timestamp_style_from_string",
                }
            ),
        ),
        "time_util_parsing": (
            basic_rust / "time_util.h",
            basic_rust / "time_util/parsing.rs",
            frozenset(
                {
                    "rs_parse_time",
                    "rs_parse_sec",
                    "rs_parse_sec_fix_0",
                    "rs_parse_sec_def_infinity",
                }
            ),
        ),
        "time_util_arithmetic": (
            basic_rust / "time_util.h",
            basic_rust / "time_util/arithmetic.rs",
            frozenset(
                {
                    "rs_timestamp_is_set",
                    "rs_dual_timestamp_is_set",
                    "rs_triple_timestamp_is_set",
                    "rs_usec_add",
                    "rs_usec_sub_unsigned",
                    "rs_usec_sub_signed",
                }
            ),
        ),
        "image_name_is_valid": (
            basic_rust / "misc_validators.h",
            basic_rust / "misc_validators.rs",
            frozenset({"rs_image_name_is_valid"}),
        ),
        "alloc_util": (
            basic_rust / "alloc_util.h",
            basic_rust / "alloc_util.rs",
            frozenset({"rs_memdup", "rs_memdup_suffix0", "rs_free_many"}),
        ),
        "alloc_util_multiply": (
            basic_rust / "alloc_util.h",
            basic_rust / "alloc_util.rs",
            frozenset(
                {
                    "rs_malloc_multiply",
                    "rs_memdup_multiply",
                    "rs_memdup_suffix0_multiply",
                }
            ),
        ),
        "format_bytes_full": (
            basic_rust / "format_util.h",
            basic_rust / "format_util.rs",
            frozenset({"rs_format_bytes", "rs_format_bytes_full"}),
        ),
        "path_base_predicates": (
            basic_rust / "path_util.h",
            basic_rust / "path_util.rs",
            frozenset(
                {
                    "rs_is_path",
                    "rs_dot_or_dot_dot",
                    "rs_empty_or_root",
                    "rs_empty_to_root",
                    "rs_filename_is_valid",
                    "rs_filename_part_is_valid",
                    "rs_hidden_or_backup_file",
                    "rs_path_implies_directory",
                }
            ),
        ),
        "path_extra_abi": (
            basic_rust / "path_util.h",
            basic_rust / "path_util.rs",
            frozenset(
                {
                    "rs_fdname_is_valid",
                    "rs_file_in_same_dir",
                    "rs_path_is_absolute",
                    "rs_path_is_normalized",
                    "rs_valid_device_node_path",
                    "rs_valid_device_allow_pattern",
                }
            ),
        ),
        "escape": (
            basic_rust / "escape.h",
            basic_rust / "escape.rs",
            frozenset(
                {
                    "rs_octescape",
                    "rs_decescape",
                    "rs_shell_escape",
                    "rs_cescape_char",
                    "rs_cescape",
                    "rs_cescape_length",
                    "rs_cunescape_one",
                    "rs_cunescape",
                    "rs_cunescape_length_with_prefix",
                    "rs_xescape_full",
                    "rs_shell_maybe_quote",
                    "rs_quote_command_line",
                }
            ),
        ),
        "strv_escape_and_fnmatch": (
            basic_rust / "strv.h",
            basic_rust / "strv/matching_escape.rs",
            frozenset({"rs_strv_shell_escape", "rs_strv_fnmatch_full"}),
        ),
        "strv_extend_and_filter": (
            basic_rust / "strv.h",
            basic_rust / "strv/allocating_transforms.rs",
            frozenset({"rs_strv_extend_strv", "rs_strv_filter_prefix"}),
        ),
        "strverscmp": (
            basic_rust / "strverscmp.h",
            basic_rust / "strverscmp.rs",
            frozenset({"rs_strverscmp_improved"}),
        ),
        "strv_base": (
            basic_rust / "strv.h",
            basic_rust / "strv.rs",
            frozenset(
                {
                    "rs_strv_length",
                    "rs_strv_find",
                    "rs_strv_find_case",
                    "rs_strv_find_prefix",
                    "rs_strv_find_startswith",
                    "rs_strv_is_uniq",
                    "rs_strv_overlap",
                    "rs_strv_compare",
                    "rs_strv_equal_ignore_order",
                    "rs_strv_copy_n",
                    "rs_strv_remove",
                    "rs_strv_uniq",
                    "rs_strv_sort",
                    "rs_strv_reverse",
                    "rs_strv_skip",
                }
            ),
        ),
        "strv_registered": (
            basic_rust / "strv.h",
            basic_rust / "strv.rs",
            frozenset(
                {
                    "rs_STRV_IFNOTNULL",
                    "rs_endswith_strv_internal",
                    "rs_startswith_strv_internal",
                    "rs_strv_consume",
                    "rs_strv_consume_pair",
                    "rs_strv_consume_prepend",
                    "rs_strv_consume_with_size",
                    "rs_strv_contains",
                    "rs_strv_copy",
                    "rs_strv_copy_unless_empty",
                    "rs_strv_equal",
                    "rs_strv_extend",
                    "rs_strv_extend_assignment",
                    "rs_strv_extend_n",
                    "rs_strv_extend_strv_consume",
                    "rs_strv_find_closest",
                    "rs_strv_find_closest_prefix",
                    "rs_strv_find_closest_by_levenshtein",
                    "rs_strv_free_and_replace",
                    "rs_strv_fnmatch",
                    "rs_strv_fnmatch_or_empty",
                    "rs_strv_insert",
                    "rs_strv_isempty",
                    "rs_strv_join",
                    "rs_strv_join_full",
                    "rs_strv_prepend",
                    "rs_strv_push",
                    "rs_strv_push_pair",
                    "rs_strv_push_prepend",
                    "rs_strv_push_with_size",
                    "rs_strv_rebreak_lines",
                    "rs_strv_sort_uniq",
                    "rs_strv_split",
                    "rs_strv_split_and_extend_full",
                    "rs_strv_split_full",
                    "rs_strv_split_newlines",
                    "rs_strv_split_newlines_full",
                }
            ),
        ),
        "string_mutation_registered": (
            basic_rust / "string_util.h",
            basic_rust / "string_util.rs",
            frozenset(
                {
                    "rs_ascii_strlower",
                    "rs_ascii_strlower_n",
                    "rs_ascii_strupper",
                    "rs_delete_chars",
                    "rs_delete_trailing_chars",
                    "rs_empty_or_dash_to_null",
                    "rs_find_line_after_internal",
                    "rs_find_line_internal",
                    "rs_find_line_startswith_internal",
                    "rs_first_word",
                    "rs_memory_startswith_no_case",
                    "rs_skip_leading_chars",
                    "rs_strdup_to",
                    "rs_string_contains_word",
                    "rs_string_contains_word_strv",
                    "rs_string_extract_line",
                    "rs_string_truncate_lines",
                    "rs_strncpy_exact",
                    "rs_strstrafter_internal",
                    "rs_strstrip",
                    "rs_strstr_ptr_internal",
                    "rs_truncate_nl",
                    "rs_truncate_nl_full",
                }
            ),
        ),
        "signal_inline_registered": (
            basic_rust / "signal_util.h",
            basic_rust / "signal_util.rs",
            frozenset(
                {
                    "rs_signal_is_valid",
                    "rs_signal_to_string_with_check",
                    "rs_si_code_from_process",
                }
            ),
        ),
        "signal_util_parsing": (
            basic_rust / "signal_util.h",
            basic_rust / "signal_util.rs",
            frozenset(
                {
                    "rs_signal_to_string",
                    "rs_signal_from_string",
                    "rs_parse_signo",
                }
            ),
        ),
        "serialize_deserialization": (
            basic_rust / "serialize.h",
            basic_rust / "serialize.rs",
            frozenset({"rs_deserialize_usec", "rs_deserialize_dual_timestamp"}),
        ),
        "udev_util": (
            basic_rust / "udev_util.h",
            basic_rust / "udev_util.rs",
            frozenset({"rs_udev_replace_whitespace", "rs_udev_replace_chars"}),
        ),
        "shared_validation_facades": (
            basic_rust / "shared_facades/validation.h",
            basic_rust / "shared_facades/validation.rs",
            frozenset(
                {
                    "rs_boot_entry_token_valid",
                    "rs_documentation_url_is_valid",
                    "rs_file_url_is_valid",
                    "rs_hsv_to_rgb",
                    "rs_http_etag_is_valid",
                    "rs_http_url_is_valid",
                    "rs_parse_compare_operator",
                    "rs_pkcs11_uri_valid",
                    "rs_rgb_to_hsv",
                    "rs_suitable_blob_filename",
                    "rs_test_order",
                }
            ),
        ),
        "is_device_path": (
            basic_rust / "path_util.h",
            basic_rust / "path_util.rs",
            frozenset({"rs_is_device_path"}),
        ),
        "path_byte_abi": (
            basic_rust / "path_util.h",
            basic_rust / "path_util/byte_abi.rs",
            frozenset(
                {
                    "rs_filename_or_absolute_path_is_valid",
                    "rs_last_path_component",
                    "rs_path_compare",
                    "rs_path_compare_filename",
                    "rs_path_equal",
                    "rs_path_equal_filename",
                    "rs_path_extract_directory",
                    "rs_path_extract_filename",
                    "rs_path_find_first_component",
                    "rs_path_find_last_component",
                    "rs_path_is_safe",
                    "rs_path_is_valid",
                    "rs_path_make_relative",
                    "rs_path_simplify",
                    "rs_path_simplify_alloc",
                    "rs_path_simplify_full",
                    "rs_path_split_prefix_filename",
                    "rs_path_startswith",
                    "rs_path_startswith_full",
                    "rs_path_startswith_strv",
                    "rs_path_strv_contains",
                    "rs_prefixed_path_strv_contains",
                }
            ),
        ),
        "utf8_header_inline": (
            basic_rust / "utf8.h",
            basic_rust / "header_inline_abi.rs",
            frozenset(
                {
                    "rs_utf8_is_valid",
                    "rs_ascii_is_valid",
                    "rs_utf8_escape_non_printable",
                    "rs_utf16_is_surrogate",
                    "rs_utf16_is_trailing_surrogate",
                    "rs_utf16_surrogate_pair_to_unichar",
                }
            ),
        ),
        "terminal_header_inline": (
            basic_rust / "terminal_util.h",
            basic_rust / "terminal_util.rs",
            frozenset({"rs_osc_char_is_valid", "rs_vtnr_is_valid"}),
        ),
        "path_header_inline": (
            basic_rust / "path_util.h",
            basic_rust / "header_inline_abi.rs",
            frozenset({"rs_skip_dev_prefix"}),
        ),
        "gpt_partition_predicates": (
            basic_rust / "gpt_util.h",
            basic_rust / "gpt_util.rs",
            frozenset(
                {
                    "rs_gpt_partition_type_knows_read_only",
                    "rs_gpt_partition_type_knows_growfs",
                    "rs_gpt_partition_type_knows_no_auto",
                    "rs_gpt_partition_type_has_filesystem",
                }
            ),
        ),
        "unit_install_predicates": (
            basic_rust / "unit_file.h",
            basic_rust / "unit_inline_abi.rs",
            frozenset({"rs_unit_type_may_alias", "rs_unit_type_may_template"}),
        ),
        "misc_inline_abi": (
            basic_rust / "misc_inline_abi.h",
            basic_rust / "hexdecoct.rs",
            frozenset(
                {
                    "rs_unhexmem",
                    "rs_base64mem",
                    "rs_unbase64mem",
                    "rs_devnum_is_zero",
                    "rs_devnum_set_and_equal",
                    "rs_xattr_is_acl",
                    "rs_xattr_is_selinux",
                }
            ),
        ),
        "xattr_util": (
            basic_rust / "xattr_util.h",
            basic_rust / "xattr_util.rs",
            frozenset({"rs_xattr_is_acl", "rs_xattr_is_selinux"}),
        ),
        "misc_validator_registered": (
            basic_rust / "misc_validators.h",
            basic_rust / "misc_validators.rs",
            frozenset(
                {
                    "rs_bus_property_is_timestamp",
                    "rs_nft_identifier_valid",
                    "rs_nice_is_valid",
                    "rs_sched_policy_is_valid",
                    "rs_oom_score_adjust_is_valid",
                    "rs_valid_gecos",
                    "rs_log_namespace_name_valid",
                    "rs_valid_home",
                    "rs_valid_shell",
                }
            ),
        ),
        "mount_propagation_validator": (
            basic_rust / "mountpoint_util.h",
            basic_rust / "mountpoint_util.rs",
            frozenset(
                {
                    "rs_mount_propagation_flag_to_string",
                    "rs_mount_propagation_flag_from_string",
                    "rs_mount_propagation_flag_is_valid",
                    "rs_is_name_to_handle_at_fatal_error",
                }
            ),
        ),
        "bus_label": (
            basic_rust / "bus_label.h",
            basic_rust / "bus_label.rs",
            frozenset({"rs_bus_label_escape", "rs_bus_label_unescape_n"}),
        ),
        "gunicode": (
            basic_rust / "gunicode.h",
            basic_rust / "gunicode.rs",
            frozenset({"rs_utf8_prev_char", "rs_unichar_iswide"}),
        ),
        "efivars_util": (
            basic_rust / "efivars_util.h",
            basic_rust / "efivars_util.rs",
            frozenset(
                {
                    "rs_secure_boot_mode_to_string",
                    "rs_decode_secure_boot_mode",
                    "rs_efi_tilt_backslashes",
                    "rs_efi_guid_to_id128",
                    "rs_efi_id128_to_guid",
                }
            ),
        ),
        "device_nodes": (
            basic_rust / "device_nodes.h",
            basic_rust / "device_nodes.rs",
            frozenset(
                {"rs_allow_listed_char_for_devnode", "rs_encode_devnode_name"}
            ),
        ),
        "mount_setup": (
            basic_rust / "mount_setup.h",
            basic_rust / "mount_setup.rs",
            frozenset({"rs_mount_point_is_api", "rs_mount_point_ignore"}),
        ),
        "specifier_util": (
            basic_rust / "specifier_util.h",
            basic_rust / "specifier_util.rs",
            frozenset(
                {
                    "rs_specifier_escape",
                    "rs_specifier_escape_strv",
                    "rs_efi_loader_entry_name_valid",
                }
            ),
        ),
        "btrfs_validate_subvolume_name": (
            basic_rust / "btrfs_util.h",
            basic_rust / "btrfs_util.rs",
            frozenset({"rs_btrfs_validate_subvolume_name"}),
        ),
        "hexdecoct": (
            basic_rust / "hexdecoct.h",
            basic_rust / "hexdecoct.rs",
            frozenset(
                {
                    "rs_octchar",
                    "rs_unoctchar",
                    "rs_decchar",
                    "rs_undecchar",
                    "rs_hexchar",
                    "rs_unhexchar",
                    "rs_base32hexchar",
                    "rs_unbase32hexchar",
                    "rs_base64char",
                    "rs_urlsafe_base64char",
                    "rs_unbase64char",
                    "rs_hexmem",
                    "rs_unhexmem_full",
                    "rs_base32hexmem",
                    "rs_unbase32hexmem",
                    "rs_base64mem_full",
                    "rs_unbase64mem_full",
                    "rs_base64_append",
                }
            ),
        ),
        "env_util": (
            basic_rust / "env_util.h",
            basic_rust / "env_util.rs",
            frozenset(
                {
                    "rs_env_name_is_valid",
                    "rs_env_value_is_valid",
                    "rs_env_assignment_is_valid",
                    "rs_strv_env_is_valid",
                    "rs_strv_env_name_is_valid",
                    "rs_strv_env_name_or_assignment_is_valid",
                }
            ),
        ),
        "credential_validators": (
            basic_rust / "credential_validators.h",
            basic_rust / "credential_validators.rs",
            frozenset({"rs_credential_name_valid", "rs_credential_glob_valid"}),
        ),
        "namespace_util": (
            basic_rust / "namespace_util.h",
            basic_rust / "namespace_util.rs",
            frozenset(
                {
                    "rs_clone_flag_to_namespace_type",
                    "rs_userns_shift_range_valid",
                }
            ),
        ),
        "edid": (
            basic_rust / "edid.h",
            basic_rust / "edid.rs",
            frozenset({"rs_edid_parse_blob", "rs_edid_get_panel_id"}),
        ),
        "nsflags": (
            shared_rust / "nsflags.h",
            basic_rust / "nsflags.rs",
            frozenset(
                {
                    "rs_namespace_single_flag_to_string",
                    "rs_namespace_flags_to_strv",
                    "rs_namespace_flags_to_string",
                    "rs_namespace_flags_from_string",
                }
            ),
        ),
        "memory_util": (
            basic_rust / "memory_util.h",
            basic_rust / "memory_util.rs",
            frozenset(
                {
                    "rs_page_size",
                    "rs_memcpy_safe",
                    "rs_mempcpy_safe",
                    "rs_memcmp_safe",
                    "rs_memcmp_nn",
                    "rs_mempset",
                    "rs_memmem_safe",
                    "rs_mempmem_safe",
                    "rs_memeqbyte",
                }
            ),
        ),
        "hostname_util": (
            basic_rust / "hostname_util.h",
            basic_rust / "hostname_util.rs",
            frozenset(
                {
                    "rs_valid_ldh_char",
                    "rs_hostname_is_valid",
                    "rs_hostname_cleanup",
                    "rs_is_localhost",
                    "rs_is_gateway_hostname",
                    "rs_is_outbound_hostname",
                    "rs_is_dns_stub_hostname",
                    "rs_is_dns_proxy_stub_hostname",
                    "rs_split_user_at_host",
                    "rs_machine_spec_valid",
                }
            ),
        ),
        "id128_util": (
            basic_rust / "id128_util.h",
            basic_rust / "id128_util.rs",
            frozenset(
                {
                    "rs_sd_id128_to_string",
                    "rs_sd_id128_to_uuid_string",
                    "rs_sd_id128_from_string",
                    "rs_sd_id128_string_equal",
                    "rs_id128_from_string_nonzero",
                    "rs_id128_make_v4_uuid",
                    "rs_id128_compare_func",
                    "rs_sd_id128_equal",
                    "rs_sd_id128_is_null",
                    "rs_id128_digest",
                }
            ),
        ),
        "process_util_str_tables": (
            basic_rust / "process_util_str_tables.h",
            basic_rust / "process_util_str_tables.rs",
            frozenset(
                {
                    "rs_sigchld_code_to_string",
                    "rs_sigchld_code_from_string",
                    "rs_sched_policy_to_string_alloc",
                    "rs_sched_policy_from_string",
                }
            ),
        ),
        "string_table": (
            basic_rust / "string_table.h",
            basic_rust / "string_table.rs",
            frozenset(
                {
                    "rs_string_table_lookup_to_string",
                    "rs_string_table_lookup_from_string",
                    "rs_string_table_lookup_from_string_with_boolean",
                    "rs_string_table_lookup_to_string_fallback",
                    "rs_string_table_lookup_from_string_fallback",
                }
            ),
        ),
        "strxcpyx": (
            basic_rust / "strxcpyx.h",
            basic_rust / "strxcpyx.rs",
            frozenset(
                {
                    "rs_strnpcpy_full",
                    "rs_strpcpy_full",
                    "rs_strnscpy_full",
                    "rs_strscpy_full",
                }
            ),
        ),
        "terminal_util": (
            basic_rust / "terminal_util.h",
            basic_rust / "terminal_util.rs",
            frozenset(
                {
                    "rs_tty_is_vc",
                    "rs_tty_is_console",
                    "rs_vtnr_from_tty",
                    "rs_url_suitable_for_osc8",
                }
            ),
        ),
        "nulstr_util": (
            basic_rust / "nulstr_util.h",
            basic_rust / "nulstr_util.rs",
            frozenset({"rs_nulstr_get", "rs_strv_parse_nulstr_full"}),
        ),
        "recovery_key": (
            basic_rust / "recovery_key.h",
            basic_rust / "recovery_key.rs",
            frozenset({"rs_decode_modhex_char", "rs_normalize_recovery_key"}),
        ),
    }
    partial_extra_sources = {
        "escape": (
            basic_rust / "escape/allocating.rs",
            basic_rust / "escape/core_abi.rs",
            basic_rust / "escape/full_abi.rs",
        ),
        "misc_inline_abi": (
            basic_rust / "devnum_util.rs",
            basic_rust / "format_util.rs",
            basic_rust / "xattr_util.rs",
        ),
        "misc_validator_registered": (basic_rust / "process_util_str_tables.rs",),
        "string_mutation_registered": (basic_rust / "string_util_lines.rs",),
    }
    shadow_tests = {
        "af_list": (tests_extra / "test-af-list-rust.c",),
        "basic_validators": (tests_extra / "test-basic-validators-rust.c",),
        "bus_type_util": (
            tests_extra / "test-bus-type-util-rust.c",
            tests_extra / "test-devt-compare-rust.c",
        ),
        "capability_util": (tests_extra / "test-capability-util-rust.c",),
        "devnum_util": (tests_extra / "test-devnum-util-rust.c",),
        "dns_type_predicates": (tests_extra / "test-dns-type-predicates-rust.c",),
        "errno_util": (
            tests_extra / "test-errno-util-rust.c",
            tests_extra / "test-errno-classify-rust.c",
            tests_extra / "test-errno-util-extra3-rust.c",
        ),
        "iovec_util": (tests_extra / "test-iovec-util-rust.c",),
        "import_util": (tests_extra / "test-seccomp-import-rust.c",),
        "unit_name": (tests_extra / "test-unit-name-rust.c",),
        "percent_util": (
            tests_extra / "test-percent-util-rust.c",
            tests_extra / "test-percent-scale-rust.c",
        ),
        "procfs_util": (tests_extra / "test-procfs-util-rust.c",),
        "rlimit_util": (
            tests_extra / "test-rlimit-util-rust.c",
            tests_extra / "test-rlimit-parse-rust.c",
        ),
        "stat_util": (
            tests_extra / "test-stat-util-extra2-rust.c",
            tests_extra / "test-stat-util-inline-rust.c",
            tests_extra / "test-misc-rust2.c",
            tests_extra / "test-stat-verify-rust.c",
            tests_extra / "test-stat-util-rust.c",
        ),
        "safe_math": (tests_extra / "test-safe-math-rust.c",),
        "unaligned": (tests_extra / "test-unaligned-rust.c",),
        "user_util": (tests_extra / "test-user-util-rust.c",),
        "virt": (
            tests_extra / "test-str-tables-batch3-rust.c",
            tests_extra / "test-virt-rust.c",
        ),
    }
    partial_shadow_tests = {
        "address_label_valid": (
            tests_extra / "test-socket-util-rust.c",
            tests_extra / "test-misc-validators-rust.c",
        ),
        "exit_status_securebits": (tests_extra / "test-securebits-rust.c",),
        "exit_status_lookup": (tests_extra / "test-exit-status-rust.c",),
        "exit_status_sets": (tests_extra / "test-exit-status-rust.c",),
        "xml_tokenizer": (tests_extra / "test-xml-rust.c",),
        "parse_util": (
            tests_extra / "test-parse-util-rust.c",
            tests_extra / "test-parse-util-extra-rust.c",
            tests_extra / "test-parse-util-inline-rust.c",
            tests_extra / "test-parse-extra-rust.c",
        ),
        "utf8_abi": (tests_extra / "test-utf8-rust.c",),
        "syslog_util": (tests_extra / "test-syslog-util-rust.c",),
        "exec_util": (tests_extra / "test-exec-util-rust.c",),
        "unit_dbus": (tests_extra / "test-unit-dbus-rust.c",),
        "ratelimit": (tests_extra / "test-ratelimit-rust.c",),
        "extract_word": (tests_extra / "test-extract-word-rust.c",),
        "user_shell_util": (tests_extra / "test-user-shell-util-rust.c",),
        "parse_util_fractional": (tests_extra / "test-user-shell-util-rust.c",),
        "strbuf": (tests_extra / "test-strbuf-rust.c",),
        "mempool": (tests_extra / "test-mempool-rust.c",),
        "pe_binary": (tests_extra / "test-pe-binary-rust.c",),
        "sha1": (tests_extra / "test-sha1-rust.c",),
        "sha256_hmac": (tests_extra / "test-sha256-hmac-rust.c",),
        "siphash24": (tests_extra / "test-siphash24-rust.c",),
        "dns_domain_validators": (tests_extra / "test-dns-label-rust.c",),
        "dns_label_srv_type_abi": (tests_extra / "test-dns-label-rust.c",),
        "dns_label_abi": (tests_extra / "test-dns-label-rust.c",),
        "bitmap": (tests_extra / "test-bitmap-rust.c",),
        "iovec_wrapper": (tests_extra / "test-iovec-wrapper-rust.c",),
        "prioq": (tests_extra / "test-prioq-rust.c",),
        "image_policy_util": (tests_extra / "test-image-policy-rust.c",),
        "socket_util": (tests_extra / "test-socket-util-rust.c",),
        "sort_util": (tests_extra / "test-sort-util-rust.c",),
        "time_util_conversion": (tests_extra / "test-time-util-rust.c",),
        "time_util_formatting": (
            tests_extra / "test-parse-extra-rust.c",
            tests_extra / "test-time-util-extra-rust.c",
        ),
        "time_util_parsing": (tests_extra / "test-time-util-rust.c",),
        "time_util_arithmetic": (tests_extra / "test-time-util-extra2-rust.c",),
        "image_name_is_valid": (tests_extra / "test-image-name-rust.c",),
        "alloc_util": (tests_extra / "test-alloc-util-rust.c",),
        "alloc_util_multiply": (tests_extra / "test-alloc-util-extra2-rust.c",),
        "format_bytes_full": (
            tests_extra / "test-format-util-rust.c",
            tests_extra / "test-misc-inline-rust.c",
        ),
        "path_base_predicates": (tests_extra / "test-path-util-rust.c",),
        "path_extra_abi": (tests_extra / "test-path-util-rust.c",),
        "escape": (
            tests_extra / "test-escape-rust.c",
            tests_extra / "test-escape-extra-rust.c",
            tests_extra / "test-escape-extra2-rust.c",
        ),
        "strv_escape_and_fnmatch": (
            tests_extra / "test-string-util-extra6-rust.c",
            tests_extra / "test-strv-fnmatch-rust.c",
        ),
        "strv_extend_and_filter": (tests_extra / "test-strv-extra3-rust.c",),
        "strverscmp": (tests_extra / "test-strverscmp-rust.c",),
        "strv_base": (tests_extra / "test-strv-rust.c",),
        "strv_registered": (
            tests_extra / "test-strv-extra-rust.c",
            tests_extra / "test-strv-extra2-rust.c",
            tests_extra / "test-strv-extra4-rust.c",
            tests_extra / "test-strv-extra5-rust.c",
            tests_extra / "test-strv-extra6-rust.c",
            tests_extra / "test-strv-extra7-rust.c",
            tests_extra / "test-remaining-untested-rust.c",
        ),
        "string_mutation_registered": (
            tests_extra / "test-string-mutation-rust.c",
            tests_extra / "test-string-util-inline2-rust.c",
        ),
        "signal_inline_registered": (
            tests_extra / "test-string-util-inline2-rust.c",
            tests_extra / "test-signal-inline-rust.c",
        ),
        "signal_util_parsing": (tests_extra / "test-signal-util-rust.c",),
        "serialize_deserialization": (tests_extra / "test-serialize-rust.c",),
        "udev_util": (tests_extra / "test-udev-util-rust.c",),
        "shared_validation_facades": (
            tests_extra / "test-shared-validators-rust.c",
            tests_extra / "test-mount-color-btrfs-rust.c",
            tests_extra / "test-compare-operator-rust.c",
            tests_extra / "test-boot-entry-rust.c",
            tests_extra / "test-pkcs11-rust.c",
            tests_extra / "test-misc-rust2.c",
            tests_extra / "test-misc-untested2-rust.c",
        ),
        "is_device_path": (tests_extra / "test-stat-verify-rust.c",),
        "path_byte_abi": (
            tests_extra / "test-path-funcs-rust.c",
            tests_extra / "test-path-util-extra-rust.c",
        ),
        "utf8_header_inline": (tests_extra / "test-header-inline-rust.c",),
        "terminal_header_inline": (tests_extra / "test-header-inline-rust.c",),
        "path_header_inline": (tests_extra / "test-header-inline-rust.c",),
        "gpt_partition_predicates": (tests_extra / "test-gpt-unit-install-rust.c",),
        "unit_install_predicates": (tests_extra / "test-gpt-unit-install-rust.c",),
        "misc_inline_abi": (tests_extra / "test-misc-inline-rust.c",),
        "xattr_util": (tests_extra / "test-xattr-util-rust.c",),
        "misc_validator_registered": (tests_extra / "test-misc-validators-rust.c",),
        "mount_propagation_validator": (
            tests_extra / "test-namespace-mountpoint-rust.c",
        ),
        "bus_label": (tests_extra / "test-bus-label-rust.c",),
        "gunicode": (tests_extra / "test-gunicode-rust.c",),
        "efivars_util": (
            tests_extra / "test-efivars-rust.c",
            tests_extra / "test-efi-guid-rust.c",
            tests_extra / "test-misc-rust3.c",
        ),
        "device_nodes": (tests_extra / "test-device-nodes-rust.c",),
        "mount_setup": (tests_extra / "test-mount-setup-rust.c",),
        "specifier_util": (tests_extra / "test-specifier-efi-rust.c",),
        "btrfs_validate_subvolume_name": (tests_extra / "test-btrfs-util-rust.c",),
        "hexdecoct": (tests_extra / "test-hexdecoct-rust.c",),
        "env_util": (tests_extra / "test-env-util-rust.c",),
        "credential_validators": (
            tests_extra / "test-credential-validators-rust.c",
        ),
        "namespace_util": (tests_extra / "test-namespace-mountpoint-rust.c",),
        "edid": (tests_extra / "test-edid-rust.c",),
        "nsflags": (tests_extra / "test-nsflags-rust.c",),
        "memory_util": (tests_extra / "test-memory-util-rust.c",),
        "hostname_util": (tests_extra / "test-hostname-util-rust.c",),
        "id128_util": (tests_extra / "test-id128-rust.c",),
        "process_util_str_tables": (
            tests_extra / "test-process-util-str-tables-rust.c",
        ),
        "string_table": (tests_extra / "test-string-table-rust.c",),
        "strxcpyx": (tests_extra / "test-strxcpyx-rust.c",),
        "terminal_util": (tests_extra / "test-terminal-util-rust.c",),
        "nulstr_util": (tests_extra / "test-nulstr-util-rust.c",),
        "recovery_key": (tests_extra / "test-recovery-key-rust.c",),
    }
    # These C-versus-Rust fixtures are reviewed by their dedicated static ABI
    # gates rather than by `check-basic-rust-ffi-abi.py`'s generic surface
    # parser. Keeping them here still makes the reviewed CI target set one
    # source of truth.
    ci_only_shadow_tests = (
        tests_extra / "test-inline-helpers-rust.c",
        tests_extra / "test-string-util-fundamental-rust.c",
        tests_extra / "test-string-util-rust.c",
        tests_extra / "test-string-util-extra-rust.c",
        tests_extra / "test-string-util-extra2-rust.c",
        tests_extra / "test-string-util-extra7-rust.c",
        tests_extra / "test-make-cstring-rust.c",
        tests_extra / "test-strreplace-rust.c",
        tests_extra / "test-ether-addr-util-rust.c",
        tests_extra / "test-seccomp-util-rust.c",
    )
    c_authorities = {
        "af_list": (root / "src/basic/af-list.c",),
        "basic_validators": (
            root / "src/basic/cgroup-util.h",
            root / "src/basic/io-util.h",
            root / "src/basic/audit-util.h",
            root / "src/basic/errno-list.h",
            root / "src/basic/socket-util.h",
            root / "src/basic/process-util.h",
            root / "src/basic/pidref.h",
            root / "src/basic/pidref.c",
            root / "src/basic/alloc-util.h",
            root / "src/basic/fileio.h",
            root / "src/basic/string-util.h",
        ),
        "bus_type_util": (root / "src/libsystemd/sd-bus/bus-type.c", root / "src/basic/hash-funcs.c"),
        "capability_util": (root / "src/basic/capability-util.h",),
        "devnum_util": (root / "src/basic/devnum-util.c", root / "src/basic/devnum-util.h"),
        "dns_type_predicates": (root / "src/shared/dns-type.c", root / "src/shared/dns-type.h"),
        "errno_util": (
            root / "src/basic/errno-util.c",
            root / "src/basic/errno-util.h",
            root / "src/basic/errno-list.c",
            root / "src/basic/errno-list.h",
            root / "src/shared/seccomp-util.h",
        ),
        "iovec_util": (root / "src/basic/iovec-util.c", root / "src/fundamental/iovec-util.h"),
        "import_util": (root / "src/shared/import-util.c", root / "src/shared/reboot-util.c"),
        "unit_name": (root / "src/basic/unit-name.c",),
        "percent_util": (root / "src/basic/percent-util.c", root / "src/basic/percent-util.h"),
        "procfs_util": (root / "src/basic/procfs-util.c", root / "src/basic/procfs-util.h"),
        "rlimit_util": (root / "src/basic/rlimit-util.c", root / "src/basic/rlimit-util.h"),
        "stat_util": (
            root / "src/basic/stat-util.c",
            root / "src/basic/stat-util.h",
            root / "src/basic/siphash24.c",
            root / "src/basic/siphash24.h",
            root / "src/basic/chattr-util.c",
            root / "src/basic/chattr-util.h",
            root / "src/basic/chase.c",
            root / "src/basic/chase.h",
            root / "src/basic/dirent-util.h",
            root / "src/basic/fd-util.c",
            root / "src/basic/fd-util.h",
            root / "src/basic/filesystem-sets.py",
            root / "src/basic/fs-util.c",
            root / "src/basic/fs-util.h",
            root / "src/basic/mountpoint-util.c",
            root / "src/basic/mountpoint-util.h",
            root / "src/basic/path-util.c",
            root / "src/basic/path-util.h",
            root / "src/include/uapi/linux/magic.h",
            root / "src/basic/time-util.c",
            root / "src/shared/btrfs-util.c",
            root / "src/shared/btrfs-util.h",
        ),
        "safe_math": (root / "src/basic/macro.h",),
        "unaligned": (root / "src/basic/unaligned.h",),
        "user_util": (
            root / "src/basic/user-util.c",
            root / "src/basic/user-util.h",
            root / "src/basic/capsule-util.c",
            root / "src/basic/capsule-util.h",
            root / "src/libsystemd/sd-id128/id128-util.c",
            root / "src/libsystemd/sd-id128/id128-util.h",
        ),
        "virt": (root / "src/basic/virt.c", root / "src/basic/virt.h"),
    }
    partial_c_authorities = {
        "address_label_valid": (root / "src/basic/socket-util.c",),
        "exit_status_securebits": (root / "src/shared/securebits-util.h",),
        "exit_status_lookup": (
            root / "src/shared/exit-status.c",
            root / "src/shared/exit-status.h",
            root / "src/shared/securebits-util.c",
            root / "src/shared/securebits-util.h",
        ),
        "exit_status_sets": (
            root / "src/shared/exit-status.c",
            root / "src/shared/exit-status.h",
        ),
        "xml_tokenizer": (root / "src/shared/xml.c", root / "src/shared/xml.h"),
        "parse_util": (root / "src/basic/parse-util.c", root / "src/basic/parse-util.h"),
        "utf8_abi": (
            root / "src/basic/utf8.c",
            root / "src/basic/utf8.h",
            root / "src/basic/gunicode.c",
            root / "src/basic/gunicode.h",
        ),
        "syslog_util": (root / "src/basic/syslog-util.c", root / "src/basic/syslog-util.h"),
        "exec_util": (
            root / "src/shared/exec-util.c",
            root / "src/shared/exec-util.h",
            root / "src/shared/bootspec.c",
            root / "src/shared/bootspec.h",
        ),
        "unit_dbus": (root / "src/basic/unit-def.c", root / "src/basic/unit-def.h"),
        "ratelimit": (root / "src/basic/ratelimit.c", root / "src/basic/ratelimit.h"),
        "extract_word": (
            root / "src/basic/extract-word.c",
            root / "src/basic/extract-word.h",
        ),
        "user_shell_util": (
            root / "src/basic/user-util.c",
            root / "src/basic/user-util.h",
            root / "src/basic/parse-util.c",
            root / "src/basic/parse-util.h",
        ),
        "parse_util_fractional": (
            root / "src/basic/parse-util.c",
            root / "src/basic/parse-util.h",
        ),
        "strbuf": (root / "src/basic/strbuf.c", root / "src/basic/strbuf.h"),
        "mempool": (
            root / "src/basic/mempool.c",
            root / "src/basic/mempool.h",
            root / "src/basic/memory-util.c",
            root / "src/basic/memory-util.h",
            root / "src/fundamental/memory-util.h",
        ),
        "pe_binary": (root / "src/shared/pe-binary.c", root / "src/shared/pe-binary.h"),
        "sha1": (root / "src/fundamental/sha1.c", root / "src/fundamental/sha1.h"),
        "sha256_hmac": (
            root / "src/basic/sha256.c",
            root / "src/basic/sha256.h",
            root / "src/basic/hmac.c",
            root / "src/basic/hmac.h",
            root / "src/fundamental/sha256.c",
            root / "src/fundamental/sha256.h",
        ),
        "siphash24": (root / "src/basic/siphash24.c", root / "src/basic/siphash24.h"),
        "dns_domain_validators": (
            root / "src/shared/dns-domain.c",
            root / "src/shared/dns-domain.h",
        ),
        "dns_label_srv_type_abi": (
            root / "src/shared/dns-domain.c",
            root / "src/shared/dns-domain.h",
        ),
        "dns_label_abi": (
            root / "src/shared/dns-domain.c",
            root / "src/shared/dns-domain.h",
        ),
        "bitmap": (
            root / "src/shared/bitmap.c",
            root / "src/shared/bitmap.h",
            root / "src/basic/iterator.h",
        ),
        "iovec_wrapper": (
            root / "src/basic/iovec-wrapper.c",
            root / "src/basic/iovec-wrapper.h",
            root / "src/basic/iovec-util.c",
            root / "src/basic/iovec-util.h",
            root / "src/basic/alloc-util.c",
            root / "src/basic/alloc-util.h",
        ),
        "prioq": (root / "src/basic/prioq.c", root / "src/basic/prioq.h"),
        "image_policy_util": (
            root / "src/shared/image-policy.c",
            root / "src/shared/image-policy.h",
        ),
        "socket_util": (
            root / "src/basic/socket-util.c",
            root / "src/basic/socket-util.h",
        ),
        "sort_util": (
            root / "src/basic/sort-util.c",
            root / "src/basic/sort-util.h",
        ),
        "time_util_conversion": (
            root / "src/basic/time-util.c",
            root / "src/basic/time-util.h",
        ),
        "time_util_formatting": (
            root / "src/basic/time-util.c",
            root / "src/basic/time-util.h",
        ),
        "time_util_parsing": (
            root / "src/basic/time-util.c",
            root / "src/basic/time-util.h",
        ),
        "time_util_arithmetic": (root / "src/basic/time-util.h",),
        "image_name_is_valid": (root / "src/basic/os-util.c",),
        "alloc_util": (
            root / "src/basic/alloc-util.c",
            root / "src/basic/alloc-util.h",
        ),
        "alloc_util_multiply": (root / "src/basic/alloc-util.h",),
        "format_bytes_full": (
            root / "src/basic/format-util.c",
            root / "src/basic/format-util.h",
        ),
        "path_base_predicates": (
            root / "src/basic/path-util.c",
            root / "src/basic/path-util.h",
        ),
        "path_extra_abi": (
            root / "src/basic/path-util.c",
            root / "src/basic/path-util.h",
            root / "src/basic/fd-util.c",
            root / "src/basic/fd-util.h",
        ),
        "escape": (root / "src/basic/escape.c", root / "src/basic/escape.h"),
        "strv_escape_and_fnmatch": (root / "src/basic/strv.c", root / "src/basic/strv.h"),
        "strv_extend_and_filter": (root / "src/basic/strv.c", root / "src/basic/strv.h"),
        "strverscmp": (
            root / "src/fundamental/string-util.c",
            root / "src/fundamental/string-util.h",
        ),
        "strv_base": (
            root / "src/basic/strv.c",
            root / "src/basic/strv.h",
            root / "src/fundamental/strv.h",
        ),
        "strv_registered": (
            root / "src/fundamental/strv.h",
            root / "src/basic/strv.h",
            root / "src/basic/strv.c",
        ),
        "string_mutation_registered": (
            root / "src/basic/string-util.h",
            root / "src/basic/string-util.c",
        ),
        "signal_inline_registered": (
            root / "src/basic/signal-util.h",
            root / "src/basic/signal-util.c",
        ),
        "signal_util_parsing": (
            root / "src/basic/signal-util.c",
            root / "src/basic/signal-util.h",
        ),
        "serialize_deserialization": (
            root / "src/shared/serialize.c",
            root / "src/shared/serialize.h",
        ),
        "udev_util": (root / "src/shared/udev-util.c", root / "src/shared/udev-util.h"),
        "shared_validation_facades": (
            root / "src/shared/boot-entry.c",
            root / "src/shared/boot-entry.h",
            root / "src/shared/color-util.c",
            root / "src/shared/color-util.h",
            root / "src/shared/compare-operator.c",
            root / "src/shared/compare-operator.h",
            root / "src/shared/pkcs11-util.c",
            root / "src/shared/pkcs11-util.h",
            root / "src/shared/user-record.c",
            root / "src/shared/user-record.h",
            root / "src/shared/web-util.c",
            root / "src/shared/web-util.h",
        ),
        "is_device_path": (root / "src/basic/path-util.c", root / "src/basic/path-util.h"),
        "path_byte_abi": (root / "src/basic/path-util.h", root / "src/basic/path-util.c"),
        "utf8_header_inline": (root / "src/basic/utf8.h",),
        "terminal_header_inline": (root / "src/basic/terminal-util.h",),
        "path_header_inline": (root / "src/basic/path-util.h",),
        "gpt_partition_predicates": (root / "src/shared/gpt.c", root / "src/shared/gpt.h"),
        "unit_install_predicates": (root / "src/shared/unit-file.h",),
        "misc_inline_abi": (
            root / "src/basic/devnum-util.h",
            root / "src/basic/format-util.c",
            root / "src/basic/format-util.h",
            root / "src/basic/hexdecoct.c",
            root / "src/basic/hexdecoct.h",
            root / "src/basic/xattr-util.c",
            root / "src/basic/xattr-util.h",
        ),
        "xattr_util": (root / "src/basic/xattr-util.c", root / "src/basic/xattr-util.h"),
        "misc_validator_registered": (
            root / "src/basic/parse-util.c",
            root / "src/basic/parse-util.h",
            root / "src/basic/process-util.c",
            root / "src/basic/process-util.h",
            root / "src/basic/syslog-util.c",
            root / "src/basic/syslog-util.h",
            root / "src/basic/user-util.c",
            root / "src/basic/user-util.h",
            root / "src/shared/bus-print-properties.c",
            root / "src/shared/bus-print-properties.h",
        ),
        "mount_propagation_validator": (
            root / "src/basic/mountpoint-util.c",
            root / "src/basic/mountpoint-util.h",
        ),
        "bus_label": (
            root / "src/basic/bus-label.c",
            root / "src/basic/bus-label.h",
        ),
        "gunicode": (
            root / "src/basic/gunicode.c",
            root / "src/basic/gunicode.h",
        ),
        "efivars_util": (
            root / "src/fundamental/efivars.c",
            root / "src/fundamental/efivars.h",
            root / "src/basic/efivars.c",
            root / "src/basic/efivars.h",
            root / "src/shared/efi-api.c",
            root / "src/shared/efi-api.h",
        ),
        "device_nodes": (
            root / "src/basic/device-nodes.c",
            root / "src/basic/device-nodes.h",
            root / "src/basic/utf8.c",
            root / "src/basic/utf8.h",
        ),
        "mount_setup": (
            root / "src/shared/mount-setup.c",
            root / "src/shared/mount-setup.h",
        ),
        "specifier_util": (
            root / "src/shared/specifier.c",
            root / "src/shared/specifier.h",
            root / "src/shared/efi-loader.c",
            root / "src/shared/efi-loader.h",
        ),
        "btrfs_validate_subvolume_name": (
            root / "src/basic/btrfs-util.c",
            root / "src/basic/btrfs-util.h",
        ),
        "hexdecoct": (root / "src/basic/hexdecoct.c", root / "src/basic/hexdecoct.h"),
        "env_util": (root / "src/basic/env-util.c", root / "src/basic/env-util.h"),
        "credential_validators": (
            root / "src/shared/creds-util.c",
            root / "src/shared/creds-util.h",
        ),
        "namespace_util": (
            root / "src/basic/namespace-util.c",
            root / "src/basic/namespace-util.h",
        ),
        "edid": (
            root / "src/fundamental/edid.c",
            root / "src/fundamental/edid.h",
        ),
        "nsflags": (
            root / "src/shared/nsflags.c",
            root / "src/shared/nsflags.h",
        ),
        "memory_util": (
            root / "src/basic/memory-util.c",
            root / "src/basic/memory-util.h",
            root / "src/fundamental/memory-util.c",
            root / "src/fundamental/memory-util.h",
        ),
        "hostname_util": (
            root / "src/basic/hostname-util.c",
            root / "src/basic/hostname-util.h",
            root / "src/basic/user-util.c",
            root / "src/basic/user-util.h",
            root / "src/basic/string-util.c",
            root / "src/basic/string-util.h",
            root / "src/basic/utf8.c",
            root / "src/basic/utf8.h",
        ),
        "id128_util": (
            root / "src/libsystemd/sd-id128/sd-id128.c",
            root / "src/libsystemd/sd-id128/id128-util.c",
            root / "src/libsystemd/sd-id128/id128-util.h",
            root / "src/systemd/sd-id128.h",
            root / "src/fundamental/sha256.c",
            root / "src/fundamental/sha256.h",
        ),
        "process_util_str_tables": (
            root / "src/basic/process-util.c",
            root / "src/basic/process-util.h",
            root / "src/basic/string-table.c",
            root / "src/basic/string-table.h",
            root / "src/basic/parse-util.c",
            root / "src/basic/parse-util.h",
        ),
        "string_table": (
            root / "src/basic/string-table.c",
            root / "src/basic/string-table.h",
            root / "src/basic/parse-util.c",
            root / "src/basic/parse-util.h",
        ),
        "strxcpyx": (root / "src/basic/strxcpyx.c", root / "src/basic/strxcpyx.h"),
        "terminal_util": (
            root / "src/basic/terminal-util.c",
            root / "src/basic/terminal-util.h",
            root / "src/shared/pretty-print.c",
        ),
        "nulstr_util": (
            root / "src/basic/nulstr-util.c",
            root / "src/basic/nulstr-util.h",
        ),
        "recovery_key": (
            root / "src/shared/recovery-key.c",
            root / "src/shared/recovery-key.h",
        ),
    }
    return BasicFfiReviewCatalog(
        surfaces=surfaces,
        surface_extra_sources=surface_extra_sources,
        partial_surfaces=partial_surfaces,
        partial_extra_sources=partial_extra_sources,
        shadow_tests=shadow_tests,
        partial_shadow_tests=partial_shadow_tests,
        ci_only_shadow_tests=ci_only_shadow_tests,
        c_authorities=c_authorities,
        partial_c_authorities=partial_c_authorities,
    )
