// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bpf-program.c, tpm2-util.c, wifi-util.c

use super::*;

// ── wifi-util: nl80211_iftype (ADHOC=1..NAN=12, UNSPECIFIED=0 has no string) ──

static NL80211_IFTYPE_TABLE: &[(i32, &[u8])] = &[
    (1, b"ad-hoc\0"),
    (2, b"station\0"),
    (3, b"ap\0"),
    (4, b"ap-vlan\0"),
    (5, b"wds\0"),
    (6, b"monitor\0"),
    (7, b"mesh-point\0"),
    (8, b"p2p-client\0"),
    (9, b"p2p-go\0"),
    (10, b"p2p-device\0"),
    (11, b"ocb\0"),
    (12, b"nan\0"),
];

string_table!(
    rs_nl80211_iftype_to_string,
    rs_nl80211_iftype_from_string,
    NL80211_IFTYPE_TABLE
);

// ── netif-sriov: sr_iov_attribute (VF_MAC=0..VF_VLAN_LIST=5, to_string only) ──

static SR_IOV_ATTRIBUTE_TABLE: &[(i32, &[u8])] = &[
    (0, b"MAC address\0"),
    (1, b"spoof check\0"),
    (2, b"RSS query\0"),
    (3, b"trust\0"),
    (4, b"link state\0"),
    (5, b"vlan list\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_sr_iov_attribute_to_string(v: i32) -> *const c_char {
    for &(idx, name) in SR_IOV_ATTRIBUTE_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// ── bpf-program: bpf_cgroup_attach_type (INGRESS=0..SETSOCKOPT=17, gaps at 5,7,17) ──

static BPF_CGROUP_ATTACH_TYPE_TABLE: &[(i32, &[u8])] = &[
    (0, b"ingress\0"),
    (1, b"egress\0"),
    (2, b"sock_create\0"),
    (3, b"sock_ops\0"),
    // 4 = BPF_SK_SKB_STREAM_PARSER (no string)
    // 5 = BPF_SK_SKB_STREAM_VERDICT (no string)
    (6, b"device\0"),
    // 7 = BPF_SK_MSG_VERDICT (no string)
    (8, b"bind4\0"),
    (9, b"bind6\0"),
    (10, b"connect4\0"),
    (11, b"connect6\0"),
    (12, b"post_bind4\0"),
    (13, b"post_bind6\0"),
    (14, b"sendmsg4\0"),
    (15, b"sendmsg6\0"),
    // 16 = BPF_LIRC_MODE2 (no string)
    // 17 = BPF_FLOW_DISSECTOR (no string)
    (18, b"sysctl\0"),
    (19, b"recvmsg4\0"),
    (20, b"recvmsg6\0"),
    (21, b"getsockopt\0"),
    (22, b"setsockopt\0"),
];

string_table!(
    rs_bpf_cgroup_attach_type_to_string,
    rs_bpf_cgroup_attach_type_from_string,
    BPF_CGROUP_ATTACH_TYPE_TABLE
);

// ── tpm2-util: tpm2_userspace_event_type (PHASE=0..OS_SEPARATOR=10) ──

static TPM2_USERSPACE_EVENT_TYPE_TABLE: &[(i32, &[u8])] = &[
    (0, b"phase\0"),
    (1, b"filesystem\0"),
    (2, b"volume-key\0"),
    (3, b"machine-id\0"),
    (4, b"product-id\0"),
    (5, b"keyslot\0"),
    (6, b"nvpcr-init\0"),
    (7, b"nvpcr-separator\0"),
    (8, b"dm-verity\0"),
    (9, b"imds-userdata\0"),
    (10, b"os-separator\0"),
    (11, b"login\0"),
];

string_table!(
    rs_tpm2_userspace_event_type_to_string,
    rs_tpm2_userspace_event_type_from_string,
    TPM2_USERSPACE_EVENT_TYPE_TABLE
);

// ── tpm2-util: tpm2_pcr_index (PLATFORM_CODE=0..APPLICATION_SUPPORT=23, sparse) ──
// DEFINE_STRING_TABLE_LOOKUP_TO_STRING: to_string only (no from_string from this macro)
// DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_FALLBACK: from_string with numeric fallback (0..23)

static TPM2_PCR_INDEX_TABLE: &[(i32, &[u8])] = &[
    (0, b"platform-code\0"),
    (1, b"platform-config\0"),
    (2, b"external-code\0"),
    (3, b"external-config\0"),
    (4, b"boot-loader-code\0"),
    (5, b"boot-loader-config\0"),
    (6, b"host-platform\0"),
    (7, b"secure-boot-policy\0"),
    // 8 = undefined (no string)
    (9, b"kernel-initrd\0"),
    (10, b"ima\0"),
    (11, b"kernel-boot\0"),
    (12, b"kernel-config\0"),
    (13, b"sysexts\0"),
    (14, b"shim-policy\0"),
    (15, b"system-identity\0"),
    (16, b"debug\0"),
    // 17-22 = undefined (no string)
    (23, b"application-support\0"),
];

// to_string: simple lookup (DEFINE_STRING_TABLE_LOOKUP_TO_STRING)
/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_tpm2_pcr_index_to_string(v: i32) -> *const c_char {
    for &(idx, name) in TPM2_PCR_INDEX_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// from_string with numeric fallback (DEFINE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_FALLBACK)
/// C ABI facade. `s` must be null or a valid NUL-terminated C string.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_tpm2_pcr_index_from_string(s: *const c_char) -> i32 {
    // SAFETY: required by this C ABI entry point's contract.
    let Some(input) = (unsafe { input_bytes(s) }) else {
        return Errno::EINVAL.to_neg_errno();
    };
    // Try table lookup first
    if let Some(idx) = from_bytes(TPM2_PCR_INDEX_TABLE, input) {
        return idx;
    }
    // Numeric fallback: 0..TPM2_PCRS_MAX-1
    // SAFETY: the entry point's C-string contract remains valid for the
    // delegated safe_atou-compatible numeric parser.
    if let Some(u) = unsafe { parse_uint(s) }
        && u < TPM2_PCRS_MAX as u32
    {
        return u as i32;
    }
    Errno::EINVAL.to_neg_errno()
}

// ── tpm2-util: hash algorithm size/string/parse ──

const TPM2_ALG_SHA1: u16 = 0x4;
const TPM2_ALG_SHA256: u16 = 0xB;
const TPM2_ALG_SHA384: u16 = 0xC;
const TPM2_ALG_SHA512: u16 = 0xD;
const TPM2_ALG_ECC: u16 = 0x23;
const TPM2_ALG_RSA: u16 = 0x1;
const TPM2_PCRS_MAX: i32 = 24;

/// Shadow of C tpm2_hash_alg_to_size()
/// C ABI facade. Accepts a TPM algorithm identifier.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_tpm2_hash_alg_to_size(alg: u16) -> i32 {
    match alg {
        TPM2_ALG_SHA1 => 20,
        TPM2_ALG_SHA256 => 32,
        TPM2_ALG_SHA384 => 48,
        TPM2_ALG_SHA512 => 64,
        _ => Errno::EINVAL.to_neg_errno(),
    }
}

/// Shadow of C tpm2_hash_alg_to_string()
/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_tpm2_hash_alg_to_string(alg: u16) -> *const c_char {
    match alg {
        TPM2_ALG_SHA1 => static_cstr_ptr(b"sha1\0"),
        TPM2_ALG_SHA256 => static_cstr_ptr(b"sha256\0"),
        TPM2_ALG_SHA384 => static_cstr_ptr(b"sha384\0"),
        TPM2_ALG_SHA512 => static_cstr_ptr(b"sha512\0"),
        _ => std::ptr::null(),
    }
}

/// Shadow of C tpm2_hash_alg_from_string()
/// C ABI facade. `alg` must be null or a valid NUL-terminated C string.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_tpm2_hash_alg_from_string(alg: *const c_char) -> i32 {
    // SAFETY: the caller guarantees alg is null or a live NUL-terminated C string.
    if unsafe { cstr_eq_ignore_ascii_case_static(alg, b"sha1\0") } {
        return TPM2_ALG_SHA1 as i32;
    }
    // SAFETY: as above.
    if unsafe { cstr_eq_ignore_ascii_case_static(alg, b"sha256\0") } {
        return TPM2_ALG_SHA256 as i32;
    }
    // SAFETY: as above.
    if unsafe { cstr_eq_ignore_ascii_case_static(alg, b"sha384\0") } {
        return TPM2_ALG_SHA384 as i32;
    }
    // SAFETY: as above.
    if unsafe { cstr_eq_ignore_ascii_case_static(alg, b"sha512\0") } {
        return TPM2_ALG_SHA512 as i32;
    }
    Errno::EINVAL.to_neg_errno()
}

// ── tpm2-util: asymmetric algorithm string/parse ──

/// Shadow of C tpm2_asym_alg_to_string()
/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_tpm2_asym_alg_to_string(alg: u16) -> *const c_char {
    match alg {
        TPM2_ALG_ECC => static_cstr_ptr(b"ecc\0"),
        TPM2_ALG_RSA => static_cstr_ptr(b"rsa\0"),
        _ => std::ptr::null(),
    }
}

/// Shadow of C tpm2_asym_alg_from_string()
/// C ABI facade. `alg` must be null or a valid NUL-terminated C string.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_tpm2_asym_alg_from_string(alg: *const c_char) -> i32 {
    // SAFETY: the caller guarantees alg is null or a live NUL-terminated C string.
    if unsafe { cstr_eq_ignore_ascii_case_static(alg, b"ecc\0") } {
        return TPM2_ALG_ECC as i32;
    }
    // SAFETY: as above.
    if unsafe { cstr_eq_ignore_ascii_case_static(alg, b"rsa\0") } {
        return TPM2_ALG_RSA as i32;
    }
    Errno::EINVAL.to_neg_errno()
}

// ── tpm2-util: pcr_mask_to_string ──

/// Shadow of C tpm2_pcr_mask_to_string()
/// Converts a uint32 bitmask of PCR indices to a "0+1+2+..." string.
/// Returns NULL on OOM, empty string "" for mask==0.
/// C ABI facade. Returned storage is allocated with the C allocator and must be freed by C.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_tpm2_pcr_mask_to_string(mask: u32) -> *mut c_char {
    if mask == 0 {
        // SAFETY: the source is immutable static NUL-terminated storage.
        return unsafe { rust_strdup(static_cstr_ptr(b"\0")) };
    }

    // Count set bits to estimate output size (each PCR index <= 2 digits + '+' separator)
    let n_bits = mask.count_ones() as usize;
    // Max: "23+23+23+..." = 3*n_bits chars + NUL
    let alloc_size = 3 * n_bits + 1;
    // SAFETY: malloc accepts the bounded allocation size derived from a u32 bit count.
    let buf = malloc(alloc_size) as *mut u8;
    if buf.is_null() {
        return std::ptr::null_mut();
    }

    let mut j: usize = 0;
    let mut first = true;
    let mut m = mask;
    while m != 0 {
        let bit = m.trailing_zeros();
        m &= !(1u32 << bit);

        if !first {
            // SAFETY: j remains below alloc_size by the 3*n_bits+1 bound.
            unsafe { *buf.add(j) = b'+' };
            j += 1;
        }
        first = false;

        // Convert bit (0..23) to decimal string
        let mut digits: [u8; 3] = [0; 3];
        let mut n_digits = 0usize;
        let mut v = bit;
        loop {
            digits[n_digits] = b'0' + (v % 10) as u8;
            n_digits += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        // Digits are reversed, copy them in reverse order
        for k in (0..n_digits).rev() {
            // SAFETY: j remains below alloc_size by the 3*n_bits+1 bound.
            unsafe { *buf.add(j) = digits[k] };
            j += 1;
        }
    }
    // SAFETY: alloc_size reserves the final NUL after every encoded index.
    unsafe { *buf.add(j) = 0 };
    buf.cast::<c_char>()
}

// ── tpm2-util: nvpcr_name_is_valid ──

/// Shadow of C tpm2_nvpcr_name_is_valid()
/// A valid NV PCR name must be a valid filename, contain only safe chars,
/// and NOT be parseable as a PCR index name.
/// C ABI facade. `name` must be null or a valid NUL-terminated C string.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_tpm2_nvpcr_name_is_valid(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }
    // filename_is_valid
    // SAFETY: the caller guarantees name is a live NUL-terminated C string.
    if !unsafe { crate::path_util::rs_filename_is_valid(name) } {
        return false;
    }
    // string_is_safe
    // SAFETY: the same caller contract applies to the string validator.
    if !unsafe { crate::string_util::rs_string_is_safe(name) } {
        return false;
    }
    // Must NOT be a valid PCR index name
    // SAFETY: the same caller contract applies to the PCR parser.
    if unsafe { rs_tpm2_pcr_index_from_string(name) } >= 0 {
        return false;
    }
    true
}

// ── wifi-util: nl80211_cmd (GET_WIPHY=1..COLOR_CHANGE_COMPLETED=145, TO_STRING only) ──

static NL80211_CMD_TABLE: &[(i32, &[u8])] = &[
    (1, b"get_wiphy\0"),
    (2, b"set_wiphy\0"),
    (3, b"new_wiphy\0"),
    (4, b"del_wiphy\0"),
    (5, b"get_interface\0"),
    (6, b"set_interface\0"),
    (7, b"new_interface\0"),
    (8, b"del_interface\0"),
    (9, b"get_key\0"),
    (10, b"set_key\0"),
    (11, b"new_key\0"),
    (12, b"del_key\0"),
    (13, b"get_beacon\0"),
    (14, b"set_beacon\0"),
    (15, b"start_ap\0"),
    (16, b"stop_ap\0"),
    (17, b"get_station\0"),
    (18, b"set_station\0"),
    (19, b"new_station\0"),
    (20, b"del_station\0"),
    (21, b"get_mpath\0"),
    (22, b"set_mpath\0"),
    (23, b"new_mpath\0"),
    (24, b"del_mpath\0"),
    (25, b"set_bss\0"),
    (26, b"set_reg\0"),
    (27, b"req_set_reg\0"),
    (28, b"get_mesh_config\0"),
    (29, b"set_mesh_config\0"),
    (30, b"set_mgmt_extra_ie\0"),
    (31, b"get_reg\0"),
    (32, b"get_scan\0"),
    (33, b"trigger_scan\0"),
    (34, b"new_scan_results\0"),
    (35, b"scan_aborted\0"),
    (36, b"reg_change\0"),
    (37, b"authenticate\0"),
    (38, b"associate\0"),
    (39, b"deauthenticate\0"),
    (40, b"disassociate\0"),
    (41, b"michael_mic_failure\0"),
    (42, b"reg_beacon_hint\0"),
    (43, b"join_ibss\0"),
    (44, b"leave_ibss\0"),
    (45, b"testmode\0"),
    (46, b"connect\0"),
    (47, b"roam\0"),
    (48, b"disconnect\0"),
    (49, b"set_wiphy_netns\0"),
    (50, b"get_survey\0"),
    (51, b"new_survey_results\0"),
    (52, b"set_pmksa\0"),
    (53, b"del_pmksa\0"),
    (54, b"flush_pmksa\0"),
    (55, b"remain_on_channel\0"),
    (56, b"cancel_remain_on_channel\0"),
    (57, b"set_tx_bitrate_mask\0"),
    (58, b"register_frame\0"),
    (59, b"frame\0"),
    (60, b"frame_tx_status\0"),
    (61, b"set_power_save\0"),
    (62, b"get_power_save\0"),
    (63, b"set_cqm\0"),
    (64, b"notify_cqm\0"),
    (65, b"set_channel\0"),
    (66, b"set_wds_peer\0"),
    (67, b"frame_wait_cancel\0"),
    (68, b"join_mesh\0"),
    (69, b"leave_mesh\0"),
    (70, b"unprot_deauthenticate\0"),
    (71, b"unprot_disassociate\0"),
    (72, b"new_peer_candidate\0"),
    (73, b"get_wowlan\0"),
    (74, b"set_wowlan\0"),
    (75, b"start_sched_scan\0"),
    (76, b"stop_sched_scan\0"),
    (77, b"sched_scan_results\0"),
    (78, b"sched_scan_stopped\0"),
    (79, b"set_rekey_offload\0"),
    (80, b"pmksa_candidate\0"),
    (81, b"tdls_oper\0"),
    (82, b"tdls_mgmt\0"),
    (83, b"unexpected_frame\0"),
    (84, b"probe_client\0"),
    (85, b"register_beacons\0"),
    (86, b"unexpected_4addr_frame\0"),
    (87, b"set_noack_map\0"),
    (88, b"ch_switch_notify\0"),
    (89, b"start_p2p_device\0"),
    (90, b"stop_p2p_device\0"),
    (91, b"conn_failed\0"),
    (92, b"set_mcast_rate\0"),
    (93, b"set_mac_acl\0"),
    (94, b"radar_detect\0"),
    (95, b"get_protocol_features\0"),
    (96, b"update_ft_ies\0"),
    (97, b"ft_event\0"),
    (98, b"crit_protocol_start\0"),
    (99, b"crit_protocol_stop\0"),
    (100, b"get_coalesce\0"),
    (101, b"set_coalesce\0"),
    (102, b"channel_switch\0"),
    (103, b"vendor\0"),
    (104, b"set_qos_map\0"),
    (105, b"add_tx_ts\0"),
    (106, b"del_tx_ts\0"),
    (107, b"get_mpp\0"),
    (108, b"join_ocb\0"),
    (109, b"leave_ocb\0"),
    (110, b"ch_switch_started_notify\0"),
    (111, b"tdls_channel_switch\0"),
    (112, b"tdls_cancel_channel_switch\0"),
    (113, b"wiphy_reg_change\0"),
    (114, b"abort_scan\0"),
    (115, b"start_nan\0"),
    (116, b"stop_nan\0"),
    (117, b"add_nan_function\0"),
    (118, b"del_nan_function\0"),
    (119, b"change_nan_config\0"),
    (120, b"nan_match\0"),
    (121, b"set_multicast_to_unicast\0"),
    (122, b"update_connect_params\0"),
    (123, b"set_pmk\0"),
    (124, b"del_pmk\0"),
    (125, b"port_authorized\0"),
    (126, b"reload_regdb\0"),
    (127, b"external_auth\0"),
    (128, b"sta_opmode_changed\0"),
    (129, b"control_port_frame\0"),
    (130, b"get_ftm_responder_stats\0"),
    (131, b"peer_measurement_start\0"),
    (132, b"peer_measurement_result\0"),
    (133, b"peer_measurement_complete\0"),
    (134, b"notify_radar\0"),
    (135, b"update_owe_info\0"),
    (136, b"probe_mesh_link\0"),
    (137, b"set_tid_config\0"),
    (138, b"unprot_beacon\0"),
    (139, b"control_port_frame_tx_status\0"),
    (140, b"set_sar_specs\0"),
    (141, b"obss_color_collision\0"),
    (142, b"color_change_request\0"),
    (143, b"color_change_started\0"),
    (144, b"color_change_aborted\0"),
    (145, b"color_change_completed\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_nl80211_cmd_to_string(v: i32) -> *const c_char {
    for &(idx, name) in NL80211_CMD_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}
