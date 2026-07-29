// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: multi-source shadow. Source ownership is grouped in
//            src/shared/rust/netdev_str_tables.h and includes basic/, shared/,
//            resolve/, and network/ string-table subsets. Every group must be
//            checked against its current named C source before changing data.
//
// ABI facade for a multi-source string-table shadow. Domain modules own their
// tables; this file owns only the shared lookup machinery and exceptional ABI
// adapters that cannot be expressed as a table pair.

use crate::ffi::Errno;
use libc::c_char;
use std::ffi::c_void;

#[path = "netdev_str_tables/core.rs"]
mod table_core;

use table_core::{from_bytes, input_bytes, static_cstr, static_cstr_ptr};

#[inline]
#[cfg(test)]
// SAFETY: `s` must be a live NUL-terminated C string; `table_entry` is static
// NUL-terminated table storage.
unsafe fn cstr_eq_static(s: *const c_char, table_entry: &'static [u8]) -> bool {
    // SAFETY: propagated from the caller; this is the sole inbound C-string
    // borrow used by the table facade.
    unsafe { input_bytes(s) }.is_some_and(|input| input == static_cstr(table_entry).to_bytes())
}

#[inline]
// SAFETY: `s` must be a live NUL-terminated C string; `table_entry` is static
// NUL-terminated table storage.
unsafe fn cstr_eq_ignore_ascii_case_static(s: *const c_char, table_entry: &'static [u8]) -> bool {
    // SAFETY: propagated from the caller; see `table_core::input_bytes`.
    unsafe { input_bytes(s) }
        .is_some_and(|input| input.eq_ignore_ascii_case(static_cstr(table_entry).to_bytes()))
}

/// Generates a pair of FFI functions for a string table lookup:
/// - `rs_<to_fn>(v: i32) -> *const c_char` — returns a NUL-terminated string
///   for the given enum value, or NULL if not found.
/// - `rs_<from_fn>(s: *const c_char) -> i32` — returns the enum value for
///   the given NUL-terminated string, or -EINVAL if not found or input is NULL.
macro_rules! string_table {
    ($to_fn:ident, $from_fn:ident, $table:expr) => {
        #[doc = "C ABI facade. Returns a borrowed static string or NULL for an unknown value."]
        #[unsafe(no_mangle)]
        ///
        /// # Safety
        /// Every non-null input pointer must be valid and properly aligned for all
        /// reads performed by this call, and every non-null output pointer must be
        /// valid and properly aligned for all writes. Pointer ranges must not alias
        /// in ways forbidden by the operation's documented ownership contract.
        /// C-string inputs must remain NUL-terminated and live for the call.
        pub unsafe extern "C" fn $to_fn(v: i32) -> *const c_char {
            table_core::to_cstr($table, v).map_or(std::ptr::null(), |name| name.as_ptr())
        }

        #[doc = "C ABI facade. `s` must be null or a valid NUL-terminated C string."]
        #[unsafe(no_mangle)]
        ///
        /// # Safety
        /// Every non-null input pointer must be valid and properly aligned for all
        /// reads performed by this call, and every non-null output pointer must be
        /// valid and properly aligned for all writes. Pointer ranges must not alias
        /// in ways forbidden by the operation's documented ownership contract.
        /// C-string inputs must remain NUL-terminated and live for the call.
        pub unsafe extern "C" fn $from_fn(s: *const c_char) -> i32 {
            // SAFETY: required by this C ABI entry point's contract.
            unsafe { input_bytes(s) }
                .and_then(|input| from_bytes($table, input))
                .unwrap_or_else(|| Errno::EINVAL.to_neg_errno())
        }
    };
}

mod network_link;
pub use network_link::*;
mod network_virtual;
pub use network_virtual::*;
mod boot_import;
pub use boot_import::*;

// ── coredump_filter: PRIVATE_ANONYMOUS=0..SHARED_DAX=8 ───────────────────

static COREDUMP_FILTER_TABLE: &[(i32, &[u8])] = &[
    (0, b"private-anonymous\0"),
    (1, b"shared-anonymous\0"),
    (2, b"private-file-backed\0"),
    (3, b"shared-file-backed\0"),
    (4, b"elf-headers\0"),
    (5, b"private-huge\0"),
    (6, b"shared-huge\0"),
    (7, b"private-dax\0"),
    (8, b"shared-dax\0"),
];

string_table!(
    rs_coredump_filter_to_string,
    rs_coredump_filter_from_string,
    COREDUMP_FILTER_TABLE
);

// ── coredump_filter_mask_from_string ─────────────────────────────────────

/// Shadow of C coredump_filter_mask_from_string()
/// Parses a space-separated list of coredump filter names, "default", "all", or hex values.
/// C ABI facade. `s` and `ret` must be valid for the duration of this call.
#[unsafe(no_mangle)]
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe extern "C" fn rs_coredump_filter_mask_from_string(
    s: *const c_char,
    ret: *mut u64,
) -> i32 {
    if s.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut mask: u64 = 0;
    let mut pos = s;

    loop {
        let mut word: *mut c_char = std::ptr::null_mut();
        // SAFETY: `pos` initially comes from the caller's live C string and is
        // subsequently advanced only by `rs_extract_first_word`; `word` is a
        // writable output slot owned by this stack frame.
        let r = unsafe {
            crate::extract_word::rs_extract_first_word(&mut pos, &mut word, std::ptr::null(), 0)
        };
        if r < 0 {
            return r;
        }
        if r == 0 {
            break;
        }

        // SAFETY: `rs_extract_first_word` returned a live, NUL-terminated
        // allocation when it returned a positive value above.
        let Some(w) = (unsafe { input_bytes(word) }) else {
            // SAFETY: `rs_extract_first_word` returned an owned C allocation.
            unsafe { crate::ffi::free(word as *mut c_void) };
            return Errno::EINVAL.to_neg_errno();
        };

        if w == b"default" {
            mask |= (1u64 << 0) | (1u64 << 1) | (1u64 << 4) | (1u64 << 5);
            // SAFETY: `rs_extract_first_word` returned an owned C allocation.
            unsafe { crate::ffi::free(word as *mut c_void) };
            continue;
        }

        if w == b"all" {
            mask = u32::MAX as u64;
            // SAFETY: `rs_extract_first_word` returned an owned C allocation.
            unsafe { crate::ffi::free(word as *mut c_void) };
            continue;
        }

        // Try named filter (word still alive)
        // SAFETY: a positive `rs_extract_first_word` result supplied `word` as
        // a live NUL-terminated allocation, which remains owned here.
        let named = unsafe { rs_coredump_filter_from_string(word) };
        if named >= 0 {
            mask |= 1u64 << named;
            // SAFETY: `rs_extract_first_word` returned an owned C allocation.
            unsafe { crate::ffi::free(word as *mut c_void) };
            continue;
        }

        // Try hex value (word still alive)
        let mut x: u64 = 0;
        // SAFETY: `word` is still a live NUL-terminated allocation and `x` is
        // a writable output local.
        let hr = unsafe { crate::parse_util::rs_safe_atoux64(word.cast::<libc::c_char>(), &mut x) };
        // SAFETY: `rs_extract_first_word` returned an owned C allocation.
        unsafe { crate::ffi::free(word as *mut c_void) };
        if hr < 0 {
            return hr;
        }

        mask |= x;
    }

    // SAFETY: `ret` was checked non-null above and is writable by the caller
    // contract.
    unsafe { *ret = mask };
    0
}

// ── sleep_operation: SUSPEND=0, HIBERNATE=1, HYBRID_SLEEP=2, SUSPEND_THEN_HIBERNATE=4 ──

static SLEEP_OPERATION_TABLE: &[(i32, &[u8])] = &[
    (0, b"suspend\0"),
    (1, b"hibernate\0"),
    (2, b"hybrid-sleep\0"),
    (4, b"suspend-then-hibernate\0"),
];

string_table!(
    rs_sleep_operation_to_string,
    rs_sleep_operation_from_string,
    SLEEP_OPERATION_TABLE
);

// ── factory_reset_mode: UNSUPPORTED=0..PENDING=5 ────────────────────────

static FACTORY_RESET_MODE_TABLE: &[(i32, &[u8])] = &[
    (0, b"unsupported\0"),
    (1, b"unspecified\0"),
    (2, b"off\0"),
    (3, b"on\0"),
    (4, b"complete\0"),
    (5, b"pending\0"),
];

string_table!(
    rs_factory_reset_mode_to_string,
    rs_factory_reset_mode_from_string,
    FACTORY_RESET_MODE_TABLE
);

// ── hostname_source: STATIC=0, TRANSIENT=1, DEFAULT=2 ───────────────────

static HOSTNAME_SOURCE_TABLE: &[(i32, &[u8])] =
    &[(0, b"static\0"), (1, b"transient\0"), (2, b"default\0")];

string_table!(
    rs_hostname_source_to_string,
    rs_hostname_source_from_string,
    HOSTNAME_SOURCE_TABLE
);

// ── mpol: DEFAULT=0..WEIGHTED_INTERLEAVE=6 ──────────────────────────────

static MPOL_TABLE: &[(i32, &[u8])] = &[
    (0, b"default\0"),
    (1, b"preferred\0"),
    (2, b"bind\0"),
    (3, b"interleave\0"),
    (4, b"local\0"),
    (5, b"preferred-many\0"),
    (6, b"weighted-interleave\0"),
];

string_table!(rs_mpol_to_string, rs_mpol_from_string, MPOL_TABLE);

// ── output_mode: SHORT=0..WITH_UNIT=14 ─────────────────────────────────

static OUTPUT_MODE_TABLE: &[(i32, &[u8])] = &[
    (0, b"short\0"),
    (1, b"short-full\0"),
    (2, b"short-iso\0"),
    (3, b"short-iso-precise\0"),
    (4, b"short-precise\0"),
    (5, b"short-monotonic\0"),
    (6, b"short-delta\0"),
    (7, b"short-unix\0"),
    (8, b"verbose\0"),
    (9, b"export\0"),
    (10, b"json\0"),
    (11, b"json-pretty\0"),
    (12, b"json-sse\0"),
    (13, b"json-seq\0"),
    (14, b"cat\0"),
    (15, b"with-unit\0"),
];

string_table!(
    rs_output_mode_to_string,
    rs_output_mode_from_string,
    OUTPUT_MODE_TABLE
);

// ── volatile_mode: NO=0, YES=1, STATE=2, OVERLAY=3 ─────────────────────

static VOLATILE_MODE_TABLE: &[(i32, &[u8])] = &[
    (0, b"no\0"),
    (1, b"yes\0"),
    (2, b"state\0"),
    (3, b"overlay\0"),
];

string_table!(
    rs_volatile_mode_to_string,
    rs_volatile_mode_from_string,
    VOLATILE_MODE_TABLE
);

// ── unit_file_state: ENABLED=0..BAD=12 ─────────────────────────────────

static UNIT_FILE_STATE_TABLE: &[(i32, &[u8])] = &[
    (0, b"enabled\0"),
    (1, b"enabled-runtime\0"),
    (2, b"linked\0"),
    (3, b"linked-runtime\0"),
    (4, b"alias\0"),
    (5, b"masked\0"),
    (6, b"masked-runtime\0"),
    (7, b"static\0"),
    (8, b"disabled\0"),
    (9, b"indirect\0"),
    (10, b"generated\0"),
    (11, b"transient\0"),
    (12, b"bad\0"),
];

string_table!(
    rs_unit_file_state_to_string,
    rs_unit_file_state_from_string,
    UNIT_FILE_STATE_TABLE
);

// ── preset_action_past_tense: UNKNOWN=0..IGNORED=3 (to_string only) ──

static PRESET_ACTION_PAST_TENSE_TABLE: &[(i32, &[u8])] = &[
    (0, b"unknown\0"),
    (1, b"enabled\0"),
    (2, b"disabled\0"),
    (3, b"ignored\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
#[unsafe(no_mangle)]
pub extern "C" fn rs_preset_action_past_tense_to_string(v: i32) -> *const c_char {
    for &(idx, name) in PRESET_ACTION_PAST_TENSE_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// ── image_type: DIRECTORY=0..MSTACK=4 ─────────────────────────────────

static IMAGE_TYPE_TABLE: &[(i32, &[u8])] = &[
    (0, b"directory\0"),
    (1, b"subvolume\0"),
    (2, b"raw\0"),
    (3, b"block\0"),
    (4, b"mstack\0"),
];

string_table!(
    rs_image_type_to_string,
    rs_image_type_from_string,
    IMAGE_TYPE_TABLE
);

// ── kernel_image_type: UNKNOWN=0..PE=3 (to_string only) ───────────────

static KERNEL_IMAGE_TYPE_TABLE: &[(i32, &[u8])] = &[
    (0, b"unknown\0"),
    (1, b"uki\0"),
    (2, b"addon\0"),
    (3, b"pe\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
#[unsafe(no_mangle)]
pub extern "C" fn rs_kernel_image_type_to_string(v: i32) -> *const c_char {
    for &(idx, name) in KERNEL_IMAGE_TYPE_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// ── open_file_flags: READ_ONLY=1, APPEND=2, TRUNCATE=4, GRACEFUL=8 ───

static OPEN_FILE_FLAGS_TABLE: &[(i32, &[u8])] = &[
    (1, b"read-only\0"),
    (2, b"append\0"),
    (4, b"truncate\0"),
    (8, b"graceful\0"),
];

string_table!(
    rs_open_file_flags_to_string,
    rs_open_file_flags_from_string,
    OPEN_FILE_FLAGS_TABLE
);

// ── socket_address_bind_ipv6_only: DEFAULT=0, BOTH=1, IPV6_ONLY=2 ──

static SOCKET_ADDRESS_BIND_IPV6_ONLY_TABLE: &[(i32, &[u8])] =
    &[(0, b"default\0"), (1, b"both\0"), (2, b"ipv6-only\0")];

string_table!(
    rs_socket_address_bind_ipv6_only_to_string,
    rs_socket_address_bind_ipv6_only_from_string,
    SOCKET_ADDRESS_BIND_IPV6_ONLY_TABLE
);

// ── metric_family_type: COUNTER=0..OBJECT=3 (to_string only) ─────────

static METRIC_FAMILY_TYPE_TABLE: &[(i32, &[u8])] = &[
    (0, b"counter\0"),
    (1, b"gauge\0"),
    (2, b"string\0"),
    (3, b"object\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
#[unsafe(no_mangle)]
pub extern "C" fn rs_metric_family_type_to_string(v: i32) -> *const c_char {
    for &(idx, name) in METRIC_FAMILY_TYPE_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// ── mstack_mount_type: ROOT=0..ROBIND=4 (to_string only) ───────────

static MSTACK_MOUNT_TYPE_TABLE: &[(i32, &[u8])] = &[
    (0, b"root\0"),
    (1, b"layer\0"),
    (2, b"rw\0"),
    (3, b"bind\0"),
    (4, b"robind\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
#[unsafe(no_mangle)]
pub extern "C" fn rs_mstack_mount_type_to_string(v: i32) -> *const c_char {
    for &(idx, name) in MSTACK_MOUNT_TYPE_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// ── bus_transport: LOCAL=0..CAPSULE=3 (to_string only) ───────────────

static BUS_TRANSPORT_TABLE: &[(i32, &[u8])] = &[
    (0, b"local\0"),
    (1, b"remote\0"),
    (2, b"machine\0"),
    (3, b"capsule\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
#[unsafe(no_mangle)]
pub extern "C" fn rs_bus_transport_to_string(v: i32) -> *const c_char {
    for &(idx, name) in BUS_TRANSPORT_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// ── user_storage: CLASSIC=0..CIFS=5 ───────────────────────────────────

static USER_STORAGE_TABLE: &[(i32, &[u8])] = &[
    (0, b"classic\0"),
    (1, b"luks\0"),
    (2, b"directory\0"),
    (3, b"subvolume\0"),
    (4, b"fscrypt\0"),
    (5, b"cifs\0"),
];

string_table!(
    rs_user_storage_to_string,
    rs_user_storage_from_string,
    USER_STORAGE_TABLE
);

// ── user_disposition: INTRINSIC=0..RESERVED=6 ─────────────────────────

static USER_DISPOSITION_TABLE: &[(i32, &[u8])] = &[
    (0, b"intrinsic\0"),
    (1, b"system\0"),
    (2, b"dynamic\0"),
    (3, b"regular\0"),
    (4, b"container\0"),
    (5, b"foreign\0"),
    (6, b"reserved\0"),
];

string_table!(
    rs_user_disposition_to_string,
    rs_user_disposition_from_string,
    USER_DISPOSITION_TABLE
);

// ── auto_resize_mode: OFF=0, GROW=1, SHRINK_AND_GROW=2 ────────────────

static AUTO_RESIZE_MODE_TABLE: &[(i32, &[u8])] =
    &[(0, b"off\0"), (1, b"grow\0"), (2, b"shrink-and-grow\0")];

string_table!(
    rs_auto_resize_mode_to_string,
    rs_auto_resize_mode_from_string,
    AUTO_RESIZE_MODE_TABLE
);

// ── partition_designator: ROOT=0..VAR=12 ───────────────────────────────

static PARTITION_DESIGNATOR_TABLE: &[(i32, &[u8])] = &[
    (0, b"root\0"),
    (1, b"usr\0"),
    (2, b"home\0"),
    (3, b"srv\0"),
    (4, b"esp\0"),
    (5, b"xbootldr\0"),
    (6, b"swap\0"),
    (7, b"root-verity\0"),
    (8, b"usr-verity\0"),
    (9, b"root-verity-sig\0"),
    (10, b"usr-verity-sig\0"),
    (11, b"tmp\0"),
    (12, b"var\0"),
];

string_table!(
    rs_partition_designator_to_string,
    rs_partition_designator_from_string,
    PARTITION_DESIGNATOR_TABLE
);

// ── name_policy: KERNEL=0..MAC=6 ──────────────────────────────────────

static NAME_POLICY_TABLE: &[(i32, &[u8])] = &[
    (0, b"kernel\0"),
    (1, b"keep\0"),
    (2, b"database\0"),
    (3, b"onboard\0"),
    (4, b"slot\0"),
    (5, b"path\0"),
    (6, b"mac\0"),
];

string_table!(
    rs_name_policy_to_string,
    rs_name_policy_from_string,
    NAME_POLICY_TABLE
);

// ── alternative_names_policy: DATABASE=2..MAC=6 ────────────────────────

static ALTERNATIVE_NAMES_POLICY_TABLE: &[(i32, &[u8])] = &[
    (2, b"database\0"),
    (3, b"onboard\0"),
    (4, b"slot\0"),
    (5, b"path\0"),
    (6, b"mac\0"),
];

string_table!(
    rs_alternative_names_policy_to_string,
    rs_alternative_names_policy_from_string,
    ALTERNATIVE_NAMES_POLICY_TABLE
);

// ── condition_result: UNTESTED=0..ERROR=3 ─────────────────────────────

static CONDITION_RESULT_TABLE: &[(i32, &[u8])] = &[
    (0, b"untested\0"),
    (1, b"succeeded\0"),
    (2, b"failed\0"),
    (3, b"error\0"),
];

string_table!(
    rs_condition_result_to_string,
    rs_condition_result_from_string,
    CONDITION_RESULT_TABLE
);

// ── Helper: parse_boolean (returns 1, 0, or negative errno) ─────────────

fn parse_boolean(v: &[u8]) -> i32 {
    if [b"1".as_slice(), b"yes", b"y", b"true", b"t", b"on"]
        .iter()
        .any(|candidate| v.eq_ignore_ascii_case(candidate))
    {
        return 1;
    }
    if [b"0".as_slice(), b"no", b"n", b"false", b"f", b"off"]
        .iter()
        .any(|candidate| v.eq_ignore_ascii_case(candidate))
    {
        return 0;
    }
    Errno::EINVAL.to_neg_errno()
}

// ── Macro for WITH_BOOLEAN tables ────────────────────────────────────────

/// Like `string_table!` but with boolean parsing support. When the input
/// string is a recognized boolean value ("yes", "no", etc.), returns the
/// `$yes` enum value for truthy inputs or 0 for falsy inputs.
macro_rules! string_table_boolean {
    ($to_fn:ident, $from_fn:ident, $table:expr, $yes:expr) => {
        #[doc = "C ABI facade. Returns a borrowed static string or NULL for an unknown value."]
        #[unsafe(no_mangle)]
        ///
        /// # Safety
        /// Every non-null input pointer must be valid and properly aligned for all
        /// reads performed by this call, and every non-null output pointer must be
        /// valid and properly aligned for all writes. Pointer ranges must not alias
        /// in ways forbidden by the operation's documented ownership contract.
        /// C-string inputs must remain NUL-terminated and live for the call.
        pub unsafe extern "C" fn $to_fn(v: i32) -> *const c_char {
            table_core::to_cstr($table, v).map_or(std::ptr::null(), |name| name.as_ptr())
        }

        #[doc = "C ABI facade. `s` must be null or a valid NUL-terminated C string."]
        #[unsafe(no_mangle)]
        ///
        /// # Safety
        /// Every non-null input pointer must be valid and properly aligned for all
        /// reads performed by this call, and every non-null output pointer must be
        /// valid and properly aligned for all writes. Pointer ranges must not alias
        /// in ways forbidden by the operation's documented ownership contract.
        /// C-string inputs must remain NUL-terminated and live for the call.
        pub unsafe extern "C" fn $from_fn(s: *const c_char) -> i32 {
            // SAFETY: required by this C ABI entry point's contract.
            let Some(input) = (unsafe { input_bytes(s) }) else {
                return Errno::EINVAL.to_neg_errno();
            };
            let b = parse_boolean(input);
            if b == 0 {
                return 0;
            }
            if b > 0 {
                return $yes;
            }
            from_bytes($table, input).unwrap_or_else(|| Errno::EINVAL.to_neg_errno())
        }
    };
}

mod resolve_modes;
pub use resolve_modes::*;

// ── firewall-util: nfproto (ARP=3, BRIDGE=7, INET=1, IPV4=2, IPV6=10, NETDEV=5) ──

static NFPROTO_TABLE: &[(i32, &[u8])] = &[
    (3, b"arp\0"),
    (7, b"bridge\0"),
    (1, b"inet\0"),
    (2, b"ip\0"),
    (10, b"ip6\0"),
    (5, b"netdev\0"),
];

string_table!(rs_nfproto_to_string, rs_nfproto_from_string, NFPROTO_TABLE);

// ── firewall-util: nft_set_source (ADDRESS=0..GROUP=5) ──

static NFT_SET_SOURCE_TABLE: &[(i32, &[u8])] = &[
    (0, b"address\0"),
    (1, b"prefix\0"),
    (2, b"ifindex\0"),
    (3, b"cgroup\0"),
    (4, b"user\0"),
    (5, b"group\0"),
];

string_table!(
    rs_nft_set_source_to_string,
    rs_nft_set_source_from_string,
    NFT_SET_SOURCE_TABLE
);

// ── install: install_change_type (SYMLINK=0..AUXILIARY_FAILED=6) ──

static INSTALL_CHANGE_TYPE_TABLE: &[(i32, &[u8])] = &[
    (0, b"symlink\0"),
    (1, b"unlink\0"),
    (2, b"masked\0"),
    (3, b"masked by generator\0"),
    (4, b"dangling\0"),
    (5, b"destination not present\0"),
    (6, b"auxiliary unit failed\0"),
];

string_table!(
    rs_install_change_type_to_string,
    rs_install_change_type_from_string,
    INSTALL_CHANGE_TYPE_TABLE
);

// ── install: unit_file_preset_mode (FULL=0, ENABLE_ONLY=1, DISABLE_ONLY=2) ──

static UNIT_FILE_PRESET_MODE_TABLE: &[(i32, &[u8])] = &[
    (0, b"full\0"),
    (1, b"enable-only\0"),
    (2, b"disable-only\0"),
];

string_table!(
    rs_unit_file_preset_mode_to_string,
    rs_unit_file_preset_mode_from_string,
    UNIT_FILE_PRESET_MODE_TABLE
);

// ── bootspec: boot_entry_type (TYPE1=0..AUTO=3) ──

static BOOT_ENTRY_TYPE_TABLE: &[(i32, &[u8])] = &[
    (0, b"type1\0"),
    (1, b"type2\0"),
    (2, b"loader\0"),
    (3, b"auto\0"),
];

string_table!(
    rs_boot_entry_type_to_string,
    rs_boot_entry_type_from_string,
    BOOT_ENTRY_TYPE_TABLE
);

// ── bootspec: boot_entry_type_description (TYPE1=0..AUTO=3, to_string only) ──

static BOOT_ENTRY_TYPE_DESCRIPTION_TABLE: &[(i32, &[u8])] = &[
    (0, b"Boot Loader Specification Type #1 (.conf)\0"),
    (1, b"Boot Loader Specification Type #2 (UKI, .efi)\0"),
    (2, b"Reported by Boot Loader\0"),
    (3, b"Automatic\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
#[unsafe(no_mangle)]
pub extern "C" fn rs_boot_entry_type_description_to_string(v: i32) -> *const c_char {
    for &(idx, name) in BOOT_ENTRY_TYPE_DESCRIPTION_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// ── bootspec: boot_entry_source (ESP=0, XBOOTLDR=1, to_string only) ──

static BOOT_ENTRY_SOURCE_TABLE: &[(i32, &[u8])] = &[(0, b"esp\0"), (1, b"xbootldr\0")];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
#[unsafe(no_mangle)]
pub extern "C" fn rs_boot_entry_source_to_string(v: i32) -> *const c_char {
    for &(idx, name) in BOOT_ENTRY_SOURCE_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// ── bootspec: boot_entry_source_description (ESP=0, XBOOTLDR=1, to_string only) ──

static BOOT_ENTRY_SOURCE_DESCRIPTION_TABLE: &[(i32, &[u8])] = &[
    (0, b"EFI System Partition\0"),
    (1, b"Extended Boot Loader Partition\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
#[unsafe(no_mangle)]
pub extern "C" fn rs_boot_entry_source_description_to_string(v: i32) -> *const c_char {
    for &(idx, name) in BOOT_ENTRY_SOURCE_DESCRIPTION_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// ── WITH_FALLBACK infrastructure ────────────────────────────────────────
//
// DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK generates:
//   to_string_alloc(type i, char **ret) → int (0=ok, negative=error)
//   from_string(const char *s) → type (table lookup, then numeric fallback)

use crate::ffi::malloc;

#[allow(unused_imports)]
use libc::snprintf;

/// Duplicate a NUL-terminated C string (caller frees with libc free).
// SAFETY: `s` must be null or readable through its terminating NUL; the caller
// owns the returned allocation and must release it with the matching C allocator.
unsafe fn rust_strdup(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut len: usize = 0;
    // SAFETY: the caller guarantees s is readable through its terminating NUL.
    while unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    let dst = malloc(len + 1) as *mut c_char;
    if dst.is_null() {
        return std::ptr::null_mut();
    }
    let mut i: usize = 0;
    while i <= len {
        // SAFETY: i includes the terminating NUL and stays within both ranges.
        unsafe { *dst.add(i) = *s.add(i) };
        i += 1;
    }
    dst
}

/// Parse the full `safe_atou()` grammar from a NUL-terminated C string.
///
/// # Safety
/// `s` must be a live NUL-terminated C string for the duration of this call.
unsafe fn parse_uint(s: *const c_char) -> Option<u32> {
    let mut value = 0;
    // SAFETY: propagated from this helper's C-string contract; `value` is a
    // writable stack local and base zero matches C's safe_atou().
    (unsafe { crate::parse_util::safe_atou_full_inner(s, 0, &mut value) } >= 0).then_some(value)
}

/// Generates a pair of FFI functions with numeric fallback support.
///
/// - `to_string_alloc(v: i32, ret: *mut *mut c_char) -> i32` — allocates a
///   string representation of the value. If the value is in the table, uses the
///   table name; otherwise formats the number as a decimal string.
/// - `from_string(s: *const c_char) -> i32` — parses a string, first trying
///   the table lookup, then falling back to numeric parsing if the input is a
///   valid decimal number within the `max` range.
///
/// The `max` parameter defines the upper bound for numeric fallback validation.
macro_rules! string_table_fallback {
    ($to_alloc_fn:ident, $from_fn:ident, $table:expr, $max:expr) => {
        #[doc = "C ABI facade. `ret` must be a valid writable `char **`; successful output uses the C allocator."]
        #[unsafe(no_mangle)]
        ///
        /// # Safety
        /// Every non-null input pointer must be valid and properly aligned for all
        /// reads performed by this call, and every non-null output pointer must be
        /// valid and properly aligned for all writes. Pointer ranges must not alias
        /// in ways forbidden by the operation's documented ownership contract.
        /// C-string inputs must remain NUL-terminated and live for the call.
        pub unsafe extern "C" fn $to_alloc_fn(v: i32, ret: *mut *mut c_char) -> i32 {
            if ret.is_null() {
                return Errno::EINVAL.to_neg_errno();
            }
            // SAFETY: `ret` was checked non-null and is writable by this ABI
            // entry point's caller contract.
            unsafe { *ret = std::ptr::null_mut() };
            if v < 0 || v > $max as i32 {
                return Errno::ERANGE.to_neg_errno(); // -ERANGE
            }
            // Check table
            let mut found: *const c_char = std::ptr::null();
            for &(idx, name) in $table {
                if idx == v {
                    found = static_cstr_ptr(name);
                    break;
                }
            }
            if !found.is_null() {
                // SAFETY: `found` points into validated static table storage.
                let dup = unsafe { rust_strdup(found) };
                if dup.is_null() {
                    return Errno::ENOMEM.to_neg_errno(); // -ENOMEM
                }
                // SAFETY: `ret` was checked non-null above.
                unsafe { *ret = dup };
                return 0;
            }
            // Numeric fallback: format the number as string
            let buf = malloc(16) as *mut c_char;
            if buf.is_null() {
                return Errno::ENOMEM.to_neg_errno(); // -ENOMEM
            }
            // SAFETY: `buf` is a live 16-byte allocation, the format string is
            // static and NUL-terminated, and the sole variadic argument matches
            // `%d`.
            unsafe { snprintf(buf, 16, b"%d\0".as_ptr().cast::<c_char>(), v) };
            // SAFETY: `ret` was checked non-null above.
            unsafe { *ret = buf };
            0
        }

        #[doc = "C ABI facade. `s` must be null or a valid NUL-terminated C string."]
        #[unsafe(no_mangle)]
        ///
        /// # Safety
        /// Every non-null input pointer must be valid and properly aligned for all
        /// reads performed by this call, and every non-null output pointer must be
        /// valid and properly aligned for all writes. Pointer ranges must not alias
        /// in ways forbidden by the operation's documented ownership contract.
        /// C-string inputs must remain NUL-terminated and live for the call.
        pub unsafe extern "C" fn $from_fn(s: *const c_char) -> i32 {
            // SAFETY: required by this C ABI entry point's contract.
            let Some(input) = (unsafe { input_bytes(s) }) else {
                return Errno::EINVAL.to_neg_errno();
            };
            if let Some(value) = from_bytes($table, input) {
                return value;
            }
            // Numeric fallback
            // SAFETY: the entry point's C-string contract remains valid for
            // the delegated safe_atou-compatible numeric parser.
            if let Some(u) = unsafe { parse_uint(s) }
                && u <= $max as u32
            {
                return u as i32;
            }
            Errno::EINVAL.to_neg_errno()
        }
    };
}

mod dns_security;
pub use dns_security::*;
mod tpm_bpf_wifi;
pub use tpm_bpf_wifi::*;

// ── ioprio_class: NONE=0, RT=1, BE=2, IDLE=3 (WITH_FALLBACK max=7) ──

static IOPRIO_CLASS_TABLE: &[(i32, &[u8])] = &[
    (0, b"none\0"),
    (1, b"realtime\0"),
    (2, b"best-effort\0"),
    (3, b"idle\0"),
];

string_table_fallback!(
    rs_ioprio_class_to_string_alloc,
    rs_ioprio_class_from_string,
    IOPRIO_CLASS_TABLE,
    7
);

// ── wol_options: bitfield-to-string (WAKE_PHY=1..WAKE_MAGICSECURE=64) ──

static WOL_OPTION_MAP: &[(u32, &[u8])] = &[
    (1 << 0, b"phy\0"),
    (1 << 1, b"unicast\0"),
    (1 << 2, b"multicast\0"),
    (1 << 3, b"broadcast\0"),
    (1 << 4, b"arp\0"),
    (1 << 5, b"magic\0"),
    (1 << 6, b"secureon\0"),
];

/// Shadow of C wol_options_to_string_alloc()
/// Converts a WAKE_* bitfield to a comma-separated string.
/// Returns 1 on success (with *ret set), 0 when opts==UINT32_MAX (with *ret=NULL).
/// C ABI facade. `ret` must be a valid writable `char **`; output uses the C allocator.
#[unsafe(no_mangle)]
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe extern "C" fn rs_wol_options_to_string_alloc(opts: u32, ret: *mut *mut c_char) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: ret is non-null and writable by the caller contract.
    unsafe { *ret = std::ptr::null_mut() };

    if opts == u32::MAX {
        return 0; // *ret stays NULL
    }

    // Count matching bits and compute total string length
    let mut count: usize = 0;
    let mut total_len: usize = 0;
    for &(bit, name) in WOL_OPTION_MAP.iter() {
        if (opts & bit) != 0 {
            let name = static_cstr(name);
            if count > 0 {
                total_len += 1; // comma separator
            }
            total_len += name.to_bytes().len();
            count += 1;
        }
    }

    if count == 0 {
        // No bits set → "off"
        // SAFETY: the source is immutable static NUL-terminated storage.
        let s = unsafe { rust_strdup(static_cstr_ptr(b"off\0")) };
        if s.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: ret is non-null and writable by the caller contract.
        unsafe { *ret = s };
        return 1;
    }

    let buf = malloc(total_len + 1) as *mut c_char;
    if buf.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    let mut pos: usize = 0;
    let mut first = true;
    for &(bit, name) in WOL_OPTION_MAP.iter() {
        if (opts & bit) != 0 {
            let name = static_cstr(name);
            if !first {
                // SAFETY: total_len includes every separator and table entry.
                unsafe { *buf.add(pos) = b',' as c_char };
                pos += 1;
            }
            first = false;
            let name_bytes = name.to_bytes();
            let name_len = name_bytes.len();
            // SAFETY: the destination range is within the total_len allocation
            // and static table bytes cannot overlap it.
            unsafe {
                std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), buf.add(pos).cast(), name_len)
            };
            pos += name_len;
        }
    }
    // SAFETY: the allocation reserves one final byte after total_len.
    unsafe { *buf.add(pos) = 0 };

    // SAFETY: ret is non-null and writable by the caller contract.
    unsafe { *ret = buf };
    1
}

#[cfg(test)]
#[path = "netdev_str_tables/tests.rs"]
mod tests;
