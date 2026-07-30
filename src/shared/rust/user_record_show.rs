// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/user-record-show.c / src/shared/user-record-show.h

use std::fmt::Write;

use crate::group_record::GroupRecord;
use crate::user_record::{
    AutoResizeMode, REBALANCE_WEIGHT_OFF, REBALANCE_WEIGHT_UNSET, UserDisposition, UserStorage,
};

const ANSI_NORMAL: &str = "\x1b[0m";
const ANSI_HIGHLIGHT: &str = "\x1b[1m";
const ANSI_GREY: &str = "\x1b[90m";
const ANSI_HIGHLIGHT_GREEN: &str = "\x1b[1;32m";
const ANSI_HIGHLIGHT_YELLOW: &str = "\x1b[1;33m";
const ANSI_HIGHLIGHT_RED: &str = "\x1b[1;31m";
const UID_INVALID: u32 = u32::MAX;
const GID_INVALID: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LoginStatus {
    #[default]
    Yes,
    Locked,
    NotValidYet,
    NotValidAnymore,
    NoLoginShell,
    RateLimited,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PasswordStatus {
    Yes,
    ChangeNow,
    ExpiredChangeNow,
    ExpiredForGood,
    ExpiresSoon,
    NoTimestamp,
    ChangeNotPermitted,
    LastChangeInFuture,
    NoneSet,
    EmptySet,
    Locked,
    Error(String),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextTry {
    Anytime,
    In(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TmpfsLimitDisplay {
    pub is_set: bool,
    pub bytes: Option<u64>,
    pub percent: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobEntry {
    pub name: String,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLimitEntry {
    pub name: String,
    pub soft: u64,
    pub hard: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserRecord {
    pub user_name: String,
    pub user_name_and_realm: String,
    pub aliases: Vec<String>,
    pub state: Option<String>,
    pub disposition: UserDisposition,
    pub last_change: Option<String>,
    pub last_change_in_future: bool,
    pub last_password_change: Option<String>,
    pub login_status: LoginStatus,
    pub password_status: PasswordStatus,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub gid_name: Option<String>,
    pub gid_error: Option<String>,
    pub auxiliary_groups: Vec<String>,
    pub auxiliary_groups_error: Option<String>,
    pub uuid: Option<String>,
    pub real_name: Option<String>,
    pub home_directory: Option<String>,
    pub fallback_home_directory: bool,
    pub use_fallback: bool,
    pub default_area: Option<String>,
    pub blob_directory: Option<String>,
    pub blob_manifest: Vec<BlobEntry>,
    pub storage: Option<UserStorage>,
    pub image_path: Option<String>,
    pub removable: Option<bool>,
    pub shell: Option<String>,
    pub fallback_shell: bool,
    pub email_address: Option<String>,
    pub location: Option<String>,
    pub birth_date: Option<String>,
    pub password_hint: Option<String>,
    pub icon_name: Option<String>,
    pub time_zone: Option<String>,
    pub languages: Vec<String>,
    pub languages_error: Option<String>,
    pub locked: Option<bool>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub umask: Option<u32>,
    pub nice_level: Option<i32>,
    pub rlimits: Vec<RLimitEntry>,
    pub tasks_max: Option<u64>,
    pub memory_high: Option<u64>,
    pub memory_max: Option<u64>,
    pub cpu_weight: Option<u64>,
    pub cpu_weight_idle: bool,
    pub io_weight: Option<u64>,
    pub tmp_limit: TmpfsLimitDisplay,
    pub dev_shm_limit: TmpfsLimitDisplay,
    pub access_mode: Option<u32>,
    pub capability_bounding_set: Option<String>,
    pub capability_ambient_set: Option<String>,
    pub luks_discard_online: Option<bool>,
    pub luks_discard_offline: Option<bool>,
    pub luks_uuid: Option<String>,
    pub partition_uuid: Option<String>,
    pub file_system_uuid: Option<String>,
    pub file_system_type: Option<String>,
    pub luks_extra_mount_options: Option<String>,
    pub luks_cipher: Option<String>,
    pub luks_cipher_mode: Option<String>,
    pub luks_volume_key_size_bytes: Option<u64>,
    pub luks_pbkdf_type: Option<String>,
    pub luks_pbkdf_hash_algorithm: Option<String>,
    pub luks_pbkdf_force_iterations: Option<u64>,
    pub luks_pbkdf_time_cost: Option<String>,
    pub luks_pbkdf_memory_cost: Option<u64>,
    pub luks_pbkdf_parallel_threads: Option<u64>,
    pub luks_sector_size: Option<u64>,
    pub cifs_service: Option<String>,
    pub cifs_extra_mount_options: Option<String>,
    pub cifs_user_name: Option<String>,
    pub cifs_domain: Option<String>,
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
    pub skeleton_directory: Option<String>,
    pub disk_size: Option<u64>,
    pub disk_usage: Option<u64>,
    pub disk_free: Option<u64>,
    pub disk_floor: Option<u64>,
    pub disk_ceiling: Option<u64>,
    pub good_authentication_counter: Option<u64>,
    pub last_good_authentication: Option<String>,
    pub bad_authentication_counter: Option<u64>,
    pub last_bad_authentication: Option<String>,
    pub next_try: Option<NextTry>,
    pub auth_limit_burst: Option<u64>,
    pub auth_limit_interval: Option<String>,
    pub enforce_password_policy: Option<bool>,
    pub password_change_min: Option<String>,
    pub password_change_max: Option<String>,
    pub password_change_warn: Option<String>,
    pub password_change_inactive: Option<String>,
    pub password_change_now: Option<bool>,
    pub drop_caches: Option<bool>,
    pub auto_resize_mode: Option<AutoResizeMode>,
    pub rebalance_weight: Option<u64>,
    pub ssh_authorized_keys_count: usize,
    pub pkcs11_token_uri: Vec<String>,
    pub fido2_hmac_credential_count: usize,
    pub recovery_key_type_count: usize,
    pub hashed_password: Vec<String>,
    pub signed_locally: Option<bool>,
    pub stop_delay: Option<String>,
    pub auto_login: Option<bool>,
    pub preferred_session_launcher: Option<String>,
    pub preferred_session_type: Option<String>,
    pub kill_processes: Option<bool>,
    pub service: Option<String>,
    pub self_modifiable_fields: Option<Vec<String>>,
    pub effective_self_modifiable_fields: Option<Vec<String>>,
    pub self_modifiable_blobs: Option<Vec<String>>,
    pub effective_self_modifiable_blobs: Option<Vec<String>>,
    pub self_modifiable_privileged: Option<Vec<String>>,
    pub effective_self_modifiable_privileged: Option<Vec<String>>,
}

pub const SOURCE_PATH: &str = "src/shared/user-record-show.c";
pub const SOURCE_TEXT: &str = include_str!("../user-record-show.c");

pub fn user_record_state_color(state: &str) -> Option<&'static str> {
    match state {
        "unfixated" | "absent" => Some(ANSI_GREY),
        "active" => Some(ANSI_HIGHLIGHT_GREEN),
        "locked" | "dirty" => Some(ANSI_HIGHLIGHT_YELLOW),
        _ => None,
    }
}

pub fn show_self_modifiable(
    heading: &str,
    field: Option<&[String]>,
    value: Option<&[String]>,
) -> String {
    let mut out = String::new();

    match value {
        None => {
            let _ = writeln!(out, "{:>13} {}none{}", heading, ANSI_HIGHLIGHT, ANSI_NORMAL);
        }
        Some([]) => {
            let _ = writeln!(
                out,
                "{:>13} {}disabled by administrator{}",
                heading, ANSI_HIGHLIGHT_RED, ANSI_NORMAL
            );
        }
        Some(values) if field.is_none() => {
            for (index, item) in values.iter().enumerate() {
                let label = if index == 0 { heading } else { "" };
                let _ = writeln!(out, "{:>13} {}{}{}", label, ANSI_GREY, item, ANSI_NORMAL);
            }
        }
        Some(values) => {
            for (index, item) in values.iter().enumerate() {
                let label = if index == 0 { heading } else { "" };
                let _ = writeln!(out, "{:>13} {}", label, item);
            }
        }
    }

    out
}

pub fn show_tmpfs_limit(tmpfs: &str, limit: &TmpfsLimitDisplay) -> String {
    if !limit.is_set {
        return String::new();
    }

    let mut out = String::new();
    let _ = write!(out, "   {} Limit:", tmpfs);

    if let Some(bytes) = limit.bytes {
        let _ = write!(out, " {}", format_bytes(bytes));
    }

    if let Some(percent) = limit.percent {
        if limit.bytes.is_some() {
            out.push_str(" or");
        }
        let _ = write!(out, " {}%", percent);
    }

    out.push('\n');
    out
}

pub fn user_record_show(record: &UserRecord, show_full_group_info: bool) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "   User name: {}", record.user_name_and_realm);

    if !record.aliases.is_empty() {
        let _ = writeln!(out, "       Alias: {}", record.aliases.join(", "));
    }

    if let Some(state) = &record.state {
        if let Some(color) = user_record_state_color(state) {
            let _ = writeln!(out, "       State: {}{}{}", color, state, ANSI_NORMAL);
        } else {
            let _ = writeln!(out, "       State: {}", state);
        }
    }

    let _ = writeln!(
        out,
        " Disposition: {}",
        user_disposition_to_string(record.disposition)
    );

    if let Some(last_change) = &record.last_change {
        let _ = writeln!(out, " Last Change: {}", last_change);
        if record.last_change_in_future {
            let _ = writeln!(
                out,
                "              {}Modification time lies in the future, system clock wrong?{}",
                ANSI_HIGHLIGHT_YELLOW, ANSI_NORMAL
            );
        }
    }

    if let Some(last_password_change) = &record.last_password_change {
        if record.last_change.as_ref() != Some(last_password_change) {
            let _ = writeln!(out, " Last Passw.: {}", last_password_change);
        }
    }

    push_login_status(&mut out, &record.login_status);
    push_password_status(&mut out, &record.password_status);

    if let Some(uid) = record.uid.filter(|uid| *uid != UID_INVALID) {
        let _ = writeln!(out, "         UID: {}", uid);
    }

    match (
        record.gid.filter(|gid| *gid != GID_INVALID),
        show_full_group_info,
    ) {
        (Some(gid), true) => {
            if let Some(error) = &record.gid_error {
                let _ = writeln!(out, "         GID: {} (unresolvable: {})", gid, error);
            } else if let Some(name) = &record.gid_name {
                let _ = writeln!(out, "         GID: {} ({})", gid, name);
            } else {
                let _ = writeln!(out, "         GID: {}", gid);
            }
        }
        (Some(gid), false) => {
            let _ = writeln!(out, "         GID: {}", gid);
        }
        (None, _) => {
            if let Some(uid) = record.uid.filter(|uid| *uid != UID_INVALID) {
                let _ = writeln!(out, "         GID: {}", uid);
            }
        }
    }

    if show_full_group_info {
        if let Some(error) = &record.auxiliary_groups_error {
            let _ = writeln!(out, " Aux. Groups: (can't acquire: {})", error);
        } else {
            for (index, group) in record.auxiliary_groups.iter().enumerate() {
                let prefix = if index == 0 {
                    " Aux. Groups:"
                } else {
                    "             "
                };
                let _ = writeln!(out, "{} {}", prefix, group);
            }
        }
    }

    if let Some(uuid) = &record.uuid {
        let _ = writeln!(out, "        UUID: {}", uuid);
    }

    if let Some(real_name) = &record.real_name {
        if real_name != &record.user_name {
            let _ = writeln!(out, "   Real Name: {}", real_name);
        }
    }

    if let Some(home_directory) = &record.home_directory {
        let _ = write!(out, "   Directory: {}", home_directory);
        if record.fallback_home_directory && record.use_fallback {
            let _ = write!(out, " {}(fallback){}", ANSI_HIGHLIGHT_YELLOW, ANSI_NORMAL);
        }
        out.push('\n');
    }

    if let Some(default_area) = &record.default_area {
        let _ = writeln!(out, "Default Area: {}", default_area);
    }

    if let Some(blob_directory) = &record.blob_directory {
        let _ = writeln!(out, "   Blob Dir.: {}", blob_directory);
        for (index, blob) in record.blob_manifest.iter().enumerate() {
            let glyph = if index + 1 == record.blob_manifest.len() {
                "└─"
            } else {
                "├─"
            };
            let hash = blob.sha256.as_deref().unwrap_or("can't display hash");
            let _ = writeln!(
                out,
                "              {} {} {}({}){}",
                glyph, blob.name, ANSI_GREY, hash, ANSI_NORMAL
            );
        }
    }

    if let Some(storage) = record.storage {
        let _ = writeln!(
            out,
            "     Storage: {}{}",
            storage_to_string(storage),
            storage_security_suffix(storage)
        );
    }

    if let Some(image_path) = &record.image_path {
        if record.home_directory.as_ref() != Some(image_path) {
            let _ = writeln!(out, "  Image Path: {}", image_path);
        }
    }

    if let Some(removable) = record.removable {
        let _ = writeln!(out, "   Removable: {}", yes_no(removable));
    }

    if let Some(shell) = &record.shell {
        let _ = write!(out, "       Shell: {}", shell);
        if record.fallback_shell && record.use_fallback {
            let _ = write!(out, " {}(fallback){}", ANSI_HIGHLIGHT_YELLOW, ANSI_NORMAL);
        }
        out.push('\n');
    }

    push_optional_line(&mut out, "       Email", record.email_address.as_deref());
    push_optional_line(&mut out, "    Location", record.location.as_deref());
    push_optional_line(&mut out, "  Birth Date", record.birth_date.as_deref());
    push_optional_line(&mut out, " Passw. Hint", record.password_hint.as_deref());
    push_optional_line(&mut out, "   Icon Name", record.icon_name.as_deref());
    push_optional_line(&mut out, "   Time Zone", record.time_zone.as_deref());

    if let Some(error) = &record.languages_error {
        let _ = writeln!(out, "   Languages: (can't acquire: {})", error);
    } else if !record.languages.is_empty() {
        let _ = writeln!(out, "   Languages: {}", record.languages.join(", "));
    }

    if let Some(locked) = record.locked {
        let _ = writeln!(out, "      Locked: {}", yes_no(locked));
    }

    push_optional_line(&mut out, "  Not Before", record.not_before.as_deref());
    push_optional_line(&mut out, "   Not After", record.not_after.as_deref());

    if let Some(umask) = record.umask {
        let _ = writeln!(out, "       UMask: {}", format_mode(umask));
    }

    if let Some(nice) = record.nice_level {
        let _ = writeln!(out, "        Nice: {}", nice);
    }

    for rlimit in &record.rlimits {
        let _ = writeln!(
            out,
            "       Limit: RLIMIT_{}={}:{}",
            rlimit.name, rlimit.soft, rlimit.hard
        );
    }

    if let Some(tasks_max) = record.tasks_max {
        let _ = writeln!(out, "   Tasks Max: {}", tasks_max);
    }
    if let Some(memory_high) = record.memory_high {
        let _ = writeln!(out, " Memory High: {}", format_bytes(memory_high));
    }
    if let Some(memory_max) = record.memory_max {
        let _ = writeln!(out, "  Memory Max: {}", format_bytes(memory_max));
    }

    match (record.cpu_weight_idle, record.cpu_weight) {
        (true, _) => {
            let _ = writeln!(out, "  CPU Weight: idle");
        }
        (false, Some(cpu_weight)) => {
            let _ = writeln!(out, "  CPU Weight: {}", cpu_weight);
        }
        _ => {}
    }

    if let Some(io_weight) = record.io_weight {
        let _ = writeln!(out, "   IO Weight: {}", io_weight);
    }

    out.push_str(&show_tmpfs_limit("TMP", &record.tmp_limit));
    out.push_str(&show_tmpfs_limit("SHM", &record.dev_shm_limit));

    if let Some(access_mode) = record.access_mode {
        let _ = writeln!(out, " Access Mode: {}", format_mode(access_mode));
    }

    push_optional_line(
        &mut out,
        " Bound. Caps",
        record.capability_bounding_set.as_deref(),
    );
    push_optional_line(
        &mut out,
        "Ambient Caps",
        record.capability_ambient_set.as_deref(),
    );

    match record.storage {
        Some(UserStorage::LUKS) => {
            if let (Some(online), Some(offline)) =
                (record.luks_discard_online, record.luks_discard_offline)
            {
                let _ = writeln!(
                    out,
                    "LUKS Discard: online={} offline={}",
                    yes_no(online),
                    yes_no(offline)
                );
            }

            push_optional_line(&mut out, "   LUKS UUID", record.luks_uuid.as_deref());
            push_optional_line(&mut out, "   Part UUID", record.partition_uuid.as_deref());
            push_optional_line(&mut out, "     FS UUID", record.file_system_uuid.as_deref());
            push_optional_line(&mut out, " File System", record.file_system_type.as_deref());
            push_optional_line(
                &mut out,
                "LUKS MntOpts",
                record.luks_extra_mount_options.as_deref(),
            );
            push_optional_line(&mut out, " LUKS Cipher", record.luks_cipher.as_deref());
            push_optional_line(&mut out, " Cipher Mode", record.luks_cipher_mode.as_deref());

            if let Some(key_size) = record.luks_volume_key_size_bytes {
                let _ = writeln!(out, "  Volume Key: {}bit", key_size * 8);
            }

            push_optional_line(&mut out, "  PBKDF Type", record.luks_pbkdf_type.as_deref());
            push_optional_line(
                &mut out,
                "  PBKDF Hash",
                record.luks_pbkdf_hash_algorithm.as_deref(),
            );

            if let Some(iterations) = record.luks_pbkdf_force_iterations {
                let _ = writeln!(out, " PBKDF Iters: {}", iterations);
            }
            push_optional_line(
                &mut out,
                "  PBKDF Time",
                record.luks_pbkdf_time_cost.as_deref(),
            );

            if let Some(memory_cost) = record.luks_pbkdf_memory_cost {
                let _ = writeln!(out, " PBKDF Bytes: {}", format_bytes(memory_cost));
            }
            if let Some(threads) = record.luks_pbkdf_parallel_threads {
                let _ = writeln!(out, "PBKDF Thread: {}", threads);
            }
            if let Some(sector_size) = record.luks_sector_size {
                let _ = writeln!(out, " Sector Size: {}", sector_size);
            }
        }
        Some(UserStorage::CIFS) => {
            push_optional_line(&mut out, "CIFS Service", record.cifs_service.as_deref());
            push_optional_line(
                &mut out,
                "CIFS MntOpts",
                record.cifs_extra_mount_options.as_deref(),
            );
        }
        _ => {}
    }

    push_optional_line(&mut out, "   CIFS User", record.cifs_user_name.as_deref());
    push_optional_line(&mut out, " CIFS Domain", record.cifs_domain.as_deref());

    if record.storage != Some(UserStorage::Classic) {
        let _ = writeln!(
            out,
            " Mount Flags: {} {} {}",
            if record.nosuid { "nosuid" } else { "suid" },
            if record.nodev { "nodev" } else { "dev" },
            if record.noexec { "noexec" } else { "exec" }
        );
    }

    push_optional_line(
        &mut out,
        "  Skel. Dir.",
        record.skeleton_directory.as_deref(),
    );

    if let Some(disk_size) = record.disk_size {
        let _ = writeln!(out, "   Disk Size: {}", format_bytes(disk_size));
    }

    if let Some(disk_usage) = record.disk_usage {
        if let Some(disk_size) = record.disk_size {
            let permille = permille_rounded_up(disk_usage, disk_size);
            let _ = writeln!(
                out,
                "  Disk Usage: {} (= {}.{}%)",
                format_bytes(disk_usage),
                permille / 10,
                permille % 10
            );
        } else {
            let _ = writeln!(out, "  Disk Usage: {}", format_bytes(disk_usage));
        }
    }

    if let Some(disk_free) = record.disk_free {
        if let Some(disk_size) = record.disk_size {
            let permille = permille_rounded_down(disk_free, disk_size);
            let (on, off) = disk_free_color(disk_free, permille);
            let _ = writeln!(
                out,
                "   Disk Free: {}{} (= {}.{}%){}",
                on,
                format_bytes(disk_free),
                permille / 10,
                permille % 10,
                off
            );
        } else {
            let _ = writeln!(out, "   Disk Free: {}", format_bytes(disk_free));
        }
    }

    if let Some(disk_floor) = record.disk_floor {
        let _ = writeln!(out, "  Disk Floor: {}", format_bytes(disk_floor));
    }
    if let Some(disk_ceiling) = record.disk_ceiling {
        let _ = writeln!(out, "Disk Ceiling: {}", format_bytes(disk_ceiling));
    }

    if let Some(good_auth) = record.good_authentication_counter {
        let _ = writeln!(out, "  Good Auth.: {}", good_auth);
    }
    push_optional_line(
        &mut out,
        "   Last Good",
        record.last_good_authentication.as_deref(),
    );
    if let Some(bad_auth) = record.bad_authentication_counter {
        let _ = writeln!(out, "   Bad Auth.: {}", bad_auth);
    }
    push_optional_line(
        &mut out,
        "    Last Bad",
        record.last_bad_authentication.as_deref(),
    );

    if let Some(next_try) = &record.next_try {
        match next_try {
            NextTry::Anytime => {
                let _ = writeln!(out, "    Next Try: anytime");
            }
            NextTry::In(span) => {
                let _ = writeln!(
                    out,
                    "    Next Try: {}in {}{}",
                    ANSI_HIGHLIGHT_RED, span, ANSI_NORMAL
                );
            }
        }
    }

    if record.storage != Some(UserStorage::Classic) {
        if let (Some(burst), Some(interval)) = (
            record.auth_limit_burst,
            record.auth_limit_interval.as_deref(),
        ) {
            let _ = writeln!(out, " Auth. Limit: {} attempts per {}", burst, interval);
        }
    }

    if let Some(enforce) = record.enforce_password_policy {
        let _ = writeln!(out, " Passwd Pol.: {}", yes_no(enforce));
    }

    if record.password_change_min.is_some()
        || record.password_change_max.is_some()
        || record.password_change_warn.is_some()
        || record.password_change_inactive.is_some()
    {
        out.push_str(" Passwd Chg.:");

        if let Some(min) = &record.password_change_min {
            let _ = write!(out, " min {}", min);
            if record.password_change_max.is_some() {
                out.push_str(" …");
            }
        }
        if let Some(max) = &record.password_change_max {
            let _ = write!(out, " max {}", max);
        }
        if let Some(warn) = &record.password_change_warn {
            let _ = write!(out, "/warn {}", warn);
        }
        if let Some(inactive) = &record.password_change_inactive {
            let _ = write!(out, "/inactive {}", inactive);
        }

        out.push('\n');
    }

    if let Some(change_now) = record.password_change_now {
        let _ = writeln!(out, "Pas. Ch. Now: {}", yes_no(change_now));
    }

    if let Some(drop_caches) = record.drop_caches {
        let _ = writeln!(out, " Drop Caches: {}", yes_no(drop_caches));
    }

    if let Some(mode) = record.auto_resize_mode {
        let _ = writeln!(out, " Auto Resize: {}", auto_resize_mode_to_string(mode));
    }

    if let Some(rebalance_weight) = record.rebalance_weight {
        if rebalance_weight != REBALANCE_WEIGHT_UNSET {
            if rebalance_weight == REBALANCE_WEIGHT_OFF {
                let _ = writeln!(out, "   Rebalance: off");
            } else {
                let _ = writeln!(out, "   Rebalance: weight {}", rebalance_weight);
            }
        }
    }

    if record.ssh_authorized_keys_count > 0 {
        let _ = writeln!(out, "SSH Pub. Key: {}", record.ssh_authorized_keys_count);
    }

    for (index, token) in record.pkcs11_token_uri.iter().enumerate() {
        let prefix = if index == 0 {
            "PKCS11 Token:"
        } else {
            "              "
        };
        let _ = writeln!(out, "{} {}", prefix, token);
    }

    if record.fido2_hmac_credential_count > 0 {
        let _ = writeln!(out, " FIDO2 Token: {}", record.fido2_hmac_credential_count);
    }

    if record.recovery_key_type_count > 0 {
        let _ = writeln!(out, "Recovery Key: {}", record.recovery_key_type_count);
    }

    if record.hashed_password.is_empty() {
        let color = if record.disposition == UserDisposition::Regular {
            ANSI_HIGHLIGHT_YELLOW
        } else {
            ANSI_NORMAL
        };
        let _ = writeln!(out, "   Passwords: {}none{}", color, ANSI_NORMAL);
    } else {
        let _ = writeln!(out, "   Passwords: {}", record.hashed_password.len());
    }

    if let Some(signed_locally) = record.signed_locally {
        let _ = writeln!(out, "  Local Sig.: {}", yes_no(signed_locally));
    }

    push_optional_line(&mut out, "  Stop Delay", record.stop_delay.as_deref());

    if let Some(auto_login) = record.auto_login {
        let _ = writeln!(out, "Autom. Login: {}", yes_no(auto_login));
    }

    push_optional_line(
        &mut out,
        "Sess. Launch",
        record.preferred_session_launcher.as_deref(),
    );
    push_optional_line(
        &mut out,
        "Session Type",
        record.preferred_session_type.as_deref(),
    );

    if let Some(kill_processes) = record.kill_processes {
        let _ = writeln!(out, "  Kill Proc.: {}", yes_no(kill_processes));
    }

    push_optional_line(&mut out, "     Service", record.service.as_deref());

    out.push_str(&show_self_modifiable(
        "Self Modify:",
        record.self_modifiable_fields.as_deref(),
        record.effective_self_modifiable_fields.as_deref(),
    ));
    out.push_str(&show_self_modifiable(
        "(Blobs)",
        record.self_modifiable_blobs.as_deref(),
        record.effective_self_modifiable_blobs.as_deref(),
    ));
    out.push_str(&show_self_modifiable(
        "(Privileged)",
        record.self_modifiable_privileged.as_deref(),
        record.effective_self_modifiable_privileged.as_deref(),
    ));

    out
}

pub fn group_record_show(record: &GroupRecord, _show_full_user_info: bool) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "  Group name: {}", record.group_name_and_realm());
    let _ = writeln!(
        out,
        " Disposition: {}",
        user_disposition_to_string(record.disposition())
    );

    if record.last_change_usec != u64::MAX {
        let _ = writeln!(out, " Last Change: {} usec", record.last_change_usec);
    }

    if record.gid != GID_INVALID {
        let _ = writeln!(out, "         GID: {}", record.gid);
    }

    if !is_null_uuid(&record.uuid) {
        let _ = writeln!(out, "        UUID: {}", format_uuid(&record.uuid));
    }

    let members = &record.members;
    for (index, member) in members.iter().enumerate() {
        let prefix = if index == 0 {
            "     Members:"
        } else {
            "             "
        };
        let _ = writeln!(out, "{} {}", prefix, member);
    }

    for (index, admin) in record.administrators.iter().enumerate() {
        let prefix = if index == 0 {
            "      Admins:"
        } else {
            "             "
        };
        let _ = writeln!(out, "{} {}", prefix, admin);
    }

    if let Some(description) = &record.description {
        if record.group_name.as_deref() != Some(description.as_str()) {
            let _ = writeln!(out, " Description: {}", description);
        }
    }

    if !record.hashed_password.is_empty() {
        let _ = writeln!(out, "   Passwords: {}", record.hashed_password.len());
    }

    if let Some(service) = &record.service {
        let _ = writeln!(out, "     Service: {}", service);
    }

    out
}

pub fn user_record_show_table(records: &[UserRecord]) -> String {
    let headers = ["USER", "UID", "GID", "STATE", "STORAGE", "HOME"];
    let rows: Vec<[String; 6]> = records
        .iter()
        .map(|record| {
            [
                record.user_name_and_realm.clone(),
                record
                    .uid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                record
                    .gid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                record.state.clone().unwrap_or_else(|| "-".into()),
                record
                    .storage
                    .map(storage_to_string)
                    .unwrap_or("-")
                    .to_string(),
                record.home_directory.clone().unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();

    let mut widths = headers.map(str::len);
    for row in &rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.len());
        }
    }

    let mut out = String::new();
    for (index, header) in headers.iter().enumerate() {
        if index + 1 < headers.len() {
            let _ = write!(out, "{header:<width$} ", width = widths[index]);
        } else {
            let _ = write!(out, "{header}");
        }
    }
    out.push('\n');

    for (index, width) in widths.iter().enumerate() {
        if index + 1 < widths.len() {
            let _ = write!(out, "{:-<width$} ", "", width = *width);
        } else {
            let _ = write!(out, "{:-<width$}", "", width = headers[index].len());
        }
    }
    out.push('\n');

    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if index + 1 < widths.len() {
                let _ = write!(out, "{cell:<width$} ", width = widths[index]);
            } else {
                let _ = write!(out, "{cell}");
            }
        }
        out.push('\n');
    }

    out
}

pub fn user_record_show_json(json: &str) -> Result<String, JsonFormatError> {
    let mut parser = JsonParser::new(json);
    let value = parser.parse_value()?;
    parser.skip_ws();
    if !parser.is_eof() {
        return Err(JsonFormatError::new(parser.pos, "trailing characters"));
    }
    Ok(pretty_print_json(&value, 0))
}

fn push_login_status(out: &mut String, status: &LoginStatus) {
    match status {
        LoginStatus::Yes => {
            let _ = writeln!(
                out,
                "    Login OK: {}yes{}",
                ANSI_HIGHLIGHT_GREEN, ANSI_NORMAL
            );
        }
        LoginStatus::Locked => {
            let _ = writeln!(
                out,
                "    Login OK: {}no{} (record is locked)",
                ANSI_HIGHLIGHT_RED, ANSI_NORMAL
            );
        }
        LoginStatus::NotValidYet => {
            let _ = writeln!(
                out,
                "    Login OK: {}no{} (record not valid yet))",
                ANSI_HIGHLIGHT_RED, ANSI_NORMAL
            );
        }
        LoginStatus::NotValidAnymore => {
            let _ = writeln!(
                out,
                "    Login OK: {}no{} (record not valid anymore))",
                ANSI_HIGHLIGHT_RED, ANSI_NORMAL
            );
        }
        LoginStatus::NoLoginShell => {
            let _ = writeln!(
                out,
                "    Login OK: {}no{} (nologin shell)",
                ANSI_HIGHLIGHT_RED, ANSI_NORMAL
            );
        }
        LoginStatus::RateLimited => {
            let _ = writeln!(
                out,
                "    Login OK: {}no{} (ratelimit)",
                ANSI_HIGHLIGHT_RED, ANSI_NORMAL
            );
        }
        LoginStatus::Error(error) => {
            let _ = writeln!(
                out,
                "    Login OK: {}no{} ({})",
                ANSI_HIGHLIGHT_RED, ANSI_NORMAL, error
            );
        }
    }
}

fn push_password_status(out: &mut String, status: &PasswordStatus) {
    match status {
        PasswordStatus::ChangeNow => {
            let _ = writeln!(
                out,
                " Password OK: {}change now{}",
                ANSI_HIGHLIGHT_YELLOW, ANSI_NORMAL
            );
        }
        PasswordStatus::ExpiredChangeNow => {
            let _ = writeln!(
                out,
                " Password OK: {}expired{} (change now!)",
                ANSI_HIGHLIGHT_YELLOW, ANSI_NORMAL
            );
        }
        PasswordStatus::ExpiredForGood => {
            let _ = writeln!(
                out,
                " Password OK: {}expired{} (for good)",
                ANSI_HIGHLIGHT_RED, ANSI_NORMAL
            );
        }
        PasswordStatus::ExpiresSoon => {
            let _ = writeln!(
                out,
                " Password OK: {}expires soon{}",
                ANSI_HIGHLIGHT_YELLOW, ANSI_NORMAL
            );
        }
        PasswordStatus::NoTimestamp => {
            let _ = writeln!(
                out,
                " Password OK: {}no timestamp{}",
                ANSI_HIGHLIGHT_RED, ANSI_NORMAL
            );
        }
        PasswordStatus::ChangeNotPermitted => {
            let _ = writeln!(
                out,
                " Password OK: {}change not permitted{}",
                ANSI_HIGHLIGHT_YELLOW, ANSI_NORMAL
            );
        }
        PasswordStatus::LastChangeInFuture => {
            let _ = writeln!(
                out,
                " Password OK: {}last password change in future{}",
                ANSI_HIGHLIGHT_YELLOW, ANSI_NORMAL
            );
        }
        PasswordStatus::NoneSet => {
            let _ = writeln!(
                out,
                " Password OK: {}no{} (none set)",
                ANSI_HIGHLIGHT, ANSI_NORMAL
            );
        }
        PasswordStatus::EmptySet => {
            let _ = writeln!(
                out,
                " Password OK: {}no{} (empty set)",
                ANSI_HIGHLIGHT_RED, ANSI_NORMAL
            );
        }
        PasswordStatus::Yes => {
            let _ = writeln!(
                out,
                " Password OK: {}yes{}",
                ANSI_HIGHLIGHT_GREEN, ANSI_NORMAL
            );
        }
        PasswordStatus::Locked => {
            let _ = writeln!(
                out,
                " Password OK: {}no{} (locked)",
                ANSI_HIGHLIGHT, ANSI_NORMAL
            );
        }
        PasswordStatus::Error(error) => {
            let _ = writeln!(
                out,
                " Password OK: {}no{} ({})",
                ANSI_HIGHLIGHT_YELLOW, ANSI_NORMAL, error
            );
        }
        PasswordStatus::Unknown => {}
    }
}

fn push_optional_line(out: &mut String, label: &str, value: Option<&str>) {
    if let Some(value) = value {
        let _ = writeln!(out, "{}: {}", label, value);
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn user_disposition_to_string(disposition: UserDisposition) -> &'static str {
    disposition.to_cstr()
}

fn storage_to_string(storage: UserStorage) -> &'static str {
    storage.to_cstr()
}

fn storage_security_suffix(storage: UserStorage) -> &'static str {
    match storage {
        UserStorage::LUKS => " (strong encryption)",
        UserStorage::FSCrypt => " (weak encryption)",
        UserStorage::Directory | UserStorage::Subvolume => " (no encryption)",
        _ => "",
    }
}

fn auto_resize_mode_to_string(mode: AutoResizeMode) -> &'static str {
    match mode {
        AutoResizeMode::Off => "off",
        AutoResizeMode::Grow => "grow",
        AutoResizeMode::ShrinkAndGrow => "shrink-and-grow",
    }
}

fn format_mode(mode: u32) -> String {
    format!("0{:03o}", mode)
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "K", "M", "G", "T", "P", "E"];

    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{}{}", bytes, UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.0}{}", UNITS[unit])
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

fn permille_rounded_up(value: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    (value.saturating_mul(1000).saturating_add(total - 1)) / total
}

fn permille_rounded_down(value: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    value.saturating_mul(1000) / total
}

fn disk_free_color(disk_free: u64, permille: u64) -> (&'static str, &'static str) {
    if permille <= 100 && disk_free < 1024 * 1024 * 1024 {
        (ANSI_HIGHLIGHT_RED, ANSI_NORMAL)
    } else if permille <= 250 && disk_free < 2 * 1024 * 1024 * 1024 {
        (ANSI_HIGHLIGHT_YELLOW, ANSI_NORMAL)
    } else {
        ("", "")
    }
}

fn is_null_uuid(uuid: &[u8; 16]) -> bool {
    uuid.iter().all(|byte| *byte == 0)
}

fn format_uuid(uuid: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15],
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonFormatError {
    pub position: usize,
    pub message: String,
}

impl JsonFormatError {
    fn new(position: usize, message: impl Into<String>) -> Self {
        Self {
            position,
            message: message.into(),
        }
    }
}

struct JsonParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_ascii_whitespace() {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn consume(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn parse_value(&mut self) -> Result<JsonValue, JsonFormatError> {
        self.skip_ws();
        match self.peek() {
            Some('n') => self.parse_literal("null", JsonValue::Null),
            Some('t') => self.parse_literal("true", JsonValue::Bool(true)),
            Some('f') => self.parse_literal("false", JsonValue::Bool(false)),
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('[') => self.parse_array(),
            Some('{') => self.parse_object(),
            Some('-' | '0'..='9') => self.parse_number().map(JsonValue::Number),
            Some(ch) => Err(JsonFormatError::new(
                self.pos,
                format!("unexpected character {ch:?}"),
            )),
            None => Err(JsonFormatError::new(self.pos, "unexpected end of input")),
        }
    }

    fn parse_literal(
        &mut self,
        literal: &str,
        value: JsonValue,
    ) -> Result<JsonValue, JsonFormatError> {
        if self.input[self.pos..].starts_with(literal) {
            self.pos += literal.len();
            Ok(value)
        } else {
            Err(JsonFormatError::new(
                self.pos,
                format!("expected {literal}"),
            ))
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonFormatError> {
        if self.consume() != Some('"') {
            return Err(JsonFormatError::new(self.pos, "expected string"));
        }

        let mut out = String::new();
        loop {
            match self.consume() {
                Some('"') => return Ok(out),
                Some('\\') => match self.consume() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('b') => out.push('\u{0008}'),
                    Some('f') => out.push('\u{000C}'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('u') => {
                        let code = self.parse_hex4()?;
                        let ch = char::from_u32(code as u32).ok_or_else(|| {
                            JsonFormatError::new(self.pos, "invalid unicode escape")
                        })?;
                        out.push(ch);
                    }
                    Some(other) => {
                        return Err(JsonFormatError::new(
                            self.pos,
                            format!("invalid escape {other:?}"),
                        ));
                    }
                    None => return Err(JsonFormatError::new(self.pos, "unterminated escape")),
                },
                Some(ch) if ch >= '\u{20}' => out.push(ch),
                Some(_) => {
                    return Err(JsonFormatError::new(
                        self.pos,
                        "control character in string",
                    ));
                }
                None => return Err(JsonFormatError::new(self.pos, "unterminated string")),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, JsonFormatError> {
        let mut value = 0u16;
        for _ in 0..4 {
            let ch = self
                .consume()
                .ok_or_else(|| JsonFormatError::new(self.pos, "unterminated unicode escape"))?;
            value = (value << 4)
                | ch.to_digit(16)
                    .ok_or_else(|| JsonFormatError::new(self.pos, "invalid unicode escape"))?
                    as u16;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<String, JsonFormatError> {
        let start = self.pos;

        if self.peek() == Some('-') {
            self.consume();
        }

        match self.peek() {
            Some('0') => {
                self.consume();
            }
            Some('1'..='9') => {
                self.consume();
                while matches!(self.peek(), Some('0'..='9')) {
                    self.consume();
                }
            }
            _ => return Err(JsonFormatError::new(self.pos, "invalid number")),
        }

        if self.peek() == Some('.') {
            self.consume();
            if !matches!(self.peek(), Some('0'..='9')) {
                return Err(JsonFormatError::new(self.pos, "invalid fraction"));
            }
            while matches!(self.peek(), Some('0'..='9')) {
                self.consume();
            }
        }

        if matches!(self.peek(), Some('e' | 'E')) {
            self.consume();
            if matches!(self.peek(), Some('+' | '-')) {
                self.consume();
            }
            if !matches!(self.peek(), Some('0'..='9')) {
                return Err(JsonFormatError::new(self.pos, "invalid exponent"));
            }
            while matches!(self.peek(), Some('0'..='9')) {
                self.consume();
            }
        }

        Ok(self.input[start..self.pos].to_string())
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonFormatError> {
        self.consume();
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(']') {
            self.consume();
            return Ok(JsonValue::Array(items));
        }

        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.consume() {
                Some(',') => self.skip_ws(),
                Some(']') => break,
                _ => return Err(JsonFormatError::new(self.pos, "expected ',' or ']'")),
            }
        }

        Ok(JsonValue::Array(items))
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonFormatError> {
        self.consume();
        self.skip_ws();
        let mut fields = Vec::new();
        if self.peek() == Some('}') {
            self.consume();
            return Ok(JsonValue::Object(fields));
        }

        loop {
            let key = self.parse_string()?;
            self.skip_ws();
            if self.consume() != Some(':') {
                return Err(JsonFormatError::new(self.pos, "expected ':'"));
            }
            let value = self.parse_value()?;
            fields.push((key, value));
            self.skip_ws();
            match self.consume() {
                Some(',') => {
                    self.skip_ws();
                }
                Some('}') => break,
                _ => return Err(JsonFormatError::new(self.pos, "expected ',' or '}'")),
            }
        }

        Ok(JsonValue::Object(fields))
    }
}

fn pretty_print_json(value: &JsonValue, indent: usize) -> String {
    match value {
        JsonValue::Null => "null".into(),
        JsonValue::Bool(value) => value.to_string(),
        JsonValue::Number(value) => value.clone(),
        JsonValue::String(value) => format!("\"{}\"", escape_json_string(value)),
        JsonValue::Array(items) => {
            if items.is_empty() {
                return "[]".into();
            }

            let mut out = String::from("[\n");
            for (index, item) in items.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                out.push_str(&pretty_print_json(item, indent + 2));
                if index + 1 != items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push(']');
            out
        }
        JsonValue::Object(fields) => {
            if fields.is_empty() {
                return "{}".into();
            }

            let mut out = String::from("{\n");
            for (index, (key, value)) in fields.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                let _ = write!(
                    out,
                    "\"{}\": {}",
                    escape_json_string(key),
                    pretty_print_json(value, indent + 2)
                );
                if index + 1 != fields.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push('}');
            out
        }
    }
}

fn escape_json_string(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            ch if ch < '\u{20}' => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_record::GroupRecord;
    use crate::user_record::{AutoResizeMode, UserDisposition, UserStorage};

    #[test]
    fn state_color_matches_c() {
        assert_eq!(user_record_state_color("unfixated"), Some(ANSI_GREY));
        assert_eq!(user_record_state_color("absent"), Some(ANSI_GREY));
        assert_eq!(
            user_record_state_color("active"),
            Some(ANSI_HIGHLIGHT_GREEN)
        );
        assert_eq!(
            user_record_state_color("locked"),
            Some(ANSI_HIGHLIGHT_YELLOW)
        );
        assert_eq!(
            user_record_state_color("dirty"),
            Some(ANSI_HIGHLIGHT_YELLOW)
        );
        assert_eq!(user_record_state_color("bogus"), None);
    }

    #[test]
    fn self_modifiable_none_matches_c_case_1() {
        let rendered = show_self_modifiable("Self Modify:", Some(&[]), None);
        assert!(rendered.contains("none"));
    }

    #[test]
    fn self_modifiable_empty_matches_c_case_2() {
        let values: Vec<String> = vec![];
        let rendered = show_self_modifiable("Self Modify:", Some(&values), Some(&values));
        assert!(rendered.contains("disabled by administrator"));
    }

    #[test]
    fn self_modifiable_defaults_match_c_case_3() {
        let values = vec!["shell".to_string(), "realName".to_string()];
        let rendered = show_self_modifiable("Self Modify:", None, Some(&values));
        assert!(rendered.contains("shell"));
        assert!(rendered.contains(ANSI_GREY));
    }

    #[test]
    fn self_modifiable_admin_values_match_c_case_4() {
        let field = vec!["shell".to_string()];
        let values = vec!["shell".to_string(), "location".to_string()];
        let rendered = show_self_modifiable("Self Modify:", Some(&field), Some(&values));
        assert!(rendered.contains("location"));
        assert!(!rendered.contains(ANSI_GREY));
    }

    #[test]
    fn tmpfs_limit_formats_bytes_and_percent() {
        let rendered = show_tmpfs_limit(
            "TMP",
            &TmpfsLimitDisplay {
                is_set: true,
                bytes: Some(1024 * 1024),
                percent: Some(15),
            },
        );
        assert_eq!(rendered, "   TMP Limit: 1.0M or 15%\n");
    }

    #[test]
    fn user_record_show_renders_core_fields() {
        let record = UserRecord {
            user_name: "lennart".into(),
            user_name_and_realm: "lennart@example.com".into(),
            aliases: vec!["poettering".into(), "lp".into()],
            state: Some("active".into()),
            disposition: UserDisposition::Regular,
            last_change: Some("2026-04-08 10:00:00 UTC".into()),
            last_password_change: Some("2026-04-07 08:00:00 UTC".into()),
            login_status: LoginStatus::Yes,
            password_status: PasswordStatus::ExpiresSoon,
            uid: Some(1000),
            gid: Some(1000),
            gid_name: Some("users".into()),
            auxiliary_groups: vec!["wheel".into(), "audio".into()],
            uuid: Some("11111111-2222-3333-4444-555555555555".into()),
            real_name: Some("Lennart Poettering".into()),
            home_directory: Some("/home/lennart".into()),
            storage: Some(UserStorage::LUKS),
            shell: Some("/bin/bash".into()),
            email_address: Some("lennart@example.com".into()),
            password_hint: Some("dog name".into()),
            languages: vec!["en_US.UTF-8".into(), "de_DE.UTF-8".into()],
            disk_size: Some(10 * 1024 * 1024 * 1024),
            disk_usage: Some(3 * 1024 * 1024 * 1024),
            disk_free: Some(512 * 1024 * 1024),
            next_try: Some(NextTry::In("5min".into())),
            auth_limit_burst: Some(30),
            auth_limit_interval: Some("1min".into()),
            auto_resize_mode: Some(AutoResizeMode::Grow),
            rebalance_weight: Some(250),
            ssh_authorized_keys_count: 2,
            pkcs11_token_uri: vec!["pkcs11:token=main".into()],
            hashed_password: vec!["$y$j9T$...".into()],
            service: Some("io.systemd.Home".into()),
            effective_self_modifiable_fields: Some(vec!["realName".into()]),
            effective_self_modifiable_blobs: Some(Vec::new()),
            ..Default::default()
        };

        let rendered = user_record_show(&record, true);
        assert!(rendered.contains("User name: lennart@example.com"));
        assert!(rendered.contains("Alias: poettering, lp"));
        assert!(rendered.contains("State: \u{1b}[1;32mactive\u{1b}[0m"));
        assert!(rendered.contains("Disposition: regular"));
        assert!(rendered.contains("Login OK: \u{1b}[1;32myes\u{1b}[0m"));
        assert!(rendered.contains("Password OK: \u{1b}[1;33mexpires soon\u{1b}[0m"));
        assert!(rendered.contains("GID: 1000 (users)"));
        assert!(rendered.contains("Aux. Groups: wheel"));
        assert!(rendered.contains("Passw. Hint: dog name"));
        assert!(rendered.contains("Disk Usage: 3.0G (= 30.0%)"));
        assert!(rendered.contains("Disk Free: \u{1b}[1;31m512M (= 5.0%)\u{1b}[0m"));
        assert!(rendered.contains("Auth. Limit: 30 attempts per 1min"));
        assert!(rendered.contains("Auto Resize: grow"));
        assert!(rendered.contains("Rebalance: weight 250"));
        assert!(rendered.contains("SSH Pub. Key: 2"));
        assert!(rendered.contains("PKCS11 Token: pkcs11:token=main"));
        assert!(rendered.contains("Passwords: 1"));
        assert!(rendered.contains("Service: io.systemd.Home"));
        assert!(rendered.contains("disabled by administrator"));
    }

    #[test]
    fn user_record_show_handles_password_none_for_regular_users() {
        let record = UserRecord {
            user_name: "alice".into(),
            user_name_and_realm: "alice".into(),
            disposition: UserDisposition::Regular,
            login_status: LoginStatus::Locked,
            password_status: PasswordStatus::NoneSet,
            ..Default::default()
        };

        let rendered = user_record_show(&record, false);
        assert!(rendered.contains("record is locked"));
        assert!(rendered.contains("Password OK: \u{1b}[1mno\u{1b}[0m (none set)"));
        assert!(rendered.contains("Passwords: \u{1b}[1;33mnone\u{1b}[0m"));
    }

    #[test]
    fn group_record_show_renders_members_admins_and_uuid() {
        let mut record = GroupRecord::new();
        record.group_name = Some("wheel".into());
        record.group_name_and_realm_auto = Some("wheel@example.com".into());
        record.gid = 10;
        record.uuid = [
            0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55,
        ];
        record.members = vec!["alice".into(), "bob".into()];
        record.administrators = vec!["root".into()];
        record.description = Some("wheel admins".into());
        record.hashed_password = vec!["hash".into()];
        record.service = Some("io.systemd.UserDatabase".into());

        let rendered = group_record_show(&record, false);
        assert!(rendered.contains("Group name: wheel@example.com"));
        assert!(rendered.contains("Disposition: system"));
        assert!(rendered.contains("GID: 10"));
        assert!(rendered.contains("UUID: 11111111-2222-3333-4444-555555555555"));
        assert!(rendered.contains("Members: alice"));
        assert!(rendered.contains("Admins: root"));
        assert!(rendered.contains("Passwords: 1"));
        assert!(rendered.contains("Service: io.systemd.UserDatabase"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn user_record_show_table_aligns_columns() {
        let first = UserRecord {
            user_name: "alice".into(),
            user_name_and_realm: "alice".into(),
            uid: Some(1000),
            gid: Some(1000),
            state: Some("active".into()),
            storage: Some(UserStorage::Directory),
            home_directory: Some("/home/alice".into()),
            ..Default::default()
        };
        let second = UserRecord {
            user_name: "service-account".into(),
            user_name_and_realm: "service-account@example.com".into(),
            uid: Some(999),
            gid: Some(999),
            state: Some("locked".into()),
            storage: Some(UserStorage::LUKS),
            home_directory: Some("/srv/service".into()),
            ..Default::default()
        };

        let rendered = user_record_show_table(&[first, second]);
        assert!(rendered.contains("USER                        UID  GID  STATE   STORAGE   HOME"));
        assert!(rendered.contains("alice"));
        assert!(rendered.contains("service-account@example.com"));
    }

    #[test]
    fn user_record_show_json_pretty_prints_and_preserves_escapes() {
        let rendered =
            user_record_show_json(r#"{"user":"alice","flags":[true,null,"a\n b"]}"#).unwrap();
        assert_eq!(
            rendered,
            "{\n  \"user\": \"alice\",\n  \"flags\": [\n    true,\n    null,\n    \"a\\n b\"\n  ]\n}"
        );
    }

    #[test]
    fn user_record_show_json_rejects_invalid_json() {
        let error = user_record_show_json(r#"{"user":}"#).unwrap_err();
        assert!(
            error.message.contains("unexpected character") || error.message.contains("expected")
        );
    }

    #[test]
    fn source_is_embedded() {
        assert!(SOURCE_TEXT.contains("user_record_show(UserRecord *hr"));
    }
}
