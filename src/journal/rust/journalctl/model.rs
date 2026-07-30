// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::BTreeSet;
use systemd_shared_rs::output_mode::OutputMode;

pub(crate) const ARG_LINES_DEFAULT: i32 = -2;
pub(crate) const ARG_LINES_ALL: i32 = -1;
pub(crate) const PAGER_DISABLE: u32 = 1 << 0;
pub(crate) const PAGER_JUMP_TO_END: u32 = 1 << 1;
pub(crate) const SD_JSON_FORMAT_OFF: u64 = 1 << 0;
pub(crate) const SD_JSON_FORMAT_COLOR_AUTO: u64 = 1 << 5;
pub(crate) const SD_JOURNAL_SYSTEM: u32 = 1 << 2;
pub(crate) const SD_JOURNAL_CURRENT_USER: u32 = 1 << 3;
pub(crate) const SD_JOURNAL_ALL_NAMESPACES: u32 = 1 << 5;
pub(crate) const SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE: u32 = 1 << 6;
pub(crate) const SD_JOURNAL_ASSUME_IMMUTABLE: u32 = 1 << 8;
pub(crate) const ID128_HEX_LEN: usize = 32;
pub(crate) const LOG_DEBUG: i32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternCase {
    Auto,
    Sensitive,
    Insensitive,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // SAFETY: as_mut_vec() grants mutable access to valid UTF-8 bytes.
        unsafe {
            self.0.as_mut_vec().fill(b'x');
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalctlAction {
    Show,
    NewId128,
    SetupKeys,
    ListCatalog,
    DumpCatalog,
    UpdateCatalog,
    PrintHeader,
    Verify,
    DiskUsage,
    ListBoots,
    ListFields,
    ListFieldNames,
    ListInvocations,
    ListNamespaces,
    Flush,
    RelinquishVar,
    Sync,
    Rotate,
    Vacuum,
    RotateAndVacuum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdDescriptor {
    pub id: Option<[u8; 16]>,
    pub offset: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseIdDescriptorError {
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLines {
    pub value: i32,
    pub oldest_first: bool,
    pub explicit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalctlArgs {
    pub action: JournalctlAction,
    pub output: OutputMode,
    pub json_format_flags: u64,
    pub pager_flags: u32,
    pub follow: bool,
    pub full: bool,
    pub all: bool,
    pub lines: i32,
    pub lines_oldest: bool,
    pub no_tail: bool,
    pub truncate_newline: bool,
    pub quiet: bool,
    pub merge: bool,
    pub boot: i8,
    // Tracks an explicit --boot restriction separately from the implicit boot
    // default selected for follow/dmesg/pager-end modes.
    pub boot_filter: bool,
    pub boot_id: Option<[u8; 16]>,
    pub boot_offset: i32,
    pub invocation: bool,
    pub invocation_id: Option<[u8; 16]>,
    pub invocation_offset: i32,
    pub dmesg: bool,
    pub no_hostname: bool,
    pub show_cursor: bool,
    pub utc: bool,
    pub catalog: bool,
    pub reverse: bool,
    pub case: PatternCase,
    pub directory: Option<String>,
    pub file: Vec<String>,
    pub file_stdin: bool,
    pub machine: Option<String>,
    pub root: Option<String>,
    pub image: Option<String>,
    pub image_policy: Option<String>,
    pub namespace_flags: u32,
    pub namespace: Option<String>,
    pub priorities_mask: u32,
    pub facilities: BTreeSet<u8>,
    pub cursor: Option<String>,
    pub cursor_file: Option<String>,
    pub after_cursor: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub syslog_identifier: Vec<String>,
    pub exclude_identifier: Vec<String>,
    pub system_units: Vec<String>,
    pub user_units: Vec<String>,
    pub field: Option<String>,
    pub pattern: Option<String>,
    pub output_fields: BTreeSet<String>,
    pub synchronize_on_exit: bool,
    pub verify_key: Option<SecretString>,
    pub interval: Option<String>,
    pub force: bool,
    pub smart_relinquish_var: bool,
    pub journal_type: u32,
    pub journal_additional_open_flags: u32,
    pub positional_matches: Vec<String>,
    pub vacuum_size: u64,
    pub vacuum_n_files: u64,
    pub vacuum_time: u64,
}

impl Default for JournalctlArgs {
    fn default() -> Self {
        Self {
            action: JournalctlAction::Show,
            output: OutputMode::Short,
            json_format_flags: SD_JSON_FORMAT_OFF,
            pager_flags: 0,
            follow: false,
            full: true,
            all: false,
            lines: ARG_LINES_DEFAULT,
            lines_oldest: false,
            no_tail: false,
            truncate_newline: false,
            quiet: false,
            merge: false,
            boot: -1,
            boot_filter: false,
            boot_id: None,
            boot_offset: 0,
            invocation: false,
            invocation_id: None,
            invocation_offset: 0,
            dmesg: false,
            no_hostname: false,
            show_cursor: false,
            utc: false,
            catalog: false,
            reverse: false,
            case: PatternCase::Auto,
            directory: None,
            file: Vec::new(),
            file_stdin: false,
            machine: None,
            root: None,
            image: None,
            image_policy: None,
            namespace_flags: 0,
            namespace: None,
            priorities_mask: 0,
            facilities: BTreeSet::new(),
            cursor: None,
            cursor_file: None,
            after_cursor: None,
            since: None,
            until: None,
            syslog_identifier: Vec::new(),
            exclude_identifier: Vec::new(),
            system_units: Vec::new(),
            user_units: Vec::new(),
            field: None,
            pattern: None,
            output_fields: BTreeSet::new(),
            synchronize_on_exit: false,
            verify_key: None,
            interval: None,
            force: false,
            smart_relinquish_var: false,
            journal_type: 0,
            journal_additional_open_flags: 0,
            positional_matches: Vec::new(),
            vacuum_size: 0,
            vacuum_n_files: 0,
            vacuum_time: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// PORT-RATIONALE: parse_argv() returns this public C-shaped result directly to
// callers. Boxing its successful payload would add allocation and change the
// established parser API without making the owned argument state safer.
#[allow(clippy::large_enum_variant)]
pub enum ParseArgvResult {
    Parsed(JournalctlArgs),
    HelpRequested,
    VersionRequested,
    OutputModeHelpRequested,
    FacilitiesHelpRequested,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseArgvError {
    Invalid(&'static str),
}
