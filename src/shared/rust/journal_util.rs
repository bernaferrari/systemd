// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/journal-util.c, src/shared/journal-util.h, src/shared/logs-show.c
//
use std::fmt;

pub const JOURNAL_FILES_MAX: u32 = 7168;
pub const RUNTIME_JOURNAL_DIR: &str = "/run/log/journal";
pub const PERSISTENT_JOURNAL_DIR: &str = "/var/log/journal";

type Result<T> = std::result::Result<T, JournalUtilError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalUtilError {
    InvalidArgument(&'static str),
    PermissionDenied(&'static str),
    MissingBootId,
    InvalidBootId(String),
}

impl fmt::Display for JournalUtilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(arg) => write!(f, "invalid argument: {arg}"),
            Self::PermissionDenied(msg) => write!(f, "permission denied: {msg}"),
            Self::MissingBootId => write!(f, "missing boot ID"),
            Self::InvalidBootId(value) => write!(f, "invalid boot ID: {value}"),
        }
    }
}

impl std::error::Error for JournalUtilError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalAccessScope {
    SystemOnly,
    SystemAndOtherUsers,
}

impl JournalAccessScope {
    fn hidden_subject(self) -> &'static str {
        match self {
            Self::SystemOnly => "the system",
            Self::SystemAndOtherUsers => "other users and the system",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalDirectory {
    Runtime,
    Persistent,
}

impl JournalDirectory {
    pub fn path(self) -> &'static str {
        match self {
            Self::Runtime => RUNTIME_JOURNAL_DIR,
            Self::Persistent => PERSISTENT_JOURNAL_DIR,
        }
    }
}

pub fn preferred_journal_directory(runtime_journal_exists: bool) -> JournalDirectory {
    if runtime_journal_exists {
        JournalDirectory::Runtime
    } else {
        JournalDirectory::Persistent
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalUserContext {
    pub is_root: bool,
    pub in_systemd_journal_group: bool,
    pub acl_groups: Vec<String>,
    pub runtime_journal_exists: bool,
}

impl JournalUserContext {
    pub fn visible_to_all(&self) -> bool {
        self.is_root || self.in_systemd_journal_group
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalFileProblem {
    PermissionDenied,
    Truncated,
    UnsupportedFeature,
    Corrupted,
    TooManyFiles,
    Other(i32),
}

impl JournalFileProblem {
    pub fn from_errno(errno: i32) -> Self {
        match errno.abs() {
            x if x == libc::EACCES => Self::PermissionDenied,
            x if x == libc::ENODATA => Self::Truncated,
            x if x == libc::EPROTONOSUPPORT => Self::UnsupportedFeature,
            x if x == libc::EBADMSG => Self::Corrupted,
            x if x == libc::ETOOMANYREFS => Self::TooManyFiles,
            other => Self::Other(other),
        }
    }

    pub fn warning_message(&self, path: &str) -> Option<String> {
        match self {
            Self::PermissionDenied => None,
            Self::Truncated => Some(format!(
                "Journal file {path} is truncated, ignoring file."
            )),
            Self::UnsupportedFeature => Some(format!(
                "Journal file {path} uses an unsupported feature, ignoring file.\nUse SYSTEMD_LOG_LEVEL=debug journalctl --file={path} to see the details."
            )),
            Self::Corrupted => Some(format!("Journal file {path} corrupted, ignoring file.")),
            Self::TooManyFiles => Some(format!(
                "Too many journal files (limit is at {JOURNAL_FILES_MAX}) in scope, ignoring file '{path}'."
            )),
            Self::Other(errno) => Some(format!(
                "An error was encountered while opening journal file or directory {path}, ignoring file: errno({errno})"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalOpenFailure {
    pub path: String,
    pub problem: JournalFileProblem,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalAccessCheck {
    pub return_code: i32,
    pub notices: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JournalAccessSummary {
    pub opened_files: usize,
    pub failures: Vec<JournalOpenFailure>,
}

impl JournalAccessSummary {
    pub fn is_empty(&self) -> bool {
        self.opened_files == 0 && self.failures.is_empty()
    }

    pub fn access_blocked(&self) -> bool {
        self.failures
            .iter()
            .any(|failure| failure.problem == JournalFileProblem::PermissionDenied)
    }

    pub fn check_and_warn(
        &self,
        quiet: bool,
        scope: JournalAccessScope,
        user: &JournalUserContext,
    ) -> JournalAccessCheck {
        let mut check = JournalAccessCheck {
            return_code: 0,
            notices: Vec::new(),
            warnings: Vec::new(),
        };

        if self.failures.is_empty() {
            if self.opened_files == 0 && !quiet {
                check.notices.push("No journal files were found.".into());
            }
            return check;
        }

        if self.access_blocked() {
            if !quiet {
                if let Some(hint) = journal_access_hint(user, scope) {
                    check.notices.push(hint);
                }
            }

            if self.opened_files == 0 {
                check.return_code = -libc::EACCES;
                check
                    .warnings
                    .push("No journal files were opened due to insufficient permissions.".into());
            }
        }

        check.warnings.extend(
            self.failures
                .iter()
                .filter_map(|failure| failure.problem.warning_message(&failure.path)),
        );

        check
    }
}

pub fn journal_access_hint(user: &JournalUserContext, scope: JournalAccessScope) -> Option<String> {
    if user.visible_to_all() {
        return None;
    }

    let mut groups = user
        .acl_groups
        .iter()
        .map(|group| group.trim())
        .filter(|group| !group.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    if !groups.is_empty() {
        groups.push("systemd-journal".into());
        groups.sort();
        groups.dedup();

        return Some(format!(
            "Hint: You are currently not seeing messages from {}.\n      Users in groups '{}' can see all messages.\n      Pass -q to turn off this notice.",
            scope.hidden_subject(),
            groups.join("', '")
        ));
    }

    Some(format!(
        "Hint: You are currently not seeing messages from {}.\n      Users in the 'systemd-journal' group can see all messages. Pass -q to\n      turn off this notice.",
        scope.hidden_subject(),
    ))
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct JournalOpenFlags: u32 {
        const OS_ROOT = 1 << 6;
        const TAKE_DIRECTORY_FD = 1 << 7;
        const INCLUDE_DEFAULT_NAMESPACE = 1 << 8;
        const ASSUME_IMMUTABLE = 1 << 9;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceOpenOptions {
    pub namespace: Option<String>,
    pub flags: JournalOpenFlags,
}

pub fn normalize_namespace(namespace: Option<&str>) -> Result<Option<String>> {
    match namespace.map(str::trim) {
        None | Some("") => Ok(None),
        Some(value) if value.bytes().any(|b| b == 0) => {
            Err(JournalUtilError::InvalidArgument("namespace contains NUL"))
        }
        Some(value) => Ok(Some(value.to_string())),
    }
}

pub fn journal_access_merged(namespace: Option<&str>, flags: JournalOpenFlags) -> bool {
    normalize_namespace(namespace).ok().flatten().is_some()
        && flags.contains(JournalOpenFlags::INCLUDE_DEFAULT_NAMESPACE)
}

pub fn namespace_open_options(
    namespace: Option<&str>,
    extra_flags: JournalOpenFlags,
) -> Result<NamespaceOpenOptions> {
    Ok(NamespaceOpenOptions {
        namespace: normalize_namespace(namespace)?,
        flags: extra_flags,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootId(pub [u8; 16]);

impl BootId {
    pub const NULL: Self = Self([0; 16]);

    pub fn is_null(self) -> bool {
        self == Self::NULL
    }

    pub fn parse(input: &str) -> Result<Self> {
        let compact = input.trim().replace('-', "");
        if compact.len() != 32 || !compact.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(JournalUtilError::InvalidBootId(input.to_string()));
        }

        let mut bytes = [0u8; 16];
        for (idx, chunk) in compact.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(chunk)
                .map_err(|_| JournalUtilError::InvalidBootId(input.to_string()))?;
            bytes[idx] = u8::from_str_radix(pair, 16)
                .map_err(|_| JournalUtilError::InvalidBootId(input.to_string()))?;
        }

        Ok(Self(bytes))
    }

    pub fn as_match(self) -> String {
        format!("_BOOT_ID={self}")
    }
}

impl fmt::Display for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalMatchExpression {
    pub matches: Vec<String>,
    pub append_conjunction: bool,
}

pub fn journal_boot_id_filter(
    requested: Option<BootId>,
    current_boot: Option<BootId>,
) -> Result<JournalMatchExpression> {
    let boot_id = match requested {
        Some(id) if !id.is_null() => id,
        _ => current_boot.ok_or(JournalUtilError::MissingBootId)?,
    };

    Ok(JournalMatchExpression {
        matches: vec![boot_id.as_match()],
        append_conjunction: true,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineJournalOpenPlan {
    pub machine: String,
    pub flags: JournalOpenFlags,
}

impl MachineJournalOpenPlan {
    pub fn new(machine: &str, caller_is_root: bool, extra_flags: JournalOpenFlags) -> Result<Self> {
        let machine = machine.trim();
        if machine.is_empty() {
            return Err(JournalUtilError::InvalidArgument("machine"));
        }
        if !caller_is_root {
            return Err(JournalUtilError::PermissionDenied(
                "using --machine requires root privileges",
            ));
        }

        Ok(Self {
            machine: machine.to_string(),
            flags: JournalOpenFlags::OS_ROOT | JournalOpenFlags::TAKE_DIRECTORY_FD | extra_flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_context() -> JournalUserContext {
        JournalUserContext {
            is_root: false,
            in_systemd_journal_group: false,
            acl_groups: Vec::new(),
            runtime_journal_exists: true,
        }
    }

    #[test]
    fn preferred_runtime_directory_wins() {
        assert_eq!(
            preferred_journal_directory(true).path(),
            RUNTIME_JOURNAL_DIR
        );
    }

    #[test]
    fn preferred_persistent_directory_is_fallback() {
        assert_eq!(
            preferred_journal_directory(false).path(),
            PERSISTENT_JOURNAL_DIR
        );
    }

    #[test]
    fn root_user_gets_no_access_hint() {
        let mut user = user_context();
        user.is_root = true;
        assert_eq!(
            journal_access_hint(&user, JournalAccessScope::SystemOnly),
            None
        );
    }

    #[test]
    fn journal_group_user_gets_no_access_hint() {
        let mut user = user_context();
        user.in_systemd_journal_group = true;
        assert_eq!(
            journal_access_hint(&user, JournalAccessScope::SystemOnly),
            None
        );
    }

    #[test]
    fn acl_groups_are_sorted_and_deduplicated_in_hint() {
        let mut user = user_context();
        user.acl_groups = vec!["wheel".into(), "adm".into(), "wheel".into()];

        let hint = journal_access_hint(&user, JournalAccessScope::SystemAndOtherUsers).unwrap();

        assert!(hint.contains("other users and the system"));
        assert!(hint.contains("groups 'adm', 'systemd-journal', 'wheel'"));
    }

    #[test]
    fn fallback_hint_mentions_systemd_journal_group() {
        let hint = journal_access_hint(&user_context(), JournalAccessScope::SystemOnly).unwrap();
        assert!(hint.contains("systemd-journal"));
        assert!(hint.contains("the system"));
    }

    #[test]
    fn access_blocked_detects_eacces_failure() {
        let summary = JournalAccessSummary {
            opened_files: 1,
            failures: vec![JournalOpenFailure {
                path: "a.journal".into(),
                problem: JournalFileProblem::PermissionDenied,
            }],
        };

        assert!(summary.access_blocked());
    }

    #[test]
    fn empty_summary_warns_about_missing_files() {
        let check = JournalAccessSummary::default().check_and_warn(
            false,
            JournalAccessScope::SystemOnly,
            &user_context(),
        );

        assert_eq!(check.return_code, 0);
        assert_eq!(check.notices, vec!["No journal files were found."]);
        assert!(check.warnings.is_empty());
    }

    #[test]
    fn permission_denied_without_opened_files_returns_eacces() {
        let summary = JournalAccessSummary {
            opened_files: 0,
            failures: vec![JournalOpenFailure {
                path: "denied.journal".into(),
                problem: JournalFileProblem::PermissionDenied,
            }],
        };

        let check = summary.check_and_warn(false, JournalAccessScope::SystemOnly, &user_context());

        assert_eq!(check.return_code, -libc::EACCES);
        assert_eq!(check.warnings.len(), 1);
        assert!(check.warnings[0].contains("insufficient permissions"));
        assert_eq!(check.notices.len(), 1);
    }

    #[test]
    fn warning_messages_cover_all_problem_kinds() {
        let failures = vec![
            JournalOpenFailure {
                path: "truncated.journal".into(),
                problem: JournalFileProblem::Truncated,
            },
            JournalOpenFailure {
                path: "feature.journal".into(),
                problem: JournalFileProblem::UnsupportedFeature,
            },
            JournalOpenFailure {
                path: "corrupt.journal".into(),
                problem: JournalFileProblem::Corrupted,
            },
            JournalOpenFailure {
                path: "many.journal".into(),
                problem: JournalFileProblem::TooManyFiles,
            },
            JournalOpenFailure {
                path: "other.journal".into(),
                problem: JournalFileProblem::Other(libc::EIO),
            },
        ];

        let summary = JournalAccessSummary {
            opened_files: 1,
            failures,
        };
        let check = summary.check_and_warn(true, JournalAccessScope::SystemOnly, &user_context());

        assert_eq!(check.warnings.len(), 5);
        assert!(check.warnings.iter().any(|w| w.contains("truncated")));
        assert!(check
            .warnings
            .iter()
            .any(|w| w.contains("unsupported feature")));
        assert!(check.warnings.iter().any(|w| w.contains("corrupted")));
        assert!(check
            .warnings
            .iter()
            .any(|w| w.contains("limit is at 7168")));
        assert!(check.warnings.iter().any(|w| w.contains("errno(5)")));
    }

    #[test]
    fn namespace_normalization_maps_empty_to_default() {
        assert_eq!(normalize_namespace(None).unwrap(), None);
        assert_eq!(normalize_namespace(Some("   ")).unwrap(), None);
        assert_eq!(
            normalize_namespace(Some(" ns0 ")).unwrap(),
            Some("ns0".into())
        );
    }

    #[test]
    fn namespace_normalization_rejects_nul() {
        let err = normalize_namespace(Some("bad\0ns")).unwrap_err();
        assert!(matches!(err, JournalUtilError::InvalidArgument(_)));
    }

    #[test]
    fn merged_access_requires_named_namespace_and_flag() {
        assert!(journal_access_merged(
            Some("tenant"),
            JournalOpenFlags::INCLUDE_DEFAULT_NAMESPACE
        ));
        assert!(!journal_access_merged(
            Some("tenant"),
            JournalOpenFlags::empty()
        ));
        assert!(!journal_access_merged(
            None,
            JournalOpenFlags::INCLUDE_DEFAULT_NAMESPACE
        ));
    }

    #[test]
    fn namespace_open_options_preserve_flags() {
        let options = namespace_open_options(
            Some("tenant"),
            JournalOpenFlags::INCLUDE_DEFAULT_NAMESPACE | JournalOpenFlags::ASSUME_IMMUTABLE,
        )
        .unwrap();

        assert_eq!(options.namespace, Some("tenant".into()));
        assert!(options
            .flags
            .contains(JournalOpenFlags::INCLUDE_DEFAULT_NAMESPACE));
        assert!(options.flags.contains(JournalOpenFlags::ASSUME_IMMUTABLE));
    }

    #[test]
    fn boot_id_parses_compact_form() {
        let id = BootId::parse("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(id.to_string(), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn boot_id_parses_uuid_form() {
        let id = BootId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(id.to_string(), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn boot_id_parse_rejects_invalid_length() {
        let err = BootId::parse("abcd").unwrap_err();
        assert!(matches!(err, JournalUtilError::InvalidBootId(_)));
    }

    #[test]
    fn boot_id_filter_uses_requested_id() {
        let requested = BootId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let current = BootId::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();

        let expression = journal_boot_id_filter(Some(requested), Some(current)).unwrap();

        assert_eq!(
            expression.matches,
            vec!["_BOOT_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        );
        assert!(expression.append_conjunction);
    }

    #[test]
    fn boot_id_filter_falls_back_to_current_boot_for_null_request() {
        let current = BootId::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let expression = journal_boot_id_filter(Some(BootId::NULL), Some(current)).unwrap();

        assert_eq!(
            expression.matches,
            vec!["_BOOT_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
        );
    }

    #[test]
    fn boot_id_filter_requires_some_boot_id() {
        let err = journal_boot_id_filter(None, None).unwrap_err();
        assert_eq!(err, JournalUtilError::MissingBootId);
    }

    #[test]
    fn machine_open_plan_requires_root() {
        let err = MachineJournalOpenPlan::new("my-container", false, JournalOpenFlags::empty())
            .unwrap_err();
        assert!(matches!(err, JournalUtilError::PermissionDenied(_)));
    }

    #[test]
    fn machine_open_plan_adds_required_flags() {
        let plan =
            MachineJournalOpenPlan::new("my-container", true, JournalOpenFlags::ASSUME_IMMUTABLE)
                .unwrap();

        assert_eq!(plan.machine, "my-container");
        assert!(plan.flags.contains(JournalOpenFlags::OS_ROOT));
        assert!(plan.flags.contains(JournalOpenFlags::TAKE_DIRECTORY_FD));
        assert!(plan.flags.contains(JournalOpenFlags::ASSUME_IMMUTABLE));
    }
}
