// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/machine-id-setup/machine-id-setup-main.c
//
// Initialize /etc/machine-id from a random source.
//
// Supports: generating a new machine ID, committing a transient ID,
// printing the current ID, and operating on alternate roots or images.

// ── Error type ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

// ── Machine ID ────────────────────────────────────────────────────────────

/// A 128-bit machine identifier represented as 16 bytes.
pub type MachineId = [u8; 16];

pub const NULL_MACHINE_ID: MachineId = [0u8; 16];

pub fn is_null_machine_id(id: &MachineId) -> bool {
    id == &NULL_MACHINE_ID
}

pub fn is_valid_machine_id_str(id: &str) -> bool {
    id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn format_machine_id(id: &MachineId) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn parse_machine_id(s: &str) -> Result<MachineId> {
    if !is_valid_machine_id_str(s) {
        return Err(Errno(-libc::EINVAL));
    }
    let mut id = [0u8; 16];
    for i in 0..16 {
        id[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| Errno(-libc::EINVAL))?;
    }
    Ok(id)
}

pub fn format_machine_id_uuid(id: &MachineId) -> String {
    let h = format_machine_id(id);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

// ── Action ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineIdAction {
    Initialize,
    Commit,
}

// ── Setup arguments ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MachineIdSetupArgs {
    pub root: Option<String>,
    pub image: Option<String>,
    pub commit: bool,
    pub print: bool,
}

impl MachineIdSetupArgs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.root.is_some() && self.image.is_some() {
            return Err(Errno(-libc::EINVAL));
        }
        Ok(())
    }

    pub fn determine_action(&self) -> MachineIdAction {
        if self.commit {
            MachineIdAction::Commit
        } else {
            MachineIdAction::Initialize
        }
    }
}

// ── Machine ID state detection ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineIdState {
    NotInitialized,
    Initialized(MachineId),
    Uninitialized,
}

pub fn detect_machine_id_state(content: &str) -> MachineIdState {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return MachineIdState::NotInitialized;
    }
    if trimmed.chars().all(|c| c == '0') {
        return MachineIdState::Uninitialized;
    }
    match parse_machine_id(trimmed) {
        Ok(id) => MachineIdState::Initialized(id),
        Err(_) => MachineIdState::NotInitialized,
    }
}

// ── Image policy ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePolicy {
    pub policy_string: String,
}

impl ImagePolicy {
    pub fn new(s: &str) -> Self {
        Self {
            policy_string: s.to_string(),
        }
    }
}

// ── Path validation ───────────────────────────────────────────────────────

pub fn is_valid_root_path(path: &str) -> bool {
    !path.is_empty() && path.starts_with('/')
}

pub fn is_valid_image_path(path: &str) -> bool {
    !path.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_and_parse_roundtrip() {
        let id: MachineId = [
            0xf4, 0x7a, 0xc1, 0x0b, 0x58, 0xcc, 0x45, 0x82, 0xae, 0x85, 0x1e, 0x73, 0x96, 0xc8,
            0x05, 0x1d,
        ];
        let formatted = format_machine_id(&id);
        assert_eq!(formatted, "f47ac10b58cc4582ae851e7396c8051d");
        let parsed = parse_machine_id(&formatted).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn valid_machine_id_str() {
        assert!(is_valid_machine_id_str("f47ac10b58cc4582ae851e7396c8051d"));
        assert!(!is_valid_machine_id_str("abc"));
        assert!(!is_valid_machine_id_str("gggggggggggggggggggggggggggggggg"));
    }

    #[test]
    fn null_machine_id() {
        assert!(is_null_machine_id(&NULL_MACHINE_ID));
        assert!(!is_null_machine_id(&[1u8; 16]));
    }

    #[test]
    fn format_uuid() {
        let id: MachineId = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let uuid = format_machine_id_uuid(&id);
        assert_eq!(uuid, "01234567-89ab-cdef-fedc-ba9876543210");
    }

    #[test]
    fn default_args_validate() {
        let args = MachineIdSetupArgs::new();
        assert!(args.validate().is_ok());
        assert!(!args.commit);
        assert!(!args.print);
    }

    #[test]
    fn root_and_image_conflict() {
        let args = MachineIdSetupArgs {
            root: Some("/".into()),
            image: Some("disk.img".into()),
            ..Default::default()
        };
        assert!(args.validate().is_err());
    }

    #[test]
    fn determine_action_commit() {
        let args = MachineIdSetupArgs {
            commit: true,
            ..Default::default()
        };
        assert_eq!(args.determine_action(), MachineIdAction::Commit);
    }

    #[test]
    fn determine_action_initialize() {
        let args = MachineIdSetupArgs::new();
        assert_eq!(args.determine_action(), MachineIdAction::Initialize);
    }

    #[test]
    fn detect_state_initialized() {
        let state = detect_machine_id_state("f47ac10b58cc4582ae851e7396c8051d\n");
        match state {
            MachineIdState::Initialized(id) => {
                assert_eq!(id[0], 0xf4);
            }
            _ => panic!("expected Initialized"),
        }
    }

    #[test]
    fn detect_state_uninitialized() {
        let state = detect_machine_id_state("00000000000000000000000000000000\n");
        assert_eq!(state, MachineIdState::Uninitialized);
    }

    #[test]
    fn detect_state_empty() {
        let state = detect_machine_id_state("");
        assert_eq!(state, MachineIdState::NotInitialized);
    }

    #[test]
    fn valid_paths() {
        assert!(is_valid_root_path("/mnt"));
        assert!(!is_valid_root_path(""));
        assert!(!is_valid_root_path("relative"));
        assert!(is_valid_image_path("disk.img"));
    }
}
