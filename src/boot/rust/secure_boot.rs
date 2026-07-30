// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/secure-boot.c
//
// Secure Boot management for EFI boot loader.
//
// Provides Secure Boot state detection, mode enumeration, key enrollment,
// and security protocol override management for shim compatibility.

// ── Constants ─────────────────────────────────────────────────────────────

pub const ENROLL_OFF: u32 = 0;
pub const ENROLL_MANUAL: u32 = 1;
pub const ENROLL_IF_SAFE: u32 = 2;
pub const ENROLL_FORCE: u32 = 3;

pub const ENROLL_ACTION_REBOOT: u32 = 0;
pub const ENROLL_ACTION_SHUTDOWN: u32 = 1;

pub const ENROLL_TIMEOUT_HIDDEN: u64 = u64::MAX;

// ── Types ─────────────────────────────────────────────────────────────────

/// Secure boot mode (matches C SecureBootMode enum)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootMode {
    /// Secure boot is not supported on this firmware
    Unsupported,
    /// Secure boot is disabled
    Disabled,
    /// Firmware reported a combination of secure-boot state variables outside
    /// the UEFI-defined modes.
    Unknown,
    /// Shim has disabled verification even though firmware secure boot is on.
    Tainted,
    /// Secure boot is enabled, setup mode
    Setup,
    /// Secure boot is enabled, user mode
    User,
    /// Secure boot audit mode
    Audit,
    /// Secure boot deployed mode
    Deployed,
}

/// Error type for secure boot operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootError {
    FailedToEnableCustomMode,
    FailedToWriteVariable(&'static str),
    FailedToOpenDirectory,
    FailedToReadFile(&'static str),
    FailedToWriteKeys,
    UserInputError,
}

impl std::fmt::Display for SecureBootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureBootError::FailedToEnableCustomMode => write!(f, "failed to enable custom mode"),
            SecureBootError::FailedToWriteVariable(name) => {
                write!(f, "failed to write {} secure boot variable", name)
            }
            SecureBootError::FailedToOpenDirectory => write!(f, "failed to open keys directory"),
            SecureBootError::FailedToReadFile(name) => {
                write!(f, "failed to read file {}", name)
            }
            SecureBootError::FailedToWriteKeys => write!(f, "failed to write secure boot keys"),
            SecureBootError::UserInputError => write!(f, "error waiting for user input"),
        }
    }
}

impl std::error::Error for SecureBootError {}

/// Simulated EFI variable store for testing
#[derive(Debug, Clone)]
pub struct EfiVarStore {
    /// Whether reading the firmware `SecureBoot` variable succeeds.
    ///
    /// A failed read means the firmware does not expose Secure Boot state;
    /// that is distinct from a readable variable whose value is `false`.
    pub secure_boot_readable: bool,
    pub secure_boot: bool,
    pub audit_mode: bool,
    pub deployed_mode: bool,
    pub setup_mode: bool,
    pub mok_sb_state: bool,
    pub custom_mode: bool,
    pub in_hypervisor: bool,
}

impl Default for EfiVarStore {
    fn default() -> Self {
        Self {
            secure_boot_readable: true,
            secure_boot: false,
            audit_mode: false,
            deployed_mode: false,
            setup_mode: false,
            mok_sb_state: false,
            custom_mode: false,
            in_hypervisor: false,
        }
    }
}

impl EfiVarStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_secure_boot(mut self, enabled: bool) -> Self {
        self.secure_boot = enabled;
        self
    }

    pub fn with_secure_boot_readable(mut self, readable: bool) -> Self {
        self.secure_boot_readable = readable;
        self
    }

    pub fn with_setup_mode(mut self, enabled: bool) -> Self {
        self.setup_mode = enabled;
        self
    }

    pub fn with_audit_mode(mut self, enabled: bool) -> Self {
        self.audit_mode = enabled;
        self
    }

    pub fn with_deployed_mode(mut self, enabled: bool) -> Self {
        self.deployed_mode = enabled;
        self
    }

    pub fn with_mok_disabled(mut self, disabled: bool) -> Self {
        self.mok_sb_state = disabled;
        self
    }

    pub fn with_hypervisor(mut self, in_hyp: bool) -> Self {
        self.in_hypervisor = in_hyp;
        self
    }
}

/// Security override state (matches C `struct SecurityOverride`)
#[derive(Debug, Clone, Default)]
pub struct SecurityOverride {
    pub installed: bool,
    pub original_hook_installed: bool,
    pub original_hook2_installed: bool,
}

impl SecurityOverride {
    pub fn new() -> Self {
        Self::default()
    }
}

// ── Secure boot detection ─────────────────────────────────────────────────

/// Check if secure boot is enabled
pub fn secure_boot_enabled(vars: &EfiVarStore) -> bool {
    vars.secure_boot_readable && vars.secure_boot
}

/// Decode the secure boot mode from individual flags
/// Matches C `decode_secure_boot_mode`
pub fn decode_secure_boot_mode(
    secure: bool,
    audit: bool,
    deployed: bool,
    setup: bool,
    moksb: bool,
) -> SecureBootMode {
    // Keep this decision table in the same order as
    // `src/fundamental/efivars.c:decode_secure_boot_mode`.
    if secure && moksb {
        return SecureBootMode::Tainted;
    }
    if secure && deployed && !audit && !setup {
        return SecureBootMode::Deployed;
    }
    if secure && !deployed && !audit && !setup {
        return SecureBootMode::User;
    }
    if !secure && !deployed && audit && setup {
        return SecureBootMode::Audit;
    }
    if !secure && !deployed && !audit && setup {
        return SecureBootMode::Setup;
    }
    if !secure && !deployed && !audit && !setup {
        return SecureBootMode::Disabled;
    }
    SecureBootMode::Unknown
}

/// Determine the current secure boot mode
pub fn secure_boot_mode(vars: &EfiVarStore) -> SecureBootMode {
    if !vars.secure_boot_readable {
        return SecureBootMode::Unsupported;
    }
    decode_secure_boot_mode(
        vars.secure_boot,
        vars.audit_mode,
        vars.deployed_mode,
        vars.setup_mode,
        vars.mok_sb_state,
    )
}

/// Check if custom mode is enabled
pub fn custom_mode_enabled(vars: &EfiVarStore) -> bool {
    vars.custom_mode
}

// ── Enrollment string table ───────────────────────────────────────────────

pub fn secure_boot_enroll_to_string(action: u32) -> Option<&'static str> {
    match action {
        ENROLL_OFF => Some("off"),
        ENROLL_MANUAL => Some("manual"),
        ENROLL_IF_SAFE => Some("if-safe"),
        ENROLL_FORCE => Some("force"),
        _ => None,
    }
}

pub fn secure_boot_enroll_action_to_string(action: u32) -> Option<&'static str> {
    match action {
        ENROLL_ACTION_REBOOT => Some("reboot"),
        ENROLL_ACTION_SHUTDOWN => Some("shutdown"),
        _ => None,
    }
}

pub fn secure_boot_enroll_from_string(s: &str) -> Option<u32> {
    match s {
        "off" => Some(ENROLL_OFF),
        "manual" => Some(ENROLL_MANUAL),
        "if-safe" => Some(ENROLL_IF_SAFE),
        "force" => Some(ENROLL_FORCE),
        _ => None,
    }
}

// ── Security override management ──────────────────────────────────────────

/// Install security override hooks (matches C `install_security_override`)
pub fn install_security_override(
    secure_boot_on: bool,
    override_state: &mut SecurityOverride,
) -> bool {
    if !secure_boot_on {
        return false;
    }
    override_state.installed = true;
    override_state.original_hook_installed = true;
    override_state.original_hook2_installed = true;
    true
}

/// Check if security override is available (matches C `security_override_available`)
pub fn security_override_available(sec_proto_available: bool, sec2_proto_available: bool) -> bool {
    sec_proto_available && sec2_proto_available
}

/// Uninstall security override hooks (matches C `uninstall_security_override`)
pub fn uninstall_security_override(override_state: &mut SecurityOverride) {
    override_state.installed = false;
    override_state.original_hook_installed = false;
    override_state.original_hook2_installed = false;
}

// ── Enrollment decision logic ─────────────────────────────────────────────

/// Determine if enrollment should proceed
pub fn should_enroll(vars: &EfiVarStore, force: bool, action: u32) -> bool {
    if action == ENROLL_OFF {
        return false;
    }

    let is_safe = vars.in_hypervisor;

    if !is_safe && !force && action != ENROLL_FORCE {
        return false;
    }

    true
}

/// Check if PK signature needs custom mode
pub fn pk_needs_custom_mode(pk_buffer: &[u8]) -> bool {
    if pk_buffer.len() <= 20 {
        return false;
    }
    let sig_size = u32::from_le_bytes([pk_buffer[16], pk_buffer[17], pk_buffer[18], pk_buffer[19]]);
    sig_size <= 24
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_boot_enabled() {
        let vars = EfiVarStore::new().with_secure_boot(true);
        assert!(secure_boot_enabled(&vars));
    }

    #[test]
    fn test_secure_boot_disabled() {
        let vars = EfiVarStore::new().with_secure_boot(false);
        assert!(!secure_boot_enabled(&vars));
    }

    #[test]
    fn test_secure_boot_unreadable_is_not_enabled() {
        let vars = EfiVarStore::new()
            .with_secure_boot(true)
            .with_secure_boot_readable(false);
        assert!(!secure_boot_enabled(&vars));
    }

    #[test]
    fn test_secure_boot_mode_unsupported() {
        let vars = EfiVarStore::new().with_secure_boot_readable(false);
        assert_eq!(secure_boot_mode(&vars), SecureBootMode::Unsupported);
    }

    #[test]
    fn test_secure_boot_mode_disabled() {
        assert_eq!(
            secure_boot_mode(&EfiVarStore::new()),
            SecureBootMode::Disabled
        );
    }

    #[test]
    fn test_secure_boot_mode_user() {
        let vars = EfiVarStore::new().with_secure_boot(true);
        assert_eq!(secure_boot_mode(&vars), SecureBootMode::User);
    }

    #[test]
    fn test_secure_boot_mode_setup() {
        let vars = EfiVarStore::new().with_setup_mode(true);
        assert_eq!(secure_boot_mode(&vars), SecureBootMode::Setup);
    }

    #[test]
    fn test_secure_boot_mode_audit() {
        let vars = EfiVarStore::new()
            .with_audit_mode(true)
            .with_setup_mode(true);
        assert_eq!(secure_boot_mode(&vars), SecureBootMode::Audit);
    }

    #[test]
    fn test_secure_boot_mode_deployed() {
        let vars = EfiVarStore::new()
            .with_secure_boot(true)
            .with_deployed_mode(true);
        assert_eq!(secure_boot_mode(&vars), SecureBootMode::Deployed);
    }

    #[test]
    fn test_decode_secure_boot_mode_disabled() {
        assert_eq!(
            decode_secure_boot_mode(false, false, false, false, false),
            SecureBootMode::Disabled
        );
    }

    #[test]
    fn test_decode_secure_boot_mode_user() {
        assert_eq!(
            decode_secure_boot_mode(true, false, false, false, false),
            SecureBootMode::User
        );
    }

    #[test]
    fn test_decode_secure_boot_mode_setup() {
        assert_eq!(
            decode_secure_boot_mode(false, false, false, true, false),
            SecureBootMode::Setup
        );
    }

    #[test]
    fn test_decode_secure_boot_mode_audit() {
        assert_eq!(
            decode_secure_boot_mode(false, true, false, true, false),
            SecureBootMode::Audit
        );
    }

    #[test]
    fn test_decode_secure_boot_mode_tainted_overrides_other_flags() {
        assert_eq!(
            decode_secure_boot_mode(true, true, true, true, true),
            SecureBootMode::Tainted
        );
    }

    #[test]
    fn test_decode_secure_boot_mode_unknown_for_invalid_combination() {
        assert_eq!(
            decode_secure_boot_mode(true, true, false, false, false),
            SecureBootMode::Unknown
        );
    }

    #[test]
    fn test_install_security_override_not_needed() {
        let mut state = SecurityOverride::new();
        assert!(!install_security_override(false, &mut state));
        assert!(!state.installed);
    }

    #[test]
    fn test_install_security_override_needed() {
        let mut state = SecurityOverride::new();
        assert!(install_security_override(true, &mut state));
        assert!(state.installed);
    }

    #[test]
    fn test_uninstall_security_override() {
        let mut state = SecurityOverride::new();
        install_security_override(true, &mut state);
        uninstall_security_override(&mut state);
        assert!(!state.installed);
    }

    #[test]
    fn test_security_override_available_both() {
        assert!(security_override_available(true, true));
    }

    #[test]
    fn test_security_override_available_missing_one() {
        assert!(!security_override_available(true, false));
        assert!(!security_override_available(false, true));
    }

    #[test]
    fn test_enroll_to_string() {
        assert_eq!(secure_boot_enroll_to_string(ENROLL_OFF), Some("off"));
        assert_eq!(secure_boot_enroll_to_string(ENROLL_MANUAL), Some("manual"));
        assert_eq!(
            secure_boot_enroll_to_string(ENROLL_IF_SAFE),
            Some("if-safe")
        );
        assert_eq!(secure_boot_enroll_to_string(ENROLL_FORCE), Some("force"));
        assert_eq!(secure_boot_enroll_to_string(99), None);
    }

    #[test]
    fn test_enroll_action_to_string() {
        assert_eq!(
            secure_boot_enroll_action_to_string(ENROLL_ACTION_REBOOT),
            Some("reboot")
        );
        assert_eq!(
            secure_boot_enroll_action_to_string(ENROLL_ACTION_SHUTDOWN),
            Some("shutdown")
        );
    }

    #[test]
    fn test_enroll_from_string() {
        assert_eq!(secure_boot_enroll_from_string("off"), Some(ENROLL_OFF));
        assert_eq!(
            secure_boot_enroll_from_string("manual"),
            Some(ENROLL_MANUAL)
        );
        assert_eq!(
            secure_boot_enroll_from_string("if-safe"),
            Some(ENROLL_IF_SAFE)
        );
        assert_eq!(secure_boot_enroll_from_string("force"), Some(ENROLL_FORCE));
        assert_eq!(secure_boot_enroll_from_string("invalid"), None);
    }

    #[test]
    fn test_should_enroll_off() {
        let vars = EfiVarStore::new();
        assert!(!should_enroll(&vars, false, ENROLL_OFF));
    }

    #[test]
    fn test_should_enroll_in_hypervisor() {
        let vars = EfiVarStore::new().with_hypervisor(true);
        assert!(should_enroll(&vars, false, ENROLL_MANUAL));
    }

    #[test]
    fn test_should_enroll_forced() {
        let vars = EfiVarStore::new();
        assert!(should_enroll(&vars, true, ENROLL_MANUAL));
    }

    #[test]
    fn test_should_enroll_not_safe_no_force() {
        let vars = EfiVarStore::new();
        assert!(!should_enroll(&vars, false, ENROLL_MANUAL));
    }

    #[test]
    fn test_pk_needs_custom_mode_no_signature() {
        let pk = vec![0u8; 24];
        assert!(pk_needs_custom_mode(&pk));
    }

    #[test]
    fn test_pk_needs_custom_mode_with_signature() {
        let mut pk = vec![0u8; 64];
        pk[16..20].copy_from_slice(&100u32.to_le_bytes());
        assert!(!pk_needs_custom_mode(&pk));
    }

    #[test]
    fn test_pk_needs_custom_mode_too_short() {
        let pk = vec![0u8; 16];
        assert!(!pk_needs_custom_mode(&pk));
    }

    #[test]
    fn test_custom_mode_enabled() {
        let vars = EfiVarStore {
            custom_mode: true,
            ..EfiVarStore::default()
        };
        assert!(custom_mode_enabled(&vars));
    }
}
