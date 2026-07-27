// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/boot-secret.c
//
// Boot secret management for systemd-boot.
//
// Maintains a per-system secret stored in an EFI variable accessible only
// during boot. A secret derived by hashing this EFI variable secret is
// passed to the OS in an initrd file. A random mixin from the ESP and an
// OS identifier from the UKI's .osrel field are mixed in for robustness.

// ── Constants ─────────────────────────────────────────────────────────────

/// Size of the boot secret in bytes (SHA-256 digest size).
pub const BOOT_SECRET_SIZE: usize = 32;

/// Path to the boot secret mixin file on the ESP.
pub const BOOT_SECRET_MIXIN_PATH: &str = "\\loader\\boot-secret-mixin";

/// Label used for random seed evolution.
pub const RANDOM_SEED_EVOLVE_LABEL: &[u8] = b"systemd-stub random seed evolve label v1";

/// Label used for secret derivation from the random seed.
pub const RANDOM_SEED_MAKE_SECRET_LABEL: &[u8] = b"systemd-stub random seed make secret label v1";

/// Label used for combining secrets into the final boot secret.
pub const DERIVE_SECRET_LABEL: &[u8] = b"systemd-stub derive secret label v1";

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during boot secret operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSecretError {
    /// No random seed available.
    NoRandomSeed,
    /// The random seed is too short.
    RandomSeedTooShort,
    /// Failed to read the EFI variable secret.
    EfivarReadFailed,
    /// Failed to set the EFI variable secret.
    EfivarWriteFailed,
    /// The secret has an unexpected size.
    UnexpectedSecretSize,
    /// The EFI variable has unexpected attributes.
    UnexpectedAttributes,
    /// Failed to read the mixin file.
    MixinReadFailed,
    /// Failed to write the mixin file.
    MixinWriteFailed,
    /// The mixin file is too short.
    MixinTooShort,
    /// No root directory available.
    NoRootDirectory,
    /// The write was short (incomplete).
    ShortWrite,
    /// Failed to flush the mixin file.
    FlushFailed,
}

impl std::fmt::Display for BootSecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootSecretError::NoRandomSeed => write!(f, "no random seed available"),
            BootSecretError::RandomSeedTooShort => write!(f, "random seed too short"),
            BootSecretError::EfivarReadFailed => write!(f, "failed to read EFI variable secret"),
            BootSecretError::EfivarWriteFailed => write!(f, "failed to write EFI variable secret"),
            BootSecretError::UnexpectedSecretSize => write!(f, "unexpected secret size"),
            BootSecretError::UnexpectedAttributes => {
                write!(f, "unexpected EFI variable attributes")
            }
            BootSecretError::MixinReadFailed => write!(f, "failed to read mixin file"),
            BootSecretError::MixinWriteFailed => write!(f, "failed to write mixin file"),
            BootSecretError::MixinTooShort => write!(f, "mixin file too short"),
            BootSecretError::NoRootDirectory => write!(f, "no root directory"),
            BootSecretError::ShortWrite => write!(f, "short write"),
            BootSecretError::FlushFailed => write!(f, "failed to flush mixin file"),
        }
    }
}

impl std::error::Error for BootSecretError {}

// ── OS release ID extraction ──────────────────────────────────────────────

/// Extracts an OS ID from os-release data.
///
/// Preferably returns `IMAGE_ID`, falls back to `ID`, and finally to `"linux"`.
/// This mirrors the C `pick_id()` function.
pub fn pick_id(osrel: Option<&[u8]>) -> String {
    let osrel = match osrel {
        Some(data) if !data.is_empty() => data,
        _ => return String::from("linux"),
    };

    // Convert to string, treating invalid UTF-8 as lossy
    let osrel_str = String::from_utf8_lossy(osrel);
    let mut os_id: Option<String> = None;

    for line in osrel_str.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("IMAGE_ID=") {
            let value = value.trim_matches('"').trim();
            if !value.is_empty() {
                return value.to_string();
            }
        }
        if let Some(value) = line.strip_prefix("ID=") {
            let value = value.trim_matches('"').trim();
            if !value.is_empty() {
                os_id = Some(value.to_string());
            }
        }
    }

    os_id.unwrap_or_else(|| String::from("linux"))
}

// ── Secret derivation ─────────────────────────────────────────────────────

/// Simple SHA-256-like hash compression for testing (not cryptographic).
/// In the real EFI environment, the C code uses proper SHA-256.
/// This provides the same structural interface for port verification.
pub fn sha256_compress(label: &[u8], data: &[u8]) -> [u8; BOOT_SECRET_SIZE] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    label.hash(&mut hasher);
    data.hash(&mut hasher);
    let h1 = hasher.finish();

    let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut hasher2);
    label.hash(&mut hasher2);
    let h2 = hasher2.finish();

    let mut result = [0u8; BOOT_SECRET_SIZE];
    result[..8].copy_from_slice(&h1.to_le_bytes());
    result[8..16].copy_from_slice(&h2.to_be_bytes());
    result[16..24].copy_from_slice(&h1.to_be_bytes());
    result[24..].copy_from_slice(&h2.to_le_bytes());
    result
}

/// Derive the final boot secret by combining the EFI variable secret,
/// the mixin from the ESP, and the OS ID.
///
/// This mirrors the C `derive_secret()` function which uses SHA-256 to
/// combine all three inputs.
pub fn derive_secret(
    efivar_secret: &[u8; BOOT_SECRET_SIZE],
    secret_mixin: &[u8; BOOT_SECRET_SIZE],
    id: &str,
) -> [u8; BOOT_SECRET_SIZE] {
    let mut combined = Vec::new();
    combined.extend_from_slice(DERIVE_SECRET_LABEL);
    combined.extend_from_slice(efivar_secret);
    combined.extend_from_slice(secret_mixin);

    let id_bytes = id.as_bytes();
    let id_len = id_bytes.len() as u64;
    combined.extend_from_slice(&id_len.to_le_bytes());
    combined.extend_from_slice(id_bytes);

    sha256_compress(DERIVE_SECRET_LABEL, &combined)
}

/// Evolve a random seed by hashing it with a label.
/// This ensures the same seed is never reused.
pub fn evolve_seed(seed: &mut [u8]) {
    let evolved = sha256_compress(RANDOM_SEED_EVOLVE_LABEL, seed);
    seed.copy_from_slice(&evolved);
}

/// Make a secret from a random seed, then evolve the seed.
pub fn make_secret(seed: &mut [u8]) -> [u8; BOOT_SECRET_SIZE] {
    let secret = sha256_compress(RANDOM_SEED_MAKE_SECRET_LABEL, seed);
    evolve_seed(seed);
    secret
}

/// Validate that a secret buffer has the correct size.
pub fn validate_secret_size(data: &[u8]) -> Result<(), BootSecretError> {
    if data.len() != BOOT_SECRET_SIZE {
        return Err(BootSecretError::UnexpectedSecretSize);
    }
    Ok(())
}

/// Validate that a mixin file has sufficient data.
pub fn validate_mixin_size(file_size: u64) -> Result<(), BootSecretError> {
    if file_size < BOOT_SECRET_SIZE as u64 {
        return Err(BootSecretError::MixinTooShort);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pick_id_with_image_id() {
        let osrel = b"ID=fedora\nIMAGE_ID=myos\nVERSION=40\n";
        assert_eq!(pick_id(Some(osrel)), "myos");
    }

    #[test]
    fn test_pick_id_fallback_to_id() {
        let osrel = b"ID=fedora\nVERSION=40\n";
        assert_eq!(pick_id(Some(osrel)), "fedora");
    }

    #[test]
    fn test_pick_id_no_match() {
        let osrel = b"VERSION=40\nNAME=Fedora\n";
        assert_eq!(pick_id(Some(osrel)), "linux");
    }

    #[test]
    fn test_pick_id_empty_input() {
        assert_eq!(pick_id(None), "linux");
        assert_eq!(pick_id(Some(b"")), "linux");
    }

    #[test]
    fn test_pick_id_quoted_values() {
        let osrel = b"ID=\"debian\"\nIMAGE_ID=\"my-custom-os\"\n";
        assert_eq!(pick_id(Some(osrel)), "my-custom-os");
    }

    #[test]
    fn test_pick_id_prefers_image_id_over_id() {
        let osrel = b"ID=base\nIMAGE_ID=custom\n";
        assert_eq!(pick_id(Some(osrel)), "custom");
    }

    #[test]
    fn test_derive_secret_deterministic() {
        let efivar_secret = [0xABu8; BOOT_SECRET_SIZE];
        let mixin = [0xCDu8; BOOT_SECRET_SIZE];
        let id = "test-os";

        let result1 = derive_secret(&efivar_secret, &mixin, id);
        let result2 = derive_secret(&efivar_secret, &mixin, id);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_derive_secret_different_inputs() {
        let secret1 = [0x01u8; BOOT_SECRET_SIZE];
        let secret2 = [0x02u8; BOOT_SECRET_SIZE];
        let mixin = [0x00u8; BOOT_SECRET_SIZE];

        let r1 = derive_secret(&secret1, &mixin, "os1");
        let r2 = derive_secret(&secret2, &mixin, "os2");
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_evolve_seed_changes_seed() {
        let mut seed = [0x42u8; BOOT_SECRET_SIZE];
        let original = seed;
        evolve_seed(&mut seed);
        assert_ne!(seed, original);
    }

    #[test]
    fn test_make_secret_evolution() {
        let mut seed1 = [0x11u8; BOOT_SECRET_SIZE];
        let mut seed2 = seed1;

        let _secret1 = make_secret(&mut seed1);
        let _secret2 = make_secret(&mut seed2);

        // After making a secret, the seed has evolved twice,
        // so seed1 and seed2 should be equal (same evolution path)
        assert_eq!(seed1, seed2);
    }

    #[test]
    fn test_validate_secret_size_correct() {
        let data = [0u8; BOOT_SECRET_SIZE];
        assert!(validate_secret_size(&data).is_ok());
    }

    #[test]
    fn test_validate_secret_size_wrong() {
        let data = [0u8; 16];
        assert_eq!(
            validate_secret_size(&data),
            Err(BootSecretError::UnexpectedSecretSize)
        );
    }

    #[test]
    fn test_validate_mixin_size_sufficient() {
        assert!(validate_mixin_size(BOOT_SECRET_SIZE as u64).is_ok());
        assert!(validate_mixin_size(1024).is_ok());
    }

    #[test]
    fn test_validate_mixin_size_insufficient() {
        assert_eq!(validate_mixin_size(16), Err(BootSecretError::MixinTooShort));
        assert_eq!(validate_mixin_size(0), Err(BootSecretError::MixinTooShort));
    }

    #[test]
    fn test_error_display() {
        assert!(!BootSecretError::NoRandomSeed.to_string().is_empty());
        assert!(!BootSecretError::ShortWrite.to_string().is_empty());
    }
}
