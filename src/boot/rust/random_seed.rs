// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/random-seed.c
//
// Random seed processing for Linux EFI boot.
//
// This module currently contains the platform-independent derivation used by
// the UEFI implementation. It deliberately does not pretend that mutating an
// in-memory model has performed the EFI file and configuration-table updates.

use systemd_basic_rs::sha256_hmac::sha256;

// ── Constants ─────────────────────────────────────────────────────────────

pub const RANDOM_MAX_SIZE_MIN: usize = 32;
pub const RANDOM_MAX_SIZE_MAX: usize = 32 * 1024;
pub const HASH_VALUE_SIZE: usize = 32;
pub const DESIRED_SEED_SIZE: usize = 32;
pub const HASH_LABEL: &[u8] = b"systemd-boot random seed label v1";

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomSeedError {
    NotFound,
    WriteProtected,
    FileTooLarge,
    ShortRead,
    ShortWrite,
    InvalidParameter,
    RngNotReady,
    NoRng,
    SystemTokenTooShort,
    ProtocolError,
    OutOfMemory,
    UnsupportedPlatform,
}

impl std::fmt::Display for RandomSeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RandomSeedError::NotFound => write!(f, "random seed not found"),
            RandomSeedError::WriteProtected => write!(f, "write protected"),
            RandomSeedError::FileTooLarge => write!(f, "random seed file too large"),
            RandomSeedError::ShortRead => write!(f, "short read"),
            RandomSeedError::ShortWrite => write!(f, "short write"),
            RandomSeedError::InvalidParameter => write!(f, "invalid parameter"),
            RandomSeedError::RngNotReady => write!(f, "RNG not ready"),
            RandomSeedError::NoRng => write!(f, "no RNG available"),
            RandomSeedError::SystemTokenTooShort => write!(f, "system token too short"),
            RandomSeedError::ProtocolError => write!(f, "protocol error"),
            RandomSeedError::OutOfMemory => write!(f, "out of memory"),
            RandomSeedError::UnsupportedPlatform => {
                write!(f, "UEFI random-seed side effects are not implemented")
            }
        }
    }
}

impl std::error::Error for RandomSeedError {}

/// Input model for a UEFI RNG source.
#[derive(Debug, Clone, Default)]
pub struct RngSource {
    pub available: bool,
    pub ready: bool,
    pub data: Vec<u8>,
}

/// Input model for LoaderSystemToken.
#[derive(Debug, Clone, Default)]
pub struct SystemToken {
    pub available: bool,
    pub data: Vec<u8>,
}

/// Input model for `\loader\random-seed`.
#[derive(Debug, Clone, Default)]
pub struct SeedFile {
    pub exists: bool,
    pub writable: bool,
    pub content: Vec<u8>,
    pub newly_created: bool,
}

/// Combined random seed processing context
#[derive(Debug, Clone, Default)]
pub struct RandomSeedContext {
    pub rng: RngSource,
    pub system_token: SystemToken,
    pub seed_file: SeedFile,
    pub secure_boot_enabled: bool,
    pub uefi_monotonic_counter: u64,
    pub monotonic_counter_available: bool,
    pub previous_seed: Vec<u8>,
    /// Raw bytes of an `EFI_TIME`, including its padding bytes.
    pub uefi_time: Option<[u8; 16]>,
    pub seed_table_installed: bool,
    pub written_seed: Option<Vec<u8>>,
}

impl RandomSeedContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_no_rng(mut self) -> Self {
        self.rng.available = false;
        self
    }

    pub fn with_rng_not_ready(mut self) -> Self {
        self.rng.ready = false;
        self
    }

    pub fn with_no_seed_file(mut self) -> Self {
        self.seed_file.exists = false;
        self
    }

    pub fn with_secure_boot(mut self, enabled: bool) -> Self {
        self.secure_boot_enabled = enabled;
        self
    }

    pub fn with_previous_seed(mut self, size: usize) -> Self {
        self.previous_seed = vec![0; size];
        self
    }

    pub fn with_short_system_token(mut self) -> Self {
        self.system_token.data = vec![0x01; 8];
        self
    }

    pub fn with_no_system_token(mut self) -> Self {
        self.system_token.available = false;
        self
    }
}

// ── Validation helpers ────────────────────────────────────────────────────

pub fn validate_seed_file_size(size: usize) -> Result<(), RandomSeedError> {
    if size > RANDOM_MAX_SIZE_MAX {
        return Err(RandomSeedError::FileTooLarge);
    }
    Ok(())
}

pub fn is_created_fresh(file_size: usize) -> bool {
    file_size < RANDOM_MAX_SIZE_MIN
}

// ── Seed processing logic ─────────────────────────────────────────────────

/// Determine if we can proceed when RNG is unavailable
pub fn can_proceed_without_rng(seeded_by_efi: bool, secure_boot: bool) -> bool {
    if seeded_by_efi {
        return true;
    }
    !secure_boot
}

/// Determine if we're seeded by EFI (previous seed >= DESIRED_SEED_SIZE)
pub fn is_seeded_by_efi(previous_seed_size: usize) -> bool {
    previous_seed_size >= DESIRED_SEED_SIZE
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedSeeds {
    /// The replacement written to the first 32 bytes of the ESP seed file.
    pub disk_seed: [u8; DESIRED_SEED_SIZE],
    /// The seed installed in the Linux EFI random-seed configuration table.
    pub efi_seed: [u8; DESIRED_SEED_SIZE],
    /// Whether the UEFI backend must create the seed file.
    pub create_seed_file: bool,
    /// Bytes beyond `disk_seed` which the backend must overwrite with zeroes.
    pub trailing_bytes_to_zero: usize,
}

fn append_framed(transcript: &mut Vec<u8>, value: Option<&[u8]>) -> Result<(), RandomSeedError> {
    let value = value.unwrap_or_default();
    transcript
        .try_reserve(std::mem::size_of::<usize>() + value.len())
        .map_err(|_| RandomSeedError::OutOfMemory)?;
    transcript.extend_from_slice(&value.len().to_ne_bytes());
    transcript.extend_from_slice(value);
    Ok(())
}

/// Derive the two seeds using the exact framing in `src/boot/random-seed.c`.
///
/// The framing is `LABEL || native-size_t(length) || value ...`. The
/// monotonic counter and raw `EFI_TIME` bytes use their native in-memory byte
/// representation, just as the C implementation does. This function is pure:
/// callers still have to write and flush the ESP file, install the EFI table,
/// and erase the previous table in that order.
pub fn derive_seed_material(ctx: &RandomSeedContext) -> Result<DerivedSeeds, RandomSeedError> {
    let previous = (!ctx.previous_seed.is_empty()).then_some(ctx.previous_seed.as_slice());
    let seeded_by_previous = is_seeded_by_efi(ctx.previous_seed.len());

    let rng = if ctx.rng.available && ctx.rng.ready {
        if ctx.rng.data.len() != DESIRED_SEED_SIZE {
            return Err(RandomSeedError::InvalidParameter);
        }
        Some(ctx.rng.data.as_slice())
    } else {
        None
    };

    if rng.is_none() && !can_proceed_without_rng(seeded_by_previous, ctx.secure_boot_enabled) {
        return Err(RandomSeedError::NotFound);
    }
    let seeded_by_efi = seeded_by_previous || rng.is_some();

    let system_token = ctx
        .system_token
        .available
        .then_some(ctx.system_token.data.as_slice());
    if system_token.is_none_or(|token| token.len() < DESIRED_SEED_SIZE) && !seeded_by_efi {
        return Err(RandomSeedError::SystemTokenTooShort);
    }

    let create_seed_file = !ctx.seed_file.exists;
    if create_seed_file && !seeded_by_efi {
        return Err(RandomSeedError::NotFound);
    }
    if !ctx.seed_file.writable {
        return Err(RandomSeedError::WriteProtected);
    }

    let seed_file = if create_seed_file
        || ctx.seed_file.newly_created
        || is_created_fresh(ctx.seed_file.content.len())
    {
        None
    } else {
        validate_seed_file_size(ctx.seed_file.content.len())?;
        Some(ctx.seed_file.content.as_slice())
    };

    if !ctx.monotonic_counter_available && !seeded_by_efi {
        return Err(RandomSeedError::ProtocolError);
    }
    let monotonic_counter = if ctx.monotonic_counter_available {
        ctx.uefi_monotonic_counter
    } else {
        // The C variable is initialized to zero and is still framed when the
        // firmware call fails after another EFI entropy source succeeded.
        0
    };
    let monotonic_bytes = monotonic_counter.to_ne_bytes();

    let mut transcript = Vec::new();
    transcript
        .try_reserve(HASH_LABEL.len())
        .map_err(|_| RandomSeedError::OutOfMemory)?;
    transcript.extend_from_slice(HASH_LABEL);
    append_framed(&mut transcript, previous)?;
    append_framed(&mut transcript, rng)?;
    append_framed(&mut transcript, system_token)?;
    append_framed(&mut transcript, seed_file)?;
    append_framed(&mut transcript, Some(&monotonic_bytes))?;
    append_framed(
        &mut transcript,
        ctx.uefi_time.as_ref().map(|time| time.as_slice()),
    )?;

    let mut hash_key = sha256(&transcript);
    transcript.fill(0);

    let mut expansion = [0_u8; HASH_VALUE_SIZE + 1];
    expansion[..HASH_VALUE_SIZE].copy_from_slice(&hash_key);
    expansion[HASH_VALUE_SIZE] = 0;
    let disk_seed = sha256(&expansion);
    expansion[HASH_VALUE_SIZE] = 1;
    let efi_seed = sha256(&expansion);
    expansion.fill(0);
    hash_key.fill(0);

    Ok(DerivedSeeds {
        disk_seed,
        efi_seed,
        create_seed_file,
        trailing_bytes_to_zero: seed_file
            .map(|seed| seed.len().saturating_sub(DESIRED_SEED_SIZE))
            .unwrap_or(0),
    })
}

/// The Rust boot crate does not yet provide the UEFI file/table backend needed
/// to perform the security-critical side effects. Fail closed until it does.
pub fn process_random_seed(_ctx: &mut RandomSeedContext) -> Result<(), RandomSeedError> {
    Err(RandomSeedError::UnsupportedPlatform)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_context() -> RandomSeedContext {
        RandomSeedContext {
            rng: RngSource {
                available: true,
                ready: true,
                data: vec![0x42; DESIRED_SEED_SIZE],
            },
            system_token: SystemToken {
                available: true,
                data: vec![0xab; DESIRED_SEED_SIZE],
            },
            seed_file: SeedFile {
                exists: true,
                writable: true,
                content: vec![0x55; DESIRED_SEED_SIZE],
                newly_created: false,
            },
            monotonic_counter_available: true,
            ..RandomSeedContext::default()
        }
    }

    #[test]
    fn test_validate_seed_file_size_valid() {
        assert!(validate_seed_file_size(32).is_ok());
        assert!(validate_seed_file_size(1024).is_ok());
    }

    #[test]
    fn test_validate_seed_file_size_too_large() {
        assert_eq!(
            validate_seed_file_size(RANDOM_MAX_SIZE_MAX + 1),
            Err(RandomSeedError::FileTooLarge)
        );
    }

    #[test]
    fn test_is_created_fresh() {
        assert!(is_created_fresh(0));
        assert!(is_created_fresh(16));
        assert!(!is_created_fresh(32));
        assert!(!is_created_fresh(64));
    }

    #[test]
    fn test_can_proceed_without_rng_seeded() {
        assert!(can_proceed_without_rng(true, true));
        assert!(can_proceed_without_rng(true, false));
    }

    #[test]
    fn test_can_proceed_without_rng_not_seeded_no_secure_boot() {
        assert!(can_proceed_without_rng(false, false));
    }

    #[test]
    fn test_can_proceed_without_rng_not_seeded_secure_boot() {
        assert!(!can_proceed_without_rng(false, true));
    }

    #[test]
    fn test_is_seeded_by_efi() {
        assert!(is_seeded_by_efi(32));
        assert!(is_seeded_by_efi(64));
        assert!(!is_seeded_by_efi(0));
        assert!(!is_seeded_by_efi(16));
    }

    #[test]
    fn test_process_random_seed_fails_closed_without_uefi_backend() {
        let mut ctx = RandomSeedContext::new();
        assert_eq!(
            process_random_seed(&mut ctx),
            Err(RandomSeedError::UnsupportedPlatform)
        );
        assert!(!ctx.seed_table_installed);
        assert!(ctx.written_seed.is_none());
    }

    #[test]
    fn test_derive_no_rng_secure_boot_previous_seed() {
        let ctx = valid_context()
            .with_no_rng()
            .with_secure_boot(true)
            .with_previous_seed(DESIRED_SEED_SIZE);
        assert!(derive_seed_material(&ctx).is_ok());
    }

    #[test]
    fn test_derive_no_rng_secure_boot_no_previous() {
        let ctx = valid_context().with_no_rng().with_secure_boot(true);
        assert_eq!(derive_seed_material(&ctx), Err(RandomSeedError::NotFound));
    }

    #[test]
    fn test_derive_seed_file_too_large() {
        let mut ctx = valid_context();
        ctx.seed_file.content = vec![0u8; RANDOM_MAX_SIZE_MAX + 1];
        assert_eq!(
            derive_seed_material(&ctx),
            Err(RandomSeedError::FileTooLarge)
        );
    }

    #[test]
    fn test_derive_no_seed_file_not_seeded() {
        let ctx = valid_context().with_no_seed_file().with_no_rng();
        assert_eq!(derive_seed_material(&ctx), Err(RandomSeedError::NotFound));
    }

    #[test]
    fn test_sha256_vectors_from_c_validation() {
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn test_derives_distinct_disk_and_efi_seeds() {
        let derived = derive_seed_material(&valid_context()).unwrap();
        assert_ne!(derived.disk_seed, derived.efi_seed);
    }

    #[test]
    fn test_existing_long_file_tail_must_be_zeroed() {
        let mut ctx = valid_context();
        ctx.seed_file.content = vec![0x55; 100];
        let derived = derive_seed_material(&ctx).unwrap();
        assert!(!derived.create_seed_file);
        assert_eq!(derived.trailing_bytes_to_zero, 68);
    }
}
