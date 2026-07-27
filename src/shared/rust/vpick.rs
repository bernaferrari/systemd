// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/vpick.c, src/shared/vpick.h
//
// Version-picked file resolution (VPick).
//
// Resolves versioned filenames like "foo_1.3-7.raw" or "foo_1.3-7_x86-64.raw"
// to the latest/greatest version, supporting architecture discrimination
// and retry counters.
//
// Naming convention (BVAS: Basename, Version, Architecture, Suffix):
//   <basename><suffix>
//   <basename>_<version><suffix>
//   <basename>_<version>_<architecture><suffix>
//   <basename>_<architecture><suffix>
//
// The "_" separator is chosen because it is not used by Semver 2.0, RPM's
// "sortable" versions, or Debian package naming.

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors that can occur during vpick operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpickError {
    /// Memory allocation failed.
    OutOfMemory,
    /// Invalid argument supplied.
    InvalidArgument,
    /// Entry not found (ENOENT).
    NotFound,
    /// Not a directory (ENOTDIR).
    NotADirectory,
    /// Not a block device (ENOTBLK).
    NotABlockDevice,
    /// Not a socket (ENOTSOCK).
    NotASocket,
    /// Symbolic link loop (ELOOP).
    SymlinkLoop,
    /// Is a directory (EISDIR).
    IsADirectory,
    /// Bad file descriptor (EBADF).
    BadFileDescriptor,
    /// Operation not executable / underspecified (ENOEXEC).
    Underspecified,
    /// I/O error.
    IoError,
    /// Other OS error with raw errno.
    Other(i32),
}

impl std::fmt::Display for VpickError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpickError::OutOfMemory => write!(f, "out of memory"),
            VpickError::InvalidArgument => write!(f, "invalid argument"),
            VpickError::NotFound => write!(f, "no such file or directory"),
            VpickError::NotADirectory => write!(f, "not a directory"),
            VpickError::NotABlockDevice => write!(f, "not a block device"),
            VpickError::NotASocket => write!(f, "not a socket"),
            VpickError::SymlinkLoop => write!(f, "symbolic link loop"),
            VpickError::IsADirectory => write!(f, "is a directory"),
            VpickError::BadFileDescriptor => write!(f, "bad file descriptor"),
            VpickError::Underspecified => write!(f, "filter is underspecified"),
            VpickError::IoError => write!(f, "I/O error"),
            VpickError::Other(errno) => write!(f, "OS error (errno={})", errno),
        }
    }
}

impl std::error::Error for VpickError {}

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum tries value sentinel — means "unlimited / not applicable".
pub const TRIES_MAX: u32 = u32::MAX;

// ── Inode types ────────────────────────────────────────────────────────────

/// Filesystem inode type classification (mirrors `DT_*` constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InodeType {
    Unknown = 0,
    Fifo = 1,
    Chr = 2,
    Dir = 4,
    Blk = 6,
    Reg = 8,
    Lnk = 10,
    Sock = 12,
    Wht = 14,
}

impl InodeType {
    /// Create an [`InodeType`] from a raw `DT_*` value.
    pub fn from_dt_raw(dt: u8) -> Self {
        match dt {
            1 => InodeType::Fifo,
            2 => InodeType::Chr,
            4 => InodeType::Dir,
            6 => InodeType::Blk,
            8 => InodeType::Reg,
            10 => InodeType::Lnk,
            12 => InodeType::Sock,
            14 => InodeType::Wht,
            _ => InodeType::Unknown,
        }
    }

    /// Bit position in a type mask (`1u32 << InodeType as u32`).
    pub fn mask_bit(self) -> u32 {
        1u32 << (self as u32)
    }

    /// Convert a Unix `st_mode` value to the corresponding [`InodeType`].
    pub fn from_mode(mode: u32) -> Self {
        match mode & 0o170_000 {
            0o010_000 => InodeType::Fifo,
            0o020_000 => InodeType::Chr,
            0o040_000 => InodeType::Dir,
            0o060_000 => InodeType::Blk,
            0o100_000 => InodeType::Reg,
            0o120_000 => InodeType::Lnk,
            0o140_000 => InodeType::Sock,
            _ => InodeType::Unknown,
        }
    }
}

// ── Architecture ───────────────────────────────────────────────────────────

/// CPU architecture identifier. Mirrors the C `Architecture` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Arm64,
    Aarch64,
    IA64,
    LoongArch64,
    Mips,
    Mips64,
    MipsLe,
    Mips64Le,
    Parisc,
    Ppc,
    Ppc64,
    Ppc64Le,
    Riscv32,
    Riscv64,
    S390,
    S390x,
    Alpha,
    Arc,
    Tilegx,
    Native,
    /// Sentinel: no specific / any architecture.
    Invalid,
}

impl Architecture {
    /// Try to parse an architecture from its canonical string name.
    pub fn from_str_canonical(s: &str) -> Option<Self> {
        // Normalize: lowercase
        let s = s.to_ascii_lowercase();
        Some(match s.as_str() {
            "x86" => Architecture::X86,
            "x86-64" | "x86_64" => Architecture::X86_64,
            "arm" => Architecture::Arm,
            "arm64" | "aarch64" => Architecture::Arm64,
            "ia64" => Architecture::IA64,
            "loongarch64" => Architecture::LoongArch64,
            "mips" => Architecture::Mips,
            "mips64" => Architecture::Mips64,
            "mips-le" | "mipsel" => Architecture::MipsLe,
            "mips64-le" | "mips64el" => Architecture::Mips64Le,
            "parisc" | "hppa" => Architecture::Parisc,
            "ppc" | "powerpc" => Architecture::Ppc,
            "ppc64" | "powerpc64" => Architecture::Ppc64,
            "ppc64-le" | "ppc64le" | "powerpc64le" => Architecture::Ppc64Le,
            "riscv32" => Architecture::Riscv32,
            "riscv64" => Architecture::Riscv64,
            "s390" => Architecture::S390,
            "s390x" => Architecture::S390x,
            "alpha" => Architecture::Alpha,
            "arc" => Architecture::Arc,
            "tilegx" => Architecture::Tilegx,
            "native" => Architecture::Native,
            "any" => Architecture::Invalid,
            _ => return None,
        })
    }

    /// Return the canonical string for this architecture.
    pub fn as_str(self) -> &'static str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X86_64 => "x86-64",
            Architecture::Arm => "arm",
            Architecture::Arm64 => "arm64",
            Architecture::Aarch64 => "aarch64",
            Architecture::IA64 => "ia64",
            Architecture::LoongArch64 => "loongarch64",
            Architecture::Mips => "mips",
            Architecture::Mips64 => "mips64",
            Architecture::MipsLe => "mips-le",
            Architecture::Mips64Le => "mips64-le",
            Architecture::Parisc => "parisc",
            Architecture::Ppc => "ppc",
            Architecture::Ppc64 => "ppc64",
            Architecture::Ppc64Le => "ppc64-le",
            Architecture::Riscv32 => "riscv32",
            Architecture::Riscv64 => "riscv64",
            Architecture::S390 => "s390",
            Architecture::S390x => "s390x",
            Architecture::Alpha => "alpha",
            Architecture::Arc => "arc",
            Architecture::Tilegx => "tilegx",
            Architecture::Native => "native",
            Architecture::Invalid => "any",
        }
    }
}

// ── Pick flags ─────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling the version-pick behaviour.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PickFlags: u32 {
        /// Look for an architecture suffix in filenames.
        const PICK_ARCHITECTURE = 1 << 0;
        /// Look for tries-left / tries-done counters.
        const PICK_TRIES = 1 << 1;
        /// Return the fully resolved (chased) path rather than the entry path.
        const PICK_RESOLVE = 1 << 2;
    }
}

// ── Pick filter ────────────────────────────────────────────────────────────

/// Filter criteria for version-pick lookups.
///
/// Each field may be `None` to indicate "don't care".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickFilter {
    /// Bitmask of acceptable inode types (`InodeType::mask_bit()`).
    pub type_mask: u32,
    /// Basename prefix for matching (e.g. `"foo"` in `foo_1.0.raw`).
    pub basename: Option<String>,
    /// Exact version string to match, or `None` for "latest".
    pub version: Option<String>,
    /// Architecture to match, or `None` for "any / native".
    pub architecture: Option<Architecture>,
    /// Filename suffix (e.g. `".raw"`).
    pub suffix: Option<String>,
}

impl PickFilter {
    /// Create a new filter with all fields set to "don't care".
    pub fn new() -> Self {
        Self {
            type_mask: 0,
            basename: None,
            version: None,
            architecture: None,
            suffix: None,
        }
    }

    /// Builder-style: set the inode type mask.
    pub fn with_type_mask(mut self, mask: u32) -> Self {
        self.type_mask = mask;
        self
    }

    /// Builder-style: set the basename.
    pub fn with_basename(mut self, basename: impl Into<String>) -> Self {
        self.basename = Some(basename.into());
        self
    }

    /// Builder-style: set the version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Builder-style: set the architecture.
    pub fn with_architecture(mut self, arch: Architecture) -> Self {
        self.architecture = Some(arch);
        self
    }

    /// Builder-style: set the suffix.
    pub fn with_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.suffix = Some(suffix.into());
        self
    }

    /// Returns `true` if the filter is fully specified enough to
    /// construct an exact filename (i.e. `version` is set and
    /// `PICK_TRIES` is not requested).
    pub fn is_fully_specified(&self, flags: PickFlags) -> bool {
        if flags.contains(PickFlags::PICK_TRIES) {
            return false;
        }
        self.version.is_some()
    }
}

impl Default for PickFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Pick result ────────────────────────────────────────────────────────────

/// A resolved pick result after version selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickResult {
    /// Resolved path relative to the toplevel directory.
    pub path: Option<String>,
    /// Detected (or requested) version string.
    pub version: Option<String>,
    /// Architecture that was matched.
    pub architecture: Architecture,
    /// Remaining tries left (sentinel `TRIES_MAX` = unlimited).
    pub tries_left: u32,
    /// Tries already done (sentinel `TRIES_MAX` = N/A).
    pub tries_done: u32,
}

impl PickResult {
    /// A "null" / empty result indicating no match.
    pub fn null() -> Self {
        Self {
            path: None,
            version: None,
            architecture: Architecture::Invalid,
            tries_left: TRIES_MAX,
            tries_done: TRIES_MAX,
        }
    }

    /// Returns `true` if this result represents a successful match.
    pub fn is_match(&self) -> bool {
        self.path.is_some()
    }
}

impl Default for PickResult {
    fn default() -> Self {
        Self::null()
    }
}

// ── Preset filters ─────────────────────────────────────────────────────────

/// Filter for raw disk image files (regular files or block devices).
pub fn pick_filter_image_raw() -> PickFilter {
    PickFilter {
        type_mask: InodeType::Reg.mask_bit() | InodeType::Blk.mask_bit(),
        basename: None,
        version: None,
        architecture: Some(Architecture::Invalid),
        suffix: Some(".raw".into()),
    }
}

/// Filter for directory images.
pub fn pick_filter_image_dir() -> PickFilter {
    PickFilter {
        type_mask: InodeType::Dir.mask_bit(),
        basename: None,
        version: None,
        architecture: Some(Architecture::Invalid),
        suffix: None,
    }
}

/// Filter for mstack directory images.
pub fn pick_filter_image_mstack() -> PickFilter {
    PickFilter {
        type_mask: InodeType::Dir.mask_bit(),
        basename: None,
        version: None,
        architecture: Some(Architecture::Invalid),
        suffix: Some(".mstack".into()),
    }
}

/// Convenience: all image filters combined (raw, mstack, dir).
pub fn pick_filter_image_any() -> Vec<PickFilter> {
    vec![
        pick_filter_image_raw(),
        pick_filter_image_mstack(),
        pick_filter_image_dir(),
    ]
}

// ── Version comparison ─────────────────────────────────────────────────────

/// Improved version string comparison (`strverscmp`-like).
///
/// Compares two version strings segment by segment. Numeric segments are
/// compared by value (with leading-zero handling), non-numeric segments
/// bytewise.
///
/// Returns `> 0` if `a` is newer, `< 0` if `b` is newer, `0` if equal.
pub fn strverscmp_improved(a: &str, b: &str) -> i32 {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut ai: usize = 0;
    let mut bi: usize = 0;

    loop {
        // Skip leading zeros in both strings
        while ai < a_bytes.len() && a_bytes[ai] == b'0' {
            ai += 1;
        }
        while bi < b_bytes.len() && b_bytes[bi] == b'0' {
            bi += 1;
        }

        // Count digit run lengths
        let mut a_digits = 0usize;
        while ai + a_digits < a_bytes.len() && a_bytes[ai + a_digits].is_ascii_digit() {
            a_digits += 1;
        }
        let mut b_digits = 0usize;
        while bi + b_digits < b_bytes.len() && b_bytes[bi + b_digits].is_ascii_digit() {
            b_digits += 1;
        }

        // More digits = bigger number
        if a_digits != b_digits {
            return if a_digits > b_digits { 1 } else { -1 };
        }

        // Compare digit by digit
        for j in 0..a_digits {
            let av = a_bytes[ai + j];
            let bv = b_bytes[bi + j];
            if av != bv {
                return (av as i32) - (bv as i32);
            }
        }

        ai += a_digits;
        bi += b_digits;

        // End of either string
        if ai >= a_bytes.len() || bi >= b_bytes.len() {
            if ai < a_bytes.len() {
                return 1;
            }
            if bi < b_bytes.len() {
                return -1;
            }
            return 0;
        }

        // Compare non-digit characters
        if a_bytes[ai] != b_bytes[bi] {
            return (a_bytes[ai] as i32) - (b_bytes[bi] as i32);
        }

        ai += 1;
        bi += 1;
    }
}

// ── Pick result comparison ─────────────────────────────────────────────────

/// Compare two [`PickResult`] values to determine which is "better".
///
/// Returns `> 0` if `a` is the better pick, `< 0` if `b` is better, `0` if equal.
///
/// Comparison priority (first non-zero wins):
/// 1. Prefer entries with tries left (if `PICK_TRIES` flag set)
/// 2. Prefer newer versions
/// 3. Prefer native architecture (if `PICK_ARCHITECTURE` flag set)
/// 4. Prefer more tries left (if `PICK_TRIES`)
/// 5. Prefer fewer tries done (if `PICK_TRIES`)
/// 6. Compare filenames lexicographically
pub fn pick_result_compare(
    a: &PickResult,
    b: &PickResult,
    flags: PickFlags,
    native_arch: Architecture,
) -> i32 {
    let mut d = 0i32;

    // 1. Prefer entries with tries left over those without
    if flags.contains(PickFlags::PICK_TRIES) {
        d = cmp_bool(a.tries_left != TRIES_MAX, b.tries_left != TRIES_MAX);
    }

    // 2. Prefer newer versions
    if d == 0 {
        d = strverscmp_improved(
            a.version.as_deref().unwrap_or(""),
            b.version.as_deref().unwrap_or(""),
        );
    }

    // 3. Prefer native architectures
    if flags.contains(PickFlags::PICK_ARCHITECTURE) {
        if d == 0 {
            d = cmp_bool(a.architecture == native_arch, b.architecture == native_arch);
        }
    }

    // 4. Prefer entries with more tries left
    if flags.contains(PickFlags::PICK_TRIES) {
        if d == 0 {
            d = cmp_u32(a.tries_left, b.tries_left);
        }

        // 5. Prefer entries with fewer attempts done
        if d == 0 {
            d = -cmp_u32(a.tries_done, b.tries_done);
        }
    }

    // 6. Lexicographic filename comparison
    if d == 0 {
        d = cmp_option_str(&a.path, &b.path);
    }

    d
}

/// Three-way comparison of `bool`s (`true` > `false`).
fn cmp_bool(a: bool, b: bool) -> i32 {
    match (a, b) {
        (true, false) => 1,
        (false, true) => -1,
        _ => 0,
    }
}

/// Three-way comparison of `u32` values.
fn cmp_u32(a: u32, b: u32) -> i32 {
    a.cmp(&b) as i32
}

/// Three-way comparison of optional string references.
fn cmp_option_str(a: &Option<String>, b: &Option<String>) -> i32 {
    match (a.as_deref(), b.as_deref()) {
        (Some(av), Some(bv)) => av.cmp(bv) as i32,
        (Some(_), None) => 1,
        (None, Some(_)) => -1,
        (None, None) => 0,
    }
}

// ── Filename formatting ────────────────────────────────────────────────────

/// Construct the expected filename from filter components.
///
/// Produces one of:
/// - `<basename><suffix>`
/// - `<basename>_<version><suffix>`
/// - `<basename>_<version>_<architecture><suffix>`
/// - `<basename>_<architecture><suffix>`
///
/// Returns an error if the filter is underspecified (no version, or PICK_TRIES
/// requested).
pub fn format_fname(filter: &PickFilter, flags: PickFlags) -> Result<String, VpickError> {
    if flags.contains(PickFlags::PICK_TRIES) || filter.version.is_none() {
        return Err(VpickError::Underspecified);
    }

    let mut fn_buf = String::new();

    if let Some(ref base) = filter.basename {
        fn_buf.push_str(base);
    }

    if let Some(ref version) = filter.version {
        if fn_buf.is_empty() {
            fn_buf.push_str(version);
        } else {
            fn_buf.push('_');
            fn_buf.push_str(version);
        }
    }

    if flags.contains(PickFlags::PICK_ARCHITECTURE) {
        if let Some(arch) = filter.architecture {
            if arch != Architecture::Invalid {
                let as_str = arch.as_str();
                if fn_buf.is_empty() {
                    fn_buf.push_str(as_str);
                } else {
                    fn_buf.push('_');
                    fn_buf.push_str(as_str);
                }
            }
        }
    }

    if let Some(ref suffix) = filter.suffix {
        if !suffix.is_empty() {
            fn_buf.push_str(suffix);
        }
    }

    // Validate the resulting filename
    if fn_buf.is_empty() || !is_valid_filename(&fn_buf) {
        return Err(VpickError::InvalidArgument);
    }

    Ok(fn_buf)
}

/// Check whether a string is a valid filename (no path separators, no NUL).
pub fn is_valid_filename(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    // Reject path separators, NUL, and control characters
    !name.contains('/') && !name.contains('\0') && !name.bytes().any(|b| b < 0x20)
}

// ── Tries parsing ──────────────────────────────────────────────────────────

/// Parsed tries information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedTries {
    /// Tries remaining.
    pub left: u32,
    /// Tries already consumed.
    pub done: u32,
}

impl ParsedTries {
    /// Sentinel value indicating no tries info was found.
    pub fn no_match() -> Self {
        Self {
            left: TRIES_MAX,
            done: TRIES_MAX,
        }
    }
}

/// Parse a tries suffix from the end of a filename component.
///
/// Recognized formats:
/// - `+N`   — `N` tries left, zero done
/// - `+N-M` — `N` tries left, `M` done
///
/// Returns `Ok(parsed)` if a tries string was found, `None` if no match.
pub fn parse_tries(s: &str) -> Option<ParsedTries> {
    if !s.starts_with('+') {
        return None;
    }

    let rest = &s[1..];
    let digits_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());

    if digits_end == 0 {
        return None;
    }

    let left_str = &rest[..digits_end];
    let left: u32 = left_str.parse().ok()?;

    if digits_end == rest.len() {
        // "+N" form
        return Some(ParsedTries { left, done: 0 });
    }

    // Must be "+N-M"
    if rest.as_bytes()[digits_end] != b'-' {
        return None;
    }

    let done_str = &rest[digits_end + 1..];
    if done_str.is_empty() || !done_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let done: u32 = done_str.parse().ok()?;
    Some(ParsedTries { left, done })
}

// ── Architecture matching ──────────────────────────────────────────────────

/// Check whether a candidate architecture matches the filter's requirements.
///
/// If the filter has a specific architecture set, only that matches.
/// Otherwise native architecture and secondary architectures are accepted.
pub fn architecture_matches(
    filter_arch: Option<Architecture>,
    candidate: Architecture,
    native_arch: Architecture,
    secondary_arch: Option<Architecture>,
) -> bool {
    if let Some(fa) = filter_arch {
        return candidate == fa;
    }

    if candidate == native_arch {
        return true;
    }

    if let Some(secondary) = secondary_arch {
        if candidate == secondary {
            return true;
        }
    }

    candidate == Architecture::Invalid
}

// ── Version validation ─────────────────────────────────────────────────────

/// Check whether a version string is "valid" for vpick purposes.
///
/// A valid version string is non-empty and contains no path separators
/// or NUL bytes.
pub fn is_valid_version(s: &str) -> bool {
    !s.is_empty() && !s.contains('/') && !s.contains('\0') && !s.bytes().any(|b| b < 0x20)
}

// ── Path vpick detection ───────────────────────────────────────────────────

/// Determine whether a given path uses the vpick convention.
///
/// Returns `true` if the path matches one of:
/// - `.../NAME.SUFFIX.v` — a versioned directory
/// - `.../DIR.v/NAME___.SUFFIX` — a pattern inside a `.v` directory
pub fn path_uses_vpick(path: &str) -> bool {
    let fname = match filename_from_path(path) {
        Some(f) => f,
        None => return false,
    };

    // Case 1: path ends in ".v"
    if fname.ends_with(".v") && fname != ".v" {
        return true;
    }

    // Case 2: look for "___" wildcard in the filename
    if !fname.contains("___") {
        return false;
    }

    // Check if parent directory ends in ".v"
    let dir = match directory_from_path(path) {
        Some(d) => d,
        None => return false,
    };

    let parent = match filename_from_path(&dir) {
        Some(p) => p,
        None => return false,
    };

    parent.ends_with(".v")
}

/// Extract the final filename component from a path.
fn filename_from_path(path: &str) -> Option<&str> {
    // Handle trailing slash
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    trimmed.rsplit('/').next().filter(|s| !s.is_empty())
}

/// Extract the directory portion from a path.
fn directory_from_path(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let pos = trimmed.rfind('/')?;
    if pos == 0 {
        Some("/".into())
    } else {
        Some(trimmed[..pos].into())
    }
}

// ── Error from mode ────────────────────────────────────────────────────────

/// Map a type mask mismatch to the most appropriate errno-like error.
///
/// `type_mask` is a bitmask of `InodeType::mask_bit()` values, while
/// `found_mode` is a raw `st_mode` value.
pub fn errno_from_mode(type_mask: u32, found_mode: u32) -> VpickError {
    if type_mask == 0 {
        // Type doesn't matter
        return VpickError::Other(0); // success
    }

    let found_dt = InodeType::from_mode(found_mode);

    if type_mask & found_dt.mask_bit() != 0 {
        return VpickError::Other(0); // success
    }

    if type_mask == InodeType::Blk.mask_bit() {
        return VpickError::NotABlockDevice;
    }
    if type_mask == InodeType::Dir.mask_bit() {
        return VpickError::NotADirectory;
    }
    if type_mask == InodeType::Sock.mask_bit() {
        return VpickError::NotASocket;
    }

    // Check the found type specifically
    match found_dt {
        InodeType::Lnk => VpickError::SymlinkLoop,
        InodeType::Dir => VpickError::IsADirectory,
        _ => VpickError::BadFileDescriptor,
    }
}

// ── Path pick update (pure-logic portion) ──────────────────────────────────

/// The outcome of a [`path_pick_update`] operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickUpdateResult {
    /// Path doesn't exist — left as-is.
    NotFound,
    /// No matching entries in versioned directory.
    NoMatch,
    /// Successfully resolved to a versioned entry.
    Resolved {
        /// The resolved path.
        path: String,
        /// The pick result details.
        result: PickResult,
    },
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── InodeType tests ────────────────────────────────────────────────

    #[test]
    fn test_inode_type_from_dt_raw() {
        assert_eq!(InodeType::from_dt_raw(8), InodeType::Reg);
        assert_eq!(InodeType::from_dt_raw(4), InodeType::Dir);
        assert_eq!(InodeType::from_dt_raw(6), InodeType::Blk);
        assert_eq!(InodeType::from_dt_raw(12), InodeType::Sock);
        assert_eq!(InodeType::from_dt_raw(0), InodeType::Unknown);
        assert_eq!(InodeType::from_dt_raw(255), InodeType::Unknown);
    }

    #[test]
    fn test_inode_type_mask_bit() {
        assert_eq!(InodeType::Reg.mask_bit(), 1u32 << 8);
        assert_eq!(InodeType::Dir.mask_bit(), 1u32 << 4);
        assert_eq!(InodeType::Blk.mask_bit(), 1u32 << 6);
        assert_eq!(InodeType::Sock.mask_bit(), 1u32 << 12);
    }

    #[test]
    fn test_inode_type_from_mode() {
        assert_eq!(InodeType::from_mode(0o100_644), InodeType::Reg);
        assert_eq!(InodeType::from_mode(0o040_755), InodeType::Dir);
        assert_eq!(InodeType::from_mode(0o060_000), InodeType::Blk);
    }

    // ── Architecture tests ─────────────────────────────────────────────

    #[test]
    fn test_architecture_from_str() {
        assert_eq!(
            Architecture::from_str_canonical("x86-64"),
            Some(Architecture::X86_64)
        );
        assert_eq!(
            Architecture::from_str_canonical("x86_64"),
            Some(Architecture::X86_64)
        );
        assert_eq!(
            Architecture::from_str_canonical("arm64"),
            Some(Architecture::Arm64)
        );
        assert_eq!(
            Architecture::from_str_canonical("aarch64"),
            Some(Architecture::Arm64)
        );
        assert_eq!(Architecture::from_str_canonical("unknown"), None);
    }

    #[test]
    fn test_architecture_roundtrip() {
        let arches = [
            Architecture::X86,
            Architecture::X86_64,
            Architecture::Arm,
            Architecture::Arm64,
            Architecture::Ppc64Le,
            Architecture::Riscv64,
            Architecture::S390x,
            Architecture::Invalid,
        ];
        for arch in arches {
            let s = arch.as_str();
            assert_eq!(
                Architecture::from_str_canonical(s),
                Some(arch),
                "roundtrip failed for {:?}",
                arch
            );
        }
    }

    // ── PickFilter tests ───────────────────────────────────────────────

    #[test]
    fn test_pick_filter_builder() {
        let filter = PickFilter::new()
            .with_basename("foo")
            .with_suffix(".raw")
            .with_type_mask(InodeType::Reg.mask_bit());

        assert_eq!(filter.basename.as_deref(), Some("foo"));
        assert_eq!(filter.suffix.as_deref(), Some(".raw"));
        assert!(filter.type_mask != 0);
    }

    #[test]
    fn test_pick_filter_fully_specified() {
        let no_flags = PickFlags::empty();
        let tries_flags = PickFlags::PICK_TRIES;

        // With version and no PICK_TRIES → fully specified
        let f1 = PickFilter::new().with_version("1.0");
        assert!(f1.is_fully_specified(no_flags));

        // With PICK_TRIES → not fully specified
        assert!(!f1.is_fully_specified(tries_flags));

        // Without version → not fully specified
        let f2 = PickFilter::new().with_basename("foo");
        assert!(!f2.is_fully_specified(no_flags));
    }

    // ── PickResult tests ───────────────────────────────────────────────

    #[test]
    fn test_pick_result_null() {
        let r = PickResult::null();
        assert!(!r.is_match());
        assert_eq!(r.path, None);
        assert_eq!(r.tries_left, TRIES_MAX);
    }

    #[test]
    fn test_pick_result_match() {
        let r = PickResult {
            path: Some("foo_1.0.raw".into()),
            version: Some("1.0".into()),
            architecture: Architecture::X86_64,
            tries_left: 3,
            tries_done: 0,
        };
        assert!(r.is_match());
    }

    // ── Preset filter tests ────────────────────────────────────────────

    #[test]
    fn test_preset_filters() {
        let raw = pick_filter_image_raw();
        assert!(raw.type_mask & InodeType::Reg.mask_bit() != 0);
        assert!(raw.type_mask & InodeType::Blk.mask_bit() != 0);
        assert_eq!(raw.suffix.as_deref(), Some(".raw"));

        let dir = pick_filter_image_dir();
        assert_eq!(dir.type_mask, InodeType::Dir.mask_bit());
        assert!(dir.suffix.is_none());

        let ms = pick_filter_image_mstack();
        assert_eq!(ms.type_mask, InodeType::Dir.mask_bit());
        assert_eq!(ms.suffix.as_deref(), Some(".mstack"));

        let any = pick_filter_image_any();
        assert_eq!(any.len(), 3);
    }

    // ── strverscmp_improved tests ──────────────────────────────────────

    #[test]
    fn test_strverscmp_improved_basic() {
        assert!(strverscmp_improved("1", "2") < 0);
        assert!(strverscmp_improved("2", "1") > 0);
        assert_eq!(strverscmp_improved("1", "1"), 0);
    }

    #[test]
    fn test_strverscmp_improved_dotted() {
        assert!(strverscmp_improved("1.0", "1.1") < 0);
        assert!(strverscmp_improved("1.2", "1.10") < 0);
        assert!(strverscmp_improved("1.10", "1.2") > 0);
    }

    #[test]
    fn test_strverscmp_improved_leading_zeros() {
        assert_eq!(strverscmp_improved("01", "1"), 0);
        assert_eq!(strverscmp_improved("001", "1"), 0);
        assert!(strverscmp_improved("001", "02") < 0);
    }

    #[test]
    fn test_strverscmp_implemented_rpm_style() {
        // RPM-style versions
        assert!(strverscmp_improved("1.3-7", "1.3-8") < 0);
        assert!(strverscmp_improved("1.3-7", "1.3-7") == 0);
        assert!(strverscmp_improved("2.0-1", "1.9-9") > 0);
    }

    #[test]
    fn test_strverscmp_improved_empty() {
        assert!(strverscmp_improved("", "1") < 0);
        assert!(strverscmp_improved("1", "") > 0);
        assert_eq!(strverscmp_improved("", ""), 0);
    }

    // ── pick_result_compare tests ──────────────────────────────────────

    #[test]
    fn test_pick_result_compare_version() {
        let a = PickResult {
            path: Some("foo_2.0.raw".into()),
            version: Some("2.0".into()),
            architecture: Architecture::Invalid,
            tries_left: TRIES_MAX,
            tries_done: TRIES_MAX,
        };
        let b = PickResult {
            path: Some("foo_1.0.raw".into()),
            version: Some("1.0".into()),
            architecture: Architecture::Invalid,
            tries_left: TRIES_MAX,
            tries_done: TRIES_MAX,
        };
        // a has newer version → a is better
        assert!(pick_result_compare(&a, &b, PickFlags::empty(), Architecture::X86_64) > 0);
    }

    #[test]
    fn test_pick_result_compare_equal() {
        let a = PickResult {
            path: Some("foo_1.0.raw".into()),
            version: Some("1.0".into()),
            architecture: Architecture::Invalid,
            tries_left: TRIES_MAX,
            tries_done: TRIES_MAX,
        };
        let b = PickResult {
            path: Some("foo_1.0.raw".into()),
            version: Some("1.0".into()),
            architecture: Architecture::Invalid,
            tries_left: TRIES_MAX,
            tries_done: TRIES_MAX,
        };
        assert_eq!(
            pick_result_compare(&a, &b, PickFlags::empty(), Architecture::X86_64),
            0
        );
    }

    #[test]
    fn test_pick_result_compare_tries() {
        let a = PickResult {
            path: Some("foo_1.0.raw".into()),
            version: Some("1.0".into()),
            architecture: Architecture::Invalid,
            tries_left: 3,
            tries_done: 1,
        };
        let b = PickResult {
            path: Some("foo_1.0.raw".into()),
            version: Some("1.0".into()),
            architecture: Architecture::Invalid,
            tries_left: 0,
            tries_done: 5,
        };
        // Same version, a has tries left → a is better with PICK_TRIES
        let d = pick_result_compare(&a, &b, PickFlags::PICK_TRIES, Architecture::X86_64);
        assert!(d > 0);
    }

    #[test]
    fn test_pick_result_compare_architecture() {
        let native = Architecture::X86_64;
        let a = PickResult {
            path: Some("foo_1.0_x86-64.raw".into()),
            version: Some("1.0".into()),
            architecture: Architecture::X86_64,
            tries_left: TRIES_MAX,
            tries_done: TRIES_MAX,
        };
        let b = PickResult {
            path: Some("foo_1.0_arm64.raw".into()),
            version: Some("1.0".into()),
            architecture: Architecture::Arm64,
            tries_left: TRIES_MAX,
            tries_done: TRIES_MAX,
        };
        // Same version, a is native → a is better with PICK_ARCHITECTURE
        let d = pick_result_compare(&a, &b, PickFlags::PICK_ARCHITECTURE, native);
        assert!(d > 0);
    }

    // ── format_fname tests ─────────────────────────────────────────────

    #[test]
    fn test_format_fname_basename_suffix() {
        let filter = PickFilter::new()
            .with_basename("foo")
            .with_version("1.0")
            .with_suffix(".raw");
        let result = format_fname(&filter, PickFlags::empty()).unwrap();
        assert_eq!(result, "foo_1.0.raw");
    }

    #[test]
    fn test_format_fname_with_architecture() {
        let filter = PickFilter::new()
            .with_basename("foo")
            .with_version("1.0")
            .with_architecture(Architecture::X86_64)
            .with_suffix(".raw");
        let result = format_fname(&filter, PickFlags::PICK_ARCHITECTURE).unwrap();
        assert_eq!(result, "foo_1.0_x86-64.raw");
    }

    #[test]
    fn test_format_fname_underspecified_no_version() {
        let filter = PickFilter::new().with_basename("foo").with_suffix(".raw");
        let result = format_fname(&filter, PickFlags::empty());
        assert_eq!(result, Err(VpickError::Underspecified));
    }

    #[test]
    fn test_format_fname_underspecified_tries() {
        let filter = PickFilter::new()
            .with_basename("foo")
            .with_version("1.0")
            .with_suffix(".raw");
        let result = format_fname(&filter, PickFlags::PICK_TRIES);
        assert_eq!(result, Err(VpickError::Underspecified));
    }

    #[test]
    fn test_format_fname_version_only() {
        let filter = PickFilter::new().with_version("1.3-7").with_suffix(".raw");
        let result = format_fname(&filter, PickFlags::empty()).unwrap();
        assert_eq!(result, "1.3-7.raw");
    }

    // ── parse_tries tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_tries_simple() {
        let t = parse_tries("+5").unwrap();
        assert_eq!(t.left, 5);
        assert_eq!(t.done, 0);
    }

    #[test]
    fn test_parse_tries_with_done() {
        let t = parse_tries("+3-10").unwrap();
        assert_eq!(t.left, 3);
        assert_eq!(t.done, 10);
    }

    #[test]
    fn test_parse_tries_no_plus() {
        assert!(parse_tries("5").is_none());
    }

    #[test]
    fn test_parse_tries_no_digits() {
        assert!(parse_tries("+").is_none());
        assert!(parse_tries("+abc").is_none());
    }

    #[test]
    fn test_parse_tries_bad_done() {
        assert!(parse_tries("+3-").is_none());
        assert!(parse_tries("+3-abc").is_none());
    }

    #[test]
    fn test_parse_tries_no_match() {
        let result = parse_tries("1.0");
        assert!(result.is_none());
    }

    // ── architecture_matches tests ─────────────────────────────────────

    #[test]
    fn test_architecture_matches_specific() {
        // Filter set to x86-64 → only x86-64 matches
        assert!(architecture_matches(
            Some(Architecture::X86_64),
            Architecture::X86_64,
            Architecture::X86_64,
            None
        ));
        assert!(!architecture_matches(
            Some(Architecture::X86_64),
            Architecture::Arm64,
            Architecture::X86_64,
            None
        ));
    }

    #[test]
    fn test_architecture_matches_any() {
        // No filter → native matches
        assert!(architecture_matches(
            None,
            Architecture::X86_64,
            Architecture::X86_64,
            None
        ));
        // No filter → Invalid matches
        assert!(architecture_matches(
            None,
            Architecture::Invalid,
            Architecture::X86_64,
            None
        ));
        // No filter → non-native, non-invalid, non-secondary doesn't match
        assert!(!architecture_matches(
            None,
            Architecture::Arm64,
            Architecture::X86_64,
            None
        ));
    }

    #[test]
    fn test_architecture_matches_secondary() {
        // No filter → secondary matches
        assert!(architecture_matches(
            None,
            Architecture::Arm64,
            Architecture::X86_64,
            Some(Architecture::Arm64)
        ));
    }

    // ── path_uses_vpick tests ──────────────────────────────────────────

    #[test]
    fn test_path_uses_vpick_dot_v() {
        assert!(path_uses_vpick("/foo/bar/baz.raw.v"));
        assert!(path_uses_vpick("/foo/bar.v"));
        assert!(!path_uses_vpick("/foo/bar.txt"));
    }

    #[test]
    fn test_path_uses_vpick_wildcard() {
        // Pattern: DIR.v/NAME___.SUFFIX
        assert!(path_uses_vpick("/foo/bar.v/waldo___.raw"));
        assert!(path_uses_vpick("/baz.v/image___.mstack"));
        // Parent doesn't end in .v
        assert!(!path_uses_vpick("/foo/bar/waldo___.raw"));
        // No wildcard
        assert!(!path_uses_vpick("/foo/bar.v/waldo.raw"));
    }

    #[test]
    fn test_path_uses_vpick_edge_cases() {
        // Root or "." edge cases
        assert!(!path_uses_vpick("/"));
        assert!(!path_uses_vpick(""));
        assert!(!path_uses_vpick(".v"));
        // Just a filename with .v
        assert!(path_uses_vpick("foo.v"));
    }

    // ── errno_from_mode tests ──────────────────────────────────────────

    #[test]
    fn test_errno_from_mode_match() {
        // type_mask matches found → no error
        let mask = InodeType::Reg.mask_bit();
        let mode = 0o100_644; // S_IFREG
        assert!(matches!(errno_from_mode(mask, mode), VpickError::Other(0)));
    }

    #[test]
    fn test_errno_from_mode_mismatch() {
        // Looking for block device, found regular file
        let mask = InodeType::Blk.mask_bit();
        let mode = 0o100_644; // S_IFREG
        assert_eq!(errno_from_mode(mask, mode), VpickError::NotABlockDevice);

        // Looking for directory, found regular file
        let mask = InodeType::Dir.mask_bit();
        let mode = 0o100_644;
        assert_eq!(errno_from_mode(mask, mode), VpickError::NotADirectory);
    }

    #[test]
    fn test_errno_from_mode_no_mask() {
        // No type mask → always success
        assert!(matches!(
            errno_from_mode(0, 0o100_644),
            VpickError::Other(0)
        ));
    }

    // ── is_valid_filename tests ────────────────────────────────────────

    #[test]
    fn test_is_valid_filename() {
        assert!(is_valid_filename("foo.raw"));
        assert!(is_valid_filename("foo_1.0-3_x86-64.raw"));
        assert!(!is_valid_filename(""));
        assert!(!is_valid_filename("foo/bar"));
        assert!(!is_valid_filename("foo\0bar"));
        assert!(!is_valid_filename("foo\nbar"));
    }

    // ── is_valid_version tests ─────────────────────────────────────────

    #[test]
    fn test_is_valid_version() {
        assert!(is_valid_version("1.0"));
        assert!(is_valid_version("1.3-7"));
        assert!(is_valid_version("255"));
        assert!(!is_valid_version(""));
        assert!(!is_valid_version("1.0/foo"));
    }

    // ── filename_from_path / directory_from_path tests ─────────────────

    #[test]
    fn test_filename_from_path() {
        assert_eq!(filename_from_path("/foo/bar/baz.raw"), Some("baz.raw"));
        assert_eq!(filename_from_path("baz.raw"), Some("baz.raw"));
        assert_eq!(filename_from_path("/foo/bar/"), Some("bar"));
        assert_eq!(filename_from_path("/"), None);
        assert_eq!(filename_from_path(""), None);
    }

    #[test]
    fn test_directory_from_path() {
        assert_eq!(
            directory_from_path("/foo/bar/baz.raw"),
            Some("/foo/bar".into())
        );
        assert_eq!(directory_from_path("baz.raw"), None);
        assert_eq!(directory_from_path("/foo"), Some("/".into()));
    }

    // ── VpickError display ─────────────────────────────────────────────

    #[test]
    fn test_vpick_error_display() {
        assert!(!VpickError::NotFound.to_string().is_empty());
        assert!(!VpickError::Underspecified.to_string().is_empty());
        assert!(!VpickError::Other(42).to_string().is_empty());
    }
}
