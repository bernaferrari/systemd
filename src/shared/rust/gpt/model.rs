// SPDX-License-Identifier: LGPL-2.1-or-later

/// GPT partition designator identifiers.
///
/// Mirrors the C `PartitionDesignator` enum from `gpt.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartitionDesignator {
    Root,
    Usr,
    Home,
    Srv,
    Esp,
    XBootldr,
    Swap,
    RootVerity,
    UsrVerity,
    RootVeritySig,
    UsrVeritySig,
    Tmp,
    Var,
    /// Sentinel for invalid or unknown designators.
    Invalid,
}

impl PartitionDesignator {
    /// Returns the canonical string name for this designator.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Usr => "usr",
            Self::Home => "home",
            Self::Srv => "srv",
            Self::Esp => "esp",
            Self::XBootldr => "xbootldr",
            Self::Swap => "swap",
            Self::RootVerity => "root-verity",
            Self::UsrVerity => "usr-verity",
            Self::RootVeritySig => "root-verity-sig",
            Self::UsrVeritySig => "usr-verity-sig",
            Self::Tmp => "tmp",
            Self::Var => "var",
            Self::Invalid => "(invalid)",
        }
    }

    /// Parses a designator from its canonical string name.
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "root" => Some(Self::Root),
            "usr" => Some(Self::Usr),
            "home" => Some(Self::Home),
            "srv" => Some(Self::Srv),
            "esp" => Some(Self::Esp),
            "xbootldr" => Some(Self::XBootldr),
            "swap" => Some(Self::Swap),
            "root-verity" => Some(Self::RootVerity),
            "usr-verity" => Some(Self::UsrVerity),
            "root-verity-sig" => Some(Self::RootVeritySig),
            "usr-verity-sig" => Some(Self::UsrVeritySig),
            "tmp" => Some(Self::Tmp),
            "var" => Some(Self::Var),
            _ => None,
        }
    }

    /// Returns the C-compatible NUL-separated mountpoint list, if any.
    pub const fn mountpoint_nulstr(self) -> Option<&'static str> {
        match self {
            Self::Root => Some("/\0"),
            Self::Usr => Some("/usr\0"),
            Self::Home => Some("/home\0"),
            Self::Srv => Some("/srv\0"),
            Self::Esp => Some("/efi\0/boot\0"),
            Self::XBootldr => Some("/boot\0"),
            Self::Tmp => Some("/var/tmp\0"),
            Self::Var => Some("/var\0"),
            _ => None,
        }
    }
}

/// A 128-bit UUID in the byte order used by `sd_id128_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id128([u8; 16]);

impl Id128 {
    /// The all-zero UUID.
    pub const NULL: Self = Self([0; 16]);

    /// Constructs an ID from the declaration-order bytes used by
    /// `SD_ID128_MAKE`.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Constructs an ID from the sixteen `SD_ID128_MAKE` byte arguments.
    #[allow(clippy::too_many_arguments)]
    pub const fn make(
        a: u8,
        b: u8,
        c: u8,
        d: u8,
        e: u8,
        f: u8,
        g: u8,
        h: u8,
        i: u8,
        j: u8,
        k: u8,
        l: u8,
        m: u8,
        n: u8,
        o: u8,
        p: u8,
    ) -> Self {
        Self([a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p])
    }

    /// Returns the canonical hyphenated UUID text.
    pub fn to_string_uuid(self) -> String {
        let b = self.0;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15],
        )
    }

    /// Returns whether this is the all-zero UUID.
    pub fn is_null(self) -> bool {
        self.0 == [0; 16]
    }
}

/// Architectures represented by the architecture-specific GPT sextets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    Alpha,
    Arc,
    Arm,
    Arm64,
    Ia64,
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
    Tilegx,
    X86,
    X86_64,
    Invalid,
}

/// One canonical or alias entry from `gpt_partition_type_table`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptPartitionType {
    pub uuid: Id128,
    pub name: &'static str,
    pub arch: Architecture,
    pub designator: PartitionDesignator,
}

impl GptPartitionType {
    /// An invalid placeholder with a null UUID.
    pub const INVALID: Self = Self {
        uuid: Id128::NULL,
        name: "",
        arch: Architecture::Invalid,
        designator: PartitionDesignator::Invalid,
    };
}
