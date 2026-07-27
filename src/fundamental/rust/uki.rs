// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/uki.h, src/fundamental/uki.c
//
// Unified Kernel Image (UKI) section definitions.

/// PE sections with special meaning for unified kernels.
/// This is the canonical order in which sections are measured into TPM PCR 11.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnifiedSection {
    Linux = 0,
    OsRel = 1,
    CmdLine = 2,
    InitRd = 3,
    UCode = 4,
    Splash = 5,
    Dtb = 6,
    UName = 7,
    Sbat = 8,
    PcrSig = 9,
    PcrPKey = 10,
    Profile = 11,
    DtbAuto = 12,
    HwIds = 13,
    EfiFw = 14,
}

const UNIFIED_SECTION_MAX: usize = 15;

/// Section names corresponding to UnifiedSection variants.
pub const UNIFIED_SECTIONS: [&str; UNIFIED_SECTION_MAX + 1] = [
    ".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname", ".sbat",
    ".pcrsig", ".pcrpkey", ".profile", ".dtbauto", ".hwids", ".efifw", "",
];

/// Don't include the PCR signature in the PCR measurements, since they sign
/// the expected result of the measurement, and hence shouldn't be input to it.
pub fn unified_section_measure(section: UnifiedSection) -> bool {
    (section as i32) >= 0
        && (section as usize) < UNIFIED_SECTION_MAX
        && section != UnifiedSection::PcrSig
}

/// Max number of profiles per UKI.
pub const UNIFIED_PROFILES_MAX: u32 = 256;

/// Native PE machine type.
#[cfg(target_arch = "x86_64")]
pub const IMAGE_FILE_MACHINE_NATIVE: u16 = 0x8664;
#[cfg(target_arch = "x86")]
pub const IMAGE_FILE_MACHINE_NATIVE: u16 = 0x014c;
#[cfg(target_arch = "aarch64")]
pub const IMAGE_FILE_MACHINE_NATIVE: u16 = 0xaa64;
#[cfg(target_arch = "arm")]
pub const IMAGE_FILE_MACHINE_NATIVE: u16 = 0x01c0;
#[cfg(target_arch = "riscv64")]
pub const IMAGE_FILE_MACHINE_NATIVE: u16 = 0x5064;
#[cfg(target_arch = "riscv32")]
pub const IMAGE_FILE_MACHINE_NATIVE: u16 = 0x5032;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_section_names() {
        assert_eq!(UNIFIED_SECTIONS[UnifiedSection::Linux as usize], ".linux");
        assert_eq!(UNIFIED_SECTIONS[UnifiedSection::OsRel as usize], ".osrel");
        assert_eq!(
            UNIFIED_SECTIONS[UnifiedSection::CmdLine as usize],
            ".cmdline"
        );
        assert_eq!(UNIFIED_SECTIONS[UnifiedSection::InitRd as usize], ".initrd");
    }

    #[test]
    fn test_unified_section_measure() {
        assert!(unified_section_measure(UnifiedSection::Linux));
        assert!(unified_section_measure(UnifiedSection::OsRel));
        assert!(!unified_section_measure(UnifiedSection::PcrSig));
        assert!(unified_section_measure(UnifiedSection::CmdLine));
    }

    #[test]
    fn test_section_count() {
        assert_eq!(UNIFIED_SECTIONS.len(), 16);
    }
}
