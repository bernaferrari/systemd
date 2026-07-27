// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/sbat.h
//
// SBAT (Secure Boot Advanced Targeting) section definitions.
// In Rust, we provide the SBAT string constants and helpers for
// embedding into PE sections.

/// SBAT magic header line.
pub const SBAT_MAGIC: &str =
    "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n";

/// Generate a SBAT section text for the boot loader.
pub fn sbat_boot_section_text(project: &str, version: &str, url: &str) -> alloc::string::String {
    alloc::format!(
        "{}{}-boot,1,The systemd Developers,{},{},{}\n",
        SBAT_MAGIC,
        project,
        project,
        version,
        url
    )
}

/// Generate a SBAT section text for the stub.
pub fn sbat_stub_section_text(project: &str, version: &str, url: &str) -> alloc::string::String {
    alloc::format!(
        "{}{}-stub,1,The systemd Developers,{},{},{}\n",
        SBAT_MAGIC,
        project,
        project,
        version,
        url
    )
}

/// SBAT section text with distro information.
pub fn sbat_with_distro(
    project: &str,
    version: &str,
    url: &str,
    distro: &str,
    distro_generation: u32,
    distro_summary: &str,
    distro_pkgname: &str,
    distro_version: &str,
    distro_url: &str,
    is_stub: bool,
) -> alloc::string::String {
    let component = if is_stub { "stub" } else { "boot" };
    alloc::format!(
        "{}{}-{},1,The systemd Developers,{},{},{}\n{}-{}.{},{},{},{},{},{}\n",
        SBAT_MAGIC,
        project,
        component,
        project,
        version,
        url,
        project,
        component,
        distro,
        distro_generation,
        distro_summary,
        distro_pkgname,
        distro_version,
        distro_url,
    )
}

/// Check if SBAT text fits within the padded section limit (512 bytes).
pub const fn sbat_fits_padded(text_len: usize) -> bool {
    text_len <= 512
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbat_magic() {
        assert!(SBAT_MAGIC.starts_with("sbat,1,"));
    }

    #[test]
    fn test_sbat_boot_section() {
        let text = sbat_boot_section_text("systemd", "255", "https://systemd.io");
        assert!(text.contains("systemd-boot"));
        assert!(text.contains("255"));
    }

    #[test]
    fn test_sbat_stub_section() {
        let text = sbat_stub_section_text("systemd", "255", "https://systemd.io");
        assert!(text.contains("systemd-stub"));
    }

    #[test]
    fn test_sbat_fits_padded() {
        assert!(sbat_fits_padded(100));
        assert!(sbat_fits_padded(512));
        assert!(!sbat_fits_padded(513));
    }
}
