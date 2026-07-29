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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbatComponent {
    Boot,
    Stub,
}

impl SbatComponent {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Stub => "stub",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SbatDistroInput<'a> {
    pub project: &'a str,
    pub version: &'a str,
    pub url: &'a str,
    pub distro: &'a str,
    pub distro_generation: u32,
    pub distro_summary: &'a str,
    pub distro_pkgname: &'a str,
    pub distro_version: &'a str,
    pub distro_url: &'a str,
    pub component: SbatComponent,
}

pub fn sbat_with_distro(input: SbatDistroInput<'_>) -> alloc::string::String {
    let component = input.component.as_str();
    alloc::format!(
        "{}{}-{},1,The systemd Developers,{},{},{}\n{}-{}.{},{},{},{},{},{}\n",
        SBAT_MAGIC,
        input.project,
        component,
        input.project,
        input.version,
        input.url,
        input.project,
        component,
        input.distro,
        input.distro_generation,
        input.distro_summary,
        input.distro_pkgname,
        input.distro_version,
        input.distro_url,
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
    fn test_sbat_with_distro_preserves_format() {
        let text = sbat_with_distro(SbatDistroInput {
            project: "systemd",
            version: "255",
            url: "https://systemd.io",
            distro: "fedora",
            distro_generation: 1,
            distro_summary: "Fedora Linux",
            distro_pkgname: "systemd",
            distro_version: "40",
            distro_url: "https://fedoraproject.org",
            component: SbatComponent::Stub,
        });
        assert_eq!(
            text,
            concat!(
                "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n",
                "systemd-stub,1,The systemd Developers,systemd,255,https://systemd.io\n",
                "systemd-stub.fedora,1,Fedora Linux,systemd,40,https://fedoraproject.org\n",
            )
        );
    }

    #[test]
    fn test_sbat_fits_padded() {
        assert!(sbat_fits_padded(100));
        assert!(sbat_fits_padded(512));
        assert!(!sbat_fits_padded(513));
    }
}
