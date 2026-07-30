// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/vmm.c
//
// Virtual-machine monitor detection: CPUID-based hypervisor checks,
// confidential-VM detection (SEV, TDX, HyperV), and direct-boot
// identification.

// ── CPUID vendor signatures ──────────────────────────────────────────────

pub const CPUID_SIG_AMD: &[u8] = b"AuthenticAMD";
pub const CPUID_SIG_INTEL: &[u8] = b"GenuineIntel";
pub const CPUID_SIG_INTEL_TDX: &[u8] = b"IntelTDX    ";
pub const CPUID_SIG_HYPERV: &[u8] = b"Microsoft Hv";

// ── CPUID leaf constants ─────────────────────────────────────────────────

pub const CPUID_GET_HIGHEST_FUNCTION: u32 = 0x8000_0000;
pub const CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES: u32 = 0x8000_001F;

/// Hyperv vendor and max functions leaf.
pub const CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x4000_0000;
pub const CPUID_HYPERV_FEATURES: u32 = 0x4000_0003;
pub const CPUID_HYPERV_ISOLATION: u32 = 0x0000_0020;
pub const CPUID_HYPERV_CPU_MANAGEMENT: u32 = 0x0000_0080;
pub const CPUID_HYPERV_ISOLATION_CONFIG: u32 = 0x4000_000C;
pub const CPUID_HYPERV_ISOLATION_TYPE_MASK: u32 = 0x000F;
pub const CPUID_HYPERV_ISOLATION_TYPE_SNP: u32 = 0x0002;
pub const CPUID_HYPERV_ISOLATION_TYPE_TDX: u32 = 0x0003;

pub const CPUID_HYPERV_MIN: u32 = 0x4000_0005;
pub const CPUID_HYPERV_MAX: u32 = 0x4000_000F;

pub const CPUID_INTEL_TDX_ENUMERATION: u32 = 0x0000_0021;

/// Bit 1 of SEV MSR: SEV feature supported.
pub const EAX_SEV: u32 = 1 << 1;

// ── MSR constants ────────────────────────────────────────────────────────

pub const MSR_AMD64_SEV: u32 = 0xC001_0130;
pub const MSR_SEV: u64 = 1 << 0;
pub const MSR_SEV_ES: u64 = 1 << 3;
pub const MSR_SEV_SNP: u64 = 1 << 4;

/// Hypervisor present bit in CPUID.1.ECX.
pub const CPUID_FEATURE_HYPERVISOR: u32 = 1 << 31;

// ── Hypervisor detection result ──────────────────────────────────────────

/// Classification of the virtual-machine environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmmType {
    BareMetal,
    Hypervisor,
    ConfidentialSev,
    ConfidentialTdx,
    ConfidentialHypervCvm,
    Unknown,
}

impl VmmType {
    pub fn is_confidential(self) -> bool {
        matches!(
            self,
            VmmType::ConfidentialSev | VmmType::ConfidentialTdx | VmmType::ConfidentialHypervCvm
        )
    }

    pub fn is_hypervisor(self) -> bool {
        self != VmmType::BareMetal
    }
}

// ── CPUID result ─────────────────────────────────────────────────────────

/// Result of a CPUID query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

// ── Platform abstraction trait ───────────────────────────────────────────

/// Abstraction over platform-specific CPUID and MSR reads.
///
/// Production code injects a real implementation; tests inject a stub.
pub trait PlatformInfo: std::fmt::Debug {
    /// Execute CPUID with the given leaf. Returns None if unsupported.
    fn cpuid(&self, leaf: u32) -> Option<CpuidResult>;

    /// Execute CPUID with leaf and sub-leaf. Returns None if unsupported.
    fn cpuid_count(&self, leaf: u32, sub_leaf: u32) -> Option<CpuidResult>;

    /// Read a model-specific register. Returns None if unsupported.
    fn read_msr(&self, index: u32) -> Option<u64>;

    /// Check SMBIOS for hypervisor indicators.
    fn smbios_in_hypervisor(&self) -> bool;
}

// ── Detection logic (pure, testable) ─────────────────────────────────────

/// Check the hypervisor bit in CPUID leaf 1, ECX bit 31.
/// Mirrors `cpuid_in_hypervisor()` in vmm.c.
pub fn cpuid_in_hypervisor(platform: &dyn PlatformInfo) -> bool {
    let Some(result) = platform.cpuid(1) else {
        return false;
    };
    (result.ecx & CPUID_FEATURE_HYPERVISOR) != 0
}

/// Cached hypervisor detection.
/// Mirrors `in_hypervisor()` in vmm.c (which uses a static cache).
pub fn in_hypervisor(platform: &dyn PlatformInfo) -> bool {
    cpuid_in_hypervisor(platform) || platform.smbios_in_hypervisor()
}

/// Read the CPU vendor signature from CPUID leaf 0.
/// Returns a 12-byte vendor string (null-padded to 13 bytes).
/// Mirrors `cpuid_leaf()` with `swapped = true` in vmm.c.
pub fn cpuid_vendor(platform: &dyn PlatformInfo) -> [u8; 13] {
    let mut sig = [0u8; 13];
    if let Some(r) = platform.cpuid(0) {
        let bytes: [u8; 4] = r.ebx.to_le_bytes();
        sig[0..4].copy_from_slice(&bytes);
        let bytes: [u8; 4] = r.edx.to_le_bytes();
        sig[4..8].copy_from_slice(&bytes);
        let bytes: [u8; 4] = r.ecx.to_le_bytes();
        sig[8..12].copy_from_slice(&bytes);
    }
    sig
}

/// Detect a HyperV confidential VM with the given isolation type.
/// Mirrors `detect_hyperv_cvm()` in vmm.c.
pub fn detect_hyperv_cvm(platform: &dyn PlatformInfo, isoltype: u32) -> bool {
    let Some(vendor_leaf) = platform.cpuid(CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS) else {
        return false;
    };

    let feat = vendor_leaf.eax;
    if !(CPUID_HYPERV_MIN..=CPUID_HYPERV_MAX).contains(&feat) {
        return false;
    }

    // Check vendor signature
    let mut sig = [0u8; 13];
    let r = vendor_leaf;
    sig[0..4].copy_from_slice(&r.ebx.to_le_bytes());
    sig[4..8].copy_from_slice(&r.edx.to_le_bytes());
    sig[8..12].copy_from_slice(&r.ecx.to_le_bytes());
    if sig[..12] != CPUID_SIG_HYPERV[..12] {
        return false;
    }

    let Some(features) = platform.cpuid_count(CPUID_HYPERV_FEATURES, 0) else {
        return false;
    };
    if (features.ebx & CPUID_HYPERV_ISOLATION) == 0
        || (features.ebx & CPUID_HYPERV_CPU_MANAGEMENT) != 0
    {
        return false;
    }

    let Some(iso) = platform.cpuid_count(CPUID_HYPERV_ISOLATION_CONFIG, 0) else {
        return false;
    };
    (iso.ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK) == isoltype
}

/// Detect AMD SEV / SEV-ES / SEV-SNP.
/// Mirrors `detect_sev()` in vmm.c.
pub fn detect_sev(platform: &dyn PlatformInfo) -> bool {
    let Some(max_leaf) = platform.cpuid(CPUID_GET_HIGHEST_FUNCTION) else {
        return false;
    };
    if max_leaf.eax < CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES {
        return false;
    }

    let Some(enc_caps) = platform.cpuid(CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES) else {
        return false;
    };

    if (enc_caps.eax & EAX_SEV) == 0 {
        return detect_hyperv_cvm(platform, CPUID_HYPERV_ISOLATION_TYPE_SNP);
    }

    if let Some(msrval) = platform.read_msr(MSR_AMD64_SEV)
        && (msrval & (MSR_SEV_SNP | MSR_SEV_ES | MSR_SEV)) != 0
    {
        return true;
    }

    false
}

/// Detect Intel TDX.
/// Mirrors `detect_tdx()` in vmm.c.
pub fn detect_tdx(platform: &dyn PlatformInfo) -> bool {
    let Some(max_leaf) = platform.cpuid(CPUID_GET_HIGHEST_FUNCTION) else {
        return false;
    };
    if max_leaf.eax < CPUID_INTEL_TDX_ENUMERATION {
        return false;
    }

    // Read TDX signature via cpuid_count (swapped order)
    if let Some(r) = platform.cpuid_count(CPUID_INTEL_TDX_ENUMERATION, 0) {
        let mut sig = [0u8; 13];
        sig[0..4].copy_from_slice(&r.eax.to_le_bytes());
        sig[4..8].copy_from_slice(&r.ecx.to_le_bytes());
        sig[8..12].copy_from_slice(&r.edx.to_le_bytes());
        if sig[..12] == CPUID_SIG_INTEL_TDX[..12] {
            return true;
        }
    }

    detect_hyperv_cvm(platform, CPUID_HYPERV_ISOLATION_TYPE_TDX)
}

/// Full confidential-VM detection.
/// Mirrors `is_confidential_vm()` in vmm.c.
pub fn is_confidential_vm(platform: &dyn PlatformInfo) -> bool {
    if !cpuid_in_hypervisor(platform) {
        return false;
    }

    let vendor = cpuid_vendor(platform);
    if vendor[..12] == CPUID_SIG_AMD[..12] {
        return detect_sev(platform);
    }
    if vendor[..12] == CPUID_SIG_INTEL[..12] {
        return detect_tdx(platform);
    }

    false
}

/// Classify the VMM environment.
pub fn detect_vmm_type(platform: &dyn PlatformInfo) -> VmmType {
    if !in_hypervisor(platform) {
        return VmmType::BareMetal;
    }

    let vendor = cpuid_vendor(platform);
    if vendor[..12] == CPUID_SIG_AMD[..12] && detect_sev(platform) {
        return VmmType::ConfidentialSev;
    }
    if vendor[..12] == CPUID_SIG_INTEL[..12] && detect_tdx(platform) {
        return VmmType::ConfidentialTdx;
    }
    if detect_hyperv_cvm(platform, CPUID_HYPERV_ISOLATION_TYPE_SNP) {
        return VmmType::ConfidentialHypervCvm;
    }

    VmmType::Hypervisor
}

// ── Direct-boot check ────────────────────────────────────────────────────

/// Device-path media sub-types used in `is_direct_boot()`.
pub const MEDIA_DEVICE_PATH: u8 = 0x04;
pub const MEDIA_VENDOR_DP: u8 = 0x03;
pub const MEDIA_PIWG_FW_VOL_DP: u8 = 0x07;

/// Simplified device-path header mirroring EFI_DEVICE_PATH_PROTOCOL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevicePathHeader {
    pub dp_type: u8,
    pub sub_type: u8,
    pub length: u16,
}

/// QEMU kernel-loader file-system media GUID (bytes, little-endian).
pub const QEMU_KERNEL_LOADER_FS_MEDIA_GUID: [u8; 16] = [
    0x72, 0xF7, 0x28, 0x14, 0x4A, 0xB6, 0x1E, 0x44, 0xB8, 0xC3, 0x9E, 0xBD, 0xD7, 0xF8, 0x93, 0xC7,
];

/// Check whether the boot device indicates a direct boot (QEMU -kernel
/// or firmware volume).  Mirrors `is_direct_boot()` in vmm.c.
pub fn is_direct_boot(device_paths: &[DevicePathHeader], vendor_guid: Option<&[u8; 16]>) -> bool {
    for dp in device_paths {
        if dp.dp_type == MEDIA_DEVICE_PATH
            && dp.sub_type == MEDIA_VENDOR_DP
            && let Some(guid) = vendor_guid
            && guid == &QEMU_KERNEL_LOADER_FS_MEDIA_GUID
        {
            return true;
        }
        if dp.dp_type == MEDIA_DEVICE_PATH && dp.sub_type == MEDIA_PIWG_FW_VOL_DP {
            return true;
        }
    }
    false
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Stub platform ─────────────────────────────────────────────────

    #[derive(Debug)]
    struct StubPlatform {
        cpuid_results: std::collections::HashMap<(u32, u32), CpuidResult>,
        msr_values: std::collections::HashMap<u32, u64>,
        smbios_hypervisor: bool,
    }

    impl StubPlatform {
        fn new() -> Self {
            Self {
                cpuid_results: std::collections::HashMap::new(),
                msr_values: std::collections::HashMap::new(),
                smbios_hypervisor: false,
            }
        }
        fn with_cpuid(mut self, leaf: u32, result: CpuidResult) -> Self {
            self.cpuid_results.insert((leaf, 0), result);
            self
        }
        fn with_msr(mut self, idx: u32, val: u64) -> Self {
            self.msr_values.insert(idx, val);
            self
        }
        fn with_smbios_hypervisor(mut self) -> Self {
            self.smbios_hypervisor = true;
            self
        }
    }

    impl PlatformInfo for StubPlatform {
        fn cpuid(&self, leaf: u32) -> Option<CpuidResult> {
            self.cpuid_results.get(&(leaf, 0)).copied()
        }
        fn cpuid_count(&self, leaf: u32, sub_leaf: u32) -> Option<CpuidResult> {
            self.cpuid_results.get(&(leaf, sub_leaf)).copied()
        }
        fn read_msr(&self, index: u32) -> Option<u64> {
            self.msr_values.get(&index).copied()
        }
        fn smbios_in_hypervisor(&self) -> bool {
            self.smbios_hypervisor
        }
    }

    // Helper to build a CPUID result encoding a vendor string in EBX/EDX/ECX.
    fn vendor_result(sig: &[u8], eax: u32) -> CpuidResult {
        let mut buf13 = [0u8; 13];
        let copy_len = sig.len().min(12);
        buf13[..copy_len].copy_from_slice(&sig[..copy_len]);
        CpuidResult {
            eax,
            ebx: u32::from_le_bytes(buf13[0..4].try_into().unwrap()),
            edx: u32::from_le_bytes(buf13[4..8].try_into().unwrap()),
            ecx: u32::from_le_bytes(buf13[8..12].try_into().unwrap()),
        }
    }

    #[test]
    fn test_cpuid_in_hypervisor_set() {
        let p = StubPlatform::new().with_cpuid(
            1,
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: CPUID_FEATURE_HYPERVISOR,
                edx: 0,
            },
        );
        assert!(cpuid_in_hypervisor(&p));
    }

    #[test]
    fn test_cpuid_in_hypervisor_not_set() {
        let p = StubPlatform::new().with_cpuid(
            1,
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
        );
        assert!(!cpuid_in_hypervisor(&p));
    }

    #[test]
    fn test_cpuid_in_hypervisor_no_leaf() {
        let p = StubPlatform::new();
        assert!(!cpuid_in_hypervisor(&p));
    }

    #[test]
    fn test_in_hypervisor_via_smbios() {
        let p = StubPlatform::new().with_smbios_hypervisor();
        assert!(in_hypervisor(&p));
    }

    #[test]
    fn test_detect_vmm_type_bare_metal() {
        let p = StubPlatform::new();
        assert_eq!(detect_vmm_type(&p), VmmType::BareMetal);
    }

    #[test]
    fn test_detect_vmm_type_hypervisor() {
        let p = StubPlatform::new()
            .with_cpuid(
                1,
                CpuidResult {
                    eax: 0,
                    ebx: 0,
                    ecx: CPUID_FEATURE_HYPERVISOR,
                    edx: 0,
                },
            )
            .with_cpuid(0, vendor_result(CPUID_SIG_AMD, 0));
        assert_eq!(detect_vmm_type(&p), VmmType::Hypervisor);
    }

    #[test]
    fn test_is_confidential_vm_amd_sev() {
        let p = StubPlatform::new()
            .with_cpuid(
                1,
                CpuidResult {
                    eax: 0,
                    ebx: 0,
                    ecx: CPUID_FEATURE_HYPERVISOR,
                    edx: 0,
                },
            )
            .with_cpuid(0, vendor_result(CPUID_SIG_AMD, 0))
            .with_cpuid(
                CPUID_GET_HIGHEST_FUNCTION,
                CpuidResult {
                    eax: CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                },
            )
            .with_cpuid(
                CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES,
                CpuidResult {
                    eax: EAX_SEV,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                },
            )
            .with_msr(MSR_AMD64_SEV, MSR_SEV);
        assert!(is_confidential_vm(&p));
    }

    #[test]
    fn test_is_confidential_vm_not_hypervisor() {
        let p = StubPlatform::new().with_cpuid(
            1,
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
        );
        assert!(!is_confidential_vm(&p));
    }

    #[test]
    fn test_is_direct_boot_qemu() {
        let guid = QEMU_KERNEL_LOADER_FS_MEDIA_GUID;
        let dps = [DevicePathHeader {
            dp_type: MEDIA_DEVICE_PATH,
            sub_type: MEDIA_VENDOR_DP,
            length: 0,
        }];
        assert!(is_direct_boot(&dps, Some(&guid)));
    }

    #[test]
    fn test_is_direct_boot_fw_vol() {
        let dps = [DevicePathHeader {
            dp_type: MEDIA_DEVICE_PATH,
            sub_type: MEDIA_PIWG_FW_VOL_DP,
            length: 0,
        }];
        assert!(is_direct_boot(&dps, None));
    }

    #[test]
    fn test_is_direct_boot_not_direct() {
        let dps = [DevicePathHeader {
            dp_type: 0x01,
            sub_type: 0x01,
            length: 0,
        }];
        assert!(!is_direct_boot(&dps, None));
    }

    #[test]
    fn test_vmm_type_is_confidential() {
        assert!(VmmType::ConfidentialSev.is_confidential());
        assert!(VmmType::ConfidentialTdx.is_confidential());
        assert!(!VmmType::BareMetal.is_confidential());
        assert!(!VmmType::Hypervisor.is_confidential());
    }

    #[test]
    fn test_vmm_type_is_hypervisor() {
        assert!(VmmType::Hypervisor.is_hypervisor());
        assert!(VmmType::ConfidentialSev.is_hypervisor());
        assert!(!VmmType::BareMetal.is_hypervisor());
    }
}
