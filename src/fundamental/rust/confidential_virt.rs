// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/confidential-virt.h
//
// Confidential VM (CVM) detection constants.

// CPUID leaves
pub const CPUID_PROCESSOR_INFO_AND_FEATURE_BITS: u32 = 0x1;
pub const CPUID_GET_HIGHEST_FUNCTION: u32 = 0x8000_0000;
pub const CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES: u32 = 0x8000_001f;
pub const CPUID_INTEL_TDX_ENUMERATION: u32 = 0x21;
pub const CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x4000_0000;
pub const CPUID_HYPERV_FEATURES: u32 = 0x4000_0003;
pub const CPUID_HYPERV_ISOLATION_CONFIG: u32 = 0x4000_000C;
pub const CPUID_HYPERV_MIN: u32 = 0x4000_0005;
pub const CPUID_HYPERV_MAX: u32 = 0x4000_FFFF;

// CPUID signatures
pub const CPUID_SIG_AMD: &[u8; 12] = b"AuthenticAMD";
pub const CPUID_SIG_INTEL: &[u8; 12] = b"GenuineIntel";
pub const CPUID_SIG_INTEL_TDX: &[u8; 12] = b"IntelTDX    ";
pub const CPUID_SIG_HYPERV: &[u8; 12] = b"Microsoft Hv";

// Feature bits
pub const CPUID_FEATURE_HYPERVISOR: u32 = 1 << 31;
pub const CPUID_HYPERV_CPU_MANAGEMENT: u32 = 1 << 12;
pub const CPUID_HYPERV_ISOLATION: u32 = 1 << 22;

// Hyper-V isolation types
pub const CPUID_HYPERV_ISOLATION_TYPE_MASK: u32 = 0xf;
pub const CPUID_HYPERV_ISOLATION_TYPE_SNP: u32 = 2;
pub const CPUID_HYPERV_ISOLATION_TYPE_TDX: u32 = 3;

// AMD SEV
pub const MSR_AMD64_SEV: u32 = 0xc001_0131;
pub const EAX_SEV: u32 = 1 << 1;
pub const MSR_SEV: u64 = 1 << 0;
pub const MSR_SEV_ES: u64 = 1 << 1;
pub const MSR_SEV_SNP: u64 = 1 << 2;
