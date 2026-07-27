// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/tpm2-pcr.h
//
// TPM PCR definitions for measured boot.

/// Platform Code (PCR 0)
pub const TPM2_PCR_PLATFORM_CODE: u32 = 0;
/// Platform Config (PCR 1)
pub const TPM2_PCR_PLATFORM_CONFIG: u32 = 1;
/// External Code (PCR 2)
pub const TPM2_PCR_EXTERNAL_CODE: u32 = 2;
/// External Config (PCR 3)
pub const TPM2_PCR_EXTERNAL_CONFIG: u32 = 3;
/// Boot Loader Code (PCR 4)
pub const TPM2_PCR_BOOT_LOADER_CODE: u32 = 4;
/// Boot Loader Config (PCR 5)
pub const TPM2_PCR_BOOT_LOADER_CONFIG: u32 = 5;
/// Host Platform (PCR 6)
pub const TPM2_PCR_HOST_PLATFORM: u32 = 6;
/// Secure Boot Policy (PCR 7)
pub const TPM2_PCR_SECURE_BOOT_POLICY: u32 = 7;
/// Kernel Initrd (PCR 9)
pub const TPM2_PCR_KERNEL_INITRD: u32 = 9;
/// IMA (PCR 10)
pub const TPM2_PCR_IMA: u32 = 10;
/// Kernel Boot — sd-stub payloads (PCR 11)
pub const TPM2_PCR_KERNEL_BOOT: u32 = 11;
/// Kernel Config — cmdline + credentials (PCR 12)
pub const TPM2_PCR_KERNEL_CONFIG: u32 = 12;
/// Sysexts (PCR 13)
pub const TPM2_PCR_SYSEXTS: u32 = 13;
/// Shim Policy (PCR 14)
pub const TPM2_PCR_SHIM_POLICY: u32 = 14;
/// System Identity — root fs volume key (PCR 15)
pub const TPM2_PCR_SYSTEM_IDENTITY: u32 = 15;
/// Debug (PCR 16)
pub const TPM2_PCR_DEBUG: u32 = 16;
/// Application Support (PCR 23)
pub const TPM2_PCR_APPLICATION_SUPPORT: u32 = 23;

// Event tag IDs
pub const LOADER_CONF_EVENT_TAG_ID: u32 = 0xf5bc582a;
pub const DEVICETREE_ADDON_EVENT_TAG_ID: u32 = 0x6c46f751;
pub const INITRD_ADDON_EVENT_TAG_ID: u32 = 0x49dffe0f;
pub const UCODE_ADDON_EVENT_TAG_ID: u32 = 0xdac08e1a;
pub const UKI_PROFILE_EVENT_TAG_ID: u32 = 0x13aed6db;
pub const SMBIOS_TYPE1_EVENT_TAG_ID: u32 = 0xd5cb7cbc;
pub const SMBIOS_TYPE2_EVENT_TAG_ID: u32 = 0xe0d47bc8;
pub const SMBIOS_TYPE11_EVENT_TAG_ID: u32 = 0xc0b3bd23;
