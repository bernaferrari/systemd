// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/efi.h
//
// EFI GUID and related structure definitions.

/// Matches EFI_GUID from the UEFI specification.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EfiGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl EfiGuid {
    pub const fn new(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Self {
        Self {
            data1: d1,
            data2: d2,
            data3: d3,
            data4: d4,
        }
    }

    /// Compare two GUIDs for equality.
    pub fn equals(&self, other: &Self) -> bool {
        self.data1 == other.data1
            && self.data2 == other.data2
            && self.data3 == other.data3
            && self.data4 == other.data4
    }
}

/// EFI_SIGNATURE_DATA
#[repr(C, packed)]
pub struct EfiSignatureData {
    pub signature_owner: EfiGuid,
    // SignatureData[] follows — flexible array member
}

/// EFI_SIGNATURE_LIST
#[repr(C, packed)]
pub struct EfiSignatureList {
    pub signature_type: EfiGuid,
    pub signature_list_size: u32,
    pub signature_header_size: u32,
    pub signature_size: u32,
    // Signatures[] follows — flexible array member
}

/// WIN_CERTIFICATE_HEADER
#[repr(C)]
pub struct WinCertificateHeader {
    pub dw_length: u32,
    pub w_revision: u16,
    pub w_certificate_type: u16,
}

/// WIN_CERTIFICATE_UEFI_GUID
#[repr(C)]
pub struct WinCertificateUefiGuid {
    pub hdr: WinCertificateHeader,
    pub cert_type: EfiGuid,
    // CertData[] follows
}

/// EFI_TIME
#[repr(C)]
pub struct EfiTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub time_zone: i16,
    pub daylight: u8,
    pub pad2: u8,
}

/// EFI_VARIABLE_AUTHENTICATION_2
#[repr(C)]
pub struct EfiVariableAuthentication2 {
    pub timestamp: EfiTime,
    pub auth_info: WinCertificateUefiGuid,
}

// ── Well-known GUIDs ────────────────────────────────────────────────────

pub const EFI_GLOBAL_VARIABLE: EfiGuid = EfiGuid::new(
    0x8be4df61,
    0x93ca,
    0x11d2,
    [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
);

pub const EFI_IMAGE_SECURITY_DATABASE_GUID: EfiGuid = EfiGuid::new(
    0xd719b2cb,
    0x3d3a,
    0x4596,
    [0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
);

pub const EFI_CERT_X509_GUID: EfiGuid = EfiGuid::new(
    0xa5c059a1,
    0x94e4,
    0x4aa7,
    [0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
);

pub const EFI_CERT_TYPE_PKCS7_GUID: EfiGuid = EfiGuid::new(
    0x4aafd29d,
    0x68df,
    0x49ee,
    [0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7],
);

pub const SHIM_LOCK_GUID: EfiGuid = EfiGuid::new(
    0x605dab50,
    0xe046,
    0x4300,
    [0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23],
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guid_equality() {
        let a = EFI_GLOBAL_VARIABLE;
        let b = EfiGuid::new(
            0x8be4df61,
            0x93ca,
            0x11d2,
            [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
        );
        assert!(a.equals(&b));
        assert!(a == b);
    }

    #[test]
    fn test_guid_inequality() {
        let a = EFI_GLOBAL_VARIABLE;
        let b = EFI_CERT_X509_GUID;
        assert!(!a.equals(&b));
    }

    #[test]
    fn test_guid_new() {
        let g = EfiGuid::new(1, 2, 3, [4, 5, 6, 7, 8, 9, 10, 11]);
        assert_eq!(g.data1, 1);
        assert_eq!(g.data2, 2);
        assert_eq!(g.data3, 3);
        assert_eq!(g.data4, [4, 5, 6, 7, 8, 9, 10, 11]);
    }
}
