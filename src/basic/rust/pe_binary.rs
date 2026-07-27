// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/pe-binary.c (pe_header_is_64bit, pe_section_table_find,
//            pe_header_find_section, pe_is_uki, pe_is_addon, pe_is_native,
//            pe_header_get_data_directory)
//
// PE binary header inspection — safe slice-based parsing.

// ── Constants ──────────────────────────────────────────────────────────────

const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;
const PE32_MAGIC: u16 = 0x010B;
const PE32PLUS_MAGIC: u16 = 0x020B;

// ── PeHeader layout offsets ────────────────────────────────────────────────
// PeHeader = le32 signature(4) + IMAGE_FILE_HEADER pe(20) + optional
// NumberOfSections at offset 6: signature(4) + Machine(2)
// Magic at offset 24: signature(4) + file_header(20)
// Subsystem at offset 92: signature(4) + file_header(20) + optional fields(68)
// PE32: NumberOfRvaAndSizes at 116, DataDirectory at 120
// PE32+: NumberOfRvaAndSizes at 132, DataDirectory at 136

// ── Types ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeKind {
    Pe32,
    Pe32Plus,
}

// ── pe_header_is_64bit ─────────────────────────────────────────────────────

pub fn pe_header_is_64bit(header: &[u8]) -> Result<PeKind, i32> {
    if header.len() < 26 {
        return Err(-22); // -EINVAL
    }
    let magic = u16::from_le_bytes([header[24], header[25]]);
    match magic {
        PE32_MAGIC => Ok(PeKind::Pe32),
        PE32PLUS_MAGIC => Ok(PeKind::Pe32Plus),
        _ => Err(-22),
    }
}

// ── pe_section_table_find ──────────────────────────────────────────────────

/// Section name is 8 bytes. Names shorter than 8 are zero-padded.
pub fn pe_section_table_find(sections: &[[u8; 40]], name: &[u8]) -> Option<usize> {
    if name.len() > 8 {
        return None;
    }
    let n = name.len();
    for (i, section) in sections.iter().enumerate() {
        if &section[..n] != name {
            continue;
        }
        if n < 8 && !section[n..8].iter().all(|&b| b == 0) {
            continue;
        }
        return Some(i);
    }
    None
}

// ── pe_header_find_section ─────────────────────────────────────────────────

pub fn pe_header_find_section(
    pe_header: &[u8],
    sections: &[[u8; 40]],
    name: &[u8],
) -> Option<usize> {
    if pe_header.len() < 8 {
        return None;
    }
    let n_sections = u16::from_le_bytes([pe_header[6], pe_header[7]]) as usize;
    if sections.len() < n_sections {
        return None;
    }
    pe_section_table_find(&sections[..n_sections], name)
}

// ── pe_is_uki ──────────────────────────────────────────────────────────────

pub fn pe_is_uki(pe_header: &[u8], sections: &[[u8; 40]]) -> bool {
    if pe_header.len() < 94 {
        return false;
    }
    let subsystem = u16::from_le_bytes([pe_header[92], pe_header[93]]);
    if subsystem != IMAGE_SUBSYSTEM_EFI_APPLICATION {
        return false;
    }
    pe_header_find_section(pe_header, sections, b".osrel").is_some()
        && pe_header_find_section(pe_header, sections, b".linux").is_some()
}

// ── pe_is_addon ────────────────────────────────────────────────────────────

pub fn pe_is_addon(pe_header: &[u8], sections: &[[u8; 40]]) -> bool {
    if pe_header.len() < 94 {
        return false;
    }
    let subsystem = u16::from_le_bytes([pe_header[92], pe_header[93]]);
    if subsystem != IMAGE_SUBSYSTEM_EFI_APPLICATION {
        return false;
    }
    pe_header_find_section(pe_header, sections, b".linux").is_none()
        && (pe_header_find_section(pe_header, sections, b".cmdline").is_some()
            || pe_header_find_section(pe_header, sections, b".dtb").is_some()
            || pe_header_find_section(pe_header, sections, b".initrd").is_some()
            || pe_header_find_section(pe_header, sections, b".ucode").is_some())
}

// ── pe_is_native ───────────────────────────────────────────────────────────

pub fn pe_is_native(pe_header: &[u8]) -> bool {
    if pe_header.len() < 6 {
        return false;
    }
    let machine = u16::from_le_bytes([pe_header[4], pe_header[5]]);
    #[cfg(target_arch = "aarch64")]
    {
        return machine == 0xaa64;
    }
    #[cfg(target_arch = "x86_64")]
    {
        return machine == 0x8664;
    }
    #[cfg(target_arch = "x86")]
    {
        return machine == 0x014c;
    }
    #[cfg(target_arch = "arm")]
    {
        return machine == 0x01c0;
    }
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "arm"
    )))]
    {
        let _ = machine;
        false
    }
}

// ── pe_header_get_data_directory ───────────────────────────────────────────

pub fn pe_header_get_data_directory(pe_header: &[u8], index: usize) -> Option<(u32, u32)> {
    let is_64 = match pe_header_is_64bit(pe_header) {
        Ok(PeKind::Pe32Plus) => true,
        Ok(PeKind::Pe32) => false,
        Err(_) => return None,
    };
    let (nrva_offset, dd_offset) = if is_64 {
        (132usize, 136usize)
    } else {
        (116usize, 120usize)
    };
    if pe_header.len() < nrva_offset + 4 {
        return None;
    }
    let nrva = u32::from_le_bytes([
        pe_header[nrva_offset],
        pe_header[nrva_offset + 1],
        pe_header[nrva_offset + 2],
        pe_header[nrva_offset + 3],
    ]) as usize;
    if index >= nrva {
        return None;
    }
    let off = dd_offset + index * 8;
    if pe_header.len() < off + 8 {
        return None;
    }
    let va = u32::from_le_bytes([
        pe_header[off],
        pe_header[off + 1],
        pe_header[off + 2],
        pe_header[off + 3],
    ]);
    let sz = u32::from_le_bytes([
        pe_header[off + 4],
        pe_header[off + 5],
        pe_header[off + 6],
        pe_header[off + 7],
    ]);
    Some((va, sz))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pe_header_buf(n_sections: u16, subsystem: u16, magic: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        buf[4] = (0x64) as u8; // Machine low byte (placeholder)
        buf[6] = (n_sections & 0xFF) as u8;
        buf[7] = (n_sections >> 8) as u8;
        buf[24] = (magic & 0xFF) as u8;
        buf[25] = (magic >> 8) as u8;
        buf[92] = (subsystem & 0xFF) as u8;
        buf[93] = (subsystem >> 8) as u8;
        buf
    }

    fn make_section(name: &[u8]) -> [u8; 40] {
        let mut sec = [0u8; 40];
        let len = name.len().min(8);
        sec[..len].copy_from_slice(&name[..len]);
        sec
    }

    #[test]
    fn test_pe_header_is_64bit_pe32plus() {
        let h = make_pe_header_buf(3, IMAGE_SUBSYSTEM_EFI_APPLICATION, PE32PLUS_MAGIC);
        assert_eq!(pe_header_is_64bit(&h), Ok(PeKind::Pe32Plus));
    }

    #[test]
    fn test_pe_header_is_64bit_pe32() {
        let h = make_pe_header_buf(3, IMAGE_SUBSYSTEM_EFI_APPLICATION, PE32_MAGIC);
        assert_eq!(pe_header_is_64bit(&h), Ok(PeKind::Pe32));
    }

    #[test]
    fn test_pe_header_is_64bit_too_short() {
        assert!(pe_header_is_64bit(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_pe_section_table_find_found() {
        let sections = [
            make_section(b".osrel\0\0"),
            make_section(b".linux\0\0"),
            make_section(b".cmdline"),
        ];
        assert_eq!(pe_section_table_find(&sections, b".linux"), Some(1));
        assert_eq!(pe_section_table_find(&sections, b".osrel"), Some(0));
    }

    #[test]
    fn test_pe_section_table_find_not_found() {
        let sections = [make_section(b".osrel\0\0"), make_section(b".linux\0\0")];
        assert_eq!(pe_section_table_find(&sections, b".cmdline"), None);
    }

    #[test]
    fn test_pe_section_table_find_name_too_long() {
        let sections = [make_section(b".osrel\0\0")];
        assert_eq!(pe_section_table_find(&sections, b".toolongname"), None);
    }

    #[test]
    fn test_pe_section_table_find_short_name_padded() {
        let sections = [make_section(b".dtb\0\0\0\0")];
        assert_eq!(pe_section_table_find(&sections, b".dtb"), Some(0));
    }

    #[test]
    fn test_pe_header_find_section_found() {
        let h = make_pe_header_buf(2, IMAGE_SUBSYSTEM_EFI_APPLICATION, PE32PLUS_MAGIC);
        let sections = [make_section(b".osrel\0\0"), make_section(b".linux\0\0")];
        assert_eq!(pe_header_find_section(&h, &sections, b".linux"), Some(1));
    }

    #[test]
    fn test_pe_header_find_section_not_found() {
        let h = make_pe_header_buf(1, IMAGE_SUBSYSTEM_EFI_APPLICATION, PE32PLUS_MAGIC);
        let sections = [make_section(b".osrel\0\0")];
        assert_eq!(pe_header_find_section(&h, &sections, b".linux"), None);
    }

    #[test]
    fn test_pe_is_uki_true() {
        let h = make_pe_header_buf(2, IMAGE_SUBSYSTEM_EFI_APPLICATION, PE32PLUS_MAGIC);
        let sections = [make_section(b".osrel\0\0"), make_section(b".linux\0\0")];
        assert!(pe_is_uki(&h, &sections));
    }

    #[test]
    fn test_pe_is_uki_missing_osrel() {
        let h = make_pe_header_buf(1, IMAGE_SUBSYSTEM_EFI_APPLICATION, PE32PLUS_MAGIC);
        let sections = [make_section(b".linux\0\0")];
        assert!(!pe_is_uki(&h, &sections));
    }

    #[test]
    fn test_pe_is_uki_wrong_subsystem() {
        let h = make_pe_header_buf(2, 7, PE32PLUS_MAGIC);
        let sections = [make_section(b".osrel\0\0"), make_section(b".linux\0\0")];
        assert!(!pe_is_uki(&h, &sections));
    }

    #[test]
    fn test_pe_is_addon_true() {
        let h = make_pe_header_buf(1, IMAGE_SUBSYSTEM_EFI_APPLICATION, PE32PLUS_MAGIC);
        let sections = [make_section(b".cmdline")];
        assert!(pe_is_addon(&h, &sections));
    }

    #[test]
    fn test_pe_is_addon_false_has_linux() {
        let h = make_pe_header_buf(2, IMAGE_SUBSYSTEM_EFI_APPLICATION, PE32PLUS_MAGIC);
        let sections = [make_section(b".linux\0\0"), make_section(b".cmdline")];
        assert!(!pe_is_addon(&h, &sections));
    }

    #[test]
    fn test_pe_is_addon_false_no_addon_sections() {
        let h = make_pe_header_buf(1, IMAGE_SUBSYSTEM_EFI_APPLICATION, PE32PLUS_MAGIC);
        let sections = [make_section(b".osrel\0\0")];
        assert!(!pe_is_addon(&h, &sections));
    }

    #[test]
    fn test_pe_is_native_short_header() {
        assert!(!pe_is_native(&[0u8; 4]));
    }

    #[test]
    fn test_pe_header_get_data_directory_valid() {
        let mut h = make_pe_header_buf(0, 0, PE32PLUS_MAGIC);
        // Write NumberOfRvaAndSizes = 2 at offset 132
        h[132] = 2;
        h[133] = 0;
        h[134] = 0;
        h[135] = 0;
        // Write first DataDirectory at offset 136: VA=0x1000, Size=0x200
        h[136] = 0x00;
        h[137] = 0x10;
        h[138] = 0;
        h[139] = 0;
        h[140] = 0x00;
        h[141] = 0x02;
        h[142] = 0;
        h[143] = 0;
        assert_eq!(pe_header_get_data_directory(&h, 0), Some((0x1000, 0x200)));
    }

    #[test]
    fn test_pe_header_get_data_directory_out_of_range() {
        let h = make_pe_header_buf(0, 0, PE32PLUS_MAGIC);
        assert_eq!(pe_header_get_data_directory(&h, 0), None);
    }
}
