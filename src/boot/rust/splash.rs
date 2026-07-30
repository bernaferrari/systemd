// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/splash.c
//
// BMP image parsing and conversion to EFI BLT pixel format.
//
// Supports 1/4/8/16/24/32-bit BMP files with optional channel masks,
// color tables, and alpha blending for 16/32-bit images.

// ── Constants ─────────────────────────────────────────────────────────────

/// BMP file header size (12 bytes).
pub const BMP_FILE_HEADER_SIZE: usize = 14;

/// Minimum DIB header size (BITMAPINFOHEADER).
pub const SIZEOF_BMP_DIB: usize = 40;

/// Maximum image size (64 MiB) to prevent OOM.
pub const MAX_IMAGE_SIZE: usize = 64 * 1024 * 1024;

/// Channel indices.
pub const CHANNEL_R: usize = 0;
pub const CHANNEL_G: usize = 1;
pub const CHANNEL_B: usize = 2;
pub const CHANNEL_A: usize = 3;
pub const CHANNELS_MAX: usize = 4;

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BmpFileHeader {
    pub signature: [u8; 2],
    pub size: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BmpDib {
    pub size: u32,
    pub x: u32,
    pub y: u32,
    pub planes: u16,
    pub depth: u16,
    pub compression: u32,
    pub image_size: u32,
    pub channel_mask_r: u32,
    pub channel_mask_g: u32,
    pub channel_mask_b: u32,
    pub channel_mask_a: u32,
    pub colors_used: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BmpMap {
    pub blue: u8,
    pub green: u8,
    pub red: u8,
    pub reserved: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BltPixel {
    pub blue: u8,
    pub green: u8,
    pub red: u8,
    pub reserved: u8,
}

#[derive(Debug, Clone)]
pub struct ChannelMasks {
    pub mask: [u32; CHANNELS_MAX],
    pub shift: [u8; CHANNELS_MAX],
    pub scale: [u8; CHANNELS_MAX],
}

/// Error type for BMP/splash operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplashError {
    /// Input data too small for header.
    DataTooSmall,
    /// Invalid BMP signature.
    InvalidSignature,
    /// File size mismatch.
    SizeMismatch,
    /// Offset exceeds file size.
    InvalidOffset,
    /// Unsupported DIB version.
    UnsupportedDib,
    /// Unsupported bit depth.
    UnsupportedDepth,
    /// Unsupported compression mode.
    UnsupportedCompression,
    /// Color table mismatch.
    ColorTableMismatch,
    /// Image exceeds maximum size.
    ImageTooLarge,
}

impl std::fmt::Display for SplashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SplashError::DataTooSmall => write!(f, "BMP data too small"),
            SplashError::InvalidSignature => write!(f, "invalid BMP signature"),
            SplashError::SizeMismatch => write!(f, "BMP size mismatch"),
            SplashError::InvalidOffset => write!(f, "invalid pixel data offset"),
            SplashError::UnsupportedDib => write!(f, "unsupported DIB version"),
            SplashError::UnsupportedDepth => write!(f, "unsupported bit depth"),
            SplashError::UnsupportedCompression => write!(f, "unsupported compression"),
            SplashError::ColorTableMismatch => write!(f, "color table mismatch"),
            SplashError::ImageTooLarge => write!(f, "image exceeds maximum size"),
        }
    }
}

impl std::error::Error for SplashError {}

// ── BMP header parsing ────────────────────────────────────────────────────

/// Parse the BMP file header from raw bytes.
pub fn parse_bmp_file_header(data: &[u8]) -> Result<BmpFileHeader, SplashError> {
    if data.len() < BMP_FILE_HEADER_SIZE {
        return Err(SplashError::DataTooSmall);
    }

    let sig = [data[0], data[1]];
    if sig != *b"BM" {
        return Err(SplashError::InvalidSignature);
    }

    let size = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
    let offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);

    Ok(BmpFileHeader {
        signature: sig,
        size,
        offset,
    })
}

/// Parse the BMP DIB (Device Independent Bitmap) header.
pub fn parse_bmp_dib(data: &[u8]) -> Result<BmpDib, SplashError> {
    if data.len() < SIZEOF_BMP_DIB - BMP_FILE_HEADER_SIZE {
        return Err(SplashError::DataTooSmall);
    }

    let dib_start = BMP_FILE_HEADER_SIZE;
    let dib_size = u32::from_le_bytes([
        data[dib_start],
        data[dib_start + 1],
        data[dib_start + 2],
        data[dib_start + 3],
    ]);

    if dib_size < 40 {
        return Err(SplashError::UnsupportedDib);
    }

    let x = u32::from_le_bytes([
        data[dib_start + 4],
        data[dib_start + 5],
        data[dib_start + 6],
        data[dib_start + 7],
    ]);
    let y = u32::from_le_bytes([
        data[dib_start + 8],
        data[dib_start + 9],
        data[dib_start + 10],
        data[dib_start + 11],
    ]);
    let planes = u16::from_le_bytes([data[dib_start + 12], data[dib_start + 13]]);
    let depth = u16::from_le_bytes([data[dib_start + 14], data[dib_start + 15]]);
    let compression = u32::from_le_bytes([
        data[dib_start + 16],
        data[dib_start + 17],
        data[dib_start + 18],
        data[dib_start + 19],
    ]);
    let image_size = u32::from_le_bytes([
        data[dib_start + 20],
        data[dib_start + 21],
        data[dib_start + 22],
        data[dib_start + 23],
    ]);
    let colors_used = u32::from_le_bytes([
        data[dib_start + 32],
        data[dib_start + 33],
        data[dib_start + 34],
        data[dib_start + 35],
    ]);

    let (cm_r, cm_g, cm_b, cm_a) = if dib_size >= 52 {
        let r = u32::from_le_bytes([
            data[dib_start + 40],
            data[dib_start + 41],
            data[dib_start + 42],
            data[dib_start + 43],
        ]);
        let g = u32::from_le_bytes([
            data[dib_start + 44],
            data[dib_start + 45],
            data[dib_start + 46],
            data[dib_start + 47],
        ]);
        let b = u32::from_le_bytes([
            data[dib_start + 48],
            data[dib_start + 49],
            data[dib_start + 50],
            data[dib_start + 51],
        ]);
        let a = if dib_size >= 56 {
            u32::from_le_bytes([
                data[dib_start + 52],
                data[dib_start + 53],
                data[dib_start + 54],
                data[dib_start + 55],
            ])
        } else {
            0
        };
        (r, g, b, a)
    } else {
        (0, 0, 0, 0)
    };

    Ok(BmpDib {
        size: dib_size,
        x,
        y,
        planes,
        depth,
        compression,
        image_size,
        channel_mask_r: cm_r,
        channel_mask_g: cm_g,
        channel_mask_b: cm_b,
        channel_mask_a: cm_a,
        colors_used,
    })
}

/// Full BMP header validation.
pub fn bmp_parse_header(data: &[u8]) -> Result<(BmpDib, usize, usize), SplashError> {
    let file_hdr = parse_bmp_file_header(data)?;
    let dib = parse_bmp_dib(data)?;

    if file_hdr.size as usize != data.len() {
        return Err(SplashError::SizeMismatch);
    }
    if file_hdr.size < file_hdr.offset {
        return Err(SplashError::InvalidOffset);
    }

    match dib.depth {
        1 | 4 | 8 | 24 => {
            if dib.compression != 0 {
                return Err(SplashError::UnsupportedCompression);
            }
        }
        16 | 32 => {
            if dib.compression != 0 && dib.compression != 3 {
                return Err(SplashError::UnsupportedCompression);
            }
        }
        _ => return Err(SplashError::UnsupportedDepth),
    }

    let row_size = ((dib.depth as usize) * (dib.x as usize)).div_ceil(32) * 4;
    let total_pixel_data = (dib.y as usize) * row_size;
    let pixel_available = if file_hdr.size >= file_hdr.offset {
        (file_hdr.size - file_hdr.offset) as usize
    } else {
        return Err(SplashError::InvalidOffset);
    };
    if pixel_available < total_pixel_data {
        return Err(SplashError::InvalidOffset);
    }
    if total_pixel_data > MAX_IMAGE_SIZE {
        return Err(SplashError::ImageTooLarge);
    }

    let map_offset = BMP_FILE_HEADER_SIZE + dib.size as usize;
    if (file_hdr.offset as usize) < map_offset {
        return Err(SplashError::InvalidOffset);
    }

    Ok((dib, file_hdr.offset as usize, map_offset))
}

// ── Channel mask computation ──────────────────────────────────────────────

fn trailing_zeros_u32(v: u32) -> u8 {
    if v == 0 {
        return 0;
    }
    let mut count = 0u8;
    let mut val = v;
    while val & 1 == 0 {
        count += 1;
        val >>= 1;
    }
    count
}

fn popcount_u32(v: u32) -> u8 {
    let mut count = 0u8;
    let mut val = v;
    while val != 0 {
        count += val as u8 & 1;
        val >>= 1;
    }
    count
}

/// Read channel masks for 16/32-bit BMP images.
///
/// Mirrors `read_channel_mask()` in C.
pub fn read_channel_mask(dib: &BmpDib) -> ChannelMasks {
    let mut masks = ChannelMasks {
        mask: [0u32; CHANNELS_MAX],
        shift: [0u8; CHANNELS_MAX],
        scale: [0u8; CHANNELS_MAX],
    };

    if matches!(dib.depth, 16 | 32) && dib.size >= 52 {
        masks.mask[CHANNEL_R] = dib.channel_mask_r;
        masks.mask[CHANNEL_G] = dib.channel_mask_g;
        masks.mask[CHANNEL_B] = dib.channel_mask_b;
        masks.shift[CHANNEL_R] = trailing_zeros_u32(dib.channel_mask_r);
        masks.shift[CHANNEL_G] = trailing_zeros_u32(dib.channel_mask_g);
        masks.shift[CHANNEL_B] = trailing_zeros_u32(dib.channel_mask_b);

        let pc_r = popcount_u32(dib.channel_mask_r);
        let pc_g = popcount_u32(dib.channel_mask_g);
        let pc_b = popcount_u32(dib.channel_mask_b);
        masks.scale[CHANNEL_R] = if pc_r > 0 {
            0xFF / ((1u32 << pc_r) - 1) as u8
        } else {
            0
        };
        masks.scale[CHANNEL_G] = if pc_g > 0 {
            0xFF / ((1u32 << pc_g) - 1) as u8
        } else {
            0
        };
        masks.scale[CHANNEL_B] = if pc_b > 0 {
            0xFF / ((1u32 << pc_b) - 1) as u8
        } else {
            0
        };

        if dib.size >= 56 && dib.channel_mask_a != 0 {
            masks.mask[CHANNEL_A] = dib.channel_mask_a;
            masks.shift[CHANNEL_A] = trailing_zeros_u32(dib.channel_mask_a);
            let pc_a = popcount_u32(dib.channel_mask_a);
            masks.scale[CHANNEL_A] = if pc_a > 0 {
                0xFF / ((1u32 << pc_a) - 1) as u8
            } else {
                0
            };
        }
    } else {
        let bpp16 = dib.depth == 16;
        masks.mask[CHANNEL_R] = if bpp16 { 0x7C00 } else { 0xFF0000 };
        masks.mask[CHANNEL_G] = if bpp16 { 0x03E0 } else { 0x00FF00 };
        masks.mask[CHANNEL_B] = if bpp16 { 0x001F } else { 0x0000FF };
        masks.shift[CHANNEL_R] = if bpp16 { 0xA } else { 0x10 };
        masks.shift[CHANNEL_G] = if bpp16 { 0x5 } else { 0x08 };
        masks.shift[CHANNEL_B] = 0;
        masks.scale[CHANNEL_R] = if bpp16 { 0x08 } else { 0x1 };
        masks.scale[CHANNEL_G] = if bpp16 { 0x08 } else { 0x1 };
        masks.scale[CHANNEL_B] = if bpp16 { 0x08 } else { 0x1 };
    }

    masks
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_bmp(depth: u16, width: u32, height: u32) -> Vec<u8> {
        let row_size = ((depth as usize) * (width as usize)).div_ceil(32) * 4;
        let pixel_data_size = row_size * (height as usize);
        let dib_size: u32 = 40;
        let offset = (BMP_FILE_HEADER_SIZE + dib_size as usize) as u32;
        let file_size = offset as usize + pixel_data_size;

        let mut data = Vec::with_capacity(file_size);
        data.extend_from_slice(b"BM");
        data.extend_from_slice(&(file_size as u32).to_le_bytes());
        data.extend_from_slice(&[0u8; 4]); // reserved
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&dib_size.to_le_bytes());
        data.extend_from_slice(&width.to_le_bytes());
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes()); // planes
        data.extend_from_slice(&depth.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // compression
        data.extend_from_slice(&(pixel_data_size as u32).to_le_bytes());
        data.extend_from_slice(&[0u8; 8]); // x/y pixel meter
        data.extend_from_slice(&0u32.to_le_bytes()); // colors used
        data.extend_from_slice(&0u32.to_le_bytes()); // colors important
        data.resize(file_size, 0);
        data
    }

    #[test]
    fn test_parse_bmp_file_header_valid() {
        let data = make_minimal_bmp(24, 4, 4);
        let hdr = parse_bmp_file_header(&data).unwrap();
        assert_eq!(hdr.signature, *b"BM");
        assert_eq!(hdr.size as usize, data.len());
    }

    #[test]
    fn test_parse_bmp_file_header_too_small() {
        assert!(parse_bmp_file_header(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_parse_bmp_file_header_bad_sig() {
        let mut data = make_minimal_bmp(24, 4, 4);
        data[0] = b'X';
        data[1] = b'Y';
        assert!(parse_bmp_file_header(&data).is_err());
    }

    #[test]
    fn test_parse_bmp_dib_24bit() {
        let data = make_minimal_bmp(24, 4, 4);
        let dib = parse_bmp_dib(&data).unwrap();
        assert_eq!(dib.depth, 24);
        assert_eq!(dib.x, 4);
        assert_eq!(dib.y, 4);
        assert_eq!(dib.compression, 0);
    }

    #[test]
    fn test_bmp_parse_header_full() {
        let data = make_minimal_bmp(24, 4, 4);
        let result = bmp_parse_header(&data);
        assert!(result.is_ok());
        let (dib, pixel_offset, _) = result.unwrap();
        assert_eq!(dib.depth, 24);
        assert_eq!(dib.x, 4);
        assert!(pixel_offset > 0);
    }

    #[test]
    fn test_bmp_parse_header_size_mismatch() {
        let mut data = make_minimal_bmp(24, 4, 4);
        data.truncate(data.len() - 1);
        assert!(bmp_parse_header(&data).is_err());
    }

    #[test]
    fn test_bmp_parse_header_unsupported_depth() {
        let data = make_minimal_bmp(7, 4, 4);
        assert!(bmp_parse_header(&data).is_err());
    }

    #[test]
    fn test_bmp_parse_header_unsupported_compression() {
        let mut data = make_minimal_bmp(8, 4, 4);
        let comp_offset = BMP_FILE_HEADER_SIZE + 16;
        data[comp_offset..comp_offset + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(bmp_parse_header(&data).is_err());
    }

    #[test]
    fn test_read_channel_mask_24bit() {
        let data = make_minimal_bmp(24, 4, 4);
        let dib = parse_bmp_dib(&data).unwrap();
        let masks = read_channel_mask(&dib);
        assert_eq!(masks.mask[CHANNEL_R], 0xFF0000);
        assert_eq!(masks.mask[CHANNEL_G], 0x00FF00);
        assert_eq!(masks.mask[CHANNEL_B], 0x0000FF);
        assert_eq!(masks.scale[CHANNEL_R], 1);
    }

    #[test]
    fn test_read_channel_mask_16bit() {
        let data = make_minimal_bmp(16, 4, 4);
        let dib = parse_bmp_dib(&data).unwrap();
        let masks = read_channel_mask(&dib);
        assert_eq!(masks.mask[CHANNEL_R], 0x7C00);
        assert_eq!(masks.mask[CHANNEL_G], 0x03E0);
        assert_eq!(masks.mask[CHANNEL_B], 0x001F);
    }

    #[test]
    fn test_trailing_zeros() {
        assert_eq!(trailing_zeros_u32(0), 0);
        assert_eq!(trailing_zeros_u32(1), 0);
        assert_eq!(trailing_zeros_u32(2), 1);
        assert_eq!(trailing_zeros_u32(0xFF00), 8);
        assert_eq!(trailing_zeros_u32(0x7C00), 10);
    }

    #[test]
    fn test_popcount() {
        assert_eq!(popcount_u32(0), 0);
        assert_eq!(popcount_u32(1), 1);
        assert_eq!(popcount_u32(0xFF), 8);
        assert_eq!(popcount_u32(0x7C00), 5);
    }
}
