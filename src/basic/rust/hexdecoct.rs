// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/hexdecoct.c

use std::ffi::CStr;

use libc::{c_char, c_void};

use crate::ffi::Errno;

pub fn octchar(x: i32) -> char {
    char::from(b'0' + (x as u8 & 7))
}

pub fn unoctchar(c: char) -> Result<i32, i32> {
    match c {
        '0'..='7' => Ok((c as u8 - b'0') as i32),
        _ => Err(Errno::EINVAL.to_neg_errno()),
    }
}

pub fn decchar(x: i32) -> char {
    char::from(b'0' + (x.rem_euclid(10) as u8))
}

pub fn undecchar(c: char) -> Result<i32, i32> {
    match c {
        '0'..='9' => Ok((c as u8 - b'0') as i32),
        _ => Err(Errno::EINVAL.to_neg_errno()),
    }
}

pub fn hexchar(x: i32) -> char {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    char::from(TABLE[x as usize & 15])
}

pub fn unhexchar(c: char) -> Result<i32, i32> {
    match c {
        '0'..='9' => Ok((c as u8 - b'0') as i32),
        'a'..='f' => Ok((c as u8 - b'a' + 10) as i32),
        'A'..='F' => Ok((c as u8 - b'A' + 10) as i32),
        _ => Err(Errno::EINVAL.to_neg_errno()),
    }
}

pub fn base32hexchar(x: i32) -> char {
    const TABLE: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    char::from(TABLE[x as usize & 31])
}

pub fn unbase32hexchar(c: char) -> Result<i32, i32> {
    match c {
        '0'..='9' => Ok((c as u8 - b'0') as i32),
        'A'..='V' => Ok((c as u8 - b'A' + 10) as i32),
        _ => Err(Errno::EINVAL.to_neg_errno()),
    }
}

pub fn base64char(x: i32) -> char {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char::from(TABLE[x as usize & 63])
}

pub fn urlsafe_base64char(x: i32) -> char {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char::from(TABLE[x as usize & 63])
}

pub fn unbase64char(c: char) -> Result<i32, i32> {
    match c {
        'A'..='Z' => Ok((c as u8 - b'A') as i32),
        'a'..='z' => Ok((c as u8 - b'a' + 26) as i32),
        '0'..='9' => Ok((c as u8 - b'0' + 52) as i32),
        '+' | '-' => Ok(62),
        '/' | '_' => Ok(63),
        _ => Err(Errno::EINVAL.to_neg_errno()),
    }
}

pub fn hexmem(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(hexchar((byte >> 4).into()));
        out.push(hexchar((byte & 0x0f).into()));
    }
    out
}

fn unhex_next(chars: &[char], index: &mut usize) -> Result<Option<i32>, i32> {
    while *index < chars.len() && chars[*index].is_ascii_whitespace() {
        *index += 1;
    }
    if *index >= chars.len() {
        return Ok(None);
    }

    let value = unhexchar(chars[*index])?;
    *index += 1;

    while *index < chars.len() && chars[*index].is_ascii_whitespace() {
        *index += 1;
    }

    Ok(Some(value))
}

pub fn unhexmem_full(s: &str) -> Result<Vec<u8>, i32> {
    let chars: Vec<char> = s.chars().collect();
    let mut index = 0;
    let mut out = Vec::with_capacity((chars.len() + 1) / 2);

    loop {
        let Some(a) = unhex_next(&chars, &mut index)? else {
            break;
        };
        let Some(b) = unhex_next(&chars, &mut index)? else {
            return Err(-libc::EPIPE);
        };
        out.push(((a as u8) << 4) | (b as u8));
    }

    Ok(out)
}

pub fn base32hexmem(data: &[u8], padding: bool) -> String {
    let mut out = String::new();

    for chunk in data.chunks(5) {
        let mut buffer = [0u8; 5];
        buffer[..chunk.len()].copy_from_slice(chunk);

        let mut block = [
            base32hexchar((buffer[0] >> 3).into()),
            base32hexchar((((buffer[0] & 7) << 2) | (buffer[1] >> 6)).into()),
            base32hexchar(((buffer[1] & 63) >> 1).into()),
            base32hexchar((((buffer[1] & 1) << 4) | (buffer[2] >> 4)).into()),
            base32hexchar((((buffer[2] & 15) << 1) | (buffer[3] >> 7)).into()),
            base32hexchar(((buffer[3] & 127) >> 2).into()),
            base32hexchar((((buffer[3] & 3) << 3) | (buffer[4] >> 5)).into()),
            base32hexchar((buffer[4] & 31).into()),
        ];

        let keep = match chunk.len() {
            0 => 0,
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 8,
        };

        if padding {
            for item in block.iter_mut().skip(keep) {
                *item = '=';
            }
            out.extend(block);
        } else {
            out.extend(block.into_iter().take(keep));
        }
    }

    out
}

pub fn unbase32hexmem(s: &str, padding: bool) -> Result<Vec<u8>, i32> {
    let mut input = s.trim().to_string();
    if padding && input.len() % 8 != 0 {
        return Err(Errno::EINVAL.to_neg_errno());
    }
    if padding {
        while input.ends_with('=') {
            input.pop();
        }
    }

    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut index = 0;

    while index < chars.len() {
        let remaining = chars.len() - index;
        let take = match remaining {
            n if n >= 8 => 8,
            7 | 5 | 4 | 2 => remaining,
            _ => return Err(Errno::EINVAL.to_neg_errno()),
        };

        let values: Result<Vec<i32>, i32> = chars[index..index + take]
            .iter()
            .copied()
            .map(unbase32hexchar)
            .collect();
        let values = values?;
        let mut padded = [0i32; 8];
        for (slot, value) in padded.iter_mut().zip(values.iter().copied()) {
            *slot = value;
        }

        match take {
            8 => {
                out.push(((padded[0] << 3) | (padded[1] >> 2)) as u8);
                out.push(((padded[1] << 6) | (padded[2] << 1) | (padded[3] >> 4)) as u8);
                out.push(((padded[3] << 4) | (padded[4] >> 1)) as u8);
                out.push(((padded[4] << 7) | (padded[5] << 2) | (padded[6] >> 3)) as u8);
                out.push(((padded[6] << 5) | padded[7]) as u8);
            }
            7 => {
                if (padded[6] & 7) != 0 {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                out.push(((padded[0] << 3) | (padded[1] >> 2)) as u8);
                out.push(((padded[1] << 6) | (padded[2] << 1) | (padded[3] >> 4)) as u8);
                out.push(((padded[3] << 4) | (padded[4] >> 1)) as u8);
                out.push(((padded[4] << 7) | (padded[5] << 2) | (padded[6] >> 3)) as u8);
            }
            5 => {
                if (padded[4] & 1) != 0 {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                out.push(((padded[0] << 3) | (padded[1] >> 2)) as u8);
                out.push(((padded[1] << 6) | (padded[2] << 1) | (padded[3] >> 4)) as u8);
                out.push(((padded[3] << 4) | (padded[4] >> 1)) as u8);
            }
            4 => {
                if (padded[3] & 15) != 0 {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                out.push(((padded[0] << 3) | (padded[1] >> 2)) as u8);
                out.push(((padded[1] << 6) | (padded[2] << 1) | (padded[3] >> 4)) as u8);
            }
            2 => {
                if (padded[1] & 3) != 0 {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                out.push(((padded[0] << 3) | (padded[1] >> 2)) as u8);
            }
            _ => unreachable!(),
        }

        index += take;
    }

    Ok(out)
}

pub fn base64mem_full(data: &[u8], line_break: usize) -> Result<String, i32> {
    if line_break == 0 {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    let mut out = String::new();
    let mut emitted = 0usize;

    let mut push = |ch: char, out: &mut String, emitted: &mut usize| {
        if line_break != usize::MAX && *emitted > 0 && *emitted % line_break == 0 {
            out.push('\n');
        }
        out.push(ch);
        *emitted += 1;
    };

    for chunk in data.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);

        push(base64char((a >> 2).into()), &mut out, &mut emitted);
        push(
            base64char((((a & 3) << 4) | (b >> 4)).into()),
            &mut out,
            &mut emitted,
        );
        match chunk.len() {
            3 => {
                push(
                    base64char((((b & 15) << 2) | (c >> 6)).into()),
                    &mut out,
                    &mut emitted,
                );
                push(base64char((c & 63).into()), &mut out, &mut emitted);
            }
            2 => {
                push(base64char(((b & 15) << 2).into()), &mut out, &mut emitted);
                push('=', &mut out, &mut emitted);
            }
            _ => {
                push('=', &mut out, &mut emitted);
                push('=', &mut out, &mut emitted);
            }
        }
    }

    Ok(out)
}

pub fn base64mem(data: &[u8]) -> Result<String, i32> {
    base64mem_full(data, usize::MAX)
}

fn unbase64_next(chars: &[char], index: &mut usize) -> Result<Option<Option<i32>>, i32> {
    while *index < chars.len() && chars[*index].is_ascii_whitespace() {
        *index += 1;
    }
    if *index >= chars.len() {
        return Ok(None);
    }
    let ch = chars[*index];
    *index += 1;
    while *index < chars.len() && chars[*index].is_ascii_whitespace() {
        *index += 1;
    }
    if ch == '=' {
        Ok(Some(None))
    } else {
        Ok(Some(Some(unbase64char(ch)?)))
    }
}

pub fn unbase64mem_full(s: &str) -> Result<Vec<u8>, i32> {
    let chars: Vec<char> = s.chars().collect();
    let mut index = 0;
    let mut out = Vec::new();

    loop {
        let Some(a) = unbase64_next(&chars, &mut index)? else {
            break;
        };
        let Some(a) = a else {
            return Err(Errno::EINVAL.to_neg_errno());
        };

        let Some(b) = unbase64_next(&chars, &mut index)? else {
            return Err(-libc::EPIPE);
        };
        let Some(b) = b else {
            return Err(Errno::EINVAL.to_neg_errno());
        };

        let Some(c) = unbase64_next(&chars, &mut index)? else {
            return Err(-libc::EPIPE);
        };
        let Some(d) = unbase64_next(&chars, &mut index)? else {
            return Err(-libc::EPIPE);
        };

        match (c, d) {
            (None, Some(_)) => return Err(Errno::EINVAL.to_neg_errno()),
            (None, None) => {
                if (b & 15) != 0 || chars[index..].iter().any(|ch| !ch.is_ascii_whitespace()) {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                out.push(((a << 2) | (b >> 4)) as u8);
                break;
            }
            (Some(c), None) => {
                if (c & 3) != 0 || chars[index..].iter().any(|ch| !ch.is_ascii_whitespace()) {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                out.push(((a << 2) | (b >> 4)) as u8);
                out.push(((b << 4) | (c >> 2)) as u8);
                break;
            }
            (Some(c), Some(d)) => {
                out.push(((a << 2) | (b >> 4)) as u8);
                out.push(((b << 4) | (c >> 2)) as u8);
                out.push(((c << 6) | d) as u8);
            }
        }
    }

    Ok(out)
}

#[inline]
fn is_systemd_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn unhex_next_byte(input: &[u8], cursor: &mut usize) -> Result<u8, i32> {
    while *cursor < input.len() && is_systemd_whitespace(input[*cursor]) {
        *cursor += 1;
    }
    if *cursor == input.len() {
        return Err(-libc::EPIPE);
    }

    let value = match input[*cursor] {
        b'0'..=b'9' => input[*cursor] - b'0',
        b'a'..=b'f' => input[*cursor] - b'a' + 10,
        b'A'..=b'F' => input[*cursor] - b'A' + 10,
        _ => return Err(Errno::EINVAL.to_neg_errno()),
    };
    *cursor += 1;
    while *cursor < input.len() && is_systemd_whitespace(input[*cursor]) {
        *cursor += 1;
    }
    Ok(value)
}

fn unhex_decode_into(input: &[u8], output: &mut [u8]) -> Result<usize, i32> {
    let mut cursor = 0;
    let mut output_len = 0;
    loop {
        let high = match unhex_next_byte(input, &mut cursor) {
            Err(error) if error == -libc::EPIPE => return Ok(output_len),
            Err(error) => return Err(error),
            Ok(value) => value,
        };
        let low = unhex_next_byte(input, &mut cursor)?;
        output[output_len] = (high << 4) | low;
        output_len += 1;
    }
}

#[derive(Clone, Copy)]
enum Base64Input {
    Value(u8),
    Padding,
}

fn unbase64_next_byte(input: &[u8], cursor: &mut usize) -> Result<Base64Input, i32> {
    while *cursor < input.len() && is_systemd_whitespace(input[*cursor]) {
        *cursor += 1;
    }
    if *cursor == input.len() {
        return Err(-libc::EPIPE);
    }

    let value = match input[*cursor] {
        b'=' => Base64Input::Padding,
        b'A'..=b'Z' => Base64Input::Value(input[*cursor] - b'A'),
        b'a'..=b'z' => Base64Input::Value(input[*cursor] - b'a' + 26),
        b'0'..=b'9' => Base64Input::Value(input[*cursor] - b'0' + 52),
        b'+' | b'-' => Base64Input::Value(62),
        b'/' | b'_' => Base64Input::Value(63),
        _ => return Err(Errno::EINVAL.to_neg_errno()),
    };
    *cursor += 1;
    while *cursor < input.len() && is_systemd_whitespace(input[*cursor]) {
        *cursor += 1;
    }
    Ok(value)
}

fn unbase64_decode_into(input: &[u8], output: &mut [u8]) -> Result<usize, i32> {
    let mut cursor = 0;
    let mut output_len = 0;
    loop {
        let a = match unbase64_next_byte(input, &mut cursor) {
            Err(error) if error == -libc::EPIPE => return Ok(output_len),
            Err(error) => return Err(error),
            Ok(Base64Input::Value(value)) => value,
            Ok(Base64Input::Padding) => return Err(Errno::EINVAL.to_neg_errno()),
        };
        let b = match unbase64_next_byte(input, &mut cursor)? {
            Base64Input::Value(value) => value,
            Base64Input::Padding => return Err(Errno::EINVAL.to_neg_errno()),
        };
        let c = unbase64_next_byte(input, &mut cursor)?;
        let d = unbase64_next_byte(input, &mut cursor)?;

        output[output_len] = (a << 2) | (b >> 4);
        output_len += 1;
        match (c, d) {
            (Base64Input::Padding, Base64Input::Padding) => {
                if b & 15 != 0 {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                if cursor != input.len() {
                    return Err(-libc::ENAMETOOLONG);
                }
                return Ok(output_len);
            }
            (Base64Input::Padding, Base64Input::Value(_)) => {
                return Err(Errno::EINVAL.to_neg_errno());
            }
            (Base64Input::Value(c), Base64Input::Padding) => {
                if c & 3 != 0 {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                if cursor != input.len() {
                    return Err(-libc::ENAMETOOLONG);
                }
                output[output_len] = (b << 4) | (c >> 2);
                return Ok(output_len + 1);
            }
            (Base64Input::Value(c), Base64Input::Value(d)) => {
                output[output_len] = (b << 4) | (c >> 2);
                output[output_len + 1] = (c << 6) | d;
                output_len += 2;
            }
        }
    }
}

fn base64_encoded_len(input_len: usize) -> Result<usize, i32> {
    input_len
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or(Errno::ENOMEM.to_neg_errno())
}

fn base64_encode_into(input: &[u8], output: &mut [u8]) {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut read = 0;
    let mut written = 0;
    while read + 3 <= input.len() {
        let a = input[read];
        let b = input[read + 1];
        let c = input[read + 2];
        output[written..written + 4].copy_from_slice(&[
            TABLE[(a >> 2) as usize],
            TABLE[(((a & 3) << 4 | b >> 4) as usize)],
            TABLE[(((b & 15) << 2 | c >> 6) as usize)],
            TABLE[(c & 63) as usize],
        ]);
        read += 3;
        written += 4;
    }
    match input.len() - read {
        2 => {
            let a = input[read];
            let b = input[read + 1];
            output[written..written + 4].copy_from_slice(&[
                TABLE[(a >> 2) as usize],
                TABLE[(((a & 3) << 4 | b >> 4) as usize)],
                TABLE[((b & 15) << 2) as usize],
                b'=',
            ]);
        }
        1 => {
            let a = input[read];
            output[written..written + 4].copy_from_slice(&[
                TABLE[(a >> 2) as usize],
                TABLE[((a & 3) << 4) as usize],
                b'=',
                b'=',
            ]);
        }
        _ => {}
    }
}

/// Decode a NUL-terminated hexadecimal string with C-allocator ownership.
///
/// # Safety
/// `p` must be either null or a readable NUL-terminated C string. Every
/// non-null output pointer must be valid writable storage for its C type.
#[unsafe(export_name = "rs_unhexmem")]
pub unsafe extern "C" fn rs_unhexmem(
    p: *const c_char,
    ret_data: *mut *mut c_void,
    ret_size: *mut usize,
) -> i32 {
    if p.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by the C ABI contract.
    let input = unsafe { CStr::from_ptr(p) }.to_bytes();
    let allocation_len = match input
        .len()
        .checked_add(1)
        .map(|length| length / 2)
        .and_then(|length| length.checked_add(1))
    {
        Some(length) => length,
        None => return Errno::ENOMEM.to_neg_errno(),
    };
    // SAFETY: `allocation_len` is non-zero and comes from checked arithmetic.
    let allocation = unsafe { libc::malloc(allocation_len) }.cast::<u8>();
    if allocation.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: the allocation is live for `allocation_len` bytes.
    let result = unsafe {
        unhex_decode_into(
            input,
            std::slice::from_raw_parts_mut(allocation, allocation_len - 1),
        )
    };
    match result {
        Ok(decoded_len) => {
            // SAFETY: the checked allocation has one byte beyond decoded output.
            unsafe { *allocation.add(decoded_len) = 0 };
            if !ret_size.is_null() {
                // SAFETY: required by the C ABI contract.
                unsafe { *ret_size = decoded_len };
            }
            if !ret_data.is_null() {
                // SAFETY: required by the C ABI contract.
                unsafe { *ret_data = allocation.cast::<c_void>() };
            } else {
                // SAFETY: the allocation has not escaped this function.
                unsafe { libc::free(allocation.cast::<c_void>()) };
            }
            0
        }
        Err(error) => {
            // SAFETY: the allocation has not escaped this function.
            unsafe { libc::free(allocation.cast::<c_void>()) };
            error
        }
    }
}

/// Base64 encode a byte range with C-allocator-owned output.
///
/// # Safety
/// `p` must point to `l` readable bytes when `l` is non-zero, and `ret` must
/// point to writable `char *` storage.
#[unsafe(export_name = "rs_base64mem")]
pub unsafe extern "C" fn rs_base64mem(p: *const c_void, l: usize, ret: *mut *mut c_char) -> isize {
    if (p.is_null() && l != 0) || ret.is_null() {
        return Errno::EINVAL.to_neg_errno() as isize;
    }
    let output_len = match base64_encoded_len(l) {
        Ok(length) if length <= isize::MAX as usize => length,
        _ => return Errno::ENOMEM.to_neg_errno() as isize,
    };
    let allocation_len = match output_len.checked_add(1) {
        Some(length) => length,
        None => return Errno::ENOMEM.to_neg_errno() as isize,
    };
    // SAFETY: this only forms a slice when `p` is non-null, as required by Rust.
    let input = if l == 0 {
        &[]
    } else {
        // SAFETY: the C ABI contract requires `p` to reference `l` readable
        // bytes whenever the length is non-zero.
        unsafe { std::slice::from_raw_parts(p.cast::<u8>(), l) }
    };
    // SAFETY: `allocation_len` is non-zero and comes from checked arithmetic.
    let allocation = unsafe { libc::malloc(allocation_len) }.cast::<u8>();
    if allocation.is_null() {
        return Errno::ENOMEM.to_neg_errno() as isize;
    }
    // SAFETY: the allocation is live for the encoded output and its terminator.
    unsafe {
        base64_encode_into(
            input,
            std::slice::from_raw_parts_mut(allocation, output_len),
        );
        *allocation.add(output_len) = 0;
        *ret = allocation.cast::<c_char>();
    }
    output_len as isize
}

/// Decode a NUL-terminated base64 string with C-allocator-owned output.
///
/// # Safety
/// `p` must be either null or a readable NUL-terminated C string. Every
/// non-null output pointer must be valid writable storage for its C type.
#[unsafe(export_name = "rs_unbase64mem")]
pub unsafe extern "C" fn rs_unbase64mem(
    p: *const c_char,
    ret_data: *mut *mut c_void,
    ret_size: *mut usize,
) -> i32 {
    if p.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by the C ABI contract.
    let input = unsafe { CStr::from_ptr(p) }.to_bytes();
    let allocation_len = match input
        .len()
        .checked_div(4)
        .and_then(|groups| groups.checked_mul(3))
        .and_then(|groups| {
            let remainder = input.len() % 4;
            groups.checked_add(if remainder == 0 { 0 } else { remainder - 1 })
        })
        .and_then(|length| length.checked_add(1))
    {
        Some(length) => length,
        None => return Errno::ENOMEM.to_neg_errno(),
    };
    // SAFETY: `allocation_len` is non-zero and comes from checked arithmetic.
    let allocation = unsafe { libc::malloc(allocation_len) }.cast::<u8>();
    if allocation.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: the allocation is live for the decoded output and its terminator.
    let result = unsafe {
        unbase64_decode_into(
            input,
            std::slice::from_raw_parts_mut(allocation, allocation_len - 1),
        )
    };
    match result {
        Ok(decoded_len) => {
            // SAFETY: the checked allocation has one byte beyond decoded output.
            unsafe { *allocation.add(decoded_len) = 0 };
            if !ret_size.is_null() {
                // SAFETY: required by the C ABI contract.
                unsafe { *ret_size = decoded_len };
            }
            if !ret_data.is_null() {
                // SAFETY: required by the C ABI contract.
                unsafe { *ret_data = allocation.cast::<c_void>() };
            } else {
                // SAFETY: the allocation has not escaped this function.
                unsafe { libc::free(allocation.cast::<c_void>()) };
            }
            0
        }
        Err(error) => {
            // SAFETY: the allocation has not escaped this function.
            unsafe { libc::free(allocation.cast::<c_void>()) };
            error
        }
    }
}

pub fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (offset, chunk) in data.chunks(16).enumerate() {
        let base = offset * 16;
        out.push_str(&format!("{base:04x}  "));

        for i in 0..16 {
            if let Some(byte) = chunk.get(i) {
                out.push_str(&format!("{byte:02x} "));
            } else {
                out.push_str("   ");
            }
            if i == 7 {
                out.push(' ');
            }
        }

        out.push(' ');
        for byte in chunk {
            let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            };
            out.push(ch);
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oct_and_dec_helpers_match_c_behavior() {
        assert_eq!(octchar(10), '2');
        assert_eq!(unoctchar('7'), Ok(7));
        assert_eq!(decchar(17), '7');
        assert_eq!(undecchar('9'), Ok(9));
    }

    #[test]
    fn hex_helpers_accept_uppercase() {
        assert_eq!(hexchar(15), 'f');
        assert_eq!(unhexchar('F'), Ok(15));
    }

    #[test]
    fn base32_helpers_roundtrip_single_character() {
        assert_eq!(base32hexchar(31), 'V');
        assert_eq!(unbase32hexchar('A'), Ok(10));
    }

    #[test]
    fn base64_helpers_accept_urlsafe_alphabet() {
        assert_eq!(base64char(62), '+');
        assert_eq!(urlsafe_base64char(63), '_');
        assert_eq!(unbase64char('-'), Ok(62));
        assert_eq!(unbase64char('_'), Ok(63));
    }

    #[test]
    fn hexmem_roundtrip_ignores_whitespace() {
        let encoded = hexmem(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(encoded, "deadbeef");
        assert_eq!(
            unhexmem_full("de ad\nbe\tef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn base32_roundtrip_with_padding() {
        let encoded = base32hexmem(b"foo", true);
        assert_eq!(encoded, "CPNMU===");
        assert_eq!(unbase32hexmem(&encoded, true).unwrap(), b"foo");
    }

    #[test]
    fn base64_roundtrip_with_padding() {
        let encoded = base64mem(b"hello").unwrap();
        assert_eq!(encoded, "aGVsbG8=");
        assert_eq!(unbase64mem_full(&encoded).unwrap(), b"hello");
    }

    #[test]
    fn base64_line_break_insertion_matches_requested_width() {
        let encoded = base64mem_full(b"abcdef", 4).unwrap();
        assert_eq!(encoded, "YWJj\nZGVm");
    }

    #[test]
    fn invalid_unhex_input_fails() {
        assert!(unhexmem_full("0").is_err());
        assert!(unhexmem_full("gg").is_err());
    }

    #[test]
    fn invalid_base32_tail_bits_fail() {
        assert!(unbase32hexmem("AAA3", false).is_err());
    }

    #[test]
    fn invalid_base64_tail_bits_fail() {
        assert!(unbase64mem_full("A=AA").is_err());
        assert!(unbase64mem_full("YQ=A").is_err());
    }

    #[test]
    fn hexdump_formats_single_line() {
        let dump = hexdump(b"AB\x01");
        assert_eq!(
            dump,
            "0000  41 42 01                                          AB.\n"
        );
    }
}
