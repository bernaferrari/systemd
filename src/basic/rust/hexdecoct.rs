// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.hexdecoct; authority=src/basic/hexdecoct.c,src/basic/hexdecoct.h

// Centralized unsafe expression boundary for this C-ABI adapter.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing adapter documents and validates the raw-pointer,
        // ownership, and lifetime contract before evaluating this expression.
        unsafe { $expression }
    }};
}
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
    char::from((i32::from(b'0') + x % 10) as u8)
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

fn decode_result(result: Result<i32, i32>) -> i32 {
    match result {
        Ok(value) | Err(value) => value,
    }
}

/// Exact scalar C ABI shadow of `octchar()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_octchar(x: i32) -> c_char {
    octchar(x) as u8 as c_char
}

/// Exact scalar C ABI shadow of `unoctchar()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_unoctchar(c: c_char) -> i32 {
    decode_result(unoctchar(char::from(c as u8)))
}

/// Exact scalar C ABI shadow of `decchar()`, including C's negative remainder.
#[unsafe(no_mangle)]
pub extern "C" fn rs_decchar(x: i32) -> c_char {
    decchar(x) as u8 as c_char
}

/// Exact scalar C ABI shadow of `undecchar()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_undecchar(c: c_char) -> i32 {
    decode_result(undecchar(char::from(c as u8)))
}

/// Exact scalar C ABI shadow of `hexchar()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_hexchar(x: i32) -> c_char {
    hexchar(x) as u8 as c_char
}

/// Exact scalar C ABI shadow of `unhexchar()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_unhexchar(c: c_char) -> i32 {
    decode_result(unhexchar(char::from(c as u8)))
}

/// Exact scalar C ABI shadow of `base32hexchar()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_base32hexchar(x: i32) -> c_char {
    base32hexchar(x) as u8 as c_char
}

/// Exact scalar C ABI shadow of `unbase32hexchar()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_unbase32hexchar(c: c_char) -> i32 {
    decode_result(unbase32hexchar(char::from(c as u8)))
}

/// Exact scalar C ABI shadow of `base64char()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_base64char(x: i32) -> c_char {
    base64char(x) as u8 as c_char
}

/// Exact scalar C ABI shadow of `urlsafe_base64char()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_urlsafe_base64char(x: i32) -> c_char {
    urlsafe_base64char(x) as u8 as c_char
}

/// Exact scalar C ABI shadow of `unbase64char()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_unbase64char(c: c_char) -> i32 {
    decode_result(unbase64char(char::from(c as u8)))
}

pub fn hexmem(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(hexchar((byte >> 4).into()));
        out.push(hexchar((byte & 0x0f).into()));
    }
    out
}

#[inline]
const fn is_systemd_whitespace_char(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\n' | '\r')
}

fn unhex_next(chars: &[char], index: &mut usize) -> Result<Option<i32>, i32> {
    while *index < chars.len() && is_systemd_whitespace_char(chars[*index]) {
        *index += 1;
    }
    if *index >= chars.len() {
        return Ok(None);
    }

    let value = unhexchar(chars[*index])?;
    *index += 1;

    while *index < chars.len() && is_systemd_whitespace_char(chars[*index]) {
        *index += 1;
    }

    Ok(Some(value))
}

pub fn unhexmem_full(s: &str) -> Result<Vec<u8>, i32> {
    let chars: Vec<char> = s.chars().collect();
    let mut index = 0;
    let mut out = Vec::with_capacity(chars.len().div_ceil(2));

    while let Some(a) = unhex_next(&chars, &mut index)? {
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
    // The C API consumes an exact `(pointer, length)` byte range; unlike the
    // streaming hex/base64 decoders, it does not skip whitespace.
    let mut input = s.to_string();
    if padding && !input.len().is_multiple_of(8) {
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
                if padded[6] & 7 != 0 {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                out.push(((padded[0] << 3) | (padded[1] >> 2)) as u8);
                out.push(((padded[1] << 6) | (padded[2] << 1) | (padded[3] >> 4)) as u8);
                out.push(((padded[3] << 4) | (padded[4] >> 1)) as u8);
                out.push(((padded[4] << 7) | (padded[5] << 2) | (padded[6] >> 3)) as u8);
            }
            5 => {
                if padded[4] & 1 != 0 {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                out.push(((padded[0] << 3) | (padded[1] >> 2)) as u8);
                out.push(((padded[1] << 6) | (padded[2] << 1) | (padded[3] >> 4)) as u8);
                out.push(((padded[3] << 4) | (padded[4] >> 1)) as u8);
            }
            4 => {
                if padded[3] & 15 != 0 {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                out.push(((padded[0] << 3) | (padded[1] >> 2)) as u8);
                out.push(((padded[1] << 6) | (padded[2] << 1) | (padded[3] >> 4)) as u8);
            }
            2 => {
                if padded[1] & 3 != 0 {
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

    let push = |ch: char, out: &mut String, emitted: &mut usize| {
        if line_break != usize::MAX && *emitted > 0 && (*emitted).is_multiple_of(line_break) {
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
    while *index < chars.len() && is_systemd_whitespace_char(chars[*index]) {
        *index += 1;
    }
    if *index >= chars.len() {
        return Ok(None);
    }
    let ch = chars[*index];
    *index += 1;
    while *index < chars.len() && is_systemd_whitespace_char(chars[*index]) {
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

    while let Some(a) = unbase64_next(&chars, &mut index)? {
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
                if b & 15 != 0
                    || chars[index..]
                        .iter()
                        .any(|ch| !is_systemd_whitespace_char(*ch))
                {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                out.push(((a << 2) | (b >> 4)) as u8);
                break;
            }
            (Some(c), None) => {
                if c & 3 != 0
                    || chars[index..]
                        .iter()
                        .any(|ch| !is_systemd_whitespace_char(*ch))
                {
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
            TABLE[((a & 3) << 4 | b >> 4) as usize],
            TABLE[((b & 15) << 2 | c >> 6) as usize],
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
                TABLE[((a & 3) << 4 | b >> 4) as usize],
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

fn base32_encoded_len(input_len: usize, padding: bool) -> Result<usize, i32> {
    if padding {
        input_len
            .checked_add(4)
            .map(|length| length / 5)
            .and_then(|groups| groups.checked_mul(8))
            .ok_or(Errno::ENOMEM.to_neg_errno())
    } else {
        let tail = match input_len % 5 {
            0 => 0,
            1 => 2,
            2 => 4,
            3 => 5,
            _ => 7,
        };
        input_len
            .checked_div(5)
            .and_then(|groups| groups.checked_mul(8))
            .and_then(|length| length.checked_add(tail))
            .ok_or(Errno::ENOMEM.to_neg_errno())
    }
}

fn base32_encode_into(input: &[u8], output: &mut [u8], padding: bool) {
    let mut read = 0;
    let mut written = 0;
    while input.len() - read >= 5 {
        let block = &input[read..read + 5];
        output[written..written + 8].copy_from_slice(&[
            base32hexchar((block[0] >> 3).into()) as u8,
            base32hexchar((((block[0] & 7) << 2) | (block[1] >> 6)).into()) as u8,
            base32hexchar(((block[1] & 63) >> 1).into()) as u8,
            base32hexchar((((block[1] & 1) << 4) | (block[2] >> 4)).into()) as u8,
            base32hexchar((((block[2] & 15) << 1) | (block[3] >> 7)).into()) as u8,
            base32hexchar(((block[3] & 127) >> 2).into()) as u8,
            base32hexchar((((block[3] & 3) << 3) | (block[4] >> 5)).into()) as u8,
            base32hexchar((block[4] & 31).into()) as u8,
        ]);
        read += 5;
        written += 8;
    }

    let tail = &input[read..];
    let mut append = |value: u8| {
        output[written] = value;
        written += 1;
    };
    match tail.len() {
        4 => {
            append(base32hexchar((tail[0] >> 3).into()) as u8);
            append(base32hexchar((((tail[0] & 7) << 2) | (tail[1] >> 6)).into()) as u8);
            append(base32hexchar(((tail[1] & 63) >> 1).into()) as u8);
            append(base32hexchar((((tail[1] & 1) << 4) | (tail[2] >> 4)).into()) as u8);
            append(base32hexchar((((tail[2] & 15) << 1) | (tail[3] >> 7)).into()) as u8);
            append(base32hexchar(((tail[3] & 127) >> 2).into()) as u8);
            append(base32hexchar(((tail[3] & 3) << 3).into()) as u8);
            if padding {
                append(b'=');
            }
        }
        3 => {
            append(base32hexchar((tail[0] >> 3).into()) as u8);
            append(base32hexchar((((tail[0] & 7) << 2) | (tail[1] >> 6)).into()) as u8);
            append(base32hexchar(((tail[1] & 63) >> 1).into()) as u8);
            append(base32hexchar((((tail[1] & 1) << 4) | (tail[2] >> 4)).into()) as u8);
            append(base32hexchar(((tail[2] & 15) << 1).into()) as u8);
            if padding {
                for _ in 0..3 {
                    append(b'=');
                }
            }
        }
        2 => {
            append(base32hexchar((tail[0] >> 3).into()) as u8);
            append(base32hexchar((((tail[0] & 7) << 2) | (tail[1] >> 6)).into()) as u8);
            append(base32hexchar(((tail[1] & 63) >> 1).into()) as u8);
            append(base32hexchar(((tail[1] & 1) << 4).into()) as u8);
            if padding {
                for _ in 0..4 {
                    append(b'=');
                }
            }
        }
        1 => {
            append(base32hexchar((tail[0] >> 3).into()) as u8);
            append(base32hexchar(((tail[0] & 7) << 2).into()) as u8);
            if padding {
                for _ in 0..6 {
                    append(b'=');
                }
            }
        }
        _ => {}
    }
    debug_assert_eq!(written, output.len());
}

fn unbase32hex_byte(byte: u8) -> Result<u8, i32> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'A'..=b'V' => Ok(byte - b'A' + 10),
        _ => Err(Errno::EINVAL.to_neg_errno()),
    }
}

fn unbase32_decode_into(input: &[u8], output: &mut [u8]) -> Result<usize, i32> {
    let mut read = 0;
    let mut written = 0;
    while input.len() - read >= 8 {
        let mut values = [0u8; 8];
        for (slot, byte) in values.iter_mut().zip(&input[read..read + 8]) {
            *slot = unbase32hex_byte(*byte)?;
        }
        output[written..written + 5].copy_from_slice(&[
            (values[0] << 3) | (values[1] >> 2),
            (values[1] << 6) | (values[2] << 1) | (values[3] >> 4),
            (values[3] << 4) | (values[4] >> 1),
            (values[4] << 7) | (values[5] << 2) | (values[6] >> 3),
            (values[6] << 5) | values[7],
        ]);
        read += 8;
        written += 5;
    }

    let tail = &input[read..];
    let mut values = [0u8; 7];
    for (slot, byte) in values.iter_mut().zip(tail) {
        *slot = unbase32hex_byte(*byte)?;
    }
    match tail.len() {
        0 => {}
        7 => {
            if values[6] & 7 != 0 {
                return Err(Errno::EINVAL.to_neg_errno());
            }
            output[written..written + 4].copy_from_slice(&[
                (values[0] << 3) | (values[1] >> 2),
                (values[1] << 6) | (values[2] << 1) | (values[3] >> 4),
                (values[3] << 4) | (values[4] >> 1),
                (values[4] << 7) | (values[5] << 2) | (values[6] >> 3),
            ]);
            written += 4;
        }
        5 => {
            if values[4] & 1 != 0 {
                return Err(Errno::EINVAL.to_neg_errno());
            }
            output[written..written + 3].copy_from_slice(&[
                (values[0] << 3) | (values[1] >> 2),
                (values[1] << 6) | (values[2] << 1) | (values[3] >> 4),
                (values[3] << 4) | (values[4] >> 1),
            ]);
            written += 3;
        }
        4 => {
            if values[3] & 15 != 0 {
                return Err(Errno::EINVAL.to_neg_errno());
            }
            output[written..written + 2].copy_from_slice(&[
                (values[0] << 3) | (values[1] >> 2),
                (values[1] << 6) | (values[2] << 1) | (values[3] >> 4),
            ]);
            written += 2;
        }
        2 => {
            if values[1] & 3 != 0 {
                return Err(Errno::EINVAL.to_neg_errno());
            }
            output[written] = (values[0] << 3) | (values[1] >> 2);
            written += 1;
        }
        _ => return Err(Errno::EINVAL.to_neg_errno()),
    }
    Ok(written)
}

fn base64_encoded_len_with_breaks(input_len: usize, line_break: usize) -> Result<usize, i32> {
    let encoded = base64_encoded_len(input_len)?;
    if encoded == 0 || line_break == usize::MAX {
        return Ok(encoded);
    }
    let breaks = (encoded - 1) / line_break;
    encoded
        .checked_add(breaks)
        .ok_or(Errno::ENOMEM.to_neg_errno())
}

fn base64_encode_with_breaks_into(
    input: &[u8],
    output: &mut [u8],
    line_break: usize,
) -> Result<(), i32> {
    let encoded_len = base64_encoded_len(input.len())?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| Errno::ENOMEM.to_neg_errno())?;
    encoded.resize(encoded_len, 0);
    base64_encode_into(input, &mut encoded);

    let mut written = 0;
    for byte in encoded {
        if line_break != usize::MAX && written % (line_break + 1) == line_break {
            output[written] = b'\n';
            written += 1;
        }
        output[written] = byte;
        written += 1;
    }
    debug_assert_eq!(written, output.len());
    Ok(())
}

/// A libc allocation used for one codec result.
///
/// Codec cores only receive its checked mutable byte slice; ABI adapters decide
/// whether to transfer the original libc allocation to C or erase and release
/// it on an error/no-output path.
struct CodecAllocation {
    ptr: *mut u8,
    len: usize,
}

impl CodecAllocation {
    fn allocate(len: usize) -> Option<Self> {
        debug_assert!(len > 0);
        // The shared allocator preserves libc ownership while handling the
        // size_t allocation call at the audited FFI boundary.
        let ptr = crate::ffi::malloc(len).cast::<u8>();
        (!ptr.is_null()).then_some(Self { ptr, len })
    }

    fn bytes_mut(&mut self, content_len: usize) -> &mut [u8] {
        debug_assert!(content_len <= self.len);
        // SAFETY: this allocation is uniquely owned and live for self.len bytes.
        unsafe_ffi!(std::slice::from_raw_parts_mut(self.ptr, content_len))
    }

    fn terminate(&mut self, index: usize) {
        debug_assert!(index < self.len);
        // SAFETY: index is within this uniquely owned allocation.
        unsafe_ffi!(*self.ptr.add(index) = 0);
    }

    fn into_raw(mut self) -> *mut u8 {
        let ptr = self.ptr;
        self.ptr = std::ptr::null_mut();
        ptr
    }

    fn erase_and_free(mut self, wipe_len: usize, secure: bool) {
        debug_assert!(wipe_len <= self.len);
        if secure {
            // SAFETY: the requested prefix lies within this live allocation.
            unsafe {
                for offset in 0..wipe_len {
                    std::ptr::write_volatile(self.ptr.add(offset), 0);
                }
            }
        }
        // SAFETY: this allocation has not escaped and uses libc ownership.
        unsafe_ffi!(libc::free(self.ptr.cast::<c_void>()));
        self.ptr = std::ptr::null_mut();
    }
}

impl Drop for CodecAllocation {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: unconsumed codec allocations are always libc-owned.
            unsafe_ffi!(libc::free(self.ptr.cast::<c_void>()));
        }
    }
}

/// Borrow an explicit byte range, or the C string selected by the `SIZE_MAX`
/// sentinel used by the C codec APIs.
///
/// # Safety
/// For an explicit length, `p` must be readable for that many bytes when the
/// length is non-zero. For `SIZE_MAX`, it must be a readable NUL-terminated C
/// string. A null pointer is accepted only with an explicit zero length.
unsafe fn codec_input_bytes<'a>(p: *const c_void, l: usize) -> Result<&'a [u8], i32> {
    if p.is_null() {
        return if l == 0 {
            Ok(&[])
        } else {
            Err(Errno::EINVAL.to_neg_errno())
        };
    }
    if l == usize::MAX {
        // SAFETY: the helper's contract requires a readable NUL-terminated C string.
        return Ok(unsafe_ffi!(CStr::from_ptr(p.cast::<c_char>())).to_bytes());
    }
    // SAFETY: the helper's contract requires `p` to reference `l` readable bytes.
    Ok(unsafe_ffi!(std::slice::from_raw_parts(p.cast::<u8>(), l)))
}

/// Hex-encode an explicit byte range with C-allocator-owned output.
///
/// # Safety
/// `p` must point to `l` readable bytes when `l` is non-zero. The returned
/// allocation has libc ownership and must be released with `free()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_hexmem(p: *const c_void, l: usize) -> *mut c_char {
    // SAFETY: this FFI boundary documents the readable-range precondition.
    let input = match unsafe_ffi!(codec_input_bytes(p, l)) {
        Ok(input) => input,
        Err(_) => return std::ptr::null_mut(),
    };
    let output_len = match input.len().checked_mul(2) {
        Some(length) => length,
        None => return std::ptr::null_mut(),
    };
    let allocation_len = match output_len.checked_add(1) {
        Some(length) => length,
        None => return std::ptr::null_mut(),
    };
    let Some(mut allocation) = CodecAllocation::allocate(allocation_len) else {
        return std::ptr::null_mut();
    };
    for (byte, pair) in input
        .iter()
        .zip(allocation.bytes_mut(output_len).chunks_exact_mut(2))
    {
        pair[0] = hexchar((byte >> 4).into()) as u8;
        pair[1] = hexchar((byte & 15).into()) as u8;
    }
    allocation.terminate(output_len);
    allocation.into_raw().cast::<c_char>()
}

/// Decode a hexadecimal byte range with C-allocator-owned output.
///
/// # Safety
/// `p` must be readable for `l` bytes when `l` is explicit and non-zero, or a
/// readable NUL-terminated C string for `SIZE_MAX`. Each non-null output must
/// point to writable storage of its C type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unhexmem_full(
    p: *const c_char,
    l: usize,
    secure: bool,
    ret_data: *mut *mut c_void,
    ret_size: *mut usize,
) -> i32 {
    // SAFETY: this FFI boundary documents both explicit and sentinel input modes.
    let input = match unsafe_ffi!(codec_input_bytes(p.cast::<c_void>(), l)) {
        Ok(input) => input,
        Err(error) => return error,
    };
    let decoded_capacity = match input.len().checked_add(1).map(|length| length / 2) {
        Some(length) => length,
        None => return Errno::ENOMEM.to_neg_errno(),
    };
    let allocation_len = match decoded_capacity.checked_add(1) {
        Some(length) => length,
        None => return Errno::ENOMEM.to_neg_errno(),
    };
    let Some(mut allocation) = CodecAllocation::allocate(allocation_len) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let result = unhex_decode_into(input, allocation.bytes_mut(decoded_capacity));
    let decoded_len = match result {
        Ok(length) => length,
        Err(error) => {
            allocation.erase_and_free(allocation_len, secure);
            return error;
        }
    };
    allocation.terminate(decoded_len);
    if !ret_size.is_null() {
        // SAFETY: required by this FFI boundary's output-pointer contract.
        unsafe_ffi!(*ret_size = decoded_len);
    }
    if !ret_data.is_null() {
        let allocation = allocation.into_raw();
        // SAFETY: required by this FFI boundary's output-pointer contract.
        unsafe_ffi!(*ret_data = allocation.cast::<c_void>());
    } else {
        allocation.erase_and_free(allocation_len, secure);
    }
    0
}

/// Base32hex-encode an explicit byte range with C-allocator-owned output.
///
/// # Safety
/// `p` must point to `l` readable bytes when `l` is non-zero. The returned
/// allocation has libc ownership and must be released with `free()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_base32hexmem(p: *const c_void, l: usize, padding: bool) -> *mut c_char {
    // SAFETY: this FFI boundary documents the readable-range precondition.
    let input = match unsafe_ffi!(codec_input_bytes(p, l)) {
        Ok(input) => input,
        Err(_) => return std::ptr::null_mut(),
    };
    let output_len = match base32_encoded_len(input.len(), padding) {
        Ok(length) => length,
        Err(_) => return std::ptr::null_mut(),
    };
    let allocation_len = match output_len.checked_add(1) {
        Some(length) => length,
        None => return std::ptr::null_mut(),
    };
    let Some(mut allocation) = CodecAllocation::allocate(allocation_len) else {
        return std::ptr::null_mut();
    };
    base32_encode_into(input, allocation.bytes_mut(output_len), padding);
    allocation.terminate(output_len);
    allocation.into_raw().cast::<c_char>()
}

/// Decode a base32hex byte range with C-allocator-owned output.
///
/// # Safety
/// `p` must be readable for `l` bytes when `l` is explicit and non-zero, or a
/// readable NUL-terminated C string for `SIZE_MAX`. `mem` and `len` must be
/// non-null writable output locations. On success, `*mem` has libc ownership.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unbase32hexmem(
    p: *const c_char,
    l: usize,
    padding: bool,
    mem: *mut *mut c_void,
    len: *mut usize,
) -> i32 {
    if mem.is_null() || len.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: this FFI boundary documents both explicit and sentinel input modes.
    let input = match unsafe_ffi!(codec_input_bytes(p.cast::<c_void>(), l)) {
        Ok(input) => input,
        Err(error) => return error,
    };
    if padding && input.len() % 8 != 0 {
        return Errno::EINVAL.to_neg_errno();
    }
    let mut encoded_len = input.len();
    if padding {
        let mut stripped = 0;
        while encoded_len > 0 && input[encoded_len - 1] == b'=' && stripped < 7 {
            encoded_len -= 1;
            stripped += 1;
        }
    }
    let decoded_capacity = match encoded_len % 8 {
        0 => encoded_len
            .checked_div(8)
            .and_then(|groups| groups.checked_mul(5)),
        2 => encoded_len
            .checked_div(8)
            .and_then(|groups| groups.checked_mul(5))
            .and_then(|length| length.checked_add(1)),
        4 => encoded_len
            .checked_div(8)
            .and_then(|groups| groups.checked_mul(5))
            .and_then(|length| length.checked_add(2)),
        5 => encoded_len
            .checked_div(8)
            .and_then(|groups| groups.checked_mul(5))
            .and_then(|length| length.checked_add(3)),
        7 => encoded_len
            .checked_div(8)
            .and_then(|groups| groups.checked_mul(5))
            .and_then(|length| length.checked_add(4)),
        _ => return Errno::EINVAL.to_neg_errno(),
    };
    let Some(decoded_capacity) = decoded_capacity else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let Some(allocation_len) = decoded_capacity.checked_add(1) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let Some(mut allocation) = CodecAllocation::allocate(allocation_len) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let decoded_len = match unbase32_decode_into(
        &input[..encoded_len],
        allocation.bytes_mut(decoded_capacity),
    ) {
        Ok(length) => length,
        Err(error) => {
            allocation.erase_and_free(allocation_len, false);
            return error;
        }
    };
    allocation.terminate(decoded_len);
    let allocation = allocation.into_raw();
    // SAFETY: mem and len satisfy this FFI boundary's output-pointer contract.
    unsafe {
        *mem = allocation.cast::<c_void>();
        *len = decoded_len;
    }
    0
}

/// Base64-encode a byte range with optional line breaks and libc-owned output.
///
/// # Safety
/// `p` must point to `l` readable bytes when `l` is non-zero, and `ret` must
/// point to writable `char *` storage. On success, `*ret` has libc ownership.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_base64mem_full(
    p: *const c_void,
    l: usize,
    line_break: usize,
    ret: *mut *mut c_char,
) -> isize {
    if ret.is_null() || line_break == 0 {
        return Errno::EINVAL.to_neg_errno() as isize;
    }
    // SAFETY: this FFI boundary documents the readable-range precondition.
    let input = match unsafe_ffi!(codec_input_bytes(p, l)) {
        Ok(input) => input,
        Err(error) => return error as isize,
    };
    let output_len = match base64_encoded_len_with_breaks(input.len(), line_break) {
        Ok(length) if length <= isize::MAX as usize => length,
        _ => return Errno::ENOMEM.to_neg_errno() as isize,
    };
    let Some(allocation_len) = output_len.checked_add(1) else {
        return Errno::ENOMEM.to_neg_errno() as isize;
    };
    let Some(mut allocation) = CodecAllocation::allocate(allocation_len) else {
        return Errno::ENOMEM.to_neg_errno() as isize;
    };
    let result =
        base64_encode_with_breaks_into(input, allocation.bytes_mut(output_len), line_break);
    if let Err(error) = result {
        allocation.erase_and_free(allocation_len, false);
        return error as isize;
    }
    allocation.terminate(output_len);
    let allocation = allocation.into_raw();
    // SAFETY: ret satisfies this FFI boundary's output-pointer contract.
    unsafe_ffi!(*ret = allocation.cast::<c_char>());
    output_len as isize
}

/// Decode a base64 byte range with C-allocator-owned output.
///
/// # Safety
/// `p` must be readable for `l` bytes when `l` is explicit and non-zero, or a
/// readable NUL-terminated C string for `SIZE_MAX`. Each non-null output must
/// point to writable storage of its C type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unbase64mem_full(
    p: *const c_char,
    l: usize,
    secure: bool,
    ret_data: *mut *mut c_void,
    ret_size: *mut usize,
) -> i32 {
    // SAFETY: this FFI boundary documents both explicit and sentinel input modes.
    let input = match unsafe_ffi!(codec_input_bytes(p.cast::<c_void>(), l)) {
        Ok(input) => input,
        Err(error) => return error,
    };
    let decoded_capacity = match input
        .len()
        .checked_div(4)
        .and_then(|groups| groups.checked_mul(3))
        .and_then(|groups| {
            let remainder = input.len() % 4;
            groups.checked_add(if remainder == 0 { 0 } else { remainder - 1 })
        }) {
        Some(length) => length,
        None => return Errno::ENOMEM.to_neg_errno(),
    };
    let Some(allocation_len) = decoded_capacity.checked_add(1) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let Some(mut allocation) = CodecAllocation::allocate(allocation_len) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let decoded_len = match unbase64_decode_into(input, allocation.bytes_mut(decoded_capacity)) {
        Ok(length) => length,
        Err(error) => {
            allocation.erase_and_free(decoded_capacity, secure);
            return error;
        }
    };
    allocation.terminate(decoded_len);
    if !ret_size.is_null() {
        // SAFETY: required by this FFI boundary's output-pointer contract.
        unsafe_ffi!(*ret_size = decoded_len);
    }
    if !ret_data.is_null() {
        let allocation = allocation.into_raw();
        // SAFETY: required by this FFI boundary's output-pointer contract.
        unsafe_ffi!(*ret_data = allocation.cast::<c_void>());
    } else {
        allocation.erase_and_free(decoded_capacity, secure);
    }
    0
}

/// Append base64 text to a libc allocation using the C line-wrapping policy.
///
/// # Safety
/// `prefix` must be writable. If `*prefix` is non-null it must be a libc
/// allocation containing at least `plen` initialized bytes; if it is null,
/// `plen` must be zero. `p` must point to `l` readable bytes when non-zero.
/// On success, `*prefix` remains libc-owned and may have moved via `realloc()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_base64_append(
    prefix: *mut *mut c_char,
    plen: usize,
    p: *const c_void,
    l: usize,
    indent: usize,
    width: usize,
) -> isize {
    if prefix.is_null() {
        return Errno::EINVAL.to_neg_errno() as isize;
    }
    // SAFETY: required by this FFI boundary's prefix-pointer contract.
    let old_prefix = unsafe_ffi!(*prefix);
    if old_prefix.is_null() && plen != 0 {
        return Errno::EINVAL.to_neg_errno() as isize;
    }
    // SAFETY: this FFI boundary documents the readable-range precondition.
    let input = match unsafe_ffi!(codec_input_bytes(p, l)) {
        Ok(input) => input,
        Err(error) => return error as isize,
    };
    let encoded_len = match base64_encoded_len(input.len()) {
        Ok(length) => length,
        Err(error) => return error as isize,
    };
    if encoded_len == 0 {
        return if plen <= isize::MAX as usize {
            plen as isize
        } else {
            Errno::ENOMEM.to_neg_errno() as isize
        };
    }
    let needs_newline = plen > width / 2
        || match plen.checked_add(indent) {
            Some(sum) => sum > width,
            None => true,
        };
    let (separator, effective_indent, effective_width) = if needs_newline {
        let Some(effective_width) = width.checked_sub(indent) else {
            return Errno::EINVAL.to_neg_errno() as isize;
        };
        (b'\n', indent, effective_width)
    } else {
        let Some(effective_indent) = plen.checked_add(1) else {
            return Errno::ENOMEM.to_neg_errno() as isize;
        };
        let Some(effective_width) = width
            .checked_sub(plen)
            .and_then(|value| value.checked_sub(1))
        else {
            return Errno::EINVAL.to_neg_errno() as isize;
        };
        (b' ', effective_indent, effective_width)
    };
    if effective_width == 0 {
        return Errno::EINVAL.to_neg_errno() as isize;
    }
    let lines = match encoded_len
        .checked_add(effective_width - 1)
        .map(|length| length / effective_width)
    {
        Some(lines) => lines,
        None => return Errno::ENOMEM.to_neg_errno() as isize,
    };
    let per_line = match effective_indent
        .checked_add(effective_width)
        .and_then(|value| value.checked_add(1))
    {
        Some(value) => value,
        None => return Errno::ENOMEM.to_neg_errno() as isize,
    };
    let allocation_len = match lines
        .checked_mul(per_line)
        .and_then(|value| value.checked_add(plen))
        .and_then(|value| value.checked_add(2))
    {
        Some(length) if length <= isize::MAX as usize => length,
        _ => return Errno::ENOMEM.to_neg_errno() as isize,
    };
    let mut encoded = Vec::new();
    if encoded.try_reserve_exact(encoded_len).is_err() {
        return Errno::ENOMEM.to_neg_errno() as isize;
    }
    encoded.resize(encoded_len, 0);
    base64_encode_into(input, &mut encoded);
    // SAFETY: `old_prefix` is either null or a libc allocation, and the new
    // checked size is non-zero. `realloc` preserves the first `plen` bytes.
    let allocation =
        unsafe_ffi!(libc::realloc(old_prefix.cast::<c_void>(), allocation_len)).cast::<u8>();
    if allocation.is_null() {
        return Errno::ENOMEM.to_neg_errno() as isize;
    }
    // SAFETY: the successful realloc result is live for `allocation_len` bytes.
    let output = unsafe_ffi!(std::slice::from_raw_parts_mut(allocation, allocation_len));
    let mut written = plen;
    for line in 0..lines {
        let amount = (encoded_len - line * effective_width).min(effective_width);
        if written > 0 {
            output[written] = if line == 0 { separator } else { b'\n' };
            written += 1;
            if output[written - 1] == b'\n' {
                output[written..written + effective_indent].fill(b' ');
                written += effective_indent;
            }
        }
        let offset = line * effective_width;
        output[written..written + amount].copy_from_slice(&encoded[offset..offset + amount]);
        written += amount;
    }
    output[written] = 0;
    // SAFETY: successful completion publishes the potentially moved allocation.
    unsafe_ffi!(*prefix = allocation.cast::<c_char>());
    written as isize
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
    let input = unsafe_ffi!(CStr::from_ptr(p)).to_bytes();
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
    let allocation = unsafe_ffi!(libc::malloc(allocation_len)).cast::<u8>();
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
            unsafe_ffi!(*allocation.add(decoded_len) = 0);
            if !ret_size.is_null() {
                // SAFETY: required by the C ABI contract.
                unsafe_ffi!(*ret_size = decoded_len);
            }
            if !ret_data.is_null() {
                // SAFETY: required by the C ABI contract.
                unsafe_ffi!(*ret_data = allocation.cast::<c_void>());
            } else {
                // SAFETY: the allocation has not escaped this function.
                unsafe_ffi!(libc::free(allocation.cast::<c_void>()));
            }
            0
        }
        Err(error) => {
            // SAFETY: the allocation has not escaped this function.
            unsafe_ffi!(libc::free(allocation.cast::<c_void>()));
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
    if p.is_null() && l != 0 || ret.is_null() {
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
        unsafe_ffi!(std::slice::from_raw_parts(p.cast::<u8>(), l))
    };
    // SAFETY: `allocation_len` is non-zero and comes from checked arithmetic.
    let allocation = unsafe_ffi!(libc::malloc(allocation_len)).cast::<u8>();
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
    let input = unsafe_ffi!(CStr::from_ptr(p)).to_bytes();
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
    let allocation = unsafe_ffi!(libc::malloc(allocation_len)).cast::<u8>();
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
            unsafe_ffi!(*allocation.add(decoded_len) = 0);
            if !ret_size.is_null() {
                // SAFETY: required by the C ABI contract.
                unsafe_ffi!(*ret_size = decoded_len);
            }
            if !ret_data.is_null() {
                // SAFETY: required by the C ABI contract.
                unsafe_ffi!(*ret_data = allocation.cast::<c_void>());
            } else {
                // SAFETY: the allocation has not escaped this function.
                unsafe_ffi!(libc::free(allocation.cast::<c_void>()));
            }
            0
        }
        Err(error) => {
            // SAFETY: the allocation has not escaped this function.
            unsafe_ffi!(libc::free(allocation.cast::<c_void>()));
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
    fn full_decoders_use_c_whitespace_grammar() {
        for separator in [' ', '\t', '\n', '\r'] {
            assert_eq!(
                unhexmem_full(&format!("de{separator}ad")).unwrap(),
                vec![0xde, 0xad]
            );
            assert_eq!(
                unbase64mem_full(&format!("aG{separator}VsbG8=")).unwrap(),
                b"hello"
            );
        }

        for separator in ['\u{b}', '\u{c}'] {
            assert!(unhexmem_full(&format!("de{separator}ad")).is_err());
            assert!(unbase64mem_full(&format!("aG{separator}VsbG8=")).is_err());
        }
    }

    #[test]
    fn base32_roundtrip_with_padding() {
        let encoded = base32hexmem(b"foo", true);
        assert_eq!(encoded, "CPNMU===");
        assert_eq!(unbase32hexmem(&encoded, true).unwrap(), b"foo");
    }

    #[test]
    fn base32_decoder_rejects_whitespace_like_c() {
        for input in [" CPNMU===", "CPNMU=== ", "CPNMU===\n", "CPNMU===\u{a0}"] {
            assert!(
                unbase32hexmem(input, true).is_err(),
                "accepted whitespace-padded base32 input: {input:?}"
            );
        }
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
