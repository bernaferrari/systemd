// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/sha1.h, src/fundamental/sha1.c
//
// Minimal no_std SHA-1 implementation.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha1State {
    h: [u32; 5],
    len: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

pub type Digest = [u8; 20];

impl Default for Sha1State {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1State {
    pub fn new() -> Self {
        Self {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            len: 0,
            buffer: [0; 64],
            buffer_len: 0,
        }
    }
    pub fn update(&mut self, mut input: &[u8]) {
        self.len = self.len.wrapping_add((input.len() as u64) * 8);
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(64 - self.buffer_len, input.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&input[..to_copy]);
            self.buffer_len += to_copy;
            input = &input[to_copy..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                process_block(&mut self.h, &block);
                self.buffer_len = 0;
            }
        }
        while input.len() >= 64 {
            process_block(&mut self.h, input[..64].try_into().unwrap());
            input = &input[64..];
        }
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }
    pub fn finish(mut self) -> Digest {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            for byte in &mut self.buffer[self.buffer_len..] {
                *byte = 0;
            }
            let block = self.buffer;
            process_block(&mut self.h, &block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        for byte in &mut self.buffer[self.buffer_len..56] {
            *byte = 0;
        }
        self.buffer[56..64].copy_from_slice(&self.len.to_be_bytes());
        let block = self.buffer;
        process_block(&mut self.h, &block);
        let mut out = [0u8; 20];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.h) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

pub fn sha1_digest(data: &[u8]) -> Digest {
    let mut state = Sha1State::new();
    state.update(data);
    state.finish()
}

fn process_block(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (i, chunk) in block.chunks_exact(4).enumerate().take(16) {
        w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);
    for (i, wi) in w.into_iter().enumerate() {
        let (f, k) = match i {
            0..=19 => (((b & c) | ((!b) & d)), 0x5A827999),
            20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
            40..=59 => (((b & c) | (b & d) | (c & d)), 0x8F1BBCDC),
            _ => (b ^ c ^ d, 0xCA62C1D6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    fn hex(data: &[u8]) -> std::string::String {
        data.iter().map(|b| alloc::format!("{:02x}", b)).collect()
    }
    #[test]
    fn hashes_empty_string() {
        assert_eq!(
            hex(&sha1_digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }
    #[test]
    fn hashes_abc() {
        assert_eq!(
            hex(&sha1_digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }
    #[test]
    fn incremental_update_matches_one_shot() {
        let mut s = Sha1State::new();
        s.update(b"a");
        s.update(b"bc");
        assert_eq!(s.finish(), sha1_digest(b"abc"));
    }
}
