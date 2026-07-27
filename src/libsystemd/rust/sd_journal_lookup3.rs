// SPDX-License-Identifier: LicenseRef-lookup3-public-domain
//
// PORT-SYNC: src/libsystemd/sd-journal/lookup3.c
//

#[inline(always)]
pub const fn hashsize(n: u32) -> u32 {
    1u32 << n
}

#[inline(always)]
pub const fn hashmask(n: u32) -> u32 {
    hashsize(n) - 1
}

#[inline(always)]
const fn rot(x: u32, k: u32) -> u32 {
    x.rotate_left(k)
}

#[inline(always)]
fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c);
    *a ^= rot(*c, 4);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rot(*a, 6);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rot(*b, 8);
    *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c);
    *a ^= rot(*c, 16);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rot(*a, 19);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rot(*b, 4);
    *b = b.wrapping_add(*a);
}

#[inline(always)]
fn final_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = c.wrapping_sub(rot(*b, 14));
    *a ^= *c;
    *a = a.wrapping_sub(rot(*c, 11));
    *b ^= *a;
    *b = b.wrapping_sub(rot(*a, 25));
    *c ^= *b;
    *c = c.wrapping_sub(rot(*b, 16));
    *a ^= *c;
    *a = a.wrapping_sub(rot(*c, 4));
    *b ^= *a;
    *b = b.wrapping_sub(rot(*a, 14));
    *c ^= *b;
    *c = c.wrapping_sub(rot(*b, 24));
}

pub fn jenkins_hashword(words: &[u32], initval: u32) -> u32 {
    let mut a = 0xdeadbeefu32
        .wrapping_add((words.len() as u32) << 2)
        .wrapping_add(initval);
    let mut b = a;
    let mut c = a;

    let mut chunks = words.chunks_exact(3);
    for chunk in &mut chunks {
        a = a.wrapping_add(chunk[0]);
        b = b.wrapping_add(chunk[1]);
        c = c.wrapping_add(chunk[2]);
        mix(&mut a, &mut b, &mut c);
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        if remainder.len() >= 1 {
            a = a.wrapping_add(remainder[0]);
        }
        if remainder.len() >= 2 {
            b = b.wrapping_add(remainder[1]);
        }
        if remainder.len() == 3 {
            c = c.wrapping_add(remainder[2]);
        }
        final_mix(&mut a, &mut b, &mut c);
    }

    c
}

pub fn jenkins_hashword2(words: &[u32], pc: u32, pb: u32) -> (u32, u32) {
    let mut a = 0xdeadbeefu32
        .wrapping_add((words.len() as u32) << 2)
        .wrapping_add(pc);
    let mut b = a;
    let mut c = a.wrapping_add(pb);

    let mut chunks = words.chunks_exact(3);
    for chunk in &mut chunks {
        a = a.wrapping_add(chunk[0]);
        b = b.wrapping_add(chunk[1]);
        c = c.wrapping_add(chunk[2]);
        mix(&mut a, &mut b, &mut c);
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        if remainder.len() >= 1 {
            a = a.wrapping_add(remainder[0]);
        }
        if remainder.len() >= 2 {
            b = b.wrapping_add(remainder[1]);
        }
        if remainder.len() == 3 {
            c = c.wrapping_add(remainder[2]);
        }
        final_mix(&mut a, &mut b, &mut c);
    }

    (c, b)
}

pub fn jenkins_hashlittle(key: &[u8], initval: u32) -> u32 {
    jenkins_hashlittle2(key, initval, 0).0
}

pub fn jenkins_hashlittle2(key: &[u8], pc: u32, pb: u32) -> (u32, u32) {
    let length = key.len() as u32;
    let mut a = 0xdeadbeefu32.wrapping_add(length).wrapping_add(pc);
    let mut b = a;
    let mut c = a.wrapping_add(pb);

    let mut i = 0usize;
    while i + 12 <= key.len() {
        a = a.wrapping_add(u32::from_le_bytes(key[i..i + 4].try_into().unwrap()));
        b = b.wrapping_add(u32::from_le_bytes(key[i + 4..i + 8].try_into().unwrap()));
        c = c.wrapping_add(u32::from_le_bytes(key[i + 8..i + 12].try_into().unwrap()));
        mix(&mut a, &mut b, &mut c);
        i += 12;
    }

    let tail = &key[i..];
    let mut block = [0u8; 12];
    block[..tail.len()].copy_from_slice(tail);

    match tail.len() {
        0 => return (c, b),
        _ => {
            a = a.wrapping_add(u32::from_le_bytes(block[0..4].try_into().unwrap()));
            b = b.wrapping_add(u32::from_le_bytes(block[4..8].try_into().unwrap()));
            c = c.wrapping_add(u32::from_le_bytes(block[8..12].try_into().unwrap()));
            final_mix(&mut a, &mut b, &mut c);
        }
    }

    (c, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashsize_matches_power_of_two() {
        assert_eq!(hashsize(10), 1024);
    }

    #[test]
    fn hashmask_matches_size_minus_one() {
        assert_eq!(hashmask(10), 1023);
    }

    #[test]
    fn hashlittle_empty_uses_seed() {
        assert_eq!(jenkins_hashlittle(&[], 0), 0xdeadbeef);
    }

    #[test]
    fn hashlittle_is_stable() {
        assert_eq!(
            jenkins_hashlittle(b"abc", 1234),
            jenkins_hashlittle(b"abc", 1234)
        );
    }

    #[test]
    fn hashlittle_changes_with_input() {
        assert_ne!(jenkins_hashlittle(b"abc", 0), jenkins_hashlittle(b"abd", 0));
    }

    #[test]
    fn hashlittle2_returns_two_values() {
        let (pc, pb) = jenkins_hashlittle2(b"abcdef", 1, 2);
        assert_ne!(pc, pb);
    }

    #[test]
    fn hashword_is_stable() {
        assert_eq!(
            jenkins_hashword(&[1, 2, 3, 4], 5),
            jenkins_hashword(&[1, 2, 3, 4], 5)
        );
    }

    #[test]
    fn hashword2_returns_primary_and_secondary() {
        let (pc, pb) = jenkins_hashword2(&[1, 2, 3], 10, 11);
        assert_ne!(pc, pb);
    }

    #[test]
    fn byte_and_word_hashes_agree_for_same_bytes() {
        // On little-endian, b"abcd" as a u32 word is 0x64636261,
        // so hashword and hashlittle must produce the same result.
        let word_hash = jenkins_hashword(&[0x64636261], 0);
        let byte_hash = jenkins_hashlittle(b"abcd", 0);
        assert_eq!(word_hash, byte_hash);
    }
}
