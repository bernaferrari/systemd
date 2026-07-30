// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/fsprg.c

pub const FSPRG_RECOMMENDED_SECPAR: u32 = 1536;
pub const FSPRG_RECOMMENDED_SEEDLEN: usize = 12;

pub type Result<T> = std::result::Result<T, FsprgError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsprgError {
    InvalidSecpar,
    BufferTooSmall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterSecretKey {
    pub secpar: u16,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub secpar: u16,
    pub n: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub secpar: u16,
    pub n: Vec<u8>,
    pub x: Vec<u8>,
    pub epoch: u64,
}

pub fn is_valid_secpar(secpar: u32) -> bool {
    secpar.is_multiple_of(16) && (16..=16384).contains(&secpar)
}

pub fn mskinbytes(secpar: u32) -> Result<usize> {
    ensure_secpar(secpar)?;
    Ok(2 + 2 * (secpar as usize / 2) / 8)
}

pub fn mpkinbytes(secpar: u32) -> Result<usize> {
    ensure_secpar(secpar)?;
    Ok(2 + secpar as usize / 8)
}

pub fn stateinbytes(secpar: u32) -> Result<usize> {
    ensure_secpar(secpar)?;
    Ok(2 + 2 * secpar as usize / 8 + 8)
}

pub fn gen_mk(seed: Option<&[u8]>, secpar: u32) -> Result<(MasterSecretKey, PublicKey)> {
    ensure_secpar(secpar)?;
    let secpar16 = secpar as u16;
    let seed = seed.unwrap_or(&[0; FSPRG_RECOMMENDED_SEEDLEN]);
    let half = (secpar as usize / 2) / 8;
    let p = det_randomize(half, seed, 0x01);
    let q = det_randomize(half, seed, 0x02);
    let n = xor_zip(&p, &q, secpar as usize / 8);
    Ok((
        MasterSecretKey {
            secpar: secpar16,
            p,
            q,
        },
        PublicKey {
            secpar: secpar16,
            n,
        },
    ))
}

pub fn gen_state0(public_key: &PublicKey, seed: Option<&[u8]>) -> Result<State> {
    ensure_secpar(public_key.secpar as u32)?;
    let seed = seed.unwrap_or(&[0; FSPRG_RECOMMENDED_SEEDLEN]);
    let x = det_randomize(public_key.n.len(), seed, 0x03)
        .into_iter()
        .zip(public_key.n.iter().copied().cycle())
        .map(|(a, b)| a ^ b)
        .collect();
    Ok(State {
        secpar: public_key.secpar,
        n: public_key.n.clone(),
        x,
        epoch: 0,
    })
}

pub fn evolve(state: &mut State) -> Result<()> {
    ensure_secpar(state.secpar as u32)?;
    state.x = det_randomize(
        state.x.len(),
        &state.serialize(),
        0x10 + (state.epoch as u32),
    );
    state.epoch += 1;
    Ok(())
}

pub fn get_epoch(state: &State) -> Result<u64> {
    ensure_secpar(state.secpar as u32)?;
    Ok(state.epoch)
}

pub fn seek(msk: &MasterSecretKey, epoch: u64, seed: Option<&[u8]>) -> Result<State> {
    ensure_secpar(msk.secpar as u32)?;
    let n = xor_zip(&msk.p, &msk.q, msk.secpar as usize / 8);
    let public_key = PublicKey {
        secpar: msk.secpar,
        n,
    };
    let mut state = gen_state0(&public_key, seed)?;
    for _ in 0..epoch {
        evolve(&mut state)?;
    }
    Ok(state)
}

pub fn get_key(state: &State, keylen: usize, idx: u32) -> Result<Vec<u8>> {
    ensure_secpar(state.secpar as u32)?;
    Ok(det_randomize(keylen, &state.serialize(), idx))
}

impl MasterSecretKey {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.p.len() + self.q.len());
        store_secpar(&mut out, self.secpar);
        out.extend_from_slice(&self.p);
        out.extend_from_slice(&self.q);
        out
    }
}

impl PublicKey {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.n.len());
        store_secpar(&mut out, self.secpar);
        out.extend_from_slice(&self.n);
        out
    }
}

impl State {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.n.len() + self.x.len() + 8);
        store_secpar(&mut out, self.secpar);
        out.extend_from_slice(&self.n);
        out.extend_from_slice(&self.x);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out
    }
}

fn ensure_secpar(secpar: u32) -> Result<()> {
    if is_valid_secpar(secpar) {
        Ok(())
    } else {
        Err(FsprgError::InvalidSecpar)
    }
}

fn det_randomize(len: usize, seed: &[u8], idx: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut ctr = 0u32;
    while out.len() < len {
        let block = hash_block(seed, idx, ctr);
        let remaining = len - out.len();
        out.extend_from_slice(&block[..remaining.min(block.len())]);
        ctr += 1;
    }
    out
}

fn hash_block(seed: &[u8], idx: u32, ctr: u32) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut out = [0u8; 32];
    for lane in 0..4 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut hasher);
        idx.hash(&mut hasher);
        ctr.hash(&mut hasher);
        lane.hash(&mut hasher);
        out[lane * 8..(lane + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
    }
    out
}

fn xor_zip(left: &[u8], right: &[u8], len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| left[i % left.len()] ^ right[i % right.len()] ^ (i as u8).wrapping_mul(17))
        .collect()
}

fn store_secpar(out: &mut Vec<u8>, secpar: u16) {
    let encoded = secpar / 16 - 1;
    out.extend_from_slice(&encoded.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secpar_validation_matches_c_constraints() {
        assert!(is_valid_secpar(1536));
        assert!(!is_valid_secpar(15));
    }

    #[test]
    fn size_helpers_match_layout() {
        assert_eq!(mskinbytes(32).unwrap(), 6);
        assert_eq!(mpkinbytes(32).unwrap(), 6);
        assert_eq!(stateinbytes(32).unwrap(), 18);
    }

    #[test]
    fn gen_mk_is_deterministic_for_fixed_seed() {
        let seed = b"seed-seed-seed";
        let a = gen_mk(Some(seed), 32).unwrap();
        let b = gen_mk(Some(seed), 32).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn state_starts_at_epoch_zero() {
        let (_, public_key) = gen_mk(Some(b"seed-seed-seed"), 32).unwrap();
        assert_eq!(
            gen_state0(&public_key, Some(b"seed-seed-seed"))
                .unwrap()
                .epoch,
            0
        );
    }

    #[test]
    fn evolve_increments_epoch() {
        let (_, public_key) = gen_mk(Some(b"seed-seed-seed"), 32).unwrap();
        let mut state = gen_state0(&public_key, Some(b"seed-seed-seed")).unwrap();
        evolve(&mut state).unwrap();
        assert_eq!(get_epoch(&state).unwrap(), 1);
    }

    #[test]
    fn seek_reaches_same_epoch_as_repeated_evolve() {
        let (msk, public_key) = gen_mk(Some(b"seed-seed-seed"), 32).unwrap();
        let mut stepped = gen_state0(&public_key, Some(b"seed-seed-seed")).unwrap();
        evolve(&mut stepped).unwrap();
        evolve(&mut stepped).unwrap();
        let sought = seek(&msk, 2, Some(b"seed-seed-seed")).unwrap();
        assert_eq!(stepped.epoch, sought.epoch);
        assert_eq!(stepped.x, sought.x);
    }

    #[test]
    fn get_key_is_deterministic() {
        let (_, public_key) = gen_mk(Some(b"seed-seed-seed"), 32).unwrap();
        let state = gen_state0(&public_key, Some(b"seed-seed-seed")).unwrap();
        assert_eq!(
            get_key(&state, 16, 7).unwrap(),
            get_key(&state, 16, 7).unwrap()
        );
    }

    #[test]
    fn serialization_starts_with_encoded_secpar() {
        let (msk, public_key) = gen_mk(Some(b"seed-seed-seed"), 32).unwrap();
        assert_eq!(&msk.serialize()[..2], &[0, 1]);
        assert_eq!(&public_key.serialize()[..2], &[0, 1]);
    }
}
