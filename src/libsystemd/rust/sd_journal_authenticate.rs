// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-authenticate.c

pub type Result<T> = std::result::Result<T, i32>;

pub const TAG_LENGTH: usize = 32;
pub const FSPRG_RECOMMENDED_SECPAR: u16 = 2048;
pub const FSPRG_RECOMMENDED_SEEDLEN: usize = 64;
pub const JOURNAL_HEADER_SEALED_FLAG: u8 = 1;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const NEG_EOPNOTSUPP: i32 = -(libc::EOPNOTSUPP as i32);
pub const NEG_ESTALE: i32 = -(libc::ESTALE as i32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
    pub seed: Vec<u8>,
    pub start_usec: u64,
    pub interval_usec: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalAuthenticator {
    pub header_flags: u8,
    pub fss_start_usec: u64,
    pub fss_interval_usec: u64,
    pub current_epoch: u64,
    pub seed: Vec<u8>,
    pub hmac_running: bool,
    pub objects_hashed: usize,
    pub tags: Vec<[u8; TAG_LENGTH]>,
    header_hash: [u8; TAG_LENGTH],
}

impl JournalAuthenticator {
    pub fn new(header_flags: u8, start_usec: u64, interval_usec: u64, seed: Vec<u8>) -> Self {
        Self {
            header_flags,
            fss_start_usec: start_usec,
            fss_interval_usec: interval_usec,
            current_epoch: 0,
            seed,
            hmac_running: false,
            objects_hashed: 0,
            tags: Vec::new(),
            header_hash: [0; TAG_LENGTH],
        }
    }

    pub fn journal_file_append_tag(&mut self) -> Result<()> {
        if !journal_header_sealed(self.header_flags) {
            return Ok(());
        }
        self.journal_file_hmac_start()?;
        let tag = digest(&[
            &self.seed,
            &self.header_hash,
            &(self.current_epoch.to_le_bytes()),
            &(self.objects_hashed as u64).to_le_bytes(),
        ]);
        self.tags.push(tag);
        self.hmac_running = false;
        Ok(())
    }

    pub fn journal_file_hmac_start(&mut self) -> Result<()> {
        if !journal_header_sealed(self.header_flags) {
            return Ok(());
        }
        self.hmac_running = true;
        Ok(())
    }

    pub fn journal_file_hmac_put_object(&mut self, object_type: i32, payload: &[u8]) -> Result<()> {
        if !journal_header_sealed(self.header_flags) {
            return Ok(());
        }
        self.journal_file_hmac_start()?;
        self.header_hash = digest(&[&self.header_hash, &object_type.to_le_bytes(), payload]);
        self.objects_hashed += 1;
        Ok(())
    }

    pub fn journal_file_hmac_put_header(&mut self, header: &[u8]) -> Result<()> {
        if !journal_header_sealed(self.header_flags) {
            return Ok(());
        }
        self.journal_file_hmac_start()?;
        self.header_hash = digest(&[&self.seed, header]);
        Ok(())
    }

    pub fn journal_file_fsprg_need_evolve(&self, realtime: u64) -> Result<i32> {
        journal_file_fsprg_need_evolve(
            self.fss_start_usec,
            self.fss_interval_usec,
            journal_header_sealed(self.header_flags),
            self.current_epoch,
            realtime,
        )
    }

    pub fn journal_file_fsprg_evolve(&mut self, realtime: u64) -> Result<()> {
        let goal = journal_file_get_epoch(
            self.fss_start_usec,
            self.fss_interval_usec,
            journal_header_sealed(self.header_flags),
            realtime,
        )?;
        while self.current_epoch < goal {
            self.current_epoch += 1;
            if self.current_epoch < goal {
                self.journal_file_append_tag()?;
            }
        }
        if self.current_epoch > goal {
            return Err(NEG_ESTALE);
        }
        Ok(())
    }

    pub fn journal_file_fsprg_seek(&mut self, goal: u64) -> Result<()> {
        if !journal_header_sealed(self.header_flags) {
            return Ok(());
        }
        self.current_epoch = goal;
        Ok(())
    }

    pub fn journal_file_maybe_append_tag(&mut self, realtime: u64) -> Result<bool> {
        if self.journal_file_fsprg_need_evolve(realtime)? <= 0 {
            return Ok(false);
        }
        self.journal_file_append_tag()?;
        self.journal_file_fsprg_evolve(realtime)?;
        Ok(true)
    }

    pub fn journal_file_append_first_tag(&mut self, header: &[u8]) -> Result<()> {
        self.journal_file_hmac_put_header(header)?;
        self.journal_file_append_tag()
    }

    pub fn journal_file_fss_load(key: &VerificationKey) -> Result<(u64, u64)> {
        if key.start_usec == 0 || key.interval_usec == 0 || key.seed.is_empty() {
            return Err(NEG_EINVAL);
        }
        Ok((key.start_usec, key.interval_usec))
    }

    pub fn journal_file_hmac_setup(&mut self) -> Result<()> {
        if !journal_header_sealed(self.header_flags) {
            return Ok(());
        }
        if self.seed.is_empty() {
            return Err(NEG_EINVAL);
        }
        self.hmac_running = false;
        Ok(())
    }
}

pub fn journal_header_sealed(compatible_flags: u8) -> bool {
    compatible_flags & JOURNAL_HEADER_SEALED_FLAG != 0
}

pub fn journal_file_get_epoch(
    fss_start_usec: u64,
    fss_interval_usec: u64,
    header_sealed: bool,
    realtime: u64,
) -> Result<u64> {
    if !header_sealed || fss_start_usec == 0 || fss_interval_usec == 0 {
        return Err(NEG_EOPNOTSUPP);
    }
    if realtime < fss_start_usec {
        return Err(NEG_ESTALE);
    }
    Ok((realtime - fss_start_usec) / fss_interval_usec)
}

pub fn journal_file_fsprg_need_evolve(
    fss_start_usec: u64,
    fss_interval_usec: u64,
    header_sealed: bool,
    current_epoch: u64,
    realtime: u64,
) -> Result<i32> {
    if !header_sealed {
        return Ok(0);
    }
    let goal = journal_file_get_epoch(fss_start_usec, fss_interval_usec, header_sealed, realtime)?;
    if current_epoch > goal {
        return Err(NEG_ESTALE);
    }
    Ok((current_epoch != goal) as i32)
}

pub fn parse_verification_key(key: &str) -> Result<VerificationKey> {
    let (seed_hex, timings) = key.split_once('/').ok_or(NEG_EINVAL)?;
    let (start_hex, interval_hex) = timings.split_once('-').ok_or(NEG_EINVAL)?;
    let seed = decode_hex(seed_hex)?;
    if seed.len() != FSPRG_RECOMMENDED_SEEDLEN / 2 {
        return Err(NEG_EINVAL);
    }
    Ok(VerificationKey {
        seed,
        start_usec: u64::from_str_radix(start_hex, 16).map_err(|_| NEG_EINVAL)?,
        interval_usec: u64::from_str_radix(interval_hex, 16).map_err(|_| NEG_EINVAL)?,
    })
}

pub fn journal_file_next_evolve_usec(
    fss_start_usec: u64,
    fss_interval_usec: u64,
    header_sealed: bool,
    current_epoch: u64,
) -> Option<u64> {
    header_sealed.then_some(fss_start_usec + fss_interval_usec * (current_epoch + 1))
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(NEG_EINVAL);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        out.push((hex_value(pair[0])? << 4) | hex_value(pair[1])?);
    }
    Ok(out)
}

fn hex_value(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(NEG_EINVAL),
    }
}

fn digest(parts: &[&[u8]]) -> [u8; TAG_LENGTH] {
    let mut state = [0u32; 8];
    state.copy_from_slice(&[
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ]);
    for part in parts {
        for (idx, byte) in part.iter().enumerate() {
            let lane = idx % 8;
            state[lane] = state[lane].rotate_left(5)
                ^ ((*byte as u32) + (idx as u32).wrapping_mul(0x9e3779b9));
            state[lane] = state[lane].wrapping_add(state[(lane + 3) % 8] ^ 0xa5a5a5a5);
        }
    }
    let mut out = [0u8; TAG_LENGTH];
    for (idx, word) in state.into_iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_sealed_header() {
        assert!(journal_header_sealed(JOURNAL_HEADER_SEALED_FLAG));
    }

    #[test]
    fn computes_epoch() {
        assert_eq!(journal_file_get_epoch(100, 10, true, 135).unwrap(), 3);
    }

    #[test]
    fn rejects_unsealed_epoch_requests() {
        assert_eq!(
            journal_file_get_epoch(100, 10, false, 135),
            Err(NEG_EOPNOTSUPP)
        );
    }

    #[test]
    fn detects_need_to_evolve() {
        assert_eq!(
            journal_file_fsprg_need_evolve(100, 10, true, 1, 135).unwrap(),
            1
        );
    }

    #[test]
    fn parses_verification_key() {
        let key = parse_verification_key(
            "abababababababababababababababababababababababababababababababab/1-10",
        )
        .unwrap();
        assert_eq!(key.start_usec, 1);
        assert_eq!(key.interval_usec, 16);
    }

    #[test]
    fn computes_next_evolve_usec() {
        assert_eq!(journal_file_next_evolve_usec(10, 5, true, 2), Some(25));
    }

    #[test]
    fn appends_first_tag() {
        let mut auth = JournalAuthenticator::new(JOURNAL_HEADER_SEALED_FLAG, 10, 5, vec![1; 32]);
        auth.journal_file_append_first_tag(b"header").unwrap();
        assert_eq!(auth.tags.len(), 1);
    }

    #[test]
    fn maybe_append_tag_evolves() {
        let mut auth = JournalAuthenticator::new(JOURNAL_HEADER_SEALED_FLAG, 10, 5, vec![1; 32]);
        assert!(auth.journal_file_maybe_append_tag(20).unwrap());
        assert_eq!(auth.current_epoch, 2);
    }

    #[test]
    fn hashes_objects() {
        let mut auth = JournalAuthenticator::new(JOURNAL_HEADER_SEALED_FLAG, 10, 5, vec![1; 32]);
        auth.journal_file_hmac_put_object(7, b"payload").unwrap();
        assert_eq!(auth.objects_hashed, 1);
    }

    #[test]
    fn loads_non_empty_fss_key() {
        let key = VerificationKey {
            seed: vec![1; 32],
            start_usec: 1,
            interval_usec: 2,
        };
        assert_eq!(
            JournalAuthenticator::journal_file_fss_load(&key).unwrap(),
            (1, 2)
        );
    }
}
