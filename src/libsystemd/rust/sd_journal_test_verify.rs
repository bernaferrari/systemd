// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal-verify.c

pub type Result<T> = std::result::Result<T, i32>;

pub const N_ENTRIES: usize = 6000;
pub const RANDOM_RANGE: i32 = 77;
pub const DEFAULT_MAX_ITERATIONS: i64 = 512;
pub const BIT_TOGGLE_START: u64 = 38448 * 8;
pub const DEFAULT_VERIFICATION_KEY: &str = "c262bd-85187f-0b1b04-877cc5/1c7af8-35a4e900";
pub const JOURNAL_COMPRESS: u32 = 1;
pub const JOURNAL_SEAL: u32 = 2;
pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyParams {
    pub verification_key: Option<String>,
    pub max_iterations: i64,
    pub compact_mode: bool,
}

impl Default for VerifyParams {
    fn default() -> Self {
        Self {
            verification_key: None,
            max_iterations: DEFAULT_MAX_ITERATIONS,
            compact_mode: false,
        }
    }
}

impl VerifyParams {
    pub fn with_key(key: &str) -> Self {
        Self {
            verification_key: Some(key.to_string()),
            max_iterations: -1,
            compact_mode: false,
        }
    }

    pub fn with_compact(mut self, enabled: bool) -> Self {
        self.compact_mode = enabled;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationPlan {
    pub start_bit: u64,
    pub end_bit: u64,
    pub positions: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct DeterministicRandom(u64);

impl DeterministicRandom {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_i32(&mut self) -> i32 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
        ((self.0 >> 33) as i32).rem_euclid(RANDOM_RANGE)
    }
}

pub fn bit_toggle(buf: &mut [u8], p: u64) {
    let byte = (p / 8) as usize;
    let bit = (p % 8) as u8;
    if let Some(cell) = buf.get_mut(byte) {
        *cell ^= 1 << bit;
    }
}

pub fn bit_toggle_end(start: u64, max_iterations: i64, file_size: u64) -> u64 {
    if max_iterations < 0 {
        file_size.saturating_mul(8)
    } else {
        start.saturating_add(max_iterations as u64)
    }
}

pub fn bit_position(p: u64) -> (u64, u64) {
    (p / 8, p % 8)
}

pub fn format_bit_position(p: u64) -> String {
    let (byte, bit) = bit_position(p);
    format!("[ {}+{}]", byte, bit)
}

pub fn build_random_field(value: i32) -> Result<String> {
    if validate_random_value(value) {
        Ok(format!("RANDOM={value}"))
    } else {
        Err(NEG_EINVAL)
    }
}

pub fn parse_random_field(field: &str) -> Result<i32> {
    field
        .strip_prefix("RANDOM=")
        .ok_or(NEG_EINVAL)?
        .parse::<i32>()
        .map_err(|_| NEG_EINVAL)
        .and_then(|v| {
            if validate_random_value(v) {
                Ok(v)
            } else {
                Err(NEG_EINVAL)
            }
        })
}

pub fn validate_random_value(value: i32) -> bool {
    (0..RANDOM_RANGE).contains(&value)
}

pub fn build_verify_param_combinations() -> Vec<VerifyParams> {
    vec![
        VerifyParams::default().with_compact(false),
        VerifyParams::default().with_compact(true),
        VerifyParams::with_key(DEFAULT_VERIFICATION_KEY).with_compact(false),
        VerifyParams::with_key(DEFAULT_VERIFICATION_KEY).with_compact(true),
    ]
}

pub fn verification_plan(file_size: u64, max_iterations: i64) -> VerificationPlan {
    let end_bit = bit_toggle_end(BIT_TOGGLE_START, max_iterations, file_size);
    let positions = (BIT_TOGGLE_START..end_bit).collect::<Vec<_>>();
    VerificationPlan {
        start_bit: BIT_TOGGLE_START,
        end_bit,
        positions,
    }
}

pub fn generate_random_fields(seed: u64, count: usize) -> Vec<String> {
    let mut rng = DeterministicRandom::new(seed);
    (0..count)
        .map(|_| build_random_field(rng.next_i32()).expect("deterministic values stay in range"))
        .collect()
}

pub fn has_machine_id_at(path: &std::path::Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggles_bits_in_place() {
        let mut buf = [0u8; 2];
        bit_toggle(&mut buf, 0);
        bit_toggle(&mut buf, 15);
        assert_eq!(buf, [1, 128]);
    }

    #[test]
    fn ignores_out_of_range_bit_toggles() {
        let mut buf = [0u8; 1];
        bit_toggle(&mut buf, 8);
        assert_eq!(buf, [0]);
    }

    #[test]
    fn computes_toggle_end_for_limited_runs() {
        assert_eq!(
            bit_toggle_end(BIT_TOGGLE_START, 10, 1_000),
            BIT_TOGGLE_START + 10
        );
    }

    #[test]
    fn computes_toggle_end_for_full_file() {
        assert_eq!(bit_toggle_end(BIT_TOGGLE_START, -1, 100), 800);
    }

    #[test]
    fn formats_bit_positions() {
        assert_eq!(format_bit_position(8), "[ 1+0]");
    }

    #[test]
    fn roundtrips_random_field() {
        let field = build_random_field(42).unwrap();
        assert_eq!(parse_random_field(&field).unwrap(), 42);
    }

    #[test]
    fn rejects_out_of_range_random_field() {
        assert_eq!(build_random_field(90), Err(NEG_EINVAL));
        assert_eq!(parse_random_field("RANDOM=90"), Err(NEG_EINVAL));
    }

    #[test]
    fn builds_verify_parameter_matrix() {
        let params = build_verify_param_combinations();
        assert_eq!(params.len(), 4);
        assert!(params[2].verification_key.is_some());
    }

    #[test]
    fn generates_reproducible_random_fields() {
        assert_eq!(generate_random_fields(1, 3), generate_random_fields(1, 3));
    }

    #[test]
    fn creates_verification_plan() {
        let plan = verification_plan(100, 4);
        assert_eq!(
            plan.positions,
            vec![
                BIT_TOGGLE_START,
                BIT_TOGGLE_START + 1,
                BIT_TOGGLE_START + 2,
                BIT_TOGGLE_START + 3
            ]
        );
    }
}
