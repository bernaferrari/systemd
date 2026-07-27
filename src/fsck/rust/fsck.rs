// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fsck/fsck.c

pub const EINVAL: i32 = -22;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Auto,
    Force,
    Skip,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repair {
    No,
    Yes,
    Preen,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsckResult {
    pub raw: i32,
}
pub fn parse_mode(s: &str) -> Result<Mode, i32> {
    match s {
        "auto" => Ok(Mode::Auto),
        "force" => Ok(Mode::Force),
        "skip" => Ok(Mode::Skip),
        _ => Err(EINVAL),
    }
}
pub fn parse_repair(s: &str) -> Result<Repair, i32> {
    match s {
        "no" => Ok(Repair::No),
        "yes" | "1" | "true" => Ok(Repair::Yes),
        "preen" => Ok(Repair::Preen),
        _ => Err(EINVAL),
    }
}
pub fn repair_option(r: Repair) -> &'static str {
    match r {
        Repair::No => "-n",
        Repair::Yes => "-y",
        Repair::Preen => "-a",
    }
}
pub fn parse_cmdline(key: &str, value: Option<&str>, mode: &mut Mode, repair: &mut Repair) {
    match (key, value) {
        ("fsck.mode", Some(v)) => {
            if let Ok(m) = parse_mode(v) {
                *mode = m
            }
        }
        ("fsck.repair", Some(v)) => {
            if let Ok(x) = parse_repair(v) {
                *repair = x
            }
        }
        ("fastboot", None) => *mode = Mode::Skip,
        ("forcefsck", None) => *mode = Mode::Force,
        _ => {}
    }
}
pub fn percent(pass: i32, cur: u64, max: u64) -> f64 {
    let table = [0.0, 70.0, 90.0, 92.0, 95.0, 100.0];
    if pass <= 0 {
        0.0
    } else if pass as usize >= table.len() || max == 0 {
        100.0
    } else {
        table[(pass - 1) as usize]
            + (table[pass as usize] - table[(pass - 1) as usize]) * cur as f64 / max as f64
    }
}
impl FsckResult {
    pub fn errors_corrected(self) -> bool {
        self.raw & 1 != 0
    }
    pub fn needs_reboot(self) -> bool {
        self.raw & 2 != 0
    }
    pub fn errors_uncorrected(self) -> bool {
        self.raw & 4 != 0
    }
    pub fn success(self) -> bool {
        self.raw & (4 | 8 | 16 | 32) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_mode_auto() {
        assert_eq!(parse_mode("auto").unwrap(), Mode::Auto);
    }
    #[test]
    fn parse_mode_invalid() {
        assert!(parse_mode("x").is_err());
    }
    #[test]
    fn parse_repair_boolean() {
        assert_eq!(parse_repair("true").unwrap(), Repair::Yes);
    }
    #[test]
    fn repair_option_matches_c() {
        assert_eq!(repair_option(Repair::Preen), "-a");
    }
    #[test]
    fn fastboot_skips() {
        let mut m = Mode::Auto;
        let mut r = Repair::Preen;
        parse_cmdline("fastboot", None, &mut m, &mut r);
        assert_eq!(m, Mode::Skip);
    }
    #[test]
    fn forcefsck_forces() {
        let mut m = Mode::Auto;
        let mut r = Repair::Preen;
        parse_cmdline("forcefsck", None, &mut m, &mut r);
        assert_eq!(m, Mode::Force);
    }
    #[test]
    fn percent_for_first_pass() {
        assert_eq!(percent(1, 0, 10), 0.0);
    }
    #[test]
    fn percent_for_unknown_pass_is_done() {
        assert_eq!(percent(99, 1, 1), 100.0);
    }
    #[test]
    fn result_success() {
        assert!(FsckResult { raw: 1 }.success());
    }
    #[test]
    fn result_reboot() {
        assert!(FsckResult { raw: 2 }.needs_reboot());
    }
}
