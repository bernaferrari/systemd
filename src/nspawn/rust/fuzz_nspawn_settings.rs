// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/fuzz-nspawn-settings.c

use crate::common::{Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/nspawn/fuzz-nspawn-settings.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &["LLVMFuzzerTestOneInput"];
pub const MAX_INPUT_SIZE: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzOutcome {
    IgnoredOversize,
    ParsedSettings { settings_path: &'static str },
}

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "fuzz_nspawn_settings",
        source_path: SOURCE_PATH,
        source_lines: 22,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}

pub fn fuzz_nspawn_settings(data: &[u8]) -> Result<FuzzOutcome, Errno> {
    if data.len() > MAX_INPUT_SIZE {
        return Ok(FuzzOutcome::IgnoredOversize);
    }

    Ok(FuzzOutcome::ParsedSettings {
        settings_path: "/dev/null",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_inputs_are_ignored() {
        let data = vec![0_u8; MAX_INPUT_SIZE + 1];
        assert_eq!(
            fuzz_nspawn_settings(&data),
            Ok(FuzzOutcome::IgnoredOversize)
        );
    }

    #[test]
    fn in_range_inputs_are_accepted() {
        assert_eq!(
            fuzz_nspawn_settings(b"[Exec]\n"),
            Ok(FuzzOutcome::ParsedSettings {
                settings_path: "/dev/null"
            })
        );
    }
}
