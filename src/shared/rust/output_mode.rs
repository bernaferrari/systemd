// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/output-mode.c, src/shared/output-mode.h
//
// Output mode enumeration for journal/process display.

use std::fmt;
use std::str::FromStr;
use systemd_basic_rs::shared_facades::lookups::{
    OutputMode as BasicOutputMode, SD_JSON_FORMAT_NEWLINE as BASIC_SD_JSON_FORMAT_NEWLINE,
    SD_JSON_FORMAT_PRETTY as BASIC_SD_JSON_FORMAT_PRETTY,
    SD_JSON_FORMAT_SEQ as BASIC_SD_JSON_FORMAT_SEQ, SD_JSON_FORMAT_SSE as BASIC_SD_JSON_FORMAT_SSE,
    output_mode_to_json_format_flags as basic_output_mode_to_json_format_flags,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputMode {
    Short,
    ShortFull,
    ShortIso,
    ShortIsoPrecise,
    ShortPrecise,
    ShortMonotonic,
    ShortDelta,
    ShortUnix,
    Verbose,
    Export,
    Json,
    JsonPretty,
    JsonSse,
    JsonSeq,
    Cat,
    WithUnit,
}

impl OutputMode {
    pub const ALL: [OutputMode; 16] = [
        OutputMode::Short,
        OutputMode::ShortFull,
        OutputMode::ShortIso,
        OutputMode::ShortIsoPrecise,
        OutputMode::ShortPrecise,
        OutputMode::ShortMonotonic,
        OutputMode::ShortDelta,
        OutputMode::ShortUnix,
        OutputMode::Verbose,
        OutputMode::Export,
        OutputMode::Json,
        OutputMode::JsonPretty,
        OutputMode::JsonSse,
        OutputMode::JsonSeq,
        OutputMode::Cat,
        OutputMode::WithUnit,
    ];

    pub fn is_json(self) -> bool {
        matches!(
            self,
            OutputMode::Json | OutputMode::JsonPretty | OutputMode::JsonSse | OutputMode::JsonSeq
        )
    }
}

impl fmt::Display for OutputMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OutputMode::Short => "short",
            OutputMode::ShortFull => "short-full",
            OutputMode::ShortIso => "short-iso",
            OutputMode::ShortIsoPrecise => "short-iso-precise",
            OutputMode::ShortPrecise => "short-precise",
            OutputMode::ShortMonotonic => "short-monotonic",
            OutputMode::ShortDelta => "short-delta",
            OutputMode::ShortUnix => "short-unix",
            OutputMode::Verbose => "verbose",
            OutputMode::Export => "export",
            OutputMode::Json => "json",
            OutputMode::JsonPretty => "json-pretty",
            OutputMode::JsonSse => "json-sse",
            OutputMode::JsonSeq => "json-seq",
            OutputMode::Cat => "cat",
            OutputMode::WithUnit => "with-unit",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOutputModeError(());

impl fmt::Display for ParseOutputModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid output mode")
    }
}

impl std::error::Error for ParseOutputModeError {}

impl FromStr for OutputMode {
    type Err = ParseOutputModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "short" => OutputMode::Short,
            "short-full" => OutputMode::ShortFull,
            "short-iso" => OutputMode::ShortIso,
            "short-iso-precise" => OutputMode::ShortIsoPrecise,
            "short-precise" => OutputMode::ShortPrecise,
            "short-monotonic" => OutputMode::ShortMonotonic,
            "short-delta" => OutputMode::ShortDelta,
            "short-unix" => OutputMode::ShortUnix,
            "verbose" => OutputMode::Verbose,
            "export" => OutputMode::Export,
            "json" => OutputMode::Json,
            "json-pretty" => OutputMode::JsonPretty,
            "json-sse" => OutputMode::JsonSse,
            "json-seq" => OutputMode::JsonSeq,
            "cat" => OutputMode::Cat,
            "with-unit" => OutputMode::WithUnit,
            _ => return Err(ParseOutputModeError(())),
        })
    }
}

bitflags::bitflags! {
    pub struct OutputFlags: u32 {
        const SHOW_ALL       = 1 << 0;
        const FULL_WIDTH     = 1 << 1;
        const COLOR          = 1 << 2;
        const WARN_CUTOFF    = 1 << 3;
        const CATALOG        = 1 << 4;
        const BEGIN_NEWLINE  = 1 << 5;
        const UTC            = 1 << 6;
        const NO_HOSTNAME    = 1 << 7;
        const TRUNCATE_NEWLINE = 1 << 8;
        const KERNEL_THREADS = 1 << 9;
        const CGROUP_XATTRS  = 1 << 10;
        const CGROUP_ID      = 1 << 11;
        const HIDE_EXTRA     = 1 << 12;
    }
}

pub fn output_mode_to_json_format_flags(m: OutputMode) -> u64 {
    let basic_mode = match m {
        OutputMode::Short => BasicOutputMode::Short,
        OutputMode::ShortFull => BasicOutputMode::ShortFull,
        OutputMode::ShortIso => BasicOutputMode::ShortIso,
        OutputMode::ShortIsoPrecise => BasicOutputMode::ShortIsoPrecise,
        OutputMode::ShortPrecise => BasicOutputMode::ShortPrecise,
        OutputMode::ShortMonotonic => BasicOutputMode::ShortMonotonic,
        OutputMode::ShortDelta => BasicOutputMode::ShortDelta,
        OutputMode::ShortUnix => BasicOutputMode::ShortUnix,
        OutputMode::Verbose => BasicOutputMode::Verbose,
        OutputMode::Export => BasicOutputMode::Export,
        OutputMode::Json => BasicOutputMode::Json,
        OutputMode::JsonPretty => BasicOutputMode::JsonPretty,
        OutputMode::JsonSse => BasicOutputMode::JsonSse,
        OutputMode::JsonSeq => BasicOutputMode::JsonSeq,
        OutputMode::Cat => BasicOutputMode::Cat,
        OutputMode::WithUnit => BasicOutputMode::WithUnit,
    };

    u64::from(basic_output_mode_to_json_format_flags(basic_mode as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_json() {
        assert!(OutputMode::Json.is_json());
        assert!(OutputMode::JsonPretty.is_json());
        assert!(OutputMode::JsonSse.is_json());
        assert!(OutputMode::JsonSeq.is_json());
        assert!(!OutputMode::Short.is_json());
        assert!(!OutputMode::Cat.is_json());
        assert!(!OutputMode::Verbose.is_json());
    }

    #[test]
    fn test_display() {
        assert_eq!(OutputMode::Short.to_string(), "short");
        assert_eq!(OutputMode::ShortFull.to_string(), "short-full");
        assert_eq!(OutputMode::ShortIso.to_string(), "short-iso");
        assert_eq!(OutputMode::Json.to_string(), "json");
        assert_eq!(OutputMode::JsonPretty.to_string(), "json-pretty");
        assert_eq!(OutputMode::Cat.to_string(), "cat");
        assert_eq!(OutputMode::WithUnit.to_string(), "with-unit");
    }

    #[test]
    fn test_from_str() {
        assert_eq!("short".parse(), Ok(OutputMode::Short));
        assert_eq!("short-full".parse(), Ok(OutputMode::ShortFull));
        assert_eq!("json".parse(), Ok(OutputMode::Json));
        assert_eq!("json-pretty".parse(), Ok(OutputMode::JsonPretty));
        assert_eq!("cat".parse(), Ok(OutputMode::Cat));
        assert_eq!("verbose".parse(), Ok(OutputMode::Verbose));
        assert!("invalid".parse::<OutputMode>().is_err());
        assert!("".parse::<OutputMode>().is_err());
    }

    #[test]
    fn test_roundtrip() {
        for mode in OutputMode::ALL {
            let s = mode.to_string();
            assert_eq!(
                s.parse::<OutputMode>(),
                Ok(mode),
                "roundtrip failed for {mode:?}"
            );
        }
    }

    #[test]
    fn test_to_json_format_flags() {
        assert_eq!(
            output_mode_to_json_format_flags(OutputMode::JsonSse),
            u64::from(BASIC_SD_JSON_FORMAT_SSE)
        );
        assert_eq!(
            output_mode_to_json_format_flags(OutputMode::JsonSeq),
            u64::from(BASIC_SD_JSON_FORMAT_SEQ)
        );
        assert_eq!(
            output_mode_to_json_format_flags(OutputMode::JsonPretty),
            u64::from(BASIC_SD_JSON_FORMAT_PRETTY)
        );
        assert_eq!(
            output_mode_to_json_format_flags(OutputMode::Json),
            u64::from(BASIC_SD_JSON_FORMAT_NEWLINE)
        );
        assert_eq!(
            output_mode_to_json_format_flags(OutputMode::Short),
            u64::from(BASIC_SD_JSON_FORMAT_NEWLINE)
        );
        assert_eq!(
            output_mode_to_json_format_flags(OutputMode::Cat),
            u64::from(BASIC_SD_JSON_FORMAT_NEWLINE)
        );
    }

    #[test]
    fn test_json_format_constants_match_sd_json_bits() {
        assert_eq!(BASIC_SD_JSON_FORMAT_NEWLINE, 1 << 1);
        assert_eq!(BASIC_SD_JSON_FORMAT_PRETTY, 1 << 2);
        assert_eq!(BASIC_SD_JSON_FORMAT_SSE, 1 << 7);
        assert_eq!(BASIC_SD_JSON_FORMAT_SEQ, 1 << 8);
    }

    #[test]
    fn test_output_flags() {
        let flags = OutputFlags::SHOW_ALL | OutputFlags::COLOR;
        assert!(flags.contains(OutputFlags::SHOW_ALL));
        assert!(flags.contains(OutputFlags::COLOR));
        assert!(!flags.contains(OutputFlags::FULL_WIDTH));
    }
}
