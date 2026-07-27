// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/execute.c, src/core/execute.h
//

use crate::ffi::Errno;

pub const SOURCE_PATHS: &[&str] = &["src/core/execute.c", "src/core/execute.h"];

macro_rules! enum_table {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }

            pub fn parse(value: &str) -> Result<Self, Errno> {
                match value {
                    $($text => Ok(Self::$variant),)+
                    _ => Err(Errno::EINVAL),
                }
            }
        }
    };
}

enum_table!(ExecInput {
    Null => "null",
    Tty => "tty",
    TtyForce => "tty-force",
    TtyFail => "tty-fail",
    Socket => "socket",
    NamedFd => "fd",
    Data => "data",
    File => "file",
});

enum_table!(ExecOutput {
    Inherit => "inherit",
    Null => "null",
    Tty => "tty",
    Kmsg => "kmsg",
    KmsgAndConsole => "kmsg+console",
    Journal => "journal",
    JournalAndConsole => "journal+console",
    Socket => "socket",
    NamedFd => "fd",
    File => "file",
    FileAppend => "append",
    FileTruncate => "truncate",
});

enum_table!(ExecUtmpMode {
    Init => "init",
    Login => "login",
    User => "user",
});

enum_table!(ExecPreserveMode {
    No => "no",
    Yes => "yes",
    Restart => "restart",
    OnSuccess => "on-success",
});

enum_table!(ExecDirectoryType {
    Runtime => "runtime",
    State => "state",
    Cache => "cache",
    Logs => "logs",
    Configuration => "configuration",
});

enum_table!(ExecKeyringMode {
    Inherit => "inherit",
    Private => "private",
    Shared => "shared",
});

enum_table!(MemoryThp {
    Inherit => "inherit",
    Disable => "disable",
    Madvise => "madvise",
    System => "system",
});

pub fn exec_directory_type_symlink_to_string(value: ExecDirectoryType) -> &'static str {
    match value {
        ExecDirectoryType::Runtime => "RuntimeDirectorySymlink",
        ExecDirectoryType::State => "StateDirectorySymlink",
        ExecDirectoryType::Cache => "CacheDirectorySymlink",
        ExecDirectoryType::Logs => "LogsDirectorySymlink",
        ExecDirectoryType::Configuration => "ConfigurationDirectorySymlink",
    }
}

pub fn exec_directory_type_symlink_from_string(value: &str) -> Result<ExecDirectoryType, Errno> {
    match value {
        "RuntimeDirectorySymlink" => Ok(ExecDirectoryType::Runtime),
        "StateDirectorySymlink" => Ok(ExecDirectoryType::State),
        "CacheDirectorySymlink" => Ok(ExecDirectoryType::Cache),
        "LogsDirectorySymlink" => Ok(ExecDirectoryType::Logs),
        "ConfigurationDirectorySymlink" => Ok(ExecDirectoryType::Configuration),
        _ => Err(Errno::EINVAL),
    }
}

pub fn exec_directory_type_mode_to_string(value: ExecDirectoryType) -> &'static str {
    match value {
        ExecDirectoryType::Runtime => "RuntimeDirectoryMode",
        ExecDirectoryType::State => "StateDirectoryMode",
        ExecDirectoryType::Cache => "CacheDirectoryMode",
        ExecDirectoryType::Logs => "LogsDirectoryMode",
        ExecDirectoryType::Configuration => "ConfigurationDirectoryMode",
    }
}

pub fn exec_directory_type_mode_from_string(value: &str) -> Result<ExecDirectoryType, Errno> {
    match value {
        "RuntimeDirectoryMode" => Ok(ExecDirectoryType::Runtime),
        "StateDirectoryMode" => Ok(ExecDirectoryType::State),
        "CacheDirectoryMode" => Ok(ExecDirectoryType::Cache),
        "LogsDirectoryMode" => Ok(ExecDirectoryType::Logs),
        "ConfigurationDirectoryMode" => Ok(ExecDirectoryType::Configuration),
        _ => Err(Errno::EINVAL),
    }
}

pub fn exec_preserve_mode_from_string_with_boolean(value: &str) -> Result<ExecPreserveMode, Errno> {
    match parse_boolean(value) {
        Some(false) => Ok(ExecPreserveMode::No),
        Some(true) => Ok(ExecPreserveMode::Yes),
        None => ExecPreserveMode::parse(value),
    }
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value {
        "1" | "y" | "Y" | "yes" | "YES" | "true" | "TRUE" | "on" | "ON" => Some(true),
        "0" | "n" | "N" | "no" | "NO" | "false" | "FALSE" | "off" | "OFF" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_input_roundtrip() {
        assert_eq!(ExecInput::parse("fd"), Ok(ExecInput::NamedFd));
        assert_eq!(ExecInput::NamedFd.as_str(), "fd");
    }

    #[test]
    fn exec_output_roundtrip() {
        assert_eq!(
            ExecOutput::parse("journal+console"),
            Ok(ExecOutput::JournalAndConsole)
        );
        assert_eq!(ExecOutput::JournalAndConsole.as_str(), "journal+console");
    }

    #[test]
    fn utmp_mode_roundtrip() {
        assert_eq!(ExecUtmpMode::parse("login"), Ok(ExecUtmpMode::Login));
    }

    #[test]
    fn preserve_mode_accepts_boolean_aliases() {
        assert_eq!(
            exec_preserve_mode_from_string_with_boolean("yes"),
            Ok(ExecPreserveMode::Yes)
        );
        assert_eq!(
            exec_preserve_mode_from_string_with_boolean("0"),
            Ok(ExecPreserveMode::No)
        );
        assert_eq!(
            exec_preserve_mode_from_string_with_boolean("restart"),
            Ok(ExecPreserveMode::Restart)
        );
        assert_eq!(
            exec_preserve_mode_from_string_with_boolean("on-success"),
            Ok(ExecPreserveMode::OnSuccess)
        );
    }

    #[test]
    fn directory_type_symlink_table_matches_c() {
        assert_eq!(
            exec_directory_type_symlink_to_string(ExecDirectoryType::Logs),
            "LogsDirectorySymlink"
        );
        assert_eq!(
            exec_directory_type_symlink_from_string("ConfigurationDirectorySymlink"),
            Ok(ExecDirectoryType::Configuration)
        );
    }

    #[test]
    fn directory_type_mode_table_matches_c() {
        assert_eq!(
            exec_directory_type_mode_to_string(ExecDirectoryType::Runtime),
            "RuntimeDirectoryMode"
        );
        assert_eq!(
            exec_directory_type_mode_from_string("StateDirectoryMode"),
            Ok(ExecDirectoryType::State)
        );
    }

    #[test]
    fn resource_type_strings_match_enum_strings() {
        assert_eq!(ExecDirectoryType::Cache.as_str(), "cache");
        assert_eq!(
            ExecDirectoryType::parse("configuration"),
            Ok(ExecDirectoryType::Configuration)
        );
    }

    #[test]
    fn keyring_and_thp_roundtrip() {
        assert_eq!(
            ExecKeyringMode::parse("shared"),
            Ok(ExecKeyringMode::Shared)
        );
        assert_eq!(MemoryThp::parse("madvise"), Ok(MemoryThp::Madvise));
    }

    #[test]
    fn invalid_values_return_einval() {
        assert_eq!(ExecInput::parse("bogus"), Err(Errno::EINVAL));
        assert_eq!(
            exec_directory_type_mode_from_string("BogusDirectoryMode"),
            Err(Errno::EINVAL)
        );
    }
}
