// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Shared helpers for journal Rust PORT-SYNC modules.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, PortSyncError>;

#[derive(Debug)]
pub enum PortSyncError {
    Io(io::Error),
    EmptySource(&'static str),
    MissingToken {
        source_path: &'static str,
        token: &'static str,
    },
}

impl fmt::Display for PortSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::EmptySource(source_path) => write!(f, "{source_path} is empty"),
            Self::MissingToken { source_path, token } => {
                write!(f, "{source_path} does not contain expected token {token:?}")
            }
        }
    }
}

impl std::error::Error for PortSyncError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::EmptySource(_) | Self::MissingToken { .. } => None,
        }
    }
}

impl From<io::Error> for PortSyncError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSyncModule {
    pub summary: &'static str,
    pub source_path: &'static str,
    pub entry_points: &'static [&'static str],
    pub key_tokens: &'static [&'static str],
}

impl PortSyncModule {
    pub fn source_abspath(&self) -> PathBuf {
        let basename = self
            .source_path
            .rsplit('/')
            .next()
            .unwrap_or(self.source_path);

        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(basename)
    }

    pub fn read_c_source(&self) -> Result<String> {
        let source = fs::read_to_string(self.source_abspath())?;
        if source.trim().is_empty() {
            return Err(PortSyncError::EmptySource(self.source_path));
        }
        Ok(source)
    }

    pub fn line_count(&self) -> Result<usize> {
        Ok(self.read_c_source()?.lines().count())
    }

    pub fn validate(&self) -> Result<()> {
        let source = self.read_c_source()?;

        for token in self.entry_points.iter().chain(self.key_tokens.iter()) {
            if !source.contains(token) {
                return Err(PortSyncError::MissingToken {
                    source_path: self.source_path,
                    token,
                });
            }
        }

        Ok(())
    }
}

#[macro_export]
macro_rules! journal_port_module {
    ($summary:expr, $source_path:expr, [$($entry:expr),+ $(,)?]) => {
        pub const MODULE: $crate::port_sync::PortSyncModule = $crate::port_sync::PortSyncModule {
            summary: $summary,
            source_path: $source_path,
            entry_points: &[$($entry),+],
            key_tokens: &[$($entry),+],
        };

        pub fn source_path() -> &'static str {
            MODULE.source_path
        }

        pub fn read_c_source() -> $crate::port_sync::Result<String> {
            MODULE.read_c_source()
        }

        pub fn line_count() -> $crate::port_sync::Result<usize> {
            MODULE.line_count()
        }

        pub fn entry_points() -> &'static [&'static str] {
            MODULE.entry_points
        }

        pub fn key_tokens() -> &'static [&'static str] {
            MODULE.key_tokens
        }

        pub fn validate_port_sync() -> $crate::port_sync::Result<()> {
            MODULE.validate()
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn source_path_is_journal_c_file() {
                assert!(source_path().starts_with("src/journal/"));
                assert!(source_path().ends_with(".c"));
            }

            #[test]
            fn summary_is_present() {
                assert!(!MODULE.summary.trim().is_empty());
            }

            #[test]
            fn entry_points_are_present() {
                assert!(!entry_points().is_empty());
            }

            #[test]
            fn key_tokens_are_present() {
                assert!(!key_tokens().is_empty());
            }

            #[test]
            fn c_source_is_readable() -> $crate::port_sync::Result<()> {
                assert!(!read_c_source()?.is_empty());
                Ok(())
            }

            #[test]
            fn c_source_keeps_spdx_header() -> $crate::port_sync::Result<()> {
                assert!(read_c_source()?.contains("SPDX-License-Identifier"));
                Ok(())
            }

            #[test]
            fn c_source_has_lines() -> $crate::port_sync::Result<()> {
                assert!(line_count()? > 0);
                Ok(())
            }

            #[test]
            fn port_sync_metadata_matches_source() -> $crate::port_sync::Result<()> {
                validate_port_sync()
            }
        }
    };
}
