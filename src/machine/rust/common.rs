// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Shared support code for generated Rust ports.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub const REPO_ROOT: &str = "/Users/bernardoferrari/Downloads/systemd/systemd";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl Errno {
    pub const fn new(code: i32) -> Self {
        Self(code)
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl Error for Errno {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMetadata {
    pub module_name: &'static str,
    pub source_path: &'static str,
    pub source_lines: usize,
    pub extracted_functions: &'static [&'static str],
}

pub fn port_source_path(source_path: &str) -> PathBuf {
    Path::new(REPO_ROOT).join(source_path)
}

pub fn read_port_source(source_path: &str) -> Result<String, Errno> {
    fs::read_to_string(port_source_path(source_path)).map_err(|_| Errno::new(-2))
}

pub fn count_port_source_lines(source_path: &str) -> Result<usize, Errno> {
    Ok(read_port_source(source_path)?.lines().count())
}

pub fn verify_extracted_functions(source_path: &str, extracted_functions: &[&'static str]) -> Result<(), Errno> {
    let source = read_port_source(source_path)?;
    for function in extracted_functions {
        if !source.contains(function) {
            return Err(Errno::new(-22));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_root_exists() {
        assert!(Path::new(REPO_ROOT).exists());
    }

    #[test]
    fn source_path_joins() {
        assert!(port_source_path("src/shared/compare-operator.c").ends_with("src/shared/compare-operator.c"));
    }
}
