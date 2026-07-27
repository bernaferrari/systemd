// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Shared support code for generated Rust ports.

use std::error::Error;
use std::fmt;

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
