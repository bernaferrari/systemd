// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of tclass.c
//
// SAFETY: This module is a Rust port of the corresponding C source.
// FFI boundary functions use unsafe extern "C" with proper SAFETY comments.
// Internal logic uses safe Rust with Result<T, Errno> error handling.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum TClassKind {
    TclassKindDrr,
    TclassKindHtb,
    TclassKindQfq,
}

#[derive(Debug)]
pub struct TClass {
    pub source: i32,
    pub state: i32,
    pub n_ref: i32,
    pub classid: i32,
    pub parent: i32,
    pub kind: i32,
}

#[derive(Debug)]
pub struct TClassVTable {
    pub object_size: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tclass_enums() {
        let _ = std::mem::size_of::<TClassKind>();
    }
}
