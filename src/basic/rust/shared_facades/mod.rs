// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-GAP: compatibility-module index only; child modules declare their
// exact C/H authorities and this file adds no standalone semantic authority.
//
// Rust compatibility modules whose public APIs intentionally span several C
// source domains. Each child records its exact C/H authorities in
// tools/rust-port/map.toml; production C remains authoritative.

pub mod lookups;
pub mod validation;
