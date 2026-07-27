// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit.c
//
//! Stable facade for the Rust model of systemd's core Unit machinery.
//!
//! Implementation ownership is split below `unit/`; callers continue to use
//! `crate::unit::…` paths through these re-exports.

mod activation;
mod dependency;
mod integration;
mod inventory;
mod lifecycle;
mod model;
mod orchestration;
mod relationships;
mod runtime;

pub use activation::*;
pub use dependency::*;
pub use integration::*;
pub use inventory::*;
pub use lifecycle::*;
pub use model::*;
pub use orchestration::*;
pub use relationships::*;
pub use runtime::*;

#[cfg(test)]
mod tests;
