// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-GAP: facade index only; each child declares its exact C/H authorities
//
// Cross-subsystem shadow facades that do not yet belong to one complete
// authority module. Keep exact C/H ownership in tools/rust-port/map.toml;
// split a facade into its canonical module when that authority is completed.

pub mod header_predicates;
pub mod lookups;
pub mod policy;
pub mod validation;
