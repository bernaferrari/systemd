// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Exact raw-integer C ABI for unit-file.h's inline UnitType predicates.
//
// UnitType is an int ABI enum in C. Do not construct a Rust enum from this
// input: callers can pass invalid values and current C simply returns false.

use crate::unit_name::{unit_type_may_alias_raw, unit_type_may_template_raw};

/// C ABI for `unit_type_may_alias()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_unit_type_may_alias(type_: i32) -> bool {
    unit_type_may_alias_raw(type_)
}

/// C ABI for `unit_type_may_template()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_unit_type_may_template(type_: i32) -> bool {
    unit_type_may_template_raw(type_)
}
