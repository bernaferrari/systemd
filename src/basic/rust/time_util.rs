// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/time-util.c
//
// Public facade for the independently owned time utility domains.
//
// Scope note: this remains a shadow-tested subset rather than a full Rust
// replacement for time-util.c. The C-only clock acquisition, timestamp
// construction, calendar/timezone, sleep, and parse_nsec APIs are intentionally
// not exposed here; src/basic/rust/time_util.h defines the FFI shadow surface.

mod arithmetic;
mod conversion;
mod formatting;
mod parsing;
mod types;

pub use arithmetic::{
    rs_dual_timestamp_is_set, rs_timestamp_is_set, rs_triple_timestamp_is_set, rs_usec_add,
    rs_usec_sub_signed, rs_usec_sub_unsigned,
};
pub use conversion::{
    rs_map_clock_usec_raw, rs_timespec_load, rs_timespec_load_nsec, rs_timespec_store,
    rs_timespec_store_nsec, rs_timeval_load, rs_timeval_store, rs_triple_timestamp_by_clock,
};
pub use formatting::{
    rs_format_timespan, rs_parse_gmtoff, rs_timestamp_style_from_string,
    rs_timestamp_style_to_string,
};
pub use parsing::{
    parse_sec, rs_parse_sec, rs_parse_sec_def_infinity, rs_parse_sec_fix_0, rs_parse_time,
};
pub use types::{DualTimestamp, LibcTimespec, LibcTimeval, TripleTimestamp, USEC_PER_SEC};

#[cfg(test)]
#[path = "time_util/tests.rs"]
mod tests;
