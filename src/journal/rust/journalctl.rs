// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journalctl.c
//
// Main journalctl binary with argument parsing and action dispatch.

crate::journal_port_module!(
    "Main journalctl binary with argument parsing and action dispatch.",
    "src/journal/journalctl.c",
    [
        "parse_id_descriptor",
        "parse_lines",
        "help_facilities",
        "help",
        "vl_server",
        "parse_argv",
        "run",
    ]
);

mod argument_values;
mod arguments;
mod dispatch;
mod filter;
mod model;

pub use argument_values::{parse_id_descriptor, parse_lines};
pub use arguments::parse_argv;
pub use dispatch::{plan_dispatch, run, DispatchPlan, DispatchTarget, RunOutcome};
pub use filter::{
    build_filter_plan, FilterApplyError, FilterBackend, FilterBackendOp, FilterMatchTerm,
    FilterPlan, RecordingFilterBackend, ScopePlan, TransportFilter, UnitMatchPlan,
};
pub use model::{
    IdDescriptor, JournalctlAction, JournalctlArgs, ParseArgvError, ParseArgvResult,
    ParseIdDescriptorError, ParsedLines, PatternCase, SecretString,
};

#[cfg(test)]
mod parsing_tests;
