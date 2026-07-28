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

#[path = "journalctl/argument_values.rs"]
mod argument_values;
#[path = "journalctl/arguments.rs"]
mod arguments;
#[path = "journalctl/dispatch.rs"]
mod dispatch;
#[path = "journalctl/filter.rs"]
mod filter;
#[path = "journalctl/model.rs"]
mod model;

pub use argument_values::{parse_id_descriptor, parse_lines};
pub use arguments::parse_argv;
pub use dispatch::{DispatchPlan, DispatchTarget, RunOutcome, plan_dispatch, run};
pub use filter::{
    FilterApplyError, FilterBackend, FilterBackendOp, FilterMatchTerm, FilterPlan,
    RecordingFilterBackend, ScopePlan, TransportFilter, UnitMatchPlan, build_filter_plan,
};
pub use model::{
    IdDescriptor, JournalctlAction, JournalctlArgs, ParseArgvError, ParseArgvResult,
    ParseIdDescriptorError, ParsedLines, PatternCase, SecretString,
};

#[cfg(test)]
#[path = "journalctl/parsing_tests.rs"]
mod parsing_tests;
