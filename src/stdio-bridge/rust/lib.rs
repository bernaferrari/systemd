// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/stdio-bridge/stdio-bridge.c

pub mod stdio_bridge;

pub use stdio_bridge::{
    BridgeConfig, BridgeError, BridgeFds, ParseAction, ParseFailure, ParsedArgs, parse_args,
    parse_args_detailed, print_version, run_bridge,
};
