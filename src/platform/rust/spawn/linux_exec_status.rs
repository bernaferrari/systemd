// SPDX-License-Identifier: LGPL-2.1-or-later

//! Framing and diagnostics for the post-fork exec-status pipe.

use std::convert::TryInto;

use super::{ChildSpawnFailure, ChildSpawnStage, EXEC_STATUS_EXEC_ATTEMPT, EXEC_STATUS_FAILURE};

fn child_failure_message(failure: ChildSpawnFailure) -> String {
    let errno = if failure.errno == 0 {
        libc::EINVAL
    } else {
        failure.errno
    };
    format!(
        "child failed while {} (errno {errno}: {})",
        ChildSpawnStage::description(failure.stage),
        std::io::Error::from_raw_os_error(errno)
    )
}

fn decode_child_failure(
    bytes: &[u8; std::mem::size_of::<ChildSpawnFailure>()],
) -> ChildSpawnFailure {
    ChildSpawnFailure {
        stage: u32::from_ne_bytes(bytes[0..4].try_into().expect("fixed-size slice")),
        errno: i32::from_ne_bytes(bytes[4..8].try_into().expect("fixed-size slice")),
    }
}

pub(super) fn consume_exec_status_bytes(
    exec_attempted: &mut bool,
    failure_started: &mut bool,
    failure_bytes: &mut [u8; std::mem::size_of::<ChildSpawnFailure>()],
    failure_received: &mut usize,
    input: &[u8],
) -> Result<(), String> {
    for byte in input {
        if *failure_started {
            if *failure_received == failure_bytes.len() {
                return Err(
                    "child exec-status pipe contained data after a failure record".to_string(),
                );
            }
            failure_bytes[*failure_received] = *byte;
            *failure_received += 1;
            if *failure_received == failure_bytes.len() {
                return Err(child_failure_message(decode_child_failure(failure_bytes)));
            }
            continue;
        }

        match *byte {
            EXEC_STATUS_EXEC_ATTEMPT if !*exec_attempted => *exec_attempted = true,
            EXEC_STATUS_EXEC_ATTEMPT => {
                return Err(
                    "child exec-status pipe contained duplicate exec-attempt marker".to_string(),
                );
            }
            EXEC_STATUS_FAILURE => {
                *failure_started = true;
                *failure_received = 0;
            }
            _ => {
                return Err("child exec-status pipe contained an invalid record marker".to_string());
            }
        }
    }
    Ok(())
}
