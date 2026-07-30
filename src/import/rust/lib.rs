// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
// Rust port of systemd/src/import/

pub mod curl_util;
pub mod export;
pub mod export_raw;
pub mod export_tar;
pub mod import;
pub mod import_common;
pub mod import_compress;
pub mod import_fs;
pub mod import_generator;
pub mod import_raw;
pub mod import_tar;
pub mod importctl;
pub mod importd;
pub mod oci_util;
pub mod pull;
pub mod pull_common;
pub mod pull_job;
pub mod pull_oci;
pub mod pull_raw;
pub mod pull_tar;
pub mod qcow2_util;

// C test mirrors belong to the Rust test build; exposing them in the
// production API both leaks test-only metadata and lets their helpers drift.
#[cfg(test)]
mod test_oci_util;
#[cfg(test)]
mod test_qcow2;
#[cfg(test)]
mod test_tar;
