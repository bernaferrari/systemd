// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/import/pull-common.c
//
// Shared pull context and validation helpers.

use crate::import_common::{
    ImageClass, ImportFlags, PortError, PortMetadata, count_port_source_lines, read_port_source,
    verify_extracted_functions,
};
use std::io;

pub const SOURCE_PATH: &str = "src/import/pull-common.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "hash_url",
    "is_checksum_file",
    "pull_find_old_etags",
    "pull_job_restart_with_sha256sum",
    "pull_job_restart_with_signature",
    "pull_make_auxiliary_job",
    "pull_make_path",
    "pull_make_verification_jobs",
    "pull_url_needs_checksum",
    "pull_validate_local",
    "pull_verify",
    "signature_style_from_filename",
    "signature_style_from_url",
    "verification_style_from_url",
    "verify_gpg",
    "verify_one",
];

#[derive(Debug, Clone)]
pub struct PullContext {
    pub image_root: String,
    pub image_class: ImageClass,
    pub local: String,
    pub flags: ImportFlags,
    pub progress_percent: f32,
    pub completed: bool,
}

impl PullContext {
    pub fn new(image_root: String, image_class: ImageClass, local: String) -> Self {
        Self {
            image_root,
            image_class,
            local,
            flags: ImportFlags::empty(),
            progress_percent: 0.0,
            completed: false,
        }
    }

    pub fn set_progress(&mut self, percent: f32) {
        self.progress_percent = percent.clamp(0.0, 100.0);
    }

    pub fn image_path(&self) -> String {
        format!("{}/{}", self.image_root, self.local)
    }
}

#[derive(Debug)]
pub enum PullCommonError {
    InvalidPath(String),
    Io(io::Error),
}

impl From<io::Error> for PullCommonError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for PullCommonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath(msg) => write!(f, "{msg}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PullCommonError {}

pub fn make_local(url: &str, default: &str) -> String {
    url.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(default)
        .to_string()
}

pub fn make_tmpdir(root: &str) -> Result<String, PullCommonError> {
    if root.is_empty() {
        return Err(PullCommonError::InvalidPath("empty root".into()));
    }
    Ok(format!("{root}/.systemd-import"))
}

pub fn metadata() -> Result<PortMetadata, PortError> {
    Ok(PortMetadata {
        module_name: module_path!(),
        source_path: SOURCE_PATH,
        source_lines: count_port_source_lines(SOURCE_PATH)?,
        extracted_functions: EXTRACTED_FUNCTIONS,
    })
}

pub fn read_source() -> Result<String, PortError> {
    read_port_source(SOURCE_PATH)
}

pub fn source_lines() -> Result<usize, PortError> {
    count_port_source_lines(SOURCE_PATH)
}

pub fn verify_port_sync() -> Result<(), PortError> {
    verify_extracted_functions(SOURCE_PATH, EXTRACTED_FUNCTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pull_context_progress_is_clamped() {
        let mut ctx = PullContext::new(
            "/var/lib/machines".into(),
            ImageClass::Machine,
            "demo".into(),
        );
        ctx.set_progress(120.0);
        assert_eq!(ctx.progress_percent, 100.0);
    }

    #[test]
    fn pull_context_image_path_is_joined() {
        let ctx = PullContext::new("/var/lib".into(), ImageClass::Machine, "demo".into());
        assert_eq!(ctx.image_path(), "/var/lib/demo");
    }

    #[test]
    fn make_local_uses_last_path_segment() {
        assert_eq!(
            make_local("https://example.com/images/demo.raw", "fallback"),
            "demo.raw"
        );
    }

    #[test]
    fn pull_common_stays_in_sync() {
        verify_port_sync().unwrap();
    }
}
