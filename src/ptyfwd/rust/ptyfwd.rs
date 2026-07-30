// SPDX-License-Identifier: LGPL-2.1-or-later
//
// systemd-ptyfwd-rs: conservative Rust shadow module for ptyfwd-tool.c
//
// Shadow port of src/ptyfwd/ptyfwd-tool.c.
// Forwards data between a PTY and an event loop.

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

#[derive(Default)]
pub struct PtyForwardConfig {
    pub pty_path: Option<String>,
    pub listen: bool,
    pub pipe: bool,
    pub keep_seat: bool,
}

impl PtyForwardConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.listen && self.pipe {
            return Err(Errno(-libc::EINVAL));
        }
        Ok(())
    }

    pub fn input_mode(&self) -> PtyInputMode {
        if self.listen {
            PtyInputMode::Listen
        } else if self.pipe {
            PtyInputMode::Pipe
        } else {
            PtyInputMode::Direct
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyInputMode {
    Direct = 0,
    Listen,
    Pipe,
}

pub fn is_valid_pty_path(path: &str) -> bool {
    path.starts_with("/dev/pts/") || path.starts_with("/dev/pty")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = PtyForwardConfig::new();
        assert!(cfg.pty_path.is_none());
        assert!(!cfg.listen);
        assert!(!cfg.pipe);
    }

    #[test]
    fn validate_ok() {
        let cfg = PtyForwardConfig::new();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_listen_and_pipe_conflict() {
        let cfg = PtyForwardConfig {
            listen: true,
            pipe: true,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn input_mode_detection() {
        let cfg = PtyForwardConfig {
            listen: true,
            ..Default::default()
        };
        assert_eq!(cfg.input_mode(), PtyInputMode::Listen);
        let cfg2 = PtyForwardConfig {
            pipe: true,
            ..Default::default()
        };
        assert_eq!(cfg2.input_mode(), PtyInputMode::Pipe);
        let cfg3 = PtyForwardConfig::new();
        assert_eq!(cfg3.input_mode(), PtyInputMode::Direct);
    }

    #[test]
    fn valid_pty_paths() {
        assert!(is_valid_pty_path("/dev/pts/0"));
        assert!(is_valid_pty_path("/dev/pty/m0"));
        assert!(!is_valid_pty_path("/tmp/pty"));
    }
}
