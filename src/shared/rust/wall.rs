// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/wall.c
//
use crate::ffi::*;
use std::error::Error;
use std::fmt;
use std::time::Duration;

pub const TIMEOUT_USEC: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WallError {
    Unsupported,
    MissingHostname,
    MissingUsername,
    MissingTimestamp,
    Backend(&'static str),
    Write { tty: String, cause: &'static str },
}

impl fmt::Display for WallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "backend unsupported"),
            Self::MissingHostname => write!(f, "missing hostname"),
            Self::MissingUsername => write!(f, "missing username"),
            Self::MissingTimestamp => write!(f, "missing timestamp"),
            Self::Backend(cause) => write!(f, "backend error: {cause}"),
            Self::Write { tty, cause } => write!(f, "failed to write to {tty}: {cause}"),
        }
    }
}

impl Error for WallError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub tty_path: String,
    pub is_local: bool,
}

impl SessionRecord {
    pub fn new(tty_path: impl Into<String>, is_local: bool) -> Self {
        Self {
            tty_path: tty_path.into(),
            is_local,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendEntry {
    Session(SessionRecord),
    Skip,
    Error(WallError),
}

pub trait WallEnvironment {
    fn hostname(&self) -> Result<String, WallError>;
    fn logname(&self) -> Result<String, WallError>;
    fn stdin_tty(&self) -> Result<Option<String>, WallError>;
    fn timestamp(&self) -> Result<String, WallError>;
}

pub trait WallBackend {
    fn entries(&self) -> Result<Vec<BackendEntry>, WallError>;
}

pub trait WallTerminalWriter {
    fn write_to_terminal(
        &mut self,
        tty: &str,
        message: &str,
        timeout: Duration,
    ) -> Result<(), WallError>;
}

pub fn format_wall_message(
    message: &str,
    username: &str,
    hostname: &str,
    origin_tty: Option<&str>,
    timestamp: &str,
) -> String {
    format!(
        "\r\nBroadcast message from {username}@{hostname}{}{} ({timestamp}):\r\n\r\n{message}\r\n\r\n",
        origin_tty.map(|_| " on ").unwrap_or(""),
        origin_tty.unwrap_or("")
    )
}

pub fn wall<E, U, L, W>(
    message: &str,
    username: Option<&str>,
    origin_tty: Option<&str>,
    environment: &E,
    utmp_backend: &U,
    logind_backend: &L,
    writer: &mut W,
    mut match_tty: Option<&mut dyn FnMut(&str, bool) -> bool>,
) -> Result<(), WallError>
where
    E: WallEnvironment,
    U: WallBackend,
    L: WallBackend,
    W: WallTerminalWriter,
{
    let hostname = environment.hostname()?;

    let resolved_username = match username {
        Some(name) => name.to_owned(),
        None => environment.logname()?,
    };

    let resolved_origin_tty = match origin_tty {
        Some(tty) => Some(tty.to_owned()),
        None => environment.stdin_tty()?,
    };

    let timestamp = environment.timestamp()?;
    let text = format_wall_message(
        message,
        &resolved_username,
        &hostname,
        resolved_origin_tty.as_deref(),
        &timestamp,
    );

    let mut match_tty = match_tty;
    let unsupported = match broadcast_to_backend(utmp_backend, writer, &text, match_tty.take()) {
        Err(WallError::Unsupported) => true,
        other => return other,
    };

    if unsupported {
        broadcast_to_backend(logind_backend, writer, &text, match_tty.take()).or_else(|e| {
            if e == WallError::Unsupported {
                Ok(())
            } else {
                Err(e)
            }
        })
    } else {
        Ok(())
    }
}

fn broadcast_to_backend<B, W>(
    backend: &B,
    writer: &mut W,
    message: &str,
    mut match_tty: Option<&mut dyn FnMut(&str, bool) -> bool>,
) -> Result<(), WallError>
where
    B: WallBackend,
    W: WallTerminalWriter,
{
    let mut aggregate_error: Option<WallError> = None;

    for entry in backend.entries()? {
        match entry {
            BackendEntry::Skip => continue,
            BackendEntry::Session(record) => {
                let allowed = match match_tty.as_mut() {
                    Some(filter) => filter(&record.tty_path, record.is_local),
                    None => true,
                };

                if !allowed {
                    continue;
                }

                if let Err(error) =
                    writer.write_to_terminal(&record.tty_path, message, TIMEOUT_USEC)
                {
                    if aggregate_error.is_none() {
                        aggregate_error = Some(error);
                    }
                }
            }
            BackendEntry::Error(error) => return Err(aggregate_error.unwrap_or(error)),
        }
    }

    match aggregate_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Debug, Clone)]
    struct FakeEnvironment {
        hostname: Result<String, WallError>,
        logname: Result<String, WallError>,
        stdin_tty: Result<Option<String>, WallError>,
        timestamp: Result<String, WallError>,
    }

    impl Default for FakeEnvironment {
        fn default() -> Self {
            Self {
                hostname: Ok("host".into()),
                logname: Ok("root".into()),
                stdin_tty: Ok(Some("pts/0".into())),
                timestamp: Ok("Thu 2026-04-09 12:34:56 UTC".into()),
            }
        }
    }

    impl WallEnvironment for FakeEnvironment {
        fn hostname(&self) -> Result<String, WallError> {
            self.hostname.clone()
        }

        fn logname(&self) -> Result<String, WallError> {
            self.logname.clone()
        }

        fn stdin_tty(&self) -> Result<Option<String>, WallError> {
            self.stdin_tty.clone()
        }

        fn timestamp(&self) -> Result<String, WallError> {
            self.timestamp.clone()
        }
    }

    #[derive(Debug, Clone)]
    struct FakeBackend {
        result: Result<Vec<BackendEntry>, WallError>,
    }

    impl FakeBackend {
        fn unsupported() -> Self {
            Self {
                result: Err(WallError::Unsupported),
            }
        }

        fn with_entries(entries: Vec<BackendEntry>) -> Self {
            Self {
                result: Ok(entries),
            }
        }
    }

    impl WallBackend for FakeBackend {
        fn entries(&self) -> Result<Vec<BackendEntry>, WallError> {
            self.result.clone()
        }
    }

    #[derive(Debug, Default)]
    struct RecordingWriter {
        writes: Vec<(String, String, Duration)>,
        failures: RefCell<Vec<(String, WallError)>>,
    }

    impl RecordingWriter {
        fn fail_for(mut self, tty: &str, error: WallError) -> Self {
            self.failures.borrow_mut().push((tty.into(), error));
            self
        }
    }

    impl WallTerminalWriter for RecordingWriter {
        fn write_to_terminal(
            &mut self,
            tty: &str,
            message: &str,
            timeout: Duration,
        ) -> Result<(), WallError> {
            self.writes.push((tty.into(), message.into(), timeout));

            let index = self
                .failures
                .borrow()
                .iter()
                .position(|(failed_tty, _)| failed_tty == tty);

            if let Some(index) = index {
                return Err(self.failures.borrow_mut().remove(index).1);
            }

            Ok(())
        }
    }

    fn session(tty: &str, is_local: bool) -> BackendEntry {
        BackendEntry::Session(SessionRecord::new(tty, is_local))
    }

    #[test]
    fn formats_message_with_origin_tty() {
        let text = format_wall_message("hello", "root", "host", Some("pts/1"), "now");
        assert_eq!(
            text,
            "\r\nBroadcast message from root@host on pts/1 (now):\r\n\r\nhello\r\n\r\n"
        );
    }

    #[test]
    fn formats_message_without_origin_tty() {
        let text = format_wall_message("hello", "root", "host", None, "now");
        assert_eq!(
            text,
            "\r\nBroadcast message from root@host (now):\r\n\r\nhello\r\n\r\n"
        );
    }

    #[test]
    fn writes_using_utmp_backend_when_available() {
        let env = FakeEnvironment::default();
        let utmp = FakeBackend::with_entries(vec![session("/dev/pts/1", true)]);
        let logind = FakeBackend::with_entries(vec![session("/dev/pts/2", false)]);
        let mut writer = RecordingWriter::default();

        wall(
            "hello",
            Some("alice"),
            Some("pts/9"),
            &env,
            &utmp,
            &logind,
            &mut writer,
            None,
        )
        .unwrap();

        assert_eq!(writer.writes.len(), 1);
        assert_eq!(writer.writes[0].0, "/dev/pts/1");
    }

    #[test]
    fn falls_back_to_logind_when_utmp_is_unsupported() {
        let env = FakeEnvironment::default();
        let utmp = FakeBackend::unsupported();
        let logind = FakeBackend::with_entries(vec![session("/dev/pts/7", false)]);
        let mut writer = RecordingWriter::default();

        wall(
            "hello",
            Some("alice"),
            None,
            &env,
            &utmp,
            &logind,
            &mut writer,
            None,
        )
        .unwrap();

        assert_eq!(writer.writes.len(), 1);
        assert_eq!(writer.writes[0].0, "/dev/pts/7");
    }

    #[test]
    fn returns_success_when_both_backends_are_unsupported() {
        let env = FakeEnvironment::default();
        let utmp = FakeBackend::unsupported();
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default();

        wall(
            "hello",
            Some("alice"),
            None,
            &env,
            &utmp,
            &logind,
            &mut writer,
            None,
        )
        .unwrap();

        assert!(writer.writes.is_empty());
    }

    #[test]
    fn resolves_username_from_environment() {
        let env = FakeEnvironment::default();
        let utmp = FakeBackend::with_entries(vec![session("/dev/pts/1", true)]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default();

        wall("hello", None, None, &env, &utmp, &logind, &mut writer, None).unwrap();

        assert!(writer.writes[0].1.contains("root@host on pts/0"));
    }

    #[test]
    fn uses_explicit_origin_tty_without_environment_lookup() {
        let env = FakeEnvironment {
            stdin_tty: Err(WallError::Backend("stdin should not be used")),
            ..FakeEnvironment::default()
        };
        let utmp = FakeBackend::with_entries(vec![session("/dev/pts/1", true)]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default();

        wall(
            "hello",
            Some("alice"),
            Some("pts/42"),
            &env,
            &utmp,
            &logind,
            &mut writer,
            None,
        )
        .unwrap();

        assert!(writer.writes[0].1.contains("alice@host on pts/42"));
    }

    #[test]
    fn matcher_filters_terminals() {
        let env = FakeEnvironment::default();
        let utmp = FakeBackend::with_entries(vec![
            session("/dev/pts/1", true),
            session("/dev/pts/2", false),
        ]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default();
        let mut matcher = |tty: &str, is_local: bool| is_local && tty.ends_with('1');

        wall(
            "hello",
            Some("alice"),
            None,
            &env,
            &utmp,
            &logind,
            &mut writer,
            Some(&mut matcher),
        )
        .unwrap();

        assert_eq!(writer.writes.len(), 1);
        assert_eq!(writer.writes[0].0, "/dev/pts/1");
    }

    #[test]
    fn matcher_receives_locality_information() {
        let env = FakeEnvironment::default();
        let utmp = FakeBackend::with_entries(vec![
            session("/dev/pts/1", true),
            session("/dev/pts/2", false),
        ]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default();
        let seen = RefCell::new(Vec::new());
        let mut matcher = |tty: &str, is_local: bool| {
            seen.borrow_mut().push((tty.to_owned(), is_local));
            true
        };

        wall(
            "hello",
            Some("alice"),
            None,
            &env,
            &utmp,
            &logind,
            &mut writer,
            Some(&mut matcher),
        )
        .unwrap();

        assert_eq!(
            seen.into_inner(),
            vec![
                ("/dev/pts/1".to_owned(), true),
                ("/dev/pts/2".to_owned(), false)
            ]
        );
    }

    #[test]
    fn gathers_first_write_error_but_continues_writing() {
        let env = FakeEnvironment::default();
        let utmp = FakeBackend::with_entries(vec![
            session("/dev/pts/1", true),
            session("/dev/pts/2", true),
        ]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default().fail_for(
            "/dev/pts/1",
            WallError::Write {
                tty: "/dev/pts/1".into(),
                cause: "not a tty",
            },
        );

        let error = wall(
            "hello",
            Some("alice"),
            None,
            &env,
            &utmp,
            &logind,
            &mut writer,
            None,
        )
        .unwrap_err();

        assert_eq!(
            error,
            WallError::Write {
                tty: "/dev/pts/1".into(),
                cause: "not a tty",
            }
        );
        assert_eq!(writer.writes.len(), 2);
    }

    #[test]
    fn returns_aggregate_write_error_when_backend_errors_later() {
        let env = FakeEnvironment::default();
        let utmp = FakeBackend::with_entries(vec![
            session("/dev/pts/1", true),
            BackendEntry::Error(WallError::Backend("broken entry")),
        ]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default().fail_for(
            "/dev/pts/1",
            WallError::Write {
                tty: "/dev/pts/1".into(),
                cause: "permission denied",
            },
        );

        let error = wall(
            "hello",
            Some("alice"),
            None,
            &env,
            &utmp,
            &logind,
            &mut writer,
            None,
        )
        .unwrap_err();

        assert_eq!(
            error,
            WallError::Write {
                tty: "/dev/pts/1".into(),
                cause: "permission denied",
            }
        );
    }

    #[test]
    fn returns_backend_error_when_no_write_error_exists() {
        let env = FakeEnvironment::default();
        let utmp = FakeBackend::with_entries(vec![BackendEntry::Error(WallError::Backend("oops"))]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default();

        let error = wall(
            "hello",
            Some("alice"),
            None,
            &env,
            &utmp,
            &logind,
            &mut writer,
            None,
        )
        .unwrap_err();

        assert_eq!(error, WallError::Backend("oops"));
    }

    #[test]
    fn propagates_hostname_failure() {
        let env = FakeEnvironment {
            hostname: Err(WallError::MissingHostname),
            ..FakeEnvironment::default()
        };
        let utmp = FakeBackend::with_entries(vec![session("/dev/pts/1", true)]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default();

        let error = wall(
            "hello",
            Some("alice"),
            None,
            &env,
            &utmp,
            &logind,
            &mut writer,
            None,
        )
        .unwrap_err();

        assert_eq!(error, WallError::MissingHostname);
        assert!(writer.writes.is_empty());
    }

    #[test]
    fn propagates_username_lookup_failure() {
        let env = FakeEnvironment {
            logname: Err(WallError::MissingUsername),
            ..FakeEnvironment::default()
        };
        let utmp = FakeBackend::with_entries(vec![session("/dev/pts/1", true)]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default();

        let error = wall("hello", None, None, &env, &utmp, &logind, &mut writer, None).unwrap_err();

        assert_eq!(error, WallError::MissingUsername);
    }

    #[test]
    fn propagates_timestamp_failure() {
        let env = FakeEnvironment {
            timestamp: Err(WallError::MissingTimestamp),
            ..FakeEnvironment::default()
        };
        let utmp = FakeBackend::with_entries(vec![session("/dev/pts/1", true)]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default();

        let error = wall(
            "hello",
            Some("alice"),
            None,
            &env,
            &utmp,
            &logind,
            &mut writer,
            None,
        )
        .unwrap_err();

        assert_eq!(error, WallError::MissingTimestamp);
    }

    #[test]
    fn backend_skip_entries_are_ignored() {
        let env = FakeEnvironment::default();
        let utmp = FakeBackend::with_entries(vec![BackendEntry::Skip, session("/dev/pts/3", true)]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default();

        wall(
            "hello",
            Some("alice"),
            None,
            &env,
            &utmp,
            &logind,
            &mut writer,
            None,
        )
        .unwrap();

        assert_eq!(writer.writes.len(), 1);
        assert_eq!(writer.writes[0].0, "/dev/pts/3");
    }

    #[test]
    fn passes_c_timeout_to_writer() {
        let env = FakeEnvironment::default();
        let utmp = FakeBackend::with_entries(vec![session("/dev/pts/1", true)]);
        let logind = FakeBackend::unsupported();
        let mut writer = RecordingWriter::default();

        wall(
            "hello",
            Some("alice"),
            None,
            &env,
            &utmp,
            &logind,
            &mut writer,
            None,
        )
        .unwrap();

        assert_eq!(writer.writes[0].2, TIMEOUT_USEC);
    }
}
