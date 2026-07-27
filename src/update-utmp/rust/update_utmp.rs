// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/update-utmp/update-utmp.c

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidVerb(String),
    MissingClockSnapshot,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVerb(v) => write!(f, "invalid verb: {v}"),
            Self::MissingClockSnapshot => f.write_str("missing clock snapshot for conversion"),
        }
    }
}

impl std::error::Error for Error {}

pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const DEFAULT_UMASK: u32 = 0o022;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtmpVerb {
    Reboot,
    Shutdown,
}

impl UtmpVerb {
    pub fn parse(input: &str) -> Result<Self> {
        match input {
            "reboot" => Ok(Self::Reboot),
            "shutdown" => Ok(Self::Shutdown),
            _ => Err(Error::InvalidVerb(input.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockSnapshot {
    pub realtime_usec: u64,
    pub monotonic_usec: u64,
}

pub fn map_clock_usec(
    value: u64,
    from_clock: i32,
    to_clock: i32,
    snapshot: ClockSnapshot,
) -> Result<u64> {
    if from_clock == to_clock {
        return Ok(value);
    }
    match (from_clock, to_clock) {
        (CLOCK_MONOTONIC, CLOCK_REALTIME) => Ok(snapshot
            .realtime_usec
            .saturating_sub(snapshot.monotonic_usec)
            .saturating_add(value)),
        (CLOCK_REALTIME, CLOCK_MONOTONIC) => Ok(value.saturating_sub(
            snapshot
                .realtime_usec
                .saturating_sub(snapshot.monotonic_usec),
        )),
        _ => Err(Error::MissingClockSnapshot),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditKind {
    Boot,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtmpRecord {
    Reboot { boottime_usec: u64 },
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    pub audit: Option<AuditKind>,
    pub record: UtmpRecord,
}

pub fn build_plan(
    verb: UtmpVerb,
    audit_available: bool,
    startup_monotonic_usec: Option<u64>,
    snapshot: ClockSnapshot,
) -> Result<ExecutionPlan> {
    Ok(match verb {
        UtmpVerb::Reboot => ExecutionPlan {
            audit: audit_available.then_some(AuditKind::Boot),
            record: UtmpRecord::Reboot {
                boottime_usec: map_clock_usec(
                    startup_monotonic_usec.unwrap_or(0),
                    CLOCK_MONOTONIC,
                    CLOCK_REALTIME,
                    snapshot,
                )?,
            },
        },
        UtmpVerb::Shutdown => ExecutionPlan {
            audit: audit_available.then_some(AuditKind::Shutdown),
            record: UtmpRecord::Shutdown,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> ClockSnapshot {
        ClockSnapshot {
            realtime_usec: 1_500,
            monotonic_usec: 500,
        }
    }

    #[test]
    fn parses_reboot() {
        assert_eq!(UtmpVerb::parse("reboot").unwrap(), UtmpVerb::Reboot);
    }
    #[test]
    fn parses_shutdown() {
        assert_eq!(UtmpVerb::parse("shutdown").unwrap(), UtmpVerb::Shutdown);
    }
    #[test]
    fn rejects_unknown_verb() {
        assert!(matches!(UtmpVerb::parse("x"), Err(Error::InvalidVerb(_))));
    }
    #[test]
    fn keeps_value_for_same_clock() {
        assert_eq!(
            map_clock_usec(7, CLOCK_REALTIME, CLOCK_REALTIME, snapshot()).unwrap(),
            7
        );
    }
    #[test]
    fn converts_monotonic_to_realtime() {
        assert_eq!(
            map_clock_usec(900, CLOCK_MONOTONIC, CLOCK_REALTIME, snapshot()).unwrap(),
            1_900
        );
    }
    #[test]
    fn converts_realtime_to_monotonic() {
        assert_eq!(
            map_clock_usec(1_900, CLOCK_REALTIME, CLOCK_MONOTONIC, snapshot()).unwrap(),
            900
        );
    }
    #[test]
    fn reboot_plan_uses_boot_audit() {
        let plan = build_plan(UtmpVerb::Reboot, true, Some(900), snapshot()).unwrap();
        assert_eq!(plan.audit, Some(AuditKind::Boot));
        assert_eq!(
            plan.record,
            UtmpRecord::Reboot {
                boottime_usec: 1_900
            }
        );
    }
    #[test]
    fn shutdown_plan_has_shutdown_record() {
        let plan = build_plan(UtmpVerb::Shutdown, false, None, snapshot()).unwrap();
        assert_eq!(plan.audit, None);
        assert_eq!(plan.record, UtmpRecord::Shutdown);
    }
}
