// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-timer.c
//

use crate::ffi::Errno;

pub type Result<T> = std::result::Result<T, TimerError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerError {
    pub errno: Errno,
    pub message: String,
}

impl TimerError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            errno: Errno::EINVAL,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerBase {
    OnActiveSec,
    OnBootSec,
    OnStartupSec,
    OnUnitActiveSec,
    OnUnitInactiveSec,
    OnCalendar,
}

impl TimerBase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnActiveSec => "OnActiveSec",
            Self::OnBootSec => "OnBootSec",
            Self::OnStartupSec => "OnStartupSec",
            Self::OnUnitActiveSec => "OnUnitActiveSec",
            Self::OnUnitInactiveSec => "OnUnitInactiveSec",
            Self::OnCalendar => "OnCalendar",
        }
    }

    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "OnActiveSec" => Ok(Self::OnActiveSec),
            "OnBootSec" => Ok(Self::OnBootSec),
            "OnStartupSec" => Ok(Self::OnStartupSec),
            "OnUnitActiveSec" => Ok(Self::OnUnitActiveSec),
            "OnUnitInactiveSec" => Ok(Self::OnUnitInactiveSec),
            "OnCalendar" => Ok(Self::OnCalendar),
            other => Err(TimerError::invalid(format!("Unknown timer base: {other}"))),
        }
    }

    pub fn is_calendar(self) -> bool {
        matches!(self, Self::OnCalendar)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerValue {
    pub base: TimerBase,
    pub value: Option<u64>,
    pub calendar_spec: Option<String>,
    pub next_elapse: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonotonicTimerEntry {
    pub base: String,
    pub value: u64,
    pub next_elapse: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarTimerEntry {
    pub base: String,
    pub spec: String,
    pub next_elapse: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnitWriteFlags {
    pub noop: bool,
    pub private: bool,
    pub escape_specifiers: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimerMessage {
    Bool(bool),
    U64(u64),
    String(String),
    MonotonicSpecs(Vec<(String, u64)>),
    CalendarSpecs(Vec<(String, String)>),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TimerConfig {
    pub values: Vec<TimerValue>,
    pub accuracy_usec: u64,
    pub random_delay_usec: u64,
    pub random_offset_usec: u64,
    pub fixed_random_delay: bool,
    pub wake_system: bool,
    pub persistent: bool,
    pub remain_after_elapse: bool,
    pub on_timezone_change: bool,
    pub on_clock_change: bool,
    pub defer_reactivation: bool,
    pub write_log: Vec<String>,
}

impl TimerConfig {
    pub fn property_get_monotonic_timers(&self) -> Result<Vec<MonotonicTimerEntry>> {
        Ok(self
            .values
            .iter()
            .filter(|v| !v.base.is_calendar())
            .map(|v| MonotonicTimerEntry {
                base: v.base.as_str().to_string(),
                value: v.value.unwrap_or(0),
                next_elapse: v.next_elapse,
            })
            .collect())
    }

    pub fn property_get_calendar_timers(&self) -> Result<Vec<CalendarTimerEntry>> {
        Ok(self
            .values
            .iter()
            .filter(|v| v.base.is_calendar())
            .map(|v| CalendarTimerEntry {
                base: v.base.as_str().to_string(),
                spec: v.calendar_spec.clone().unwrap_or_default(),
                next_elapse: v.next_elapse,
            })
            .collect())
    }

    pub fn property_get_next_elapse_monotonic(&self) -> Result<u64> {
        Ok(self
            .values
            .iter()
            .filter(|v| !v.base.is_calendar())
            .map(|v| v.next_elapse)
            .min()
            .unwrap_or(0))
    }

    pub fn add_one_monotonic_spec(
        &mut self,
        name: &str,
        base: TimerBase,
        flags: UnitWriteFlags,
        usec: u64,
    ) -> Result<bool> {
        if base.is_calendar() {
            return Err(TimerError::invalid(
                "Invalid timer base for monotonic timer",
            ));
        }

        if !flags.noop {
            self.write_log
                .push(format!("{name}={}={usec}", base.as_str()));
            self.values.insert(
                0,
                TimerValue {
                    base,
                    value: Some(usec),
                    calendar_spec: None,
                    next_elapse: 0,
                },
            );
        }

        Ok(true)
    }

    pub fn add_one_calendar_spec(
        &mut self,
        name: &str,
        base: TimerBase,
        flags: UnitWriteFlags,
        spec: &str,
    ) -> Result<bool> {
        if !base.is_calendar() {
            return Err(TimerError::invalid("Invalid timer base for calendar timer"));
        }
        if spec.trim().is_empty() {
            return Err(TimerError::invalid("Invalid calendar spec"));
        }

        if !flags.noop {
            self.write_log
                .push(format!("{name}={}={spec}", base.as_str()));
            self.values.insert(
                0,
                TimerValue {
                    base,
                    value: None,
                    calendar_spec: Some(spec.to_string()),
                    next_elapse: 0,
                },
            );
        }

        Ok(true)
    }

    pub fn bus_timer_set_transient_property(
        &mut self,
        name: &str,
        message: &TimerMessage,
        mut flags: UnitWriteFlags,
    ) -> Result<bool> {
        flags.private = true;

        match (name, message) {
            ("AccuracyUSec", TimerMessage::U64(v)) | ("AccuracySec", TimerMessage::U64(v)) => {
                if !flags.noop {
                    self.accuracy_usec = *v;
                    self.write_log.push(format!("AccuracyUSec={v}"));
                }
                Ok(true)
            }
            ("RandomizedDelayUSec", TimerMessage::U64(v)) => {
                if !flags.noop {
                    self.random_delay_usec = *v;
                    self.write_log.push(format!("RandomizedDelayUSec={v}"));
                }
                Ok(true)
            }
            ("RandomizedOffsetUSec", TimerMessage::U64(v)) => {
                if !flags.noop {
                    self.random_offset_usec = *v;
                    self.write_log.push(format!("RandomizedOffsetUSec={v}"));
                }
                Ok(true)
            }
            ("FixedRandomDelay", TimerMessage::Bool(v)) => Self::set_bool(
                name,
                &mut self.fixed_random_delay,
                *v,
                flags,
                &mut self.write_log,
            ),
            ("WakeSystem", TimerMessage::Bool(v)) => {
                Self::set_bool(name, &mut self.wake_system, *v, flags, &mut self.write_log)
            }
            ("Persistent", TimerMessage::Bool(v)) => {
                Self::set_bool(name, &mut self.persistent, *v, flags, &mut self.write_log)
            }
            ("RemainAfterElapse", TimerMessage::Bool(v)) => Self::set_bool(
                name,
                &mut self.remain_after_elapse,
                *v,
                flags,
                &mut self.write_log,
            ),
            ("OnTimezoneChange", TimerMessage::Bool(v)) => Self::set_bool(
                name,
                &mut self.on_timezone_change,
                *v,
                flags,
                &mut self.write_log,
            ),
            ("OnClockChange", TimerMessage::Bool(v)) => Self::set_bool(
                name,
                &mut self.on_clock_change,
                *v,
                flags,
                &mut self.write_log,
            ),
            ("DeferReactivation", TimerMessage::Bool(v)) => Self::set_bool(
                name,
                &mut self.defer_reactivation,
                *v,
                flags,
                &mut self.write_log,
            ),
            ("TimersMonotonic", TimerMessage::MonotonicSpecs(specs)) => {
                if !flags.noop && specs.is_empty() {
                    self.values.retain(|v| v.base.is_calendar());
                    self.write_log.push("OnActiveSec=".to_string());
                    return Ok(true);
                }

                for (base_name, usec) in specs {
                    let base = TimerBase::parse(base_name)?;
                    if base.is_calendar() {
                        return Err(TimerError::invalid(format!(
                            "Invalid timer base: {base_name}"
                        )));
                    }
                    self.add_one_monotonic_spec(name, base, flags, *usec)?;
                }
                Ok(true)
            }
            ("TimersCalendar", TimerMessage::CalendarSpecs(specs)) => {
                if !flags.noop && specs.is_empty() {
                    self.values.retain(|v| !v.base.is_calendar());
                    self.write_log.push("OnCalendar=".to_string());
                    return Ok(true);
                }

                for (base_name, spec) in specs {
                    let base = TimerBase::parse(base_name)?;
                    if !base.is_calendar() {
                        return Err(TimerError::invalid(format!(
                            "Invalid timer base: {base_name}"
                        )));
                    }
                    self.add_one_calendar_spec(name, base, flags, spec)?;
                }
                Ok(true)
            }
            (
                obsolete @ ("OnActiveSec" | "OnBootSec" | "OnStartupSec" | "OnUnitActiveSec"
                | "OnUnitInactiveSec"),
                TimerMessage::U64(v),
            ) => {
                let base = TimerBase::parse(obsolete)?;
                self.add_one_monotonic_spec(obsolete, base, flags, *v)
            }
            ("OnCalendar", TimerMessage::String(spec)) => {
                self.add_one_calendar_spec("OnCalendar", TimerBase::OnCalendar, flags, spec)
            }
            _ => Ok(false),
        }
    }

    fn set_bool(
        name: &str,
        slot: &mut bool,
        value: bool,
        flags: UnitWriteFlags,
        write_log: &mut Vec<String>,
    ) -> Result<bool> {
        if !flags.noop {
            *slot = value;
            write_log.push(format!("{name}={}", if value { "yes" } else { "no" }));
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_timer_bases() {
        assert_eq!(TimerBase::parse("OnBootSec").unwrap(), TimerBase::OnBootSec);
        assert!(TimerBase::parse("Nope").is_err());
    }

    #[test]
    fn lists_monotonic_timers_only() {
        let config = TimerConfig {
            values: vec![
                TimerValue {
                    base: TimerBase::OnActiveSec,
                    value: Some(5),
                    calendar_spec: None,
                    next_elapse: 9,
                },
                TimerValue {
                    base: TimerBase::OnCalendar,
                    value: None,
                    calendar_spec: Some("daily".into()),
                    next_elapse: 10,
                },
            ],
            ..Default::default()
        };

        assert_eq!(config.property_get_monotonic_timers().unwrap().len(), 1);
    }

    #[test]
    fn lists_calendar_timers_only() {
        let config = TimerConfig {
            values: vec![TimerValue {
                base: TimerBase::OnCalendar,
                value: None,
                calendar_spec: Some("hourly".into()),
                next_elapse: 7,
            }],
            ..Default::default()
        };

        assert_eq!(
            config.property_get_calendar_timers().unwrap()[0].spec,
            "hourly"
        );
    }

    #[test]
    fn computes_next_monotonic_elapse() {
        let config = TimerConfig {
            values: vec![
                TimerValue {
                    base: TimerBase::OnActiveSec,
                    value: Some(1),
                    calendar_spec: None,
                    next_elapse: 30,
                },
                TimerValue {
                    base: TimerBase::OnBootSec,
                    value: Some(2),
                    calendar_spec: None,
                    next_elapse: 10,
                },
            ],
            ..Default::default()
        };

        assert_eq!(config.property_get_next_elapse_monotonic().unwrap(), 10);
    }

    #[test]
    fn rejects_calendar_base_for_monotonic_add() {
        let mut config = TimerConfig::default();
        assert!(config
            .add_one_monotonic_spec(
                "TimersMonotonic",
                TimerBase::OnCalendar,
                UnitWriteFlags::default(),
                1
            )
            .is_err());
    }

    #[test]
    fn adds_calendar_spec() {
        let mut config = TimerConfig::default();
        config
            .add_one_calendar_spec(
                "OnCalendar",
                TimerBase::OnCalendar,
                UnitWriteFlags::default(),
                "daily",
            )
            .unwrap();
        assert_eq!(config.values[0].calendar_spec.as_deref(), Some("daily"));
    }

    #[test]
    fn clears_monotonic_timers_on_empty_array() {
        let mut config = TimerConfig {
            values: vec![TimerValue {
                base: TimerBase::OnActiveSec,
                value: Some(3),
                calendar_spec: None,
                next_elapse: 0,
            }],
            ..Default::default()
        };
        config
            .bus_timer_set_transient_property(
                "TimersMonotonic",
                &TimerMessage::MonotonicSpecs(vec![]),
                UnitWriteFlags::default(),
            )
            .unwrap();
        assert!(config.values.is_empty());
        assert_eq!(config.write_log.last().unwrap(), "OnActiveSec=");
    }

    #[test]
    fn applies_obsolete_accuracy_sec_to_accuracy_usec() {
        let mut config = TimerConfig::default();
        config
            .bus_timer_set_transient_property(
                "AccuracySec",
                &TimerMessage::U64(55),
                UnitWriteFlags::default(),
            )
            .unwrap();
        assert_eq!(config.accuracy_usec, 55);
    }

    #[test]
    fn applies_boolean_properties() {
        let mut config = TimerConfig::default();
        config
            .bus_timer_set_transient_property(
                "WakeSystem",
                &TimerMessage::Bool(true),
                UnitWriteFlags::default(),
            )
            .unwrap();
        assert!(config.wake_system);
    }
}
