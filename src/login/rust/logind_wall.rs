// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-wall.c

use crate::logind_action::HandleAction;

const WALL_TIMERS_MINUTES: &[u64] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 25, 40, 55, 70, 100, 130, 150, 180,
];
const USEC_PER_MINUTE: u64 = 60 * 1_000_000;
const USEC_PER_HOUR: u64 = 60 * USEC_PER_MINUTE;

pub fn when_wall(now_usec: u64, elapse_usec: u64) -> u64 {
    if now_usec >= elapse_usec {
        return 0;
    }

    let left = elapse_usec - now_usec;
    for window in WALL_TIMERS_MINUTES.windows(2) {
        if window[1] * USEC_PER_MINUTE >= left {
            return left - window[0] * USEC_PER_MINUTE;
        }
    }
    left % USEC_PER_HOUR
}

pub fn logind_wall_tty_filter(
    tty: &str,
    is_local: bool,
    action: HandleAction,
    scheduled_tty: Option<&str>,
) -> bool {
    let path = match tty.strip_prefix("/dev/") {
        Some(path) => path,
        None => return true,
    };

    if is_local && action.is_sleep() {
        return false;
    }

    scheduled_tty != Some(path)
}

pub fn wall_message(prefix: Option<&str>, action: HandleAction, deadline: Option<&str>) -> String {
    let prefix = prefix.unwrap_or("");
    let joiner = if prefix.is_empty() { "" } else { "\n" };
    let timing = deadline
        .map(|ts| format!(" at {ts}"))
        .unwrap_or_else(|| " now".to_string());
    format!("{prefix}{joiner}The system will {}{timing}!", action.verb())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_sleep_messages_are_suppressed() {
        assert!(!logind_wall_tty_filter(
            "/dev/tty1",
            true,
            HandleAction::Suspend,
            None
        ));
    }

    #[test]
    fn message_uses_action_verb() {
        assert!(wall_message(None, HandleAction::Reboot, None).contains("reboot"));
    }
}
