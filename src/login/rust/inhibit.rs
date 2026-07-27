// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/inhibit.c

use crate::logind_core::InhibitWhat;
use crate::logind_inhibit::{InhibitMode, Inhibitor};

pub fn parse_what(value: &str) -> Result<Vec<InhibitWhat>, String> {
    let mut parsed = Vec::new();
    for part in value.split(':').filter(|part| !part.is_empty()) {
        let item = match part {
            "shutdown" => InhibitWhat::Shutdown,
            "sleep" => InhibitWhat::Sleep,
            "idle" => InhibitWhat::Idle,
            "handle-power-key" => InhibitWhat::HandlePowerKey,
            "handle-suspend-key" => InhibitWhat::HandleSuspendKey,
            "handle-hibernate-key" => InhibitWhat::HandleHibernateKey,
            "handle-lid-switch" => InhibitWhat::HandleLidSwitch,
            _ => return Err(format!("unknown inhibit selector: {part}")),
        };
        if !parsed.contains(&item) {
            parsed.push(item);
        }
    }

    if parsed.is_empty() {
        return Err("no inhibit selectors provided".to_string());
    }

    Ok(parsed)
}

pub fn parse_mode(value: &str) -> Result<InhibitMode, String> {
    match value {
        "block" => Ok(InhibitMode::Block),
        "delay" => Ok(InhibitMode::Delay),
        _ => Err(format!("unknown inhibit mode: {value}")),
    }
}

pub fn format_inhibitor_rows(inhibitors: &[Inhibitor]) -> Vec<String> {
    inhibitors.iter().map(Inhibitor::summary_row).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_accepts_c_variants() {
        assert_eq!(parse_mode("block"), Ok(InhibitMode::Block));
        assert!(parse_mode("bogus").is_err());
    }
}
