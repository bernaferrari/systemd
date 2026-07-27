// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-inhibit.c

use crate::logind_core::InhibitWhat;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InhibitMode {
    Block,
    Delay,
}

impl InhibitMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Delay => "delay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inhibitor {
    pub id: String,
    pub what: Vec<InhibitWhat>,
    pub who: String,
    pub why: String,
    pub mode: InhibitMode,
    pub uid: u32,
    pub pid: u32,
    pub active: bool,
}

impl Inhibitor {
    pub fn new(
        id: String,
        what: Vec<InhibitWhat>,
        who: String,
        why: String,
        mode: InhibitMode,
        uid: u32,
    ) -> Self {
        Self {
            id,
            what,
            who,
            why,
            mode,
            uid,
            pid: 0,
            active: true,
        }
    }

    pub fn summary_row(&self) -> String {
        format!(
            "what=<{}> who=<{}> why=<{}> mode=<{}> uid=<{}> pid=<{}>",
            self.what
                .iter()
                .map(inhibit_what_to_string)
                .collect::<Vec<_>>()
                .join(":"),
            self.who,
            self.why,
            self.mode.as_str(),
            self.uid,
            self.pid,
        )
    }
}

pub fn inhibit_what_to_string(what: &InhibitWhat) -> &'static str {
    match what {
        InhibitWhat::Shutdown => "shutdown",
        InhibitWhat::Sleep => "sleep",
        InhibitWhat::Idle => "idle",
        InhibitWhat::HandlePowerKey => "handle-power-key",
        InhibitWhat::HandleSuspendKey => "handle-suspend-key",
        InhibitWhat::HandleHibernateKey => "handle-hibernate-key",
        InhibitWhat::HandleLidSwitch => "handle-lid-switch",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_contains_mode_and_what() {
        let inhibitor = Inhibitor::new(
            "1".into(),
            vec![InhibitWhat::Sleep, InhibitWhat::Shutdown],
            "tool".into(),
            "test".into(),
            InhibitMode::Delay,
            1000,
        );
        let row = inhibitor.summary_row();
        assert!(row.contains("sleep:shutdown") || row.contains("shutdown:sleep"));
        assert!(row.contains("delay"));
    }
}
