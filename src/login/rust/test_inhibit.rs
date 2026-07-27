// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/test-inhibit.c

use crate::inhibit::{format_inhibitor_rows, parse_what};
use crate::logind_core::InhibitWhat;
use crate::logind_inhibit::{InhibitMode, Inhibitor};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colon_separated_what() {
        let parsed = parse_what("idle:shutdown").unwrap();
        assert_eq!(parsed, vec![InhibitWhat::Idle, InhibitWhat::Shutdown]);
    }

    #[test]
    fn formats_rows() {
        let inhibitor = Inhibitor::new(
            "1".into(),
            vec![InhibitWhat::Sleep],
            "test".into(),
            "because".into(),
            InhibitMode::Block,
            1000,
        );
        let rows = format_inhibitor_rows(&[inhibitor]);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].contains("sleep"));
    }
}
