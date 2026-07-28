// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal-send.c
//

use crate::id128_util::SdId128;
use crate::sd_journal_send::{
    JournalField, LONG_LINE_MAX, journal_perror, journal_print, journal_send,
};

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_ENOBUFS: i32 = -(libc::ENOBUFS as i32);
pub const LOG_INFO: i32 = 6;
pub const LOG_NOTICE: i32 = 5;
pub const HUGE_SIZE: usize = 4096 * 1024;
pub const MESSAGE_ID_HELLO: &str = "52fb62f99e2c49d89cfbf9d6de5e3555";

pub fn graph1_iovec() -> JournalField {
    JournalField {
        name: "GRAPH".into(),
        value: b"graph".to_vec(),
    }
}

pub fn graph2_iovec() -> JournalField {
    JournalField {
        name: "GRAPH".into(),
        value: b"graph\n".to_vec(),
    }
}

pub fn message1_iovec() -> JournalField {
    JournalField {
        name: "MESSAGE".into(),
        value: b"graph".to_vec(),
    }
}

pub fn message2_iovec() -> JournalField {
    JournalField {
        name: "MESSAGE".into(),
        value: b"graph\n".to_vec(),
    }
}

pub fn build_huge_field() -> JournalField {
    let mut value = vec![b'x'; HUGE_SIZE - 1];
    value.push(0);
    JournalField {
        name: "HUGE".into(),
        value,
    }
}

pub fn build_hello_world_fields() -> Vec<JournalField> {
    vec![
        JournalField {
            name: "MESSAGE".into(),
            value: b"Hello World!".to_vec(),
        },
        JournalField {
            name: "MESSAGE_ID".into(),
            value: MESSAGE_ID_HELLO.as_bytes().to_vec(),
        },
        JournalField {
            name: "PRIORITY".into(),
            value: b"5".to_vec(),
        },
    ]
}

pub fn validate_long_line_limit(message_len: usize) -> Result<()> {
    if message_len > LONG_LINE_MAX {
        return Err(NEG_ENOBUFS);
    }
    Ok(())
}

pub fn hello_message_id() -> SdId128 {
    crate::sd_id128_strings::sd_id128_from_string(MESSAGE_ID_HELLO).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_print_accepts_short_messages() {
        assert!(journal_print(LOG_INFO, "XXX").is_ok());
    }

    #[test]
    fn journal_print_rejects_too_long_message() {
        let msg = "X".repeat(LONG_LINE_MAX);
        assert_eq!(journal_print(LOG_INFO, &msg), Err(NEG_ENOBUFS));
    }

    #[test]
    fn builds_graph_vectors() {
        assert_eq!(graph1_iovec().value, b"graph".to_vec());
        assert_eq!(graph2_iovec().value, b"graph\n".to_vec());
    }

    #[test]
    fn builds_message_vectors() {
        assert_eq!(message1_iovec().name, "MESSAGE");
        assert_eq!(message2_iovec().value, b"graph\n".to_vec());
    }

    #[test]
    fn builds_huge_field() {
        let field = build_huge_field();
        assert_eq!(field.name, "HUGE");
        assert_eq!(field.value.len(), HUGE_SIZE);
    }

    #[test]
    fn builds_hello_world_send_fields() {
        let fields = build_hello_world_fields();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[1].value, MESSAGE_ID_HELLO.as_bytes().to_vec());
    }

    #[test]
    fn validates_long_line_limit() {
        assert!(validate_long_line_limit(LONG_LINE_MAX).is_ok());
        assert_eq!(
            validate_long_line_limit(LONG_LINE_MAX + 1),
            Err(NEG_ENOBUFS)
        );
    }

    #[test]
    fn hello_message_id_is_valid_id128() {
        let id = hello_message_id();
        assert_eq!(
            crate::sd_id128_strings::sd_id128_to_string(id),
            MESSAGE_ID_HELLO
        );
    }

    #[test]
    fn perror_generation_matches_expectation() {
        let fields = journal_perror("Foobar", libc::ENOENT).unwrap();
        assert_eq!(fields[0].name, "PRIORITY");
        assert_eq!(fields[2].name, "ERRNO");
    }

    #[test]
    fn send_injects_identifier_when_missing() {
        let encoded = journal_send(&build_hello_world_fields(), Some("test-send")).unwrap();
        let rendered = String::from_utf8_lossy(&encoded);
        assert!(rendered.contains("SYSLOG_IDENTIFIER=test-send"));
    }
}
