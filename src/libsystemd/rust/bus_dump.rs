// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-dump.c
//


pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const SD_BUS_MESSAGE_DUMP_WITH_HEADER: u64 = 1;
pub const SD_BUS_MESSAGE_DUMP_SUBTREE_ONLY: u64 = 2;
pub const KNOWN_FLAGS: u64 = SD_BUS_MESSAGE_DUMP_WITH_HEADER | SD_BUS_MESSAGE_DUMP_SUBTREE_ONLY;

#[derive(Debug, Clone, PartialEq)]
pub enum BusValue {
    Byte(u8),
    Boolean(bool),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Double(f64),
    String(String),
    ObjectPath(String),
    Signature(String),
    UnixFd(i32),
    Array(String, Vec<BusValue>),
    Variant(String, Box<BusValue>),
    Struct(String, Vec<BusValue>),
    DictEntry(String, Vec<BusValue>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BusCreds {
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub comm: Option<String>,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusHeader {
    pub message_type: String,
    pub endian: char,
    pub flags: u8,
    pub version: u8,
    pub cookie: u64,
    pub reply_cookie: Option<u64>,
    pub sender: Option<String>,
    pub destination: Option<String>,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BusMessage {
    pub header: BusHeader,
    pub root_signature: String,
    pub body: Vec<BusValue>,
    pub timestamp: Option<String>,
    pub error: Option<(String, String)>,
    pub creds: Option<BusCreds>,
}

pub fn indent(mut level: usize, flags: u64) -> Result<String> {
    if flags & !KNOWN_FLAGS != 0 {
        return Err(NEG_EINVAL);
    }
    if flags & SD_BUS_MESSAGE_DUMP_SUBTREE_ONLY != 0 && level > 0 {
        level -= 1;
    }
    let mut n = level * 8;
    if flags & SD_BUS_MESSAGE_DUMP_WITH_HEADER != 0 {
        n += 2;
    }
    Ok(" ".repeat(n))
}

pub fn dump_message(message: &BusMessage, flags: u64) -> Result<String> {
    if flags & !KNOWN_FLAGS != 0 {
        return Err(NEG_EINVAL);
    }

    let mut out = String::new();
    if flags & SD_BUS_MESSAGE_DUMP_WITH_HEADER != 0 {
        out.push_str(&format!(
            "• Type={}  Endian={}  Flags={}  Version={} Cookie={}",
            message.header.message_type,
            message.header.endian,
            message.header.flags,
            message.header.version,
            message.header.cookie,
        ));
        if let Some(reply) = message.header.reply_cookie {
            out.push_str(&format!("  ReplyCookie={reply}"));
        }
        if let Some(ts) = &message.timestamp {
            out.push_str(&format!("  Timestamp=\"{ts}\""));
        }
        out.push('\n');
    }

    if flags & SD_BUS_MESSAGE_DUMP_SUBTREE_ONLY == 0 {
        out.push_str(&format!(
            "{}MESSAGE \"{}\" {{\n",
            indent(0, flags)?,
            message.root_signature
        ));
    }

    for value in &message.body {
        dump_value(value, 1, flags, &mut out)?;
    }

    if flags & SD_BUS_MESSAGE_DUMP_SUBTREE_ONLY == 0 {
        out.push_str(&format!("{}}};\n", indent(0, flags)?));
    }

    if let Some(creds) = &message.creds {
        out.push_str(&dump_creds(creds, true));
    }

    Ok(out)
}

fn dump_value(value: &BusValue, level: usize, flags: u64, out: &mut String) -> Result<()> {
    let prefix = indent(level, flags)?;
    match value {
        BusValue::Byte(v) => out.push_str(&format!("{prefix}BYTE {v};\n")),
        BusValue::Boolean(v) => out.push_str(&format!("{prefix}BOOLEAN {v};\n")),
        BusValue::Int16(v) => out.push_str(&format!("{prefix}INT16 {v};\n")),
        BusValue::UInt16(v) => out.push_str(&format!("{prefix}UINT16 {v};\n")),
        BusValue::Int32(v) => out.push_str(&format!("{prefix}INT32 {v};\n")),
        BusValue::UInt32(v) => out.push_str(&format!("{prefix}UINT32 {v};\n")),
        BusValue::Int64(v) => out.push_str(&format!("{prefix}INT64 {v};\n")),
        BusValue::UInt64(v) => out.push_str(&format!("{prefix}UINT64 {v};\n")),
        BusValue::Double(v) => out.push_str(&format!("{prefix}DOUBLE {v};\n")),
        BusValue::String(v) => out.push_str(&format!("{prefix}STRING \"{v}\";\n")),
        BusValue::ObjectPath(v) => out.push_str(&format!("{prefix}OBJECT_PATH \"{v}\";\n")),
        BusValue::Signature(v) => out.push_str(&format!("{prefix}SIGNATURE \"{v}\";\n")),
        BusValue::UnixFd(v) => out.push_str(&format!("{prefix}UNIX_FD {v};\n")),
        BusValue::Array(sig, items) => dump_container("ARRAY", sig, items, level, flags, out)?,
        BusValue::Struct(sig, items) => dump_container("STRUCT", sig, items, level, flags, out)?,
        BusValue::DictEntry(sig, items) => {
            dump_container("DICT_ENTRY", sig, items, level, flags, out)?
        }
        BusValue::Variant(sig, value) => {
            out.push_str(&format!("{prefix}VARIANT \"{sig}\" {{\n"));
            dump_value(value, level + 1, flags, out)?;
            out.push_str(&format!("{}}};\n", indent(level, flags)?));
        }
    }
    Ok(())
}

fn dump_container(
    kind: &str,
    signature: &str,
    values: &[BusValue],
    level: usize,
    flags: u64,
    out: &mut String,
) -> Result<()> {
    out.push_str(&format!(
        "{}{} \"{}\" {{\n",
        indent(level, flags)?,
        kind,
        signature
    ));
    for value in values {
        dump_value(value, level + 1, flags, out)?;
    }
    out.push_str(&format!("{}}};\n", indent(level, flags)?));
    Ok(())
}

pub fn dump_creds(creds: &BusCreds, terse: bool) -> String {
    let prefix = if terse { "  " } else { "" };
    let mut out = String::new();
    if let Some(pid) = creds.pid {
        out.push_str(&format!("{prefix}PID={pid}\n"));
    }
    if let Some(uid) = creds.uid {
        out.push_str(&format!("{prefix}UID={uid}\n"));
    }
    if let Some(comm) = &creds.comm {
        out.push_str(&format!("{prefix}Comm={comm}\n"));
    }
    if let Some(exe) = &creds.exe {
        out.push_str(&format!("{prefix}Exe={exe}\n"));
    }
    if !creds.cmdline.is_empty() {
        out.push_str(&format!("{prefix}CmdLine={}\n", creds.cmdline.join(" ")));
    }
    out
}

pub fn pcap_header(snaplen: usize, os: Option<&str>, app: Option<&str>) -> Vec<u8> {
    format!(
        "pcapng:snaplen={snaplen};os={};app={};",
        os.unwrap_or(""),
        app.unwrap_or("")
    )
    .into_bytes()
}

pub fn pcap_frame(message: &BusMessage, snaplen: usize) -> Vec<u8> {
    let mut bytes = dump_message(message, 0).unwrap_or_default().into_bytes();
    bytes.truncate(snaplen.min(bytes.len()));
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message() -> BusMessage {
        BusMessage {
            header: BusHeader {
                message_type: "signal".into(),
                endian: 'l',
                flags: 0,
                version: 1,
                cookie: 9,
                reply_cookie: None,
                sender: None,
                destination: None,
                path: None,
                interface: None,
                member: None,
            },
            root_signature: "s".into(),
            body: vec![BusValue::String("hello".into())],
            timestamp: Some("now".into()),
            error: None,
            creds: None,
        }
    }

    #[test]
    fn computes_indent_without_header() {
        assert_eq!(indent(2, 0).unwrap(), "                ");
    }

    #[test]
    fn computes_indent_with_header() {
        assert_eq!(
            indent(1, SD_BUS_MESSAGE_DUMP_WITH_HEADER).unwrap(),
            "          "
        );
    }

    #[test]
    fn rejects_unknown_flags() {
        assert_eq!(indent(0, 8), Err(NEG_EINVAL));
    }

    #[test]
    fn dumps_basic_message() {
        let rendered = dump_message(&sample_message(), 0).unwrap();
        assert!(rendered.contains("MESSAGE \"s\""));
        assert!(rendered.contains("STRING \"hello\";"));
    }

    #[test]
    fn dumps_header_when_requested() {
        let rendered = dump_message(&sample_message(), SD_BUS_MESSAGE_DUMP_WITH_HEADER).unwrap();
        assert!(rendered.contains("Type=signal"));
        assert!(rendered.contains("Timestamp=\"now\""));
    }

    #[test]
    fn dumps_containers() {
        let mut message = sample_message();
        message.body = vec![BusValue::Array(
            "s".into(),
            vec![BusValue::String("x".into())],
        )];
        let rendered = dump_message(&message, 0).unwrap();
        assert!(rendered.contains("ARRAY \"s\""));
        assert!(rendered.contains("STRING \"x\";"));
    }

    #[test]
    fn dumps_creds_terse() {
        let creds = BusCreds {
            pid: Some(12),
            uid: Some(34),
            comm: Some("systemd".into()),
            exe: None,
            cmdline: vec![],
        };
        let rendered = dump_creds(&creds, true);
        assert!(rendered.contains("PID=12"));
        assert!(rendered.contains("UID=34"));
    }

    #[test]
    fn emits_pcap_header() {
        let header = String::from_utf8(pcap_header(64, Some("Linux"), Some("busctl"))).unwrap();
        assert!(header.contains("snaplen=64"));
        assert!(header.contains("app=busctl"));
    }
}
