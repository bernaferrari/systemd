pub struct DbusMessage {
    pub destination: String,
    pub path: String,
    pub interface: String,
    pub member: String,
    pub body: Vec<u8>,
}

impl DbusMessage {
    pub fn new(dest: &str, path: &str, iface: &str, member: &str) -> Self {
        DbusMessage {
            destination: dest.to_string(),
            path: path.to_string(),
            interface: iface.to_string(),
            member: member.to_string(),
            body: Vec::new(),
        }
    }

    pub fn signal(path: &str, iface: &str, member: &str) -> Self {
        DbusMessage {
            destination: String::new(),
            path: path.to_string(),
            interface: iface.to_string(),
            member: member.to_string(),
            body: Vec::new(),
        }
    }
}
