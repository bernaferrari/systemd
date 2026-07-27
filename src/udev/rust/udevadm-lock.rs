// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-lock.c
//
// udevadm lock — lock block devices and run a command.
//
// Defines argument parsing, device number management, lock timeout
// calculations, and binary-search deduplication for the lock subcommand.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default lock timeout is infinite.
pub const DEFAULT_TIMEOUT_USEC: u64 = u64::MAX;

// ── Parsed arguments ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LockArgs {
    pub timeout_usec: u64,
    pub devices: Vec<String>,
    pub backing: Vec<String>,
    pub cmdline: Vec<String>,
    pub print_only: bool,
}

impl LockArgs {
    pub fn new() -> Self {
        Self {
            timeout_usec: DEFAULT_TIMEOUT_USEC,
            ..Default::default()
        }
    }
}

// ── Validation ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockParseError {
    HelpRequested,
    VersionRequested,
    NoArgsWithPrint,
    TooFewArgs,
    NoDevicesSpecified,
    InvalidTimeout(String),
}

impl std::fmt::Display for LockParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockParseError::HelpRequested => write!(f, "help requested"),
            LockParseError::VersionRequested => write!(f, "version requested"),
            LockParseError::NoArgsWithPrint => write!(f, "No arguments expected."),
            LockParseError::TooFewArgs => write!(f, "Too few arguments, command to execute."),
            LockParseError::NoDevicesSpecified => {
                write!(f, "No devices to lock specified, refusing.")
            }
            LockParseError::InvalidTimeout(s) => {
                write!(f, "Failed to parse --timeout= parameter: {s}")
            }
        }
    }
}

impl std::error::Error for LockParseError {}

// ── Device number management ──────────────────────────────────────────────

/// A raw device number (major:minor) stored as a packed u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceNumber(pub u64);

impl DeviceNumber {
    pub fn new(major: u32, minor: u32) -> Self {
        DeviceNumber((major as u64) << 8 | (minor as u64))
    }

    pub fn major(self) -> u32 {
        (self.0 >> 8) as u32
    }

    pub fn minor(self) -> u32 {
        (self.0 & 0xFF) as u32
    }

    pub fn is_block_device(self) -> bool {
        true
    }
}

/// A sorted, deduplicated list of device numbers.
/// Mirrors the find_devno() logic in C: binary search + insert + re-sort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceNumberList {
    entries: Vec<DeviceNumber>,
}

impl DeviceNumberList {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Try to add a device number. Returns false if already present.
    /// Keeps the list sorted for binary search.
    pub fn add(&mut self, devno: DeviceNumber) -> bool {
        if self.entries.binary_search(&devno).is_ok() {
            return false;
        }
        let pos = self.entries.partition_point(|&d| d < devno);
        self.entries.insert(pos, devno);
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, devno: DeviceNumber) -> bool {
        self.entries.binary_search(&devno).is_ok()
    }

    pub fn iter(&self) -> impl Iterator<Item = DeviceNumber> + '_ {
        self.entries.iter().copied()
    }
}

// ── Deadline calculation ──────────────────────────────────────────────────

/// Calculate the absolute deadline from a relative timeout.
/// Returns the same value if the timeout is infinity (not set).
pub fn calculate_deadline(timeout_usec: u64, now_usec: u64) -> u64 {
    if timeout_usec == u64::MAX {
        u64::MAX
    } else {
        now_usec.saturating_add(timeout_usec)
    }
}

/// Calculate remaining time until deadline.
pub fn time_remaining(deadline_usec: u64, now_usec: u64) -> u64 {
    if deadline_usec == u64::MAX {
        u64::MAX
    } else {
        deadline_usec.saturating_sub(now_usec)
    }
}

// ── Lock result ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOutcome {
    Acquired,
    Busy,
    TimedOut,
    DeviceGone,
    Failed(i32),
}

// ── Help text ─────────────────────────────────────────────────────────────

pub fn help_text(program_name: &str) -> String {
    format!(
        "{program_name} [OPTIONS...] COMMAND\n\
         {program_name} [OPTIONS...] --print\n\
         \nLock a block device and run a command.\n\n\
         -h --help            Print this message\n\
         -V --version         Print version of the program\n\
         -d --device=DEVICE   Block device to lock\n\
         -b --backing=FILE    File whose backing block device to lock\n\
         -t --timeout=SECS    Block at most the specified time waiting for lock\n\
         -p --print           Only show which block device the lock would be taken on\n"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_args_default() {
        let args = LockArgs::new();
        assert_eq!(args.timeout_usec, DEFAULT_TIMEOUT_USEC);
        assert!(args.devices.is_empty());
        assert!(args.backing.is_empty());
        assert!(args.cmdline.is_empty());
        assert!(!args.print_only);
    }

    #[test]
    fn test_device_number_new() {
        let devno = DeviceNumber::new(8, 0);
        assert_eq!(devno.major(), 8);
        assert_eq!(devno.minor(), 0);
    }

    #[test]
    fn test_device_number_large() {
        let devno = DeviceNumber::new(252, 3);
        assert_eq!(devno.major(), 252);
        assert_eq!(devno.minor(), 3);
    }

    #[test]
    fn test_device_number_ordering() {
        let a = DeviceNumber::new(8, 0);
        let b = DeviceNumber::new(8, 1);
        let c = DeviceNumber::new(9, 0);
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn test_device_number_list_add_dedup() {
        let mut list = DeviceNumberList::new();
        assert!(list.add(DeviceNumber::new(8, 0)));
        assert!(!list.add(DeviceNumber::new(8, 0)));
        assert!(list.add(DeviceNumber::new(8, 1)));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_device_number_list_sorted() {
        let mut list = DeviceNumberList::new();
        list.add(DeviceNumber::new(9, 0));
        list.add(DeviceNumber::new(8, 0));
        list.add(DeviceNumber::new(8, 1));
        let devs: Vec<_> = list.iter().collect();
        assert!(devs.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_device_number_list_contains() {
        let mut list = DeviceNumberList::new();
        list.add(DeviceNumber::new(8, 0));
        assert!(list.contains(DeviceNumber::new(8, 0)));
        assert!(!list.contains(DeviceNumber::new(8, 1)));
    }

    #[test]
    fn test_calculate_deadline() {
        assert_eq!(calculate_deadline(5000, 1000), 6000);
        assert_eq!(calculate_deadline(u64::MAX, 1000), u64::MAX);
    }

    #[test]
    fn test_time_remaining() {
        assert_eq!(time_remaining(6000, 1000), 5000);
        assert_eq!(time_remaining(u64::MAX, 1000), u64::MAX);
        assert_eq!(time_remaining(500, 1000), 0);
    }

    #[test]
    fn test_help_text() {
        let help = help_text("udevadm");
        assert!(help.contains("--device"));
        assert!(help.contains("--backing"));
        assert!(help.contains("--timeout"));
        assert!(help.contains("--print"));
    }
}
