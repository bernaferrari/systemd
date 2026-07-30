// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/cgtop/cgtop.c
//
// Show top control groups by their resource usage.
// Tracks CPU, memory, I/O per cgroup with configurable ordering.

// ── Constants ─────────────────────────────────────────────────────────────

pub const DEFAULT_DEPTH: u32 = 3;
pub const DEFAULT_DELAY_USEC: u64 = 1_000_000;

// ── Types ─────────────────────────────────────────────────────────────────

/// Sort order for cgroup display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Path,
    Tasks,
    Cpu,
    Memory,
    Io,
}

impl Order {
    pub fn as_str(&self) -> &'static str {
        match self {
            Order::Path => "path",
            Order::Tasks => "tasks",
            Order::Cpu => "cpu",
            Order::Memory => "memory",
            Order::Io => "io",
        }
    }
}

impl std::str::FromStr for Order {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "path" => Ok(Order::Path),
            "tasks" => Ok(Order::Tasks),
            "cpu" => Ok(Order::Cpu),
            "memory" => Ok(Order::Memory),
            "io" => Ok(Order::Io),
            _ => Err(()),
        }
    }
}

/// Parse C's case-sensitive cgtop order table.
pub fn order_from_string(s: &str) -> Option<Order> {
    s.parse().ok()
}

/// CPU display type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuType {
    Percentage,
    Time,
}

impl CpuType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CpuType::Percentage => "percentage",
            CpuType::Time => "time",
        }
    }
}

impl std::str::FromStr for CpuType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "percentage" => Ok(CpuType::Percentage),
            "time" => Ok(CpuType::Time),
            _ => Err(()),
        }
    }
}

/// Parse C's case-sensitive cgtop CPU display table.
pub fn cpu_type_from_string(s: &str) -> Option<CpuType> {
    s.parse().ok()
}

/// Process counting mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PidsCount {
    UserspaceProcesses,
    AllProcesses,
    Pids,
}

impl PidsCount {
    pub fn counting_what(&self) -> &'static str {
        match self {
            PidsCount::Pids => "tasks",
            PidsCount::AllProcesses => "all processes (incl. kernel)",
            PidsCount::UserspaceProcesses => "userspace processes (excl. kernel)",
        }
    }
}

/// Resource usage data for a cgroup.
#[derive(Debug, Clone, Default)]
pub struct Group {
    pub path: String,
    pub n_tasks_valid: bool,
    pub cpu_valid: bool,
    pub memory_valid: bool,
    pub io_valid: bool,
    pub n_tasks: u64,
    pub cpu_fraction: f64,
    pub memory: u64,
    pub io_input_bps: u64,
    pub io_output_bps: u64,
}

/// Parsed command-line arguments for `systemd-cgtop`.
#[derive(Debug, Clone, PartialEq)]
pub struct CgtopArgs {
    pub depth: u32,
    pub iterations: u64,
    pub batch: bool,
    pub raw: bool,
    pub delay_usec: u64,
    pub machine: Option<String>,
    pub root: Option<String>,
    pub recursive: bool,
    pub recursive_unset: bool,
    pub count: PidsCount,
    pub order: Order,
    pub cpu_type: CpuType,
}

impl Default for CgtopArgs {
    fn default() -> Self {
        Self {
            depth: DEFAULT_DEPTH,
            iterations: u64::MAX,
            batch: false,
            raw: false,
            delay_usec: DEFAULT_DELAY_USEC,
            machine: None,
            root: None,
            recursive: true,
            recursive_unset: false,
            count: PidsCount::Pids,
            order: Order::Cpu,
            cpu_type: CpuType::Percentage,
        }
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────

pub fn parse_cgtop_args(args: &[&str]) -> Result<CgtopArgs, i32> {
    let mut result = CgtopArgs::default();
    let mut i = 0;
    let mut positional: Vec<String> = Vec::new();

    while i < args.len() {
        match args[i] {
            "--help" | "-h" => return Err(0),
            "--version" => return Err(0),
            "--batch" | "-b" => result.batch = true,
            "--raw" | "-r" => result.raw = true,
            "-p" => result.order = Order::Path,
            "-t" => result.order = Order::Tasks,
            "-c" => result.order = Order::Cpu,
            "-m" => result.order = Order::Memory,
            "-i" => result.order = Order::Io,
            "-k" => result.count = PidsCount::AllProcesses,
            "-P" => result.count = PidsCount::UserspaceProcesses,
            "-1" => result.iterations = 1,
            "--depth" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.depth = args[i].parse().map_err(|_| -libc::EINVAL)?;
            }
            "--delay" | "-d" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                let secs: f64 = args[i].parse().map_err(|_| -libc::EINVAL)?;
                if secs <= 0.0 {
                    return Err(-libc::EINVAL);
                }
                result.delay_usec = (secs * 1_000_000.0) as u64;
            }
            "--iterations" | "-n" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.iterations = args[i].parse().map_err(|_| -libc::EINVAL)?;
            }
            "--order" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.order = order_from_string(args[i]).ok_or(-libc::EINVAL)?;
            }
            "--cpu" => {
                i += 1;
                if i < args.len() && !args[i].starts_with('-') {
                    result.cpu_type = cpu_type_from_string(args[i]).ok_or(-libc::EINVAL)?;
                } else {
                    result.cpu_type = CpuType::Time;
                    continue;
                }
            }
            "--recursive" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                match args[i] {
                    "yes" | "true" | "1" | "on" => result.recursive = true,
                    "no" | "false" | "0" | "off" => {
                        result.recursive = false;
                        result.recursive_unset = true;
                    }
                    _ => return Err(-libc::EINVAL),
                }
            }
            "--machine" | "-M" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.machine = Some(args[i].to_string());
            }
            s if s.starts_with('-') => return Err(-libc::EINVAL),
            other => positional.push(other.to_string()),
        }
        i += 1;
    }

    if positional.len() == 1 {
        result.root = Some(positional.into_iter().next().unwrap());
    } else if positional.len() > 1 {
        return Err(-libc::EINVAL);
    }

    Ok(result)
}

// ── Core logic ────────────────────────────────────────────────────────────

/// Format bytes for display (human-readable or raw).
pub fn format_bytes(bytes: u64, raw: bool) -> String {
    if raw {
        return bytes.to_string();
    }
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

/// Format CPU percentage.
pub fn format_cpu_percentage(fraction: f64, raw: bool) -> String {
    if raw {
        format!("{:.1}", fraction * 100.0)
    } else {
        format!("{:6.1}", fraction * 100.0)
    }
}

/// Compare two groups for ordering.
pub fn compare_groups(a: &Group, b: &Group, order: Order) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match order {
        Order::Cpu => {
            let a_val = if a.cpu_valid { a.cpu_fraction } else { -1.0 };
            let b_val = if b.cpu_valid { b.cpu_fraction } else { -1.0 };
            b_val.partial_cmp(&a_val).unwrap_or(Ordering::Equal)
        }
        Order::Tasks => {
            let a_val = if a.n_tasks_valid {
                a.n_tasks as i64
            } else {
                -1
            };
            let b_val = if b.n_tasks_valid {
                b.n_tasks as i64
            } else {
                -1
            };
            b_val.cmp(&a_val)
        }
        Order::Memory => {
            let a_val = if a.memory_valid { a.memory as i64 } else { -1 };
            let b_val = if b.memory_valid { b.memory as i64 } else { -1 };
            b_val.cmp(&a_val)
        }
        Order::Io => {
            let a_val = if a.io_valid {
                (a.io_input_bps + a.io_output_bps) as i64
            } else {
                -1
            };
            let b_val = if b.io_valid {
                (b.io_input_bps + b.io_output_bps) as i64
            } else {
                -1
            };
            b_val.cmp(&a_val)
        }
        Order::Path => a.path.cmp(&b.path),
    }
}

/// Determine effective iteration count based on TTY presence.
pub fn resolve_iterations(iterations: u64, on_tty: bool) -> u64 {
    if iterations == u64::MAX {
        if on_tty { 0 } else { 1 }
    } else {
        iterations
    }
}

/// Validate recursive mode vs count mode.
pub fn validate_recursive_count(recursive_unset: bool, count: PidsCount) -> Result<(), i32> {
    if recursive_unset && count == PidsCount::Pids {
        return Err(-libc::EINVAL);
    }
    Ok(())
}

/// Compute effective process counting mode based on available controllers.
pub fn effective_count(supported_pids: bool, requested: PidsCount) -> PidsCount {
    let possible = if supported_pids {
        PidsCount::Pids
    } else {
        PidsCount::AllProcesses
    };
    std::cmp::min(possible, requested)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_order_from_str() {
        assert_eq!("path".parse(), Ok(Order::Path));
        assert_eq!("cpu".parse(), Ok(Order::Cpu));
        assert_eq!(order_from_string("invalid"), None);
    }

    #[test]
    fn test_order_as_str() {
        assert_eq!(Order::Path.as_str(), "path");
        assert_eq!(Order::Cpu.as_str(), "cpu");
    }

    #[test]
    fn test_cpu_type_from_str() {
        assert_eq!("percentage".parse(), Ok(CpuType::Percentage));
        assert_eq!("time".parse(), Ok(CpuType::Time));
        assert_eq!(cpu_type_from_string("invalid"), None);
    }

    #[test]
    fn test_pids_count_what() {
        assert_eq!(PidsCount::Pids.counting_what(), "tasks");
        assert_eq!(
            PidsCount::AllProcesses.counting_what(),
            "all processes (incl. kernel)"
        );
    }

    #[test]
    fn test_parse_empty_args() {
        let args = parse_cgtop_args(&[]).unwrap();
        assert_eq!(args.depth, DEFAULT_DEPTH);
        assert_eq!(args.order, Order::Cpu);
    }

    #[test]
    fn test_parse_order_short() {
        assert_eq!(parse_cgtop_args(&["-p"]).unwrap().order, Order::Path);
        assert_eq!(parse_cgtop_args(&["-t"]).unwrap().order, Order::Tasks);
        assert_eq!(parse_cgtop_args(&["-c"]).unwrap().order, Order::Cpu);
        assert_eq!(parse_cgtop_args(&["-m"]).unwrap().order, Order::Memory);
        assert_eq!(parse_cgtop_args(&["-i"]).unwrap().order, Order::Io);
    }

    #[test]
    fn test_parse_depth() {
        let args = parse_cgtop_args(&["--depth", "5"]).unwrap();
        assert_eq!(args.depth, 5);
    }

    #[test]
    fn test_parse_batch() {
        assert!(parse_cgtop_args(&["-b"]).unwrap().batch);
    }

    #[test]
    fn test_parse_raw() {
        assert!(parse_cgtop_args(&["-r"]).unwrap().raw);
    }

    #[test]
    fn test_parse_one_iteration() {
        assert_eq!(parse_cgtop_args(&["-1"]).unwrap().iterations, 1);
    }

    #[test]
    fn test_parse_root_positional() {
        let args = parse_cgtop_args(&["system.slice"]).unwrap();
        assert_eq!(args.root.as_deref(), Some("system.slice"));
    }

    #[test]
    fn test_parse_too_many_positionals() {
        assert!(parse_cgtop_args(&["a", "b"]).is_err());
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512, false), "512B");
        assert_eq!(format_bytes(1536, false), "1.5K");
        assert_eq!(format_bytes(1536, true), "1536");
    }

    #[test]
    fn test_format_cpu_percentage() {
        let s = format_cpu_percentage(0.456, false);
        assert!(s.contains("45.6"));
    }

    #[test]
    fn test_compare_groups_cpu() {
        let a = Group {
            cpu_valid: true,
            cpu_fraction: 0.5,
            ..Default::default()
        };
        let b = Group {
            cpu_valid: true,
            cpu_fraction: 0.8,
            ..Default::default()
        };
        assert_eq!(
            compare_groups(&a, &b, Order::Cpu),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_resolve_iterations_tty() {
        assert_eq!(resolve_iterations(u64::MAX, true), 0);
        assert_eq!(resolve_iterations(u64::MAX, false), 1);
        assert_eq!(resolve_iterations(5, true), 5);
    }

    #[test]
    fn test_validate_recursive_count_ok() {
        assert!(validate_recursive_count(false, PidsCount::Pids).is_ok());
    }

    #[test]
    fn test_validate_recursive_count_fail() {
        assert!(validate_recursive_count(true, PidsCount::Pids).is_err());
    }

    #[test]
    fn test_effective_count() {
        assert_eq!(effective_count(true, PidsCount::Pids), PidsCount::Pids);
        assert_eq!(
            effective_count(false, PidsCount::Pids),
            PidsCount::AllProcesses
        );
    }
}
