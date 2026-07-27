// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/cgtop/cgtop.c

pub const DEFAULT_DEPTH: u32 = 3;
pub const DEFAULT_DELAY_USEC: u64 = 1_000_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Path,
    Tasks,
    Cpu,
    Memory,
    Io,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Count {
    UserspaceProcesses,
    AllProcesses,
    Pids,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuType {
    Percentage,
    Time,
}
pub fn parse_order(s: &str) -> Result<Order, i32> {
    match s {
        "path" => Ok(Order::Path),
        "tasks" => Ok(Order::Tasks),
        "cpu" => Ok(Order::Cpu),
        "memory" | "mem" => Ok(Order::Memory),
        "io" => Ok(Order::Io),
        _ => Err(-22),
    }
}
pub fn parse_count(s: &str) -> Result<Count, i32> {
    match s {
        "userspace" | "userspace-processes" => Ok(Count::UserspaceProcesses),
        "all" | "all-processes" => Ok(Count::AllProcesses),
        "pids" => Ok(Count::Pids),
        _ => Err(-22),
    }
}
pub fn parse_cpu_type(s: &str) -> Result<CpuType, i32> {
    match s {
        "percentage" | "pct" | "%" => Ok(CpuType::Percentage),
        "time" => Ok(CpuType::Time),
        _ => Err(-22),
    }
}
pub fn format_cpu_percentage(part: u64, total: u64) -> String {
    if total == 0 {
        "0.0%".into()
    } else {
        format!("{:.1}%", part as f64 * 100.0 / total as f64)
    }
}
pub fn format_cpu_time(usec: u64) -> String {
    let s = usec / 1_000_000;
    format!("{:2}:{:02}", s / 60, s % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_constants() {
        assert_eq!(DEFAULT_DEPTH, 3);
    }
    #[test]
    fn parse_order_cpu() {
        assert_eq!(parse_order("cpu").unwrap(), Order::Cpu);
    }
    #[test]
    fn parse_order_invalid() {
        assert!(parse_order("x").is_err());
    }
    #[test]
    fn parse_count_all() {
        assert_eq!(parse_count("all").unwrap(), Count::AllProcesses);
    }
    #[test]
    fn parse_cpu_percentage() {
        assert_eq!(parse_cpu_type("%").unwrap(), CpuType::Percentage);
    }
    #[test]
    fn parse_cpu_time() {
        assert_eq!(parse_cpu_type("time").unwrap(), CpuType::Time);
    }
    #[test]
    fn percent_zero_total() {
        assert_eq!(format_cpu_percentage(1, 0), "0.0%");
    }
    #[test]
    fn percent_regular() {
        assert_eq!(format_cpu_percentage(1, 2), "50.0%");
    }
    #[test]
    fn cpu_time_format() {
        assert_eq!(format_cpu_time(65_000_000), " 1:05");
    }
    #[test]
    fn delay_constant() {
        assert_eq!(DEFAULT_DELAY_USEC, 1_000_000);
    }
}
