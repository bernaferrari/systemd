// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/sysfs-show.c

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysfsDevice {
    pub syspath: String,
    pub seat: String,
    pub subsystem: String,
    pub sysname: String,
    pub display_name: Option<String>,
    pub is_master_of_seat: bool,
}

pub fn show_sysfs_attribute(value: &str) -> Result<String, String> {
    Ok(value.trim().to_string())
}

pub fn show_sysfs_one(
    devices: &[SysfsDevice],
    seat: &str,
    prefix: &str,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();

    for device in devices
        .iter()
        .filter(|d| d.seat == seat && d.syspath.starts_with(prefix))
    {
        let glyph = if device.is_master_of_seat { "*" } else { "-" };
        let label = device.display_name.as_deref().unwrap_or(&device.sysname);
        lines.push(format!(
            "{glyph} {}/{} ({label})",
            device.subsystem, device.sysname
        ));
    }

    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_display_trims_whitespace() {
        assert_eq!(show_sysfs_attribute(" value\n").unwrap(), "value");
    }

    #[test]
    fn devices_are_filtered_by_seat_and_prefix() {
        let lines = show_sysfs_one(
            &[
                SysfsDevice {
                    syspath: "/sys/a".into(),
                    seat: "seat0".into(),
                    subsystem: "drm".into(),
                    sysname: "card0".into(),
                    display_name: None,
                    is_master_of_seat: true,
                },
                SysfsDevice {
                    syspath: "/sys/b".into(),
                    seat: "seat1".into(),
                    subsystem: "input".into(),
                    sysname: "event1".into(),
                    display_name: None,
                    is_master_of_seat: false,
                },
            ],
            "seat0",
            "/sys",
        )
        .unwrap();

        assert_eq!(lines, vec!["* drm/card0 (card0)"]);
    }
}
