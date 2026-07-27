pub const DBUS_PATH: &str = "/org/freedesktop/systemd1";
pub const DBUS_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
pub const DBUS_SERVICE: &str = "org.freedesktop.systemd1";

// Additional common D-Bus paths/interfaces used by systemd-related services
pub const JOURNALD_PATH: &str = "/org/freedesktop/Journal1";
pub const JOURNALD_SERVICE: &str = "org.freedesktop.Journald1";
pub const JOURNALD_INTERFACE: &str = "org.freedesktop.Journald1";

pub const LOGIND_PATH: &str = "/org/freedesktop/login1";
pub const LOGIND_SERVICE: &str = "org.freedesktop.login1";
pub const LOGIND_INTERFACE: &str = "org.freedesktop.login1.Manager";

pub const RESOLVED_PATH: &str = "/org/freedesktop/Resolved";
pub const RESOLVED_SERVICE: &str = "org.freedesktop.resolve1";
pub const RESOLVED_INTERFACE: &str = "org.freedesktop.resolve1.Manager";

pub const UDEV_PATH: &str = "/org/freedesktop/Udev";
pub const UDEV_SERVICE: &str = "org.freedesktop.Udev";
pub const UDEV_INTERFACE: &str = "org.freedesktop.Udev";
