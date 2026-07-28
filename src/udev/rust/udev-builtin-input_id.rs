// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-input_id.c
//
// Safe input capability classification.

use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputCapabilities {
    pub keys: BTreeSet<String>,
    pub relative_axes: BTreeSet<String>,
    pub absolute_axes: BTreeSet<String>,
    pub switches: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputClassification {
    pub is_keyboard: bool,
    pub is_mouse: bool,
    pub is_touchpad: bool,
    pub is_touchscreen: bool,
    pub is_joystick: bool,
}

pub fn classify_input(capabilities: &InputCapabilities) -> InputClassification {
    let has_key = |name: &str| capabilities.keys.contains(name);
    let has_rel = |name: &str| capabilities.relative_axes.contains(name);
    let has_abs = |name: &str| capabilities.absolute_axes.contains(name);
    InputClassification {
        is_keyboard: has_key("KEY_A") || has_key("KEY_ENTER"),
        is_mouse: has_rel("REL_X") && has_rel("REL_Y") && has_key("BTN_LEFT"),
        is_touchpad: has_abs("ABS_X") && has_abs("ABS_Y") && has_key("BTN_TOOL_FINGER"),
        is_touchscreen: has_abs("ABS_MT_POSITION_X") && has_abs("ABS_MT_POSITION_Y"),
        is_joystick: has_abs("ABS_X") && has_key("BTN_TRIGGER"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifies_keyboard() {
        let caps = InputCapabilities {
            keys: BTreeSet::from(["KEY_A".into()]),
            relative_axes: BTreeSet::new(),
            absolute_axes: BTreeSet::new(),
            switches: BTreeSet::new(),
        };
        assert!(classify_input(&caps).is_keyboard);
    }
    #[test]
    fn identifies_mouse() {
        let caps = InputCapabilities {
            keys: BTreeSet::from(["BTN_LEFT".into()]),
            relative_axes: BTreeSet::from(["REL_X".into(), "REL_Y".into()]),
            absolute_axes: BTreeSet::new(),
            switches: BTreeSet::new(),
        };
        assert!(classify_input(&caps).is_mouse);
    }
    #[test]
    fn identifies_touchscreen() {
        let caps = InputCapabilities {
            keys: BTreeSet::new(),
            relative_axes: BTreeSet::new(),
            absolute_axes: BTreeSet::from(["ABS_MT_POSITION_X".into(), "ABS_MT_POSITION_Y".into()]),
            switches: BTreeSet::new(),
        };
        assert!(classify_input(&caps).is_touchscreen);
    }
}
