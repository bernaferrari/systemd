// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-button.c

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ButtonModifierMask: u32 {
        const LEFT_SHIFT  = 1 << 0;
        const RIGHT_SHIFT = 1 << 1;
        const LEFT_CTRL   = 1 << 2;
        const RIGHT_CTRL  = 1 << 3;
        const LEFT_ALT    = 1 << 4;
        const RIGHT_ALT   = 1 << 5;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonKey {
    Power,
    Power2,
    Reboot,
    Suspend,
    LeftShift,
    RightShift,
    LeftCtrl,
    RightCtrl,
    LeftAlt,
    RightAlt,
    Esc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button {
    pub name: String,
    pub pressed: Vec<ButtonKey>,
    pub modifiers: ButtonModifierMask,
}

impl Button {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pressed: Vec::new(),
            modifiers: ButtonModifierMask::empty(),
        }
    }

    pub fn press(&mut self, key: ButtonKey) {
        if !self.pressed.contains(&key) {
            self.pressed.push(key);
        }
        self.modifiers = update_modifier_mask(self.modifiers, key, true);
    }

    pub fn release(&mut self, key: ButtonKey) {
        self.pressed.retain(|candidate| candidate != &key);
        self.modifiers = update_modifier_mask(self.modifiers, key, false);
    }
}

pub fn update_modifier_mask(
    mut mask: ButtonModifierMask,
    key: ButtonKey,
    pressed: bool,
) -> ButtonModifierMask {
    let flag = match key {
        ButtonKey::LeftShift => Some(ButtonModifierMask::LEFT_SHIFT),
        ButtonKey::RightShift => Some(ButtonModifierMask::RIGHT_SHIFT),
        ButtonKey::LeftCtrl => Some(ButtonModifierMask::LEFT_CTRL),
        ButtonKey::RightCtrl => Some(ButtonModifierMask::RIGHT_CTRL),
        ButtonKey::LeftAlt => Some(ButtonModifierMask::LEFT_ALT),
        ButtonKey::RightAlt => Some(ButtonModifierMask::RIGHT_ALT),
        _ => None,
    };

    if let Some(flag) = flag {
        if pressed {
            mask.insert(flag);
        } else {
            mask.remove(flag);
        }
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modifier_tracking_matches_key_state() {
        let mut button = Button::new("lid");
        button.press(ButtonKey::LeftShift);
        assert!(button.modifiers.contains(ButtonModifierMask::LEFT_SHIFT));
        button.release(ButtonKey::LeftShift);
        assert!(button.modifiers.is_empty());
    }
}
