// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-keyboard.c
//
// Keyboard map normalization helpers.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyboardConfig {
    pub keymap: String,
    pub layout: String,
    pub variant: Option<String>,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyboardError { EmptyKeymap, EmptyLayout }
pub type Result<T> = std::result::Result<T, KeyboardError>;

pub fn normalize_keyboard_config(config: KeyboardConfig) -> Result<KeyboardConfig> {
    if config.keymap.trim().is_empty() { return Err(KeyboardError::EmptyKeymap); }
    if config.layout.trim().is_empty() { return Err(KeyboardError::EmptyLayout); }
    Ok(KeyboardConfig {
        keymap: config.keymap.trim().to_ascii_lowercase(),
        layout: config.layout.trim().to_ascii_lowercase(),
        variant: config.variant.map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty()),
        options: config.options.into_iter().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect(),
    })
}

pub fn export_keyboard_properties(config: &KeyboardConfig) -> BTreeMap<String, String> {
    let mut map = BTreeMap::from([("ID_INPUT_KEYBOARD".into(), "1".into()), ("XKBLAYOUT".into(), config.layout.clone())]);
    map.insert("KEYMAP".into(), config.keymap.clone());
    if let Some(variant) = &config.variant { map.insert("XKBVARIANT".into(), variant.clone()); }
    if !config.options.is_empty() { map.insert("XKBOPTIONS".into(), config.options.join(",")); }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn normalizes_case_and_whitespace() { let cfg = normalize_keyboard_config(KeyboardConfig { keymap: " us ".into(), layout: " DE ".into(), variant: Some(" nodeadkeys ".into()), options: vec![" grp:alt_shift_toggle ".into()] }).unwrap(); assert_eq!(cfg.keymap, "us"); assert_eq!(cfg.layout, "de"); assert_eq!(cfg.variant.as_deref(), Some("nodeadkeys")); }
    #[test] fn exports_properties() { let cfg = normalize_keyboard_config(KeyboardConfig { keymap: "us".into(), layout: "us".into(), variant: None, options: vec![] }).unwrap(); let props = export_keyboard_properties(&cfg); assert_eq!(props["ID_INPUT_KEYBOARD"], "1"); }
    #[test] fn rejects_empty_layout() { assert_eq!(normalize_keyboard_config(KeyboardConfig { keymap: "us".into(), layout: " ".into(), variant: None, options: vec![] }), Err(KeyboardError::EmptyLayout)); }
}
