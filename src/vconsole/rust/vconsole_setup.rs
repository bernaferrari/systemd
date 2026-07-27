// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/vconsole/vconsole-setup.c

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    MissingConsole,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingConsole => f.write_str("console path is required"),
        }
    }
}

impl std::error::Error for Error {}

pub const DEFAULT_KEYMAP: &str = "us";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Context {
    pub keymap: Option<String>,
    pub keymap_toggle: Option<String>,
    pub font: Option<String>,
    pub font_map: Option<String>,
    pub font_unimap: Option<String>,
}

impl Context {
    pub fn merge_from(&mut self, source: Context, compat: Option<&Context>) {
        merge_slot(
            &mut self.keymap,
            source.keymap,
            compat.and_then(|c| c.keymap.clone()),
        );
        merge_slot(
            &mut self.keymap_toggle,
            source.keymap_toggle,
            compat.and_then(|c| c.keymap_toggle.clone()),
        );
        merge_slot(
            &mut self.font,
            source.font,
            compat.and_then(|c| c.font.clone()),
        );
        merge_slot(
            &mut self.font_map,
            source.font_map,
            compat.and_then(|c| c.font_map.clone()),
        );
        merge_slot(
            &mut self.font_unimap,
            source.font_unimap,
            compat.and_then(|c| c.font_unimap.clone()),
        );
    }
}

fn merge_slot(dest: &mut Option<String>, source: Option<String>, compat: Option<String>) {
    if source.is_some() {
        *dest = source;
    } else if compat.is_some() {
        *dest = compat;
    }
}

pub fn keyboard_command(vc: &str, context: &Context, utf8: bool) -> Result<Option<Vec<String>>> {
    if vc.is_empty() {
        return Err(Error::MissingConsole);
    }
    let keymap = context
        .keymap
        .as_deref()
        .filter(|v| !v.is_empty())
        .unwrap_or(DEFAULT_KEYMAP);
    if keymap == "@kernel" {
        return Ok(None);
    }
    let mut cmd = vec!["loadkeys".into(), "-q".into(), "-C".into(), vc.into()];
    if utf8 {
        cmd.push("-u".into());
    }
    cmd.push(keymap.into());
    if let Some(toggle) = context.keymap_toggle.as_deref().filter(|v| !v.is_empty()) {
        cmd.push(toggle.into());
    }
    Ok(Some(cmd))
}

pub fn font_command(vc: &str, context: &Context) -> Result<Option<Vec<String>>> {
    if vc.is_empty() {
        return Err(Error::MissingConsole);
    }
    let mut cmd = vec!["setfont".into(), "-C".into(), vc.into()];
    if let Some(map) = &context.font_map {
        cmd.extend(["-m".into(), map.clone()]);
    }
    if let Some(unimap) = &context.font_unimap {
        cmd.extend(["-u".into(), unimap.clone()]);
    }
    if let Some(font) = &context.font {
        cmd.push(font.clone());
    }
    if cmd.len() == 3 {
        return Ok(None);
    }
    Ok(Some(cmd))
}

pub fn load_config_layers(
    creds: Context,
    env: Context,
    cmdline: Context,
    cmdline_compat: Option<Context>,
) -> Context {
    let mut merged = Context::default();
    merged.merge_from(creds, None);
    merged.merge_from(env, None);
    merged.merge_from(cmdline, cmdline_compat.as_ref());
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_values_override_destination() {
        let mut dst = Context {
            keymap: Some("de".into()),
            ..Default::default()
        };
        dst.merge_from(
            Context {
                keymap: Some("us".into()),
                ..Default::default()
            },
            None,
        );
        assert_eq!(dst.keymap.as_deref(), Some("us"));
    }
    #[test]
    fn compat_values_fill_missing_source() {
        let mut dst = Context::default();
        dst.merge_from(
            Context::default(),
            Some(&Context {
                font_map: Some("cp437".into()),
                ..Default::default()
            }),
        );
        assert_eq!(dst.font_map.as_deref(), Some("cp437"));
    }
    #[test]
    fn keyboard_command_defaults_keymap() {
        assert_eq!(
            keyboard_command("/dev/tty1", &Context::default(), false)
                .unwrap()
                .unwrap()[4],
            "us"
        );
    }
    #[test]
    fn keyboard_command_supports_utf8() {
        assert!(keyboard_command("/dev/tty1", &Context::default(), true)
            .unwrap()
            .unwrap()
            .contains(&"-u".into()));
    }
    #[test]
    fn keyboard_command_skips_kernel_keymap() {
        assert!(keyboard_command(
            "/dev/tty1",
            &Context {
                keymap: Some("@kernel".into()),
                ..Default::default()
            },
            false
        )
        .unwrap()
        .is_none());
    }
    #[test]
    fn font_command_absent_without_settings() {
        assert!(font_command("/dev/tty1", &Context::default())
            .unwrap()
            .is_none());
    }
    #[test]
    fn font_command_includes_optional_flags() {
        let command = font_command(
            "/dev/tty1",
            &Context {
                font: Some("lat9".into()),
                font_map: Some("8859-15".into()),
                font_unimap: Some("map".into()),
                ..Default::default()
            },
        )
        .unwrap()
        .unwrap();
        assert!(command.contains(&"-m".into()));
        assert!(command.contains(&"-u".into()));
        assert!(command.contains(&"lat9".into()));
    }
    #[test]
    fn config_layers_follow_priority_order() {
        let merged = load_config_layers(
            Context {
                keymap: Some("de".into()),
                ..Default::default()
            },
            Context {
                keymap: Some("fr".into()),
                ..Default::default()
            },
            Context {
                keymap: Some("us".into()),
                ..Default::default()
            },
            None,
        );
        assert_eq!(merged.keymap.as_deref(), Some("us"));
    }
}
