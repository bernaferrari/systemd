// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/vconsole-util.c

use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct X11Context {
    pub layout: Option<String>,
    pub model: Option<String>,
    pub variant: Option<String>,
    pub options: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VCContext {
    pub keymap: Option<String>,
    pub toggle: Option<String>,
}

impl X11Context {
    pub fn clear(&mut self) {
        self.layout = None;
        self.model = None;
        self.variant = None;
        self.options = None;
    }

    pub fn replace(&mut self, other: X11Context) {
        *self = other;
    }

    pub fn isempty(&self) -> bool {
        self.layout.as_deref().is_none_or(str::is_empty)
            && self.model.as_deref().is_none_or(str::is_empty)
            && self.variant.as_deref().is_none_or(str::is_empty)
            && self.options.as_deref().is_none_or(str::is_empty)
    }

    pub fn empty_to_null(&mut self) {
        self.layout = filter_empty(&self.layout);
        self.model = filter_empty(&self.model);
        self.variant = filter_empty(&self.variant);
        self.options = filter_empty(&self.options);
    }

    pub fn is_safe(&self) -> bool {
        [
            self.layout.as_ref(),
            self.model.as_ref(),
            self.variant.as_ref(),
            self.options.as_ref(),
        ]
        .into_iter()
        .flatten()
        .all(|v| !v.chars().any(|ch| ch.is_control()))
    }

    pub fn equal(&self, other: &X11Context) -> bool {
        self.layout == other.layout
            && self.model == other.model
            && self.variant == other.variant
            && self.options == other.options
    }

    pub fn copy_from(&mut self, src: &X11Context) -> bool {
        let changed = self.layout != src.layout
            || self.model != src.model
            || self.variant != src.variant
            || self.options != src.options;
        self.layout = src.layout.clone();
        self.model = src.model.clone();
        self.variant = src.variant.clone();
        self.options = src.options.clone();
        changed
    }
}

impl VCContext {
    pub fn clear(&mut self) {
        self.keymap = None;
        self.toggle = None;
    }

    pub fn replace(&mut self, other: VCContext) {
        *self = other;
    }

    pub fn isempty(&self) -> bool {
        self.keymap.as_deref().is_none_or(str::is_empty)
            && self.toggle.as_deref().is_none_or(str::is_empty)
    }

    pub fn empty_to_null(&mut self) {
        self.keymap = filter_empty(&self.keymap);
        self.toggle = filter_empty(&self.toggle);
    }

    pub fn equal(&self, other: &VCContext) -> bool {
        self.keymap == other.keymap && self.toggle == other.toggle
    }

    pub fn copy_from(&mut self, src: &VCContext) -> bool {
        let changed = self.keymap != src.keymap || self.toggle != src.toggle;
        self.keymap = src.keymap.clone();
        self.toggle = src.toggle.clone();
        changed
    }
}

fn filter_empty(s: &Option<String>) -> Option<String> {
    s.as_ref().filter(|v| !v.is_empty()).cloned()
}

pub fn startswith_comma(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(','))
}

pub fn x11_context_isempty(xc: &X11Context) -> bool {
    xc.isempty()
}

pub fn vc_context_isempty(vc: &VCContext) -> bool {
    vc.isempty()
}

pub fn x11_context_is_safe(xc: &X11Context) -> bool {
    xc.is_safe()
}

pub fn read_mapping_file(path: &Path) -> io::Result<Vec<Vec<String>>> {
    let mut result = Vec::new();
    for line in fs::read_to_string(path)?.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        result.push(line.split_whitespace().map(str::to_string).collect());
    }
    Ok(result)
}

fn read_next_mapping_lines<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    min_fields: usize,
    max_fields: usize,
) -> Option<Vec<String>> {
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let fields: Vec<String> = trimmed.split_whitespace().map(str::to_string).collect();
        if fields.len() >= min_fields && fields.len() <= max_fields {
            return Some(fields);
        }
    }
    None
}

fn empty_or_dash_to_null(s: &str) -> Option<String> {
    match s {
        "" | "-" => None,
        v => Some(v.to_string()),
    }
}

const DEFAULT_KBD_MODEL_MAP: &str = "/usr/share/systemd/kbd-model-map";
const DEFAULT_LANGUAGE_FALLBACK_MAP: &str = "/usr/share/systemd/language-fallback-map";

fn kbd_model_map_path() -> String {
    std::env::var("SYSTEMD_KBD_MODEL_MAP").unwrap_or_else(|_| DEFAULT_KBD_MODEL_MAP.to_string())
}

fn language_fallback_map_path() -> String {
    std::env::var("SYSTEMD_LANGUAGE_FALLBACK_MAP")
        .unwrap_or_else(|_| DEFAULT_LANGUAGE_FALLBACK_MAP.to_string())
}

const KBD_KEYMAP_DIRS: &[&str] = &[
    "/usr/share/keymaps/",
    "/usr/share/kbd/keymaps/",
    "/usr/lib/kbd/keymaps/",
];

fn keymap_directories() -> Vec<String> {
    if let Ok(dirs) = std::env::var("SYSTEMD_KEYMAP_DIRECTORIES") {
        dirs.split(':').map(str::to_string).collect()
    } else {
        KBD_KEYMAP_DIRS.iter().map(|s| s.to_string()).collect()
    }
}

pub fn find_converted_keymap(xc: &X11Context) -> Option<String> {
    let layout = xc.layout.as_deref()?;

    let name = if let Some(variant) = xc.variant.as_deref() {
        format!("{layout}-{variant}")
    } else {
        layout.to_string()
    };

    let uncompressed = format!("xkb/{name}.map");
    let compressed = format!("xkb/{name}.map.gz");

    for dir in keymap_directories() {
        let base = Path::new(&dir);
        if base.join(&uncompressed).exists() || base.join(&compressed).exists() {
            return Some(name);
        }
    }

    None
}

pub fn find_legacy_keymap(xc: &X11Context) -> Option<String> {
    let layout = xc.layout.as_deref()?;

    let map_path = kbd_model_map_path();
    let content = fs::read_to_string(&map_path).ok()?;
    let mut lines = content.lines();

    let mut best_matching: u32 = 0;
    let mut new_keymap: Option<String> = None;

    while let Some(a) = read_next_mapping_lines(&mut lines, 5, usize::MAX) {
        let matching = compute_matching_score(
            layout,
            xc.model.as_deref(),
            xc.variant.as_deref(),
            xc.options.as_deref(),
            &a,
        );

        if matching >= best_matching.max(1) {
            if matching > best_matching {
                best_matching = matching;
                new_keymap = Some(a[0].clone());
            }
        }
    }

    if best_matching < 9 {
        let l = layout.split(',').next().unwrap_or("");
        let v = xc.variant.as_deref().and_then(|s| s.split(',').next());

        let search_xc = X11Context {
            layout: Some(l.to_string()),
            variant: v.map(str::to_string),
            ..X11Context::default()
        };

        if let Some(converted) = find_converted_keymap(&search_xc) {
            new_keymap = Some(converted);
        }
    }

    new_keymap
}

fn compute_matching_score(
    layout: &str,
    model: Option<&str>,
    variant: Option<&str>,
    options: Option<&str>,
    a: &[String],
) -> u32 {
    let mut matching: u32 = 0;

    if layout == a[1] {
        matching = 10;
    } else {
        let reversed: String = a[1].split(',').rev().collect::<Vec<_>>().join(",");
        if startswith_comma(&reversed, layout) {
            matching = 9;
        } else if startswith_comma(layout, &a[1]) {
            matching = 5;
        } else {
            let first_layout = a[1].split(',').next().unwrap_or("");
            if startswith_comma(layout, first_layout) {
                matching = 1;
            }
        }
    }

    if matching > 0 {
        if model == Some(&a[2]) {
            matching += 1;

            let variant_matches = variant == Some(&a[3])
                || (variant.is_none_or(|v| v.is_empty() || v.ends_with(','))
                    && (a[3] == "-" || a[3].is_empty()));
            if variant_matches {
                matching += 1;

                if options == Some(&a[4])
                    || (options.is_none_or(|o| o.is_empty()) && a[4].is_empty())
                {
                    matching += 1;
                }
            }
        }
    }

    matching
}

pub fn find_language_fallback(lang: &str) -> Option<String> {
    let map_path = language_fallback_map_path();
    let content = fs::read_to_string(&map_path).ok()?;
    let mut lines = content.lines();

    while let Some(a) = read_next_mapping_lines(&mut lines, 2, 2) {
        if a[0] == lang {
            return Some(a[1].clone());
        }
    }

    None
}

pub fn vconsole_convert_to_x11(vc: &VCContext) -> X11Context {
    let keymap = match vc.keymap.as_deref() {
        Some(k) if !k.is_empty() => k,
        _ => return X11Context::default(),
    };

    let map_path = kbd_model_map_path();
    if let Ok(content) = fs::read_to_string(&map_path) {
        let mut lines = content.lines();

        while let Some(a) = read_next_mapping_lines(&mut lines, 5, usize::MAX) {
            if a[0] == keymap {
                let xc = X11Context {
                    layout: empty_or_dash_to_null(&a[1]),
                    model: empty_or_dash_to_null(&a[2]),
                    variant: empty_or_dash_to_null(&a[3]),
                    options: empty_or_dash_to_null(&a[4]),
                };

                return xc;
            }
        }
    }

    let (xlayout, xvariant) = match keymap.split_once('-') {
        Some((l, v)) => (l.to_string(), Some(v.to_string())),
        None => (keymap.to_string(), None),
    };

    let xc_with_variant = X11Context {
        layout: Some(xlayout.clone()),
        model: Some("microsoftpro".to_string()),
        variant: xvariant.clone(),
        options: Some("terminate:ctrl_alt_bksp".to_string()),
    };

    if find_converted_keymap(&xc_with_variant).is_some() {
        return xc_with_variant;
    }

    let xc_no_variant = X11Context {
        layout: Some(xlayout),
        model: Some("microsoftpro".to_string()),
        variant: None,
        options: Some("terminate:ctrl_alt_bksp".to_string()),
    };

    if find_converted_keymap(&xc_no_variant).is_some() {
        return xc_no_variant;
    }

    X11Context::default()
}

pub fn x11_convert_to_vconsole(xc: &X11Context) -> VCContext {
    let layout = match xc.layout.as_deref() {
        Some(l) if !l.is_empty() => l,
        _ => return VCContext::default(),
    };

    if let Some(keymap) = find_converted_keymap(xc) {
        return VCContext {
            keymap: Some(keymap),
            toggle: None,
        };
    }

    if let Some(keymap) = find_legacy_keymap(xc) {
        return VCContext {
            keymap: Some(keymap),
            toggle: None,
        };
    }

    if xc.variant.is_some() {
        let xc_no_variant = X11Context {
            layout: Some(layout.to_string()),
            model: xc.model.clone(),
            variant: None,
            options: xc.options.clone(),
        };

        if let Some(keymap) = find_converted_keymap(&xc_no_variant) {
            return VCContext {
                keymap: Some(keymap),
                toggle: None,
            };
        }
    }

    VCContext::default()
}

pub fn vconsole_serialize(vc: &VCContext, xc: &X11Context) -> Vec<(String, String)> {
    let mut env = Vec::new();

    if let Some(v) = &vc.keymap {
        if !v.is_empty() {
            env.push(("KEYMAP".to_string(), v.clone()));
        }
    }
    if let Some(v) = &vc.toggle {
        if !v.is_empty() {
            env.push(("KEYMAP_TOGGLE".to_string(), v.clone()));
        }
    }
    if let Some(v) = &xc.layout {
        if !v.is_empty() {
            env.push(("XKBLAYOUT".to_string(), v.clone()));
        }
    }
    if let Some(v) = &xc.model {
        if !v.is_empty() {
            env.push(("XKBMODEL".to_string(), v.clone()));
        }
    }
    if let Some(v) = &xc.variant {
        if !v.is_empty() {
            env.push(("XKBVARIANT".to_string(), v.clone()));
        }
    }
    if let Some(v) = &xc.options {
        if !v.is_empty() {
            env.push(("XKBOPTIONS".to_string(), v.clone()));
        }
    }

    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TestEnvironment;

    #[test]
    fn startswith_comma_basic() {
        assert!(startswith_comma("us,winkeys", "us"));
        assert!(startswith_comma("us", "us"));
        assert!(!startswith_comma("usa", "us"));
        assert!(!startswith_comma("other", "us"));
        assert!(startswith_comma("us,gb", "us"));
        assert!(!startswith_comma("gb,us", "us"));
    }

    #[test]
    fn x11_context_empty_default() {
        assert!(x11_context_isempty(&X11Context::default()));
    }

    #[test]
    fn x11_context_not_empty() {
        let xc = X11Context {
            layout: Some("us".to_string()),
            ..X11Context::default()
        };
        assert!(!x11_context_isempty(&xc));
    }

    #[test]
    fn x11_context_empty_strings_count_as_empty() {
        let xc = X11Context {
            layout: Some(String::new()),
            model: Some(String::new()),
            variant: None,
            options: None,
        };
        assert!(x11_context_isempty(&xc));
    }

    #[test]
    fn x11_context_is_safe_rejects_control_chars() {
        let safe = X11Context {
            layout: Some("us".to_string()),
            ..X11Context::default()
        };
        assert!(x11_context_is_safe(&safe));

        let unsafe_xc = X11Context {
            layout: Some("us\n".to_string()),
            ..X11Context::default()
        };
        assert!(!x11_context_is_safe(&unsafe_xc));
    }

    #[test]
    fn x11_context_equal() {
        let a = X11Context {
            layout: Some("us".to_string()),
            model: Some("pc105".to_string()),
            ..X11Context::default()
        };
        let b = X11Context {
            layout: Some("us".to_string()),
            model: Some("pc105".to_string()),
            ..X11Context::default()
        };
        assert!(a.equal(&b));
    }

    #[test]
    fn x11_context_copy_from() {
        let mut dest = X11Context::default();
        let src = X11Context {
            layout: Some("us".to_string()),
            model: Some("pc105".to_string()),
            variant: Some("intl".to_string()),
            options: None,
        };
        assert!(dest.copy_from(&src));
        assert_eq!(dest.layout, Some("us".to_string()));
        assert_eq!(dest.model, Some("pc105".to_string()));
        assert_eq!(dest.variant, Some("intl".to_string()));
        assert!(dest.options.is_none());
    }

    #[test]
    fn x11_context_copy_from_unchanged() {
        let src = X11Context {
            layout: Some("us".to_string()),
            ..X11Context::default()
        };
        let mut dest = src.clone();
        assert!(!dest.copy_from(&src));
    }

    #[test]
    fn x11_context_empty_to_null() {
        let mut xc = X11Context {
            layout: Some(String::new()),
            model: Some("pc105".to_string()),
            variant: Some(String::new()),
            options: None,
        };
        xc.empty_to_null();
        assert!(xc.layout.is_none());
        assert_eq!(xc.model.as_deref(), Some("pc105"));
        assert!(xc.variant.is_none());
        assert!(xc.options.is_none());
    }

    #[test]
    fn x11_context_replace() {
        let mut dest = X11Context {
            layout: Some("old".to_string()),
            ..X11Context::default()
        };
        let src = X11Context {
            layout: Some("new".to_string()),
            model: Some("m".to_string()),
            ..X11Context::default()
        };
        dest.replace(src);
        assert_eq!(dest.layout.as_deref(), Some("new"));
        assert_eq!(dest.model.as_deref(), Some("m"));
    }

    #[test]
    fn x11_context_clear() {
        let mut xc = X11Context {
            layout: Some("us".to_string()),
            model: Some("pc105".to_string()),
            variant: Some("intl".to_string()),
            options: Some("grp:alt_shift_toggle".to_string()),
        };
        xc.clear();
        assert!(x11_context_isempty(&xc));
    }

    #[test]
    fn vc_context_empty_default() {
        assert!(vc_context_isempty(&VCContext::default()));
    }

    #[test]
    fn vc_context_not_empty() {
        let vc = VCContext {
            keymap: Some("us".to_string()),
            ..VCContext::default()
        };
        assert!(!vc_context_isempty(&vc));
    }

    #[test]
    fn vc_context_equal() {
        let a = VCContext {
            keymap: Some("us".to_string()),
            toggle: Some("grp:alt_shift_toggle".to_string()),
        };
        let b = VCContext {
            keymap: Some("us".to_string()),
            toggle: Some("grp:alt_shift_toggle".to_string()),
        };
        assert!(a.equal(&b));
    }

    #[test]
    fn vc_context_copy_from() {
        let mut dest = VCContext::default();
        let src = VCContext {
            keymap: Some("us".to_string()),
            toggle: Some("grp:alt_shift_toggle".to_string()),
        };
        assert!(dest.copy_from(&src));
        assert_eq!(dest.keymap.as_deref(), Some("us"));
        assert_eq!(dest.toggle.as_deref(), Some("grp:alt_shift_toggle"));
    }

    #[test]
    fn vc_context_replace() {
        let mut dest = VCContext {
            keymap: Some("old".to_string()),
            toggle: None,
        };
        let src = VCContext {
            keymap: Some("new".to_string()),
            toggle: Some("t".to_string()),
        };
        dest.replace(src);
        assert_eq!(dest.keymap.as_deref(), Some("new"));
        assert_eq!(dest.toggle.as_deref(), Some("t"));
    }

    #[test]
    fn vc_context_empty_to_null() {
        let mut vc = VCContext {
            keymap: Some(String::new()),
            toggle: Some("t".to_string()),
        };
        vc.empty_to_null();
        assert!(vc.keymap.is_none());
        assert_eq!(vc.toggle.as_deref(), Some("t"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn read_mapping_file_skips_comments_and_blanks() {
        let dir = std::env::temp_dir().join("vconsole_test_mapping");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.map");
        fs::write(&path, "# comment\n\nkeymap1 layout1 model1 variant1 options1\nkeymap2 layout2 model2 variant2 options2\n").unwrap();

        let rows = read_mapping_file(&path).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][0], "keymap1");
        assert_eq!(rows[1][0], "keymap2");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_mapping_file_nonexistent() {
        assert!(read_mapping_file(Path::new("/nonexistent/path/map")).is_err());
    }

    #[test]
    fn vconsole_serialize_populates_env() {
        let vc = VCContext {
            keymap: Some("us".to_string()),
            toggle: Some("grp:alt_shift_toggle".to_string()),
        };
        let xc = X11Context {
            layout: Some("us".to_string()),
            model: Some("pc105".to_string()),
            variant: Some("intl".to_string()),
            options: Some("terminate:ctrl_alt_bksp".to_string()),
        };
        let env = vconsole_serialize(&vc, &xc);
        let map: std::collections::HashMap<String, String> = env.into_iter().collect();
        assert_eq!(map.get("KEYMAP").unwrap(), "us");
        assert_eq!(map.get("KEYMAP_TOGGLE").unwrap(), "grp:alt_shift_toggle");
        assert_eq!(map.get("XKBLAYOUT").unwrap(), "us");
        assert_eq!(map.get("XKBMODEL").unwrap(), "pc105");
        assert_eq!(map.get("XKBVARIANT").unwrap(), "intl");
        assert_eq!(map.get("XKBOPTIONS").unwrap(), "terminate:ctrl_alt_bksp");
    }

    #[test]
    fn vconsole_serialize_skips_empty() {
        let vc = VCContext::default();
        let xc = X11Context {
            layout: Some(String::new()),
            ..X11Context::default()
        };
        let env = vconsole_serialize(&vc, &xc);
        assert!(env.is_empty());
    }

    #[test]
    fn empty_or_dash_to_null_conversions() {
        assert_eq!(empty_or_dash_to_null(""), None);
        assert_eq!(empty_or_dash_to_null("-"), None);
        assert_eq!(empty_or_dash_to_null("us"), Some("us".to_string()));
    }

    #[test]
    fn compute_matching_score_exact_layout() {
        let a = vec![
            "us".to_string(),
            "us".to_string(),
            "pc105".to_string(),
            "".to_string(),
            "".to_string(),
        ];
        let score = compute_matching_score("us", Some("pc105"), None, None, &a);
        assert_eq!(score, 10 + 1 + 1 + 1);
    }

    #[test]
    fn compute_matching_score_reversed_layout() {
        let a = vec![
            "keymap".to_string(),
            "gb,us".to_string(),
            "pc105".to_string(),
            "-".to_string(),
            "".to_string(),
        ];
        let score = compute_matching_score("us", None, None, None, &a);
        assert_eq!(score, 9);
    }

    #[test]
    fn compute_matching_score_no_match() {
        let a = vec![
            "fr".to_string(),
            "fr".to_string(),
            "pc105".to_string(),
            "".to_string(),
            "".to_string(),
        ];
        let score = compute_matching_score("us", None, None, None, &a);
        assert_eq!(score, 0);
    }

    #[test]
    fn vconsole_convert_to_x11_empty_keymap() {
        let vc = VCContext::default();
        let xc = vconsole_convert_to_x11(&vc);
        assert!(xc.isempty());
    }

    #[test]
    fn x11_convert_to_vconsole_empty_layout() {
        let xc = X11Context::default();
        let vc = x11_convert_to_vconsole(&xc);
        assert!(vc.isempty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn find_language_fallback_with_test_map() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        let dir = std::env::temp_dir().join("vconsole_test_lang");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lang.map");
        fs::write(&path, "pt_BR br-abnt2\nen_US us\n").unwrap();

        environment.set("SYSTEMD_LANGUAGE_FALLBACK_MAP", &path);
        assert_eq!(
            find_language_fallback("pt_BR"),
            Some("br-abnt2".to_string())
        );
        assert_eq!(find_language_fallback("en_US"), Some("us".to_string()));
        assert_eq!(find_language_fallback("xx_YY"), None);
        fs::remove_dir_all(&dir).unwrap();
    }
}
