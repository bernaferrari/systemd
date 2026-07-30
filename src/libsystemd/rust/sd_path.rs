// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-path/sd-path.c

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

pub type Result<T> = std::result::Result<T, PathError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    InvalidArgument,
    MissingHome,
    MissingPath,
    NoSuchPath,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SdPath {
    Temporary,
    TemporaryLarge,
    SystemBinaries,
    SystemShared,
    SystemConfiguration,
    SystemRuntime,
    SystemStatePrivate,
    UserBinaries,
    UserShared,
    UserConfiguration,
    UserRuntime,
    UserStateCache,
    UserStatePrivate,
    User,
    UserDocuments,
    UserMusic,
    UserPictures,
    UserVideos,
    UserDownload,
    UserPublic,
    UserTemplates,
    UserDesktop,
    SystemdUtil,
    SearchBinaries,
    SearchShared,
    SearchConfiguration,
    SystemSearchConfiguration,
    SearchBinariesDefault,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathContext {
    pub env: BTreeMap<String, String>,
    pub home_dir: Option<PathBuf>,
    pub xdg_user_dirs: BTreeMap<String, String>,
    pub default_path: Vec<String>,
}

impl PathContext {
    pub fn new(home_dir: Option<PathBuf>) -> Self {
        Self {
            env: BTreeMap::new(),
            home_dir,
            xdg_user_dirs: BTreeMap::new(),
            default_path: vec!["/usr/local/bin".into(), "/usr/bin".into()],
        }
    }

    pub fn lookup(&self, ty: SdPath, suffix: Option<&str>) -> Result<String> {
        match ty {
            SdPath::SearchBinaries
            | SdPath::SearchShared
            | SdPath::SearchConfiguration
            | SdPath::SystemSearchConfiguration
            | SdPath::SearchBinariesDefault => self
                .lookup_strv(ty, suffix)?
                .into_iter()
                .next()
                .ok_or(PathError::NoSuchPath),
            _ => {
                let base = self.base_path(ty)?;
                Ok(apply_suffix(&base, suffix))
            }
        }
    }

    pub fn lookup_strv(&self, ty: SdPath, suffix: Option<&str>) -> Result<Vec<String>> {
        let bases = match ty {
            SdPath::SearchBinaries => self.search_from_environment(
                None,
                Some(".local/bin"),
                Some("PATH"),
                true,
                &["/usr/local/bin", "/usr/bin"],
            )?,
            SdPath::SearchShared => self.search_from_environment(
                Some("XDG_DATA_HOME"),
                Some(".local/share"),
                Some("XDG_DATA_DIRS"),
                false,
                &["/usr/local/share", "/usr/share"],
            )?,
            SdPath::SearchConfiguration => self.search_from_environment(
                Some("XDG_CONFIG_HOME"),
                Some(".config"),
                Some("XDG_CONFIG_DIRS"),
                false,
                &["/etc"],
            )?,
            SdPath::SystemSearchConfiguration => {
                vec!["/etc".into(), "/usr/local/lib".into(), "/usr/lib".into()]
            }
            SdPath::SearchBinariesDefault => self.default_path.clone(),
            _ => vec![self.base_path(ty)?],
        };

        Ok(bases
            .into_iter()
            .map(|base| apply_suffix(&base, suffix))
            .collect())
    }

    fn base_path(&self, ty: SdPath) -> Result<String> {
        match ty {
            SdPath::Temporary => Ok("/tmp".into()),
            SdPath::TemporaryLarge => Ok("/var/tmp".into()),
            SdPath::SystemBinaries => Ok("/usr/bin".into()),
            SdPath::SystemShared => Ok("/usr/share".into()),
            SdPath::SystemConfiguration => Ok("/etc".into()),
            SdPath::SystemRuntime => Ok("/run".into()),
            SdPath::SystemStatePrivate => Ok("/var/lib".into()),
            SdPath::UserBinaries => self.home_path(None, ".local/bin"),
            SdPath::UserShared => self.home_path(Some("XDG_DATA_HOME"), ".local/share"),
            SdPath::UserConfiguration => self.home_path(Some("XDG_CONFIG_HOME"), ".config"),
            SdPath::UserRuntime => self.environment_path(Some("XDG_RUNTIME_DIR"), None),
            SdPath::UserStateCache => self.home_path(Some("XDG_CACHE_HOME"), ".cache"),
            SdPath::UserStatePrivate => self.home_path(Some("XDG_STATE_HOME"), ".local/state"),
            SdPath::User => self.home_string(),
            SdPath::UserDocuments => self.xdg_user_dir_path("XDG_DOCUMENTS_DIR", None),
            SdPath::UserMusic => self.xdg_user_dir_path("XDG_MUSIC_DIR", None),
            SdPath::UserPictures => self.xdg_user_dir_path("XDG_PICTURES_DIR", None),
            SdPath::UserVideos => self.xdg_user_dir_path("XDG_VIDEOS_DIR", None),
            SdPath::UserDownload => self.xdg_user_dir_path("XDG_DOWNLOAD_DIR", None),
            SdPath::UserPublic => self.xdg_user_dir_path("XDG_PUBLICSHARE_DIR", None),
            SdPath::UserTemplates => self.xdg_user_dir_path("XDG_TEMPLATES_DIR", None),
            SdPath::UserDesktop => self.xdg_user_dir_path("XDG_DESKTOP_DIR", Some("Desktop")),
            SdPath::SystemdUtil => Ok("/usr/lib/systemd".into()),
            SdPath::SearchBinaries
            | SdPath::SearchShared
            | SdPath::SearchConfiguration
            | SdPath::SystemSearchConfiguration
            | SdPath::SearchBinariesDefault => Err(PathError::Unsupported),
        }
    }

    fn environment_path(&self, env_name: Option<&str>, fallback: Option<&str>) -> Result<String> {
        if let Some(name) = env_name
            && let Some(value) = self.env.get(name).filter(|value| is_absolute(value))
        {
            return Ok(value.clone());
        }
        fallback.map(ToOwned::to_owned).ok_or(PathError::NoSuchPath)
    }

    fn home_path(&self, env_name: Option<&str>, suffix: &str) -> Result<String> {
        if let Some(name) = env_name
            && let Some(value) = self.env.get(name).filter(|value| is_absolute(value))
        {
            return Ok(value.clone());
        }
        Ok(join_and_simplify(
            self.home_dir.as_ref().ok_or(PathError::MissingHome)?,
            suffix,
        ))
    }

    fn xdg_user_dir_path(&self, field: &str, desktop_fallback: Option<&str>) -> Result<String> {
        if let Some(value) = self.xdg_user_dirs.get(field) {
            if value == "$HOME" {
                return self.home_string();
            }
            if let Some(tail) = value.strip_prefix("$HOME/") {
                return Ok(join_and_simplify(
                    self.home_dir.as_ref().ok_or(PathError::MissingHome)?,
                    tail,
                ));
            }
            if is_absolute(value) {
                return Ok(value.clone());
            }
        }

        if let Some(suffix) = desktop_fallback {
            return Ok(join_and_simplify(
                self.home_dir.as_ref().ok_or(PathError::MissingHome)?,
                suffix,
            ));
        }

        self.home_string()
    }

    fn home_string(&self) -> Result<String> {
        self.home_dir
            .as_ref()
            .and_then(|path| path.to_str())
            .map(ToOwned::to_owned)
            .ok_or(PathError::MissingHome)
    }

    fn search_from_environment(
        &self,
        env_home: Option<&str>,
        home_suffix: Option<&str>,
        env_search: Option<&str>,
        env_search_sufficient: bool,
        defaults: &[&str],
    ) -> Result<Vec<String>> {
        let mut values = if let Some(name) = env_search {
            self.env
                .get(name)
                .map(|value| split_colon_list(value))
                .filter(|items| !items.is_empty())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        if env_search_sufficient && !values.is_empty() {
            return Ok(values);
        }

        values.extend(defaults.iter().map(|value| (*value).to_string()));

        if let Some(home) = self.home_candidate(env_home, home_suffix) {
            values.insert(0, home);
        }

        values.retain(|value| is_absolute(value));
        values.dedup();

        if values.is_empty() {
            return Err(PathError::MissingPath);
        }

        Ok(values)
    }

    fn home_candidate(&self, env_home: Option<&str>, home_suffix: Option<&str>) -> Option<String> {
        if let Some(name) = env_home
            && let Some(value) = self.env.get(name).filter(|value| is_absolute(value))
        {
            return Some(value.clone());
        }

        home_suffix.and_then(|suffix| {
            self.home_dir
                .as_ref()
                .map(|hd| join_and_simplify(hd, suffix))
        })
    }
}

fn split_colon_list(value: &str) -> Vec<String> {
    value
        .split(':')
        .filter(|segment| !segment.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn apply_suffix(base: &str, suffix: Option<&str>) -> String {
    match suffix {
        Some(suffix) if !suffix.is_empty() => join_and_simplify(Path::new(base), suffix),
        _ => simplify_path(Path::new(base)),
    }
}

fn join_and_simplify(base: &Path, suffix: &str) -> String {
    simplify_path(&base.join(suffix))
}

fn simplify_path(path: &Path) -> String {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        "/".into()
    } else {
        out.to_string_lossy().into_owned()
    }
}

fn is_absolute(value: &str) -> bool {
    value.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> PathContext {
        let mut ctx = PathContext::new(Some(PathBuf::from("/home/test")));
        ctx.default_path = vec!["/usr/local/bin".into(), "/usr/bin".into()];
        ctx
    }

    #[test]
    fn uses_runtime_dir_from_environment() {
        let mut context = ctx();
        context
            .env
            .insert("XDG_RUNTIME_DIR".into(), "/run/user/1000".into());
        assert_eq!(
            context.lookup(SdPath::UserRuntime, None).unwrap(),
            "/run/user/1000"
        );
    }

    #[test]
    fn falls_back_to_home_based_user_config() {
        assert_eq!(
            ctx().lookup(SdPath::UserConfiguration, None).unwrap(),
            "/home/test/.config"
        );
    }

    #[test]
    fn xdg_user_dirs_support_home_expansion() {
        let mut context = ctx();
        context
            .xdg_user_dirs
            .insert("XDG_DOWNLOAD_DIR".into(), "$HOME/Downloads".into());
        assert_eq!(
            context.lookup(SdPath::UserDownload, None).unwrap(),
            "/home/test/Downloads"
        );
    }

    #[test]
    fn desktop_defaults_to_home_desktop() {
        assert_eq!(
            ctx().lookup(SdPath::UserDesktop, None).unwrap(),
            "/home/test/Desktop"
        );
    }

    #[test]
    fn shared_search_prepends_xdg_data_home() {
        let mut context = ctx();
        context
            .env
            .insert("XDG_DATA_HOME".into(), "/tmp/data".into());
        assert_eq!(
            context.lookup_strv(SdPath::SearchShared, None).unwrap()[0],
            "/tmp/data"
        );
    }

    #[test]
    fn path_environment_is_sufficient_for_binary_search() {
        let mut context = ctx();
        context
            .env
            .insert("PATH".into(), "/opt/bin:/usr/bin".into());
        assert_eq!(
            context.lookup_strv(SdPath::SearchBinaries, None).unwrap(),
            vec!["/opt/bin", "/usr/bin"]
        );
    }

    #[test]
    fn lookup_applies_suffix_and_simplifies() {
        assert_eq!(
            ctx()
                .lookup(SdPath::SystemConfiguration, Some("systemd/../tmpfiles.d"))
                .unwrap(),
            "/etc/tmpfiles.d"
        );
    }

    #[test]
    fn missing_home_is_reported() {
        let context = PathContext::new(None);
        assert_eq!(
            context.lookup(SdPath::User, None),
            Err(PathError::MissingHome)
        );
    }
}
