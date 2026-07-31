// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-path/path-lookup.c

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeScope {
    System,
    User,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupPathsFlags(u8);

impl LookupPathsFlags {
    pub const EXCLUDE_GENERATED: Self = Self(1 << 0);
    pub const TEMPORARY_GENERATED: Self = Self(1 << 1);
    pub const SPLIT_USR: Self = Self(1 << 2);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for LookupPathsFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LookupPaths {
    pub search_path: Vec<String>,
    pub persistent_config: Option<String>,
    pub runtime_config: Option<String>,
    pub generator: Option<String>,
    pub generator_early: Option<String>,
    pub generator_late: Option<String>,
    pub transient: Option<String>,
    pub persistent_control: Option<String>,
    pub runtime_control: Option<String>,
    pub persistent_attached: Option<String>,
    pub runtime_attached: Option<String>,
    pub root_dir: Option<String>,
    pub temporary_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Environment {
    pub runtime_directory: Option<String>,
    pub systemd_unit_path: Option<Vec<String>>,
    pub xdg_config_home: Option<String>,
    pub xdg_runtime_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    InvalidScope,
    MissingRuntimeDir,
    Unsupported,
}

pub fn user_search_dirs(suffix: &str) -> (Vec<String>, Vec<String>) {
    (
        vec![format!("$XDG_CONFIG_HOME{suffix}"), "/etc/xdg".to_string()],
        vec![format!("$XDG_DATA_HOME{suffix}"), "/usr/share".to_string()],
    )
}

pub fn config_directory_generic(
    scope: RuntimeScope,
    suffix: &str,
    env: &Environment,
) -> Result<String, LookupError> {
    match scope {
        RuntimeScope::User => Ok(format!(
            "{}/{}",
            env.xdg_config_home
                .clone()
                .unwrap_or_else(|| "~/.config".into()),
            suffix.trim_start_matches('/')
        )),
        RuntimeScope::System => Ok(format!("/etc/{}", suffix.trim_start_matches('/'))),
        RuntimeScope::Global => Err(LookupError::InvalidScope),
    }
}

pub fn runtime_directory_generic(
    scope: RuntimeScope,
    suffix: &str,
    env: &Environment,
) -> Result<String, LookupError> {
    match scope {
        RuntimeScope::User => {
            let base = env
                .xdg_runtime_dir
                .clone()
                .ok_or(LookupError::MissingRuntimeDir)?;
            Ok(format!(
                "{}/{}",
                base.trim_end_matches('/'),
                suffix.trim_start_matches('/')
            ))
        }
        RuntimeScope::System => Ok(format!("/run/{}", suffix.trim_start_matches('/'))),
        RuntimeScope::Global => Err(LookupError::InvalidScope),
    }
}

pub fn runtime_directory(
    scope: RuntimeScope,
    fallback_suffix: &str,
    env: &Environment,
) -> Result<(String, bool), LookupError> {
    if let Some(dir) = &env.runtime_directory {
        return Ok((dir.clone(), false));
    }

    runtime_directory_generic(scope, fallback_suffix, env).map(|dir| (dir, true))
}

pub fn patch_root_prefix(path: Option<String>, root_dir: Option<&str>) -> Option<String> {
    match (path, root_dir) {
        (Some(path), Some(root)) if root != "/" && !root.is_empty() => {
            Some(format!("{}{}", root.trim_end_matches('/'), path))
        }
        (path, _) => path,
    }
}

pub fn generator_binary_paths_internal(
    scope: RuntimeScope,
    env_generator: bool,
) -> Result<Vec<String>, LookupError> {
    match (scope, env_generator) {
        (RuntimeScope::System, false) => Ok(vec![
            "/run/systemd/system-generators".into(),
            "/etc/systemd/system-generators".into(),
            "/usr/local/lib/systemd/system-generators".into(),
            "/usr/lib/systemd/system-generators".into(),
        ]),
        (RuntimeScope::User, false) => Ok(vec![
            "/run/systemd/user-generators".into(),
            "/etc/systemd/user-generators".into(),
            "/usr/local/lib/systemd/user-generators".into(),
            "/usr/lib/systemd/user-generators".into(),
        ]),
        (RuntimeScope::System, true) => Ok(vec![
            "/run/systemd/system-environment-generators".into(),
            "/etc/systemd/system-environment-generators".into(),
            "/usr/local/lib/systemd/system-environment-generators".into(),
            "/usr/lib/systemd/system-environment-generators".into(),
        ]),
        (RuntimeScope::User, true) => Ok(vec![
            "/run/systemd/user-environment-generators".into(),
            "/etc/systemd/user-environment-generators".into(),
            "/usr/local/lib/systemd/user-environment-generators".into(),
            "/usr/lib/systemd/user-environment-generators".into(),
        ]),
        (RuntimeScope::Global, _) => Err(LookupError::Unsupported),
    }
}

pub fn lookup_paths_init(
    scope: RuntimeScope,
    flags: LookupPathsFlags,
    root_dir: Option<&str>,
    env: &Environment,
) -> Result<LookupPaths, LookupError> {
    let (
        persistent_config,
        runtime_config,
        persistent_control,
        runtime_control,
        persistent_attached,
        runtime_attached,
    ) = match scope {
        RuntimeScope::System => (
            Some("/etc/systemd/system".to_string()),
            Some("/run/systemd/system".to_string()),
            Some("/etc/systemd/system.control".to_string()),
            Some("/run/systemd/system.control".to_string()),
            Some("/etc/systemd/system.attached".to_string()),
            Some("/run/systemd/system.attached".to_string()),
        ),
        RuntimeScope::Global => (
            Some("/etc/systemd/user".to_string()),
            Some("/run/systemd/user".to_string()),
            None,
            None,
            None,
            None,
        ),
        RuntimeScope::User => (
            Some(config_directory_generic(
                RuntimeScope::User,
                "systemd/user",
                env,
            )?),
            env.xdg_runtime_dir
                .as_ref()
                .map(|dir| format!("{}/systemd/user", dir)),
            Some(config_directory_generic(
                RuntimeScope::User,
                "systemd/user.control",
                env,
            )?),
            env.xdg_runtime_dir
                .as_ref()
                .map(|dir| format!("{}/systemd/user.control", dir)),
            Some(config_directory_generic(
                RuntimeScope::User,
                "systemd/user.attached",
                env,
            )?),
            env.xdg_runtime_dir
                .as_ref()
                .map(|dir| format!("{}/systemd/user.attached", dir)),
        ),
    };

    let generator = if flags.contains(LookupPathsFlags::EXCLUDE_GENERATED) {
        None
    } else {
        Some(match scope {
            RuntimeScope::System => "/run/systemd/generator".into(),
            RuntimeScope::User => format!(
                "{}/systemd/generator",
                env.xdg_runtime_dir
                    .clone()
                    .ok_or(LookupError::MissingRuntimeDir)?
            ),
            RuntimeScope::Global => return Err(LookupError::Unsupported),
        })
    };
    let generator_early = generator
        .as_ref()
        .map(|path| path.replace("generator", "generator.early"));
    let generator_late = generator
        .as_ref()
        .map(|path| path.replace("generator", "generator.late"));
    let transient = match scope {
        RuntimeScope::System => Some("/run/systemd/transient".into()),
        RuntimeScope::User => env
            .xdg_runtime_dir
            .as_ref()
            .map(|dir| format!("{}/systemd/transient", dir)),
        RuntimeScope::Global => None,
    };

    let mut search = env.systemd_unit_path.clone().unwrap_or_else(|| {
        let mut defaults = match scope {
            RuntimeScope::System => vec![
                "/etc/systemd/system.control".into(),
                "/run/systemd/system.control".into(),
                "/run/systemd/transient".into(),
                "/run/systemd/generator.early".into(),
                "/etc/systemd/system".into(),
                "/etc/systemd/system.attached".into(),
                "/run/systemd/system".into(),
                "/run/systemd/system.attached".into(),
                "/run/systemd/generator".into(),
                "/usr/local/lib/systemd/system".into(),
                "/usr/lib/systemd/system".into(),
                "/run/systemd/generator.late".into(),
            ],
            RuntimeScope::Global => vec![
                "/etc/systemd/user".into(),
                "/run/systemd/user".into(),
                "/usr/local/share/systemd/user".into(),
                "/usr/share/systemd/user".into(),
                "/usr/local/lib/systemd/user".into(),
                "/usr/lib/systemd/user".into(),
            ],
            RuntimeScope::User => vec![
                persistent_control.clone().unwrap(),
                runtime_control.clone().unwrap_or_default(),
                transient.clone().unwrap_or_default(),
                generator_early.clone().unwrap_or_default(),
                persistent_config.clone().unwrap(),
                persistent_attached.clone().unwrap(),
                runtime_config.clone().unwrap_or_default(),
                runtime_attached.clone().unwrap_or_default(),
                generator.clone().unwrap_or_default(),
                generator_late.clone().unwrap_or_default(),
            ],
        };

        // Match path-lookup.c: /lib is a legacy split-/usr fallback and must
        // appear immediately before generator.late rather than shadowing the
        // regular /usr unit directory on unified-/usr systems.
        if scope == RuntimeScope::System && flags.contains(LookupPathsFlags::SPLIT_USR) {
            let late = defaults
                .pop()
                .expect("system defaults include generator.late");
            defaults.push("/lib/systemd/system".into());
            defaults.push(late);
        }
        defaults
    });

    let mut uniq = BTreeSet::new();
    search.retain(|path| !path.is_empty() && uniq.insert(path.clone()));

    Ok(LookupPaths {
        search_path: search
            .into_iter()
            .filter_map(|path| patch_root_prefix(Some(path), root_dir))
            .collect(),
        persistent_config: patch_root_prefix(persistent_config, root_dir),
        runtime_config: patch_root_prefix(runtime_config, root_dir),
        generator: patch_root_prefix(generator, root_dir),
        generator_early: patch_root_prefix(generator_early, root_dir),
        generator_late: patch_root_prefix(generator_late, root_dir),
        transient: patch_root_prefix(transient, root_dir),
        persistent_control: patch_root_prefix(persistent_control, root_dir),
        runtime_control: patch_root_prefix(runtime_control, root_dir),
        persistent_attached: patch_root_prefix(persistent_attached, root_dir),
        runtime_attached: patch_root_prefix(runtime_attached, root_dir),
        root_dir: root_dir.map(str::to_string),
        temporary_dir: flags
            .contains(LookupPathsFlags::TEMPORARY_GENERATED)
            .then(|| "/tmp/systemd-temporary-XXXXXX".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Environment {
        Environment {
            runtime_directory: None,
            systemd_unit_path: None,
            xdg_config_home: Some("/home/test/.config".into()),
            xdg_runtime_dir: Some("/run/user/1000".into()),
        }
    }

    #[test]
    fn system_config_directory_is_in_etc() {
        assert_eq!(
            config_directory_generic(RuntimeScope::System, "systemd/system", &env()).unwrap(),
            "/etc/systemd/system"
        );
    }

    #[test]
    fn user_runtime_directory_uses_xdg() {
        assert_eq!(
            runtime_directory_generic(RuntimeScope::User, "systemd", &env()).unwrap(),
            "/run/user/1000/systemd"
        );
    }

    #[test]
    fn runtime_directory_prefers_environment() {
        let mut env = env();
        env.runtime_directory = Some("/run/custom".into());
        assert_eq!(
            runtime_directory(RuntimeScope::System, "systemd", &env).unwrap(),
            ("/run/custom".into(), false)
        );
    }

    #[test]
    fn root_prefix_is_patched() {
        assert_eq!(
            patch_root_prefix(Some("/etc/systemd/system".into()), Some("/mnt/root")),
            Some("/mnt/root/etc/systemd/system".into())
        );
    }

    #[test]
    fn system_generator_paths_exist() {
        assert_eq!(
            generator_binary_paths_internal(RuntimeScope::System, false).unwrap()[0],
            "/run/systemd/system-generators"
        );
    }

    #[test]
    fn global_env_generator_is_unsupported() {
        assert!(generator_binary_paths_internal(RuntimeScope::Global, true).is_err());
    }

    #[test]
    fn system_lookup_contains_usr_lib() {
        let lp =
            lookup_paths_init(RuntimeScope::System, LookupPathsFlags(0), None, &env()).unwrap();
        assert!(
            lp.search_path
                .iter()
                .any(|path| path == "/usr/lib/systemd/system")
        );
    }

    #[test]
    fn system_lookup_matches_c_default_order() {
        let lp =
            lookup_paths_init(RuntimeScope::System, LookupPathsFlags(0), None, &env()).unwrap();
        assert_eq!(
            lp.search_path,
            [
                "/etc/systemd/system.control",
                "/run/systemd/system.control",
                "/run/systemd/transient",
                "/run/systemd/generator.early",
                "/etc/systemd/system",
                "/etc/systemd/system.attached",
                "/run/systemd/system",
                "/run/systemd/system.attached",
                "/run/systemd/generator",
                "/usr/local/lib/systemd/system",
                "/usr/lib/systemd/system",
                "/run/systemd/generator.late",
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn system_lookup_adds_legacy_lib_only_for_split_usr() {
        let lp = lookup_paths_init(
            RuntimeScope::System,
            LookupPathsFlags::SPLIT_USR,
            None,
            &env(),
        )
        .unwrap();
        assert_eq!(
            lp.search_path,
            [
                "/etc/systemd/system.control",
                "/run/systemd/system.control",
                "/run/systemd/transient",
                "/run/systemd/generator.early",
                "/etc/systemd/system",
                "/etc/systemd/system.attached",
                "/run/systemd/system",
                "/run/systemd/system.attached",
                "/run/systemd/generator",
                "/usr/local/lib/systemd/system",
                "/usr/lib/systemd/system",
                "/lib/systemd/system",
                "/run/systemd/generator.late",
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn user_lookup_respects_root_prefix() {
        let lp = lookup_paths_init(
            RuntimeScope::User,
            LookupPathsFlags::EXCLUDE_GENERATED,
            Some("/image"),
            &env(),
        )
        .unwrap();
        assert!(
            lp.search_path
                .iter()
                .all(|path| path.starts_with("/image/"))
        );
    }

    #[test]
    fn temporary_generated_sets_tempdir() {
        let lp = lookup_paths_init(
            RuntimeScope::System,
            LookupPathsFlags::TEMPORARY_GENERATED,
            None,
            &env(),
        )
        .unwrap();
        assert_eq!(
            lp.temporary_dir.as_deref(),
            Some("/tmp/systemd-temporary-XXXXXX")
        );
    }
}
