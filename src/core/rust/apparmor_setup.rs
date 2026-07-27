// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/apparmor-setup.c
//
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppArmorSetupOutcome {
    SkippedUnsupported,
    MissingCurrentProfile,
    AlreadyConfined,
    FeatureSetUnavailable,
    CacheDirectoryUnavailable,
    PolicyCacheUnavailable,
    PolicyLoadUnavailable,
    ProfileChangeUnavailable,
    ChangedToSystemd,
}

pub trait AppArmorEnvironment {
    fn use_apparmor(&self) -> bool;
    fn read_current_profile(&mut self, path: &str) -> Result<String, i32>;
    fn features_from_kernel(&mut self) -> Result<(), i32>;
    fn preview_cache_dir_path(&mut self, policy_dir: &str) -> Result<String, i32>;
    fn create_policy_cache(&mut self, policy_dir: &str) -> Result<(), i32>;
    fn replace_all_policies(&mut self) -> Result<(), i32>;
    fn change_profile(&mut self, profile: &str) -> Result<(), i32>;
    fn log(&mut self, level: LogLevel, message: String);
}

pub fn mac_apparmor_setup(env: &mut impl AppArmorEnvironment) -> AppArmorSetupOutcome {
    if !env.use_apparmor() {
        env.log(
            LogLevel::Debug,
            "Skipping AppArmor initialization: not supported by the kernel, disabled, or libapparmor not installed.".into(),
        );
        return AppArmorSetupOutcome::SkippedUnsupported;
    }

    let mut current_profile = None;

    for current_file in [
        "/proc/self/attr/apparmor/current",
        "/proc/self/attr/current",
    ] {
        match env.read_current_profile(current_file) {
            Ok(profile) => {
                current_profile = Some(profile);
                break;
            }
            Err(errno) if errno == -libc::ENOENT => {}
            Err(errno) => env.log(
                LogLevel::Warning,
                format!(
                    "Failed to read current AppArmor profile from '{current_file}', ignoring: errno {}",
                    -errno
                ),
            ),
        }
    }

    let Some(current_profile) = current_profile else {
        env.log(
            LogLevel::Warning,
            "Failed to get the current AppArmor profile of our own process, ignoring.".into(),
        );
        return AppArmorSetupOutcome::MissingCurrentProfile;
    };

    if current_profile != "unconfined" {
        env.log(
            LogLevel::Debug,
            "We are already confined in an AppArmor profile.".into(),
        );
        return AppArmorSetupOutcome::AlreadyConfined;
    }

    if let Err(errno) = env.features_from_kernel() {
        env.log(
            LogLevel::Warning,
            format!(
                "Failed to get the AppArmor feature set from the kernel, ignoring: errno {}",
                -errno
            ),
        );
        return AppArmorSetupOutcome::FeatureSetUnavailable;
    }

    let cache_dir_path = match env.preview_cache_dir_path("/etc/apparmor/earlypolicy") {
        Ok(path) => path,
        Err(errno) => {
            env.log(
                LogLevel::Debug,
                format!(
                    "Failed to get the path of the early AppArmor policy cache directory, ignoring: errno {}",
                    -errno
                ),
            );
            return AppArmorSetupOutcome::CacheDirectoryUnavailable;
        }
    };

    if let Err(errno) = env.create_policy_cache("/etc/apparmor/earlypolicy") {
        if errno == -libc::ENOENT {
            env.log(
                LogLevel::Debug,
                format!(
                    "The early AppArmor policy cache directory '{cache_dir_path}' does not exist."
                ),
            );
        } else {
            env.log(
                LogLevel::Warning,
                format!(
                    "Failed to create a new AppArmor policy cache, ignoring: errno {}",
                    -errno
                ),
            );
        }

        return AppArmorSetupOutcome::PolicyCacheUnavailable;
    }

    if let Err(errno) = env.replace_all_policies() {
        env.log(
            LogLevel::Warning,
            format!(
                "Failed to load the profiles from the early AppArmor policy cache directory '{cache_dir_path}', ignoring: errno {}",
                -errno
            ),
        );
        return AppArmorSetupOutcome::PolicyLoadUnavailable;
    }

    env.log(
        LogLevel::Info,
        format!(
            "Successfully loaded all binary profiles from AppArmor early policy cache ({cache_dir_path})."
        ),
    );

    if let Err(errno) = env.change_profile("systemd") {
        if errno == -libc::ENOENT {
            env.log(
                LogLevel::Debug,
                format!(
                    "Failed to change to AppArmor profile 'systemd'. Please ensure that one of the binary profile files in policy cache directory '{cache_dir_path}' contains a profile with that name."
                ),
            );
        } else {
            env.log(
                LogLevel::Error,
                format!(
                    "Failed to change to AppArmor profile 'systemd': errno {}",
                    -errno
                ),
            );
        }

        return AppArmorSetupOutcome::ProfileChangeUnavailable;
    }

    env.log(
        LogLevel::Info,
        "Changed to AppArmor profile systemd.".into(),
    );
    AppArmorSetupOutcome::ChangedToSystemd
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    struct MockEnv {
        use_apparmor: bool,
        reads: HashMap<String, VecDeque<Result<String, i32>>>,
        features_result: Result<(), i32>,
        cache_preview_result: Result<String, i32>,
        create_cache_result: Result<(), i32>,
        replace_result: Result<(), i32>,
        change_profile_result: Result<(), i32>,
        logs: Vec<LogRecord>,
    }

    impl Default for MockEnv {
        fn default() -> Self {
            Self {
                use_apparmor: false,
                reads: HashMap::new(),
                features_result: Ok(()),
                cache_preview_result: Ok("/etc/apparmor/cache".into()),
                create_cache_result: Ok(()),
                replace_result: Ok(()),
                change_profile_result: Ok(()),
                logs: Vec::new(),
            }
        }
    }

    impl MockEnv {
        fn with_read(mut self, path: &str, result: Result<&str, i32>) -> Self {
            self.reads
                .entry(path.to_string())
                .or_default()
                .push_back(result.map(str::to_string));
            self
        }
    }

    impl AppArmorEnvironment for MockEnv {
        fn use_apparmor(&self) -> bool {
            self.use_apparmor
        }

        fn read_current_profile(&mut self, path: &str) -> Result<String, i32> {
            self.reads
                .get_mut(path)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Err(-libc::ENOENT))
        }

        fn features_from_kernel(&mut self) -> Result<(), i32> {
            self.features_result
        }

        fn preview_cache_dir_path(&mut self, _policy_dir: &str) -> Result<String, i32> {
            self.cache_preview_result.clone()
        }

        fn create_policy_cache(&mut self, _policy_dir: &str) -> Result<(), i32> {
            self.create_cache_result
        }

        fn replace_all_policies(&mut self) -> Result<(), i32> {
            self.replace_result
        }

        fn change_profile(&mut self, _profile: &str) -> Result<(), i32> {
            self.change_profile_result
        }

        fn log(&mut self, level: LogLevel, message: String) {
            self.logs.push(LogRecord { level, message });
        }
    }

    fn happy_env() -> MockEnv {
        MockEnv {
            use_apparmor: true,
            ..MockEnv::default()
        }
    }

    #[test]
    fn skips_when_apparmor_is_disabled() {
        let mut env = MockEnv::default();
        assert_eq!(
            mac_apparmor_setup(&mut env),
            AppArmorSetupOutcome::SkippedUnsupported
        );
        assert_eq!(env.logs[0].level, LogLevel::Debug);
    }

    #[test]
    fn falls_back_to_generic_current_file() {
        let mut env = happy_env()
            .with_read("/proc/self/attr/apparmor/current", Err(-libc::ENOENT))
            .with_read("/proc/self/attr/current", Ok("unconfined"));
        assert_eq!(
            mac_apparmor_setup(&mut env),
            AppArmorSetupOutcome::ChangedToSystemd
        );
    }

    #[test]
    fn warns_on_non_enoent_profile_read_failure() {
        let mut env = happy_env()
            .with_read("/proc/self/attr/apparmor/current", Err(-libc::EIO))
            .with_read("/proc/self/attr/current", Ok("unconfined"));
        let outcome = mac_apparmor_setup(&mut env);
        assert_eq!(outcome, AppArmorSetupOutcome::ChangedToSystemd);
        assert!(env.logs.iter().any(|l| l.level == LogLevel::Warning));
    }

    #[test]
    fn returns_when_no_current_profile_is_available() {
        let mut env = MockEnv {
            use_apparmor: true,
            ..MockEnv::default()
        };
        assert_eq!(
            mac_apparmor_setup(&mut env),
            AppArmorSetupOutcome::MissingCurrentProfile
        );
    }

    #[test]
    fn returns_when_already_confined() {
        let mut env = happy_env().with_read("/proc/self/attr/apparmor/current", Ok("systemd"));
        assert_eq!(
            mac_apparmor_setup(&mut env),
            AppArmorSetupOutcome::AlreadyConfined
        );
    }

    #[test]
    fn ignores_feature_discovery_failures() {
        let mut env = happy_env().with_read("/proc/self/attr/apparmor/current", Ok("unconfined"));
        env.features_result = Err(-libc::EIO);
        assert_eq!(
            mac_apparmor_setup(&mut env),
            AppArmorSetupOutcome::FeatureSetUnavailable
        );
    }

    #[test]
    fn treats_missing_cache_directory_as_non_fatal() {
        let mut env = happy_env().with_read("/proc/self/attr/apparmor/current", Ok("unconfined"));
        env.create_cache_result = Err(-libc::ENOENT);
        assert_eq!(
            mac_apparmor_setup(&mut env),
            AppArmorSetupOutcome::PolicyCacheUnavailable
        );
        assert!(env
            .logs
            .iter()
            .any(|l| l.message.contains("does not exist")));
    }

    #[test]
    fn reports_policy_replace_failures() {
        let mut env = happy_env().with_read("/proc/self/attr/apparmor/current", Ok("unconfined"));
        env.replace_result = Err(-libc::EIO);
        assert_eq!(
            mac_apparmor_setup(&mut env),
            AppArmorSetupOutcome::PolicyLoadUnavailable
        );
    }

    #[test]
    fn reports_missing_systemd_profile_as_non_fatal() {
        let mut env = happy_env().with_read("/proc/self/attr/apparmor/current", Ok("unconfined"));
        env.change_profile_result = Err(-libc::ENOENT);
        assert_eq!(
            mac_apparmor_setup(&mut env),
            AppArmorSetupOutcome::ProfileChangeUnavailable
        );
        assert!(env.logs.iter().any(|l| l.level == LogLevel::Debug));
    }

    #[test]
    fn completes_successfully() {
        let mut env = happy_env().with_read("/proc/self/attr/apparmor/current", Ok("unconfined"));
        assert_eq!(
            mac_apparmor_setup(&mut env),
            AppArmorSetupOutcome::ChangedToSystemd
        );
        assert!(env
            .logs
            .iter()
            .any(|l| l.message.contains("Changed to AppArmor profile systemd.")));
    }
}
