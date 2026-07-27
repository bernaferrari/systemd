// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/enable-mempool.c
//
use std::cell::Cell;
use std::ffi::OsString;
use std::sync::atomic::{AtomicI8, Ordering};

const SYSTEMD_MEMPOOL: &str = "SYSTEMD_MEMPOOL";
const CACHE_UNSET: i8 = -1;
const CACHE_DISABLED: i8 = 0;
const CACHE_ENABLED: i8 = 1;

static MEMPOOL_ENABLED_CACHE: AtomicI8 = AtomicI8::new(CACHE_UNSET);

thread_local! {
    static IS_MAIN_THREAD_CACHE: Cell<Option<bool>> = const { Cell::new(None) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheState {
    Uninitialized,
    Disabled,
    Enabled,
}

impl CacheState {
    fn from_raw(raw: i8) -> Self {
        match raw {
            CACHE_DISABLED => Self::Disabled,
            CACHE_ENABLED => Self::Enabled,
            _ => Self::Uninitialized,
        }
    }

    fn to_raw(self) -> i8 {
        match self {
            Self::Uninitialized => CACHE_UNSET,
            Self::Disabled => CACHE_DISABLED,
            Self::Enabled => CACHE_ENABLED,
        }
    }

    fn as_bool(self) -> Option<bool> {
        match self {
            Self::Uninitialized => None,
            Self::Disabled => Some(false),
            Self::Enabled => Some(true),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseBooleanError {
    Unset,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EnvValue {
    Unset,
    Text(String),
    NonUtf8(OsString),
}

pub fn parse_boolean(value: &str) -> Result<bool, ParseBooleanError> {
    if value.eq_ignore_ascii_case("1")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("y")
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("t")
        || value.eq_ignore_ascii_case("on")
    {
        return Ok(true);
    }

    if value.eq_ignore_ascii_case("0")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("n")
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("f")
        || value.eq_ignore_ascii_case("off")
    {
        return Ok(false);
    }

    Err(ParseBooleanError::Invalid)
}

fn getenv_bool_from_value(value: &EnvValue) -> Result<bool, ParseBooleanError> {
    match value {
        EnvValue::Unset => Err(ParseBooleanError::Unset),
        EnvValue::Text(text) => parse_boolean(text),
        EnvValue::NonUtf8(_) => Err(ParseBooleanError::Invalid),
    }
}

fn env_value_from_process(name: &str) -> EnvValue {
    match std::env::var_os(name) {
        None => EnvValue::Unset,
        Some(value) => match value.into_string() {
            Ok(text) => EnvValue::Text(text),
            Err(raw) => EnvValue::NonUtf8(raw),
        },
    }
}

fn enabled_from_env_value(value: &EnvValue) -> bool {
    !matches!(getenv_bool_from_value(value), Ok(false))
}

fn compute_mempool_enabled(
    is_main_thread: bool,
    cached: CacheState,
    env_value: &EnvValue,
) -> (bool, CacheState) {
    if !is_main_thread {
        return (false, cached);
    }

    if let Some(enabled) = cached.as_bool() {
        return (enabled, cached);
    }

    let enabled = enabled_from_env_value(env_value);
    let new_cache = if enabled {
        CacheState::Enabled
    } else {
        CacheState::Disabled
    };

    (enabled, new_cache)
}

fn current_thread_is_main_thread() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let pid = std::process::id() as libc::pid_t;
        let tid = unsafe { libc::gettid() };
        return pid == tid;
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return unsafe { libc::pthread_main_np() == 1 };
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        true
    }
}

fn is_main_thread() -> bool {
    IS_MAIN_THREAD_CACHE.with(|cache| match cache.get() {
        Some(result) => result,
        None => {
            let result = current_thread_is_main_thread();
            cache.set(Some(result));
            result
        }
    })
}

pub fn mempool_enabled() -> bool {
    let cached = CacheState::from_raw(MEMPOOL_ENABLED_CACHE.load(Ordering::Relaxed));
    let env_value = if cached == CacheState::Uninitialized {
        env_value_from_process(SYSTEMD_MEMPOOL)
    } else {
        EnvValue::Unset
    };

    let (enabled, new_cache) = compute_mempool_enabled(is_main_thread(), cached, &env_value);

    if cached == CacheState::Uninitialized && new_cache != CacheState::Uninitialized {
        let _ = MEMPOOL_ENABLED_CACHE.compare_exchange(
            CACHE_UNSET,
            new_cache.to_raw(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    enabled
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> EnvValue {
        EnvValue::Text(value.to_string())
    }

    #[test]
    fn parse_boolean_accepts_one() {
        assert_eq!(parse_boolean("1"), Ok(true));
    }

    #[test]
    fn parse_boolean_accepts_yes_case_insensitively() {
        assert_eq!(parse_boolean("YeS"), Ok(true));
    }

    #[test]
    fn parse_boolean_accepts_true() {
        assert_eq!(parse_boolean("true"), Ok(true));
    }

    #[test]
    fn parse_boolean_accepts_on() {
        assert_eq!(parse_boolean("ON"), Ok(true));
    }

    #[test]
    fn parse_boolean_accepts_zero() {
        assert_eq!(parse_boolean("0"), Ok(false));
    }

    #[test]
    fn parse_boolean_accepts_no_case_insensitively() {
        assert_eq!(parse_boolean("nO"), Ok(false));
    }

    #[test]
    fn parse_boolean_accepts_false() {
        assert_eq!(parse_boolean("false"), Ok(false));
    }

    #[test]
    fn parse_boolean_accepts_off() {
        assert_eq!(parse_boolean("off"), Ok(false));
    }

    #[test]
    fn parse_boolean_rejects_invalid_value() {
        assert_eq!(parse_boolean("maybe"), Err(ParseBooleanError::Invalid));
    }

    #[test]
    fn unset_environment_is_treated_as_enabled() {
        assert!(enabled_from_env_value(&EnvValue::Unset));
    }

    #[test]
    fn invalid_environment_is_treated_as_enabled() {
        assert!(enabled_from_env_value(&text("garbage")));
    }

    #[test]
    fn non_utf8_environment_is_treated_as_enabled() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;

            assert!(enabled_from_env_value(&EnvValue::NonUtf8(
                OsString::from_vec(vec![0xff])
            )));
        }

        #[cfg(not(unix))]
        {
            let _ = EnvValue::NonUtf8(OsString::from("non-utf8-unavailable"));
        }
    }

    #[test]
    fn explicit_false_disables_mempool() {
        assert!(!enabled_from_env_value(&text("0")));
    }

    #[test]
    fn explicit_true_enables_mempool() {
        assert!(enabled_from_env_value(&text("1")));
    }

    #[test]
    fn non_main_thread_never_uses_mempool() {
        let (enabled, cache) =
            compute_mempool_enabled(false, CacheState::Uninitialized, &text("1"));

        assert!(!enabled);
        assert_eq!(cache, CacheState::Uninitialized);
    }

    #[test]
    fn main_thread_caches_disabled_result() {
        let (enabled, cache) = compute_mempool_enabled(true, CacheState::Uninitialized, &text("0"));

        assert!(!enabled);
        assert_eq!(cache, CacheState::Disabled);
    }

    #[test]
    fn main_thread_caches_enabled_result_for_unset_value() {
        let (enabled, cache) =
            compute_mempool_enabled(true, CacheState::Uninitialized, &EnvValue::Unset);

        assert!(enabled);
        assert_eq!(cache, CacheState::Enabled);
    }

    #[test]
    fn main_thread_uses_cached_disabled_value() {
        let (enabled, cache) = compute_mempool_enabled(true, CacheState::Disabled, &text("1"));

        assert!(!enabled);
        assert_eq!(cache, CacheState::Disabled);
    }

    #[test]
    fn main_thread_uses_cached_enabled_value() {
        let (enabled, cache) = compute_mempool_enabled(true, CacheState::Enabled, &text("0"));

        assert!(enabled);
        assert_eq!(cache, CacheState::Enabled);
    }

    #[test]
    fn cache_state_round_trips_enabled() {
        assert_eq!(
            CacheState::from_raw(CacheState::Enabled.to_raw()),
            CacheState::Enabled
        );
    }

    #[test]
    fn cache_state_round_trips_disabled() {
        assert_eq!(
            CacheState::from_raw(CacheState::Disabled.to_raw()),
            CacheState::Disabled
        );
    }

    #[test]
    fn cache_state_invalid_raw_becomes_uninitialized() {
        assert_eq!(CacheState::from_raw(99), CacheState::Uninitialized);
    }
}
