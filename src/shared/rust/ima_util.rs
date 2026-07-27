// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/ima-util.c, src/shared/ima-util.h

use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicI8, Ordering};

pub const IMA_PATH: &str = "/sys/kernel/security/ima/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheState {
    Uninitialized,
    Unavailable,
    Available,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InvalidCacheState(i8);

impl CacheState {
    const fn as_i8(self) -> i8 {
        match self {
            Self::Uninitialized => -1,
            Self::Unavailable => 0,
            Self::Available => 1,
        }
    }

    const fn as_bool(self) -> Option<bool> {
        match self {
            Self::Uninitialized => None,
            Self::Unavailable => Some(false),
            Self::Available => Some(true),
        }
    }

    const fn from_bool(value: bool) -> Self {
        if value {
            Self::Available
        } else {
            Self::Unavailable
        }
    }
}

impl TryFrom<i8> for CacheState {
    type Error = InvalidCacheState;

    fn try_from(value: i8) -> Result<Self, Self::Error> {
        match value {
            -1 => Ok(Self::Uninitialized),
            0 => Ok(Self::Unavailable),
            1 => Ok(Self::Available),
            other => Err(InvalidCacheState(other)),
        }
    }
}

static USE_IMA_CACHED: AtomicI8 = AtomicI8::new(CacheState::Uninitialized.as_i8());

fn probe_ima_path(path: &Path) -> Result<bool, io::Error> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn load_cached(cache: &AtomicI8) -> Result<Option<bool>, InvalidCacheState> {
    CacheState::try_from(cache.load(Ordering::Relaxed)).map(CacheState::as_bool)
}

fn store_cached(cache: &AtomicI8, value: bool) {
    let state = CacheState::from_bool(value).as_i8();

    let _ = cache.compare_exchange(
        CacheState::Uninitialized.as_i8(),
        state,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
}

fn use_ima_with<F>(cache: &AtomicI8, probe: F) -> bool
where
    F: FnOnce() -> Result<bool, io::Error>,
{
    match load_cached(cache) {
        Ok(Some(value)) => return value,
        Ok(None) => {}
        Err(_) => cache.store(CacheState::Uninitialized.as_i8(), Ordering::Relaxed),
    }

    let value = probe().unwrap_or(false);
    store_cached(cache, value);

    load_cached(cache).ok().flatten().unwrap_or(value)
}

pub fn use_ima() -> bool {
    use_ima_with(&USE_IMA_CACHED, || probe_ima_path(Path::new(IMA_PATH)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();

        std::env::temp_dir().join(format!("ima_util_{name}_{}_{}", std::process::id(), nanos))
    }

    #[test]
    fn cache_state_round_trips_uninitialized() {
        assert_eq!(CacheState::try_from(-1), Ok(CacheState::Uninitialized));
        assert_eq!(CacheState::Uninitialized.as_bool(), None);
    }

    #[test]
    fn cache_state_round_trips_unavailable() {
        assert_eq!(CacheState::try_from(0), Ok(CacheState::Unavailable));
        assert_eq!(CacheState::Unavailable.as_bool(), Some(false));
    }

    #[test]
    fn cache_state_round_trips_available() {
        assert_eq!(CacheState::try_from(1), Ok(CacheState::Available));
        assert_eq!(CacheState::Available.as_bool(), Some(true));
    }

    #[test]
    fn invalid_cache_state_is_rejected() {
        assert_eq!(CacheState::try_from(7), Err(InvalidCacheState(7)));
    }

    #[test]
    fn from_bool_maps_false_to_unavailable() {
        assert_eq!(CacheState::from_bool(false), CacheState::Unavailable);
    }

    #[test]
    fn from_bool_maps_true_to_available() {
        assert_eq!(CacheState::from_bool(true), CacheState::Available);
    }

    #[test]
    fn probe_ima_path_returns_true_for_existing_directory() {
        let path = unique_test_path("existing_dir");
        fs::create_dir(&path).expect("failed to create directory");

        let result = probe_ima_path(&path);

        fs::remove_dir(&path).expect("failed to remove directory");
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn probe_ima_path_returns_false_for_missing_path() {
        let path = unique_test_path("missing_path");
        assert_eq!(probe_ima_path(&path).unwrap(), false);
    }

    #[test]
    fn cached_true_result_skips_probe_after_first_call() {
        let cache = AtomicI8::new(CacheState::Uninitialized.as_i8());
        let calls = AtomicUsize::new(0);

        let first = use_ima_with(&cache, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(true)
        });
        let second = use_ima_with(&cache, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(false)
        });

        assert!(first);
        assert!(second);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cached_false_result_skips_probe_after_first_call() {
        let cache = AtomicI8::new(CacheState::Uninitialized.as_i8());
        let calls = AtomicUsize::new(0);

        let first = use_ima_with(&cache, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(false)
        });
        let second = use_ima_with(&cache, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(true)
        });

        assert!(!first);
        assert!(!second);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn probe_error_is_treated_as_false() {
        let cache = AtomicI8::new(CacheState::Uninitialized.as_i8());

        let result = use_ima_with(&cache, || {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        });

        assert!(!result);
        assert_eq!(load_cached(&cache), Ok(Some(false)));
    }

    #[test]
    fn invalid_cached_value_is_recomputed() {
        let cache = AtomicI8::new(99);
        let calls = AtomicUsize::new(0);

        let result = use_ima_with(&cache, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(true)
        });

        assert!(result);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(load_cached(&cache), Ok(Some(true)));
    }

    #[test]
    fn store_cached_does_not_overwrite_initialized_value() {
        let cache = AtomicI8::new(CacheState::Available.as_i8());

        store_cached(&cache, false);

        assert_eq!(load_cached(&cache), Ok(Some(true)));
    }

    #[test]
    fn preinitialized_cache_avoids_probe_entirely() {
        let cache = AtomicI8::new(CacheState::Unavailable.as_i8());
        let calls = AtomicUsize::new(0);

        let result = use_ima_with(&cache, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(true)
        });

        assert!(!result);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn public_use_ima_is_stable_across_repeated_calls() {
        let first = use_ima();
        let second = use_ima();

        assert_eq!(first, second);
    }
}
