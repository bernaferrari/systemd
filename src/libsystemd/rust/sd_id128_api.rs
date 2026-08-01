// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-id128/sd-id128.c

use crate::id128_util::{
    NEG_EINVAL, NEG_ENXIO, SdId128, id128_from_string_nonzero, id128_is_valid, id128_make_v4_uuid,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use systemd_basic_rs::sha256_hmac::hmac_sha256;
#[cfg(test)]
use systemd_basic_rs::sha256_hmac::sha256;

pub type Result<T> = std::result::Result<T, i32>;

const LINUX_ENOMEDIUM: i32 = 123;
const LINUX_EUCLEAN: i32 = 117;
const LINUX_ENOPKG: i32 = 65;
const MACHINE_ID_PATH: &str = "/etc/machine-id";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

pub const NEG_ENOMEDIUM: i32 = -LINUX_ENOMEDIUM;
pub const NEG_EUCLEAN: i32 = -LINUX_EUCLEAN;
pub const NEG_ENOPKG: i32 = -LINUX_ENOPKG;
pub const NEG_ENOSYS: i32 = -libc::ENOSYS;

static MACHINE_ID_CACHE: OnceLock<Mutex<Option<SdId128>>> = OnceLock::new();
static BOOT_ID_CACHE: OnceLock<Mutex<Option<SdId128>>> = OnceLock::new();

#[cfg(test)]
static TEST_MACHINE_ID_PATH: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
#[cfg(test)]
static TEST_BOOT_ID_PATH: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

pub fn sd_id128_randomize() -> Result<SdId128> {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes)?;
    Ok(id128_make_v4_uuid(SdId128(bytes)))
}

pub fn sd_id128_get_machine() -> Result<SdId128> {
    read_cached_id(&MACHINE_ID_CACHE, || {
        read_id128_file(&machine_id_path(), false)
    })
}

pub fn sd_id128_get_boot() -> Result<SdId128> {
    match read_cached_id(&BOOT_ID_CACHE, || read_id128_file(&boot_id_path(), true)) {
        Err(e) if e == -libc::ENOENT => Err(NEG_ENOSYS),
        other => other,
    }
}

pub fn sd_id128_get_invocation() -> Result<SdId128> {
    if let Ok(value) = std::env::var("INVOCATION_ID") {
        return id128_from_string_nonzero(&value)
            .map_err(|e| if e == NEG_EINVAL { NEG_EUCLEAN } else { e });
    }
    Err(NEG_ENXIO)
}

pub fn sd_id128_get_app_specific(base: SdId128, app_id: SdId128) -> Result<SdId128> {
    if app_id.is_null() {
        return Err(NEG_ENXIO);
    }
    let mac = hmac_sha256(&base.0, &app_id.0);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac[..16]);
    Ok(id128_make_v4_uuid(SdId128(out)))
}

pub fn sd_id128_get_machine_app_specific(app_id: SdId128) -> Result<SdId128> {
    sd_id128_get_app_specific(sd_id128_get_machine()?, app_id)
}

pub fn sd_id128_get_boot_app_specific(app_id: SdId128) -> Result<SdId128> {
    sd_id128_get_app_specific(sd_id128_get_boot()?, app_id)
}

pub fn sd_id128_get_invocation_app_specific(app_id: SdId128) -> Result<SdId128> {
    sd_id128_get_app_specific(sd_id128_get_invocation()?, app_id)
}

pub fn sd_id128_get_machine_for_pid(pid: libc::pid_t) -> Result<SdId128> {
    read_id128_file(
        &PathBuf::from(format!("/proc/{pid}/root/etc/machine-id")),
        false,
    )
}

pub fn sd_id128_get_boot_for_pid(pid: libc::pid_t) -> Result<SdId128> {
    read_id128_file(
        &PathBuf::from(format!("/proc/{pid}/root/proc/sys/kernel/random/boot_id")),
        true,
    )
}

pub fn read_id128_file(path: &Path, allow_uuid: bool) -> Result<SdId128> {
    let text = fs::read_to_string(path).map_err(io_to_errno)?;
    let text = text.strip_suffix('\n').unwrap_or(&text);
    if text.is_empty() {
        return Err(NEG_ENOMEDIUM);
    }
    if text == "uninitialized" {
        return Err(NEG_ENOPKG);
    }
    if text.contains('\n') {
        return Err(NEG_EUCLEAN);
    }

    if allow_uuid {
        if text.len() != 36 || !id128_is_valid(text) {
            return Err(NEG_EUCLEAN);
        }
    } else {
        if text.len() != 32 || !id128_is_valid(text) {
            return Err(NEG_EUCLEAN);
        }
    }

    id128_from_string_nonzero(text).map_err(|e| {
        if e == NEG_EINVAL {
            NEG_EUCLEAN
        } else if e == NEG_ENXIO {
            NEG_ENOMEDIUM
        } else {
            e
        }
    })
}

fn fill_random(bytes: &mut [u8]) -> Result<()> {
    getrandom::fill(bytes).map_err(getrandom_to_errno)
}

fn io_to_errno(err: std::io::Error) -> i32 {
    -err.raw_os_error().unwrap_or(libc::EIO)
}

fn getrandom_to_errno(err: getrandom::Error) -> i32 {
    -err.raw_os_error().unwrap_or(libc::EIO)
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn id_cache(slot: &OnceLock<Mutex<Option<SdId128>>>) -> &Mutex<Option<SdId128>> {
    slot.get_or_init(|| Mutex::new(None))
}

fn read_cached_id<F>(slot: &OnceLock<Mutex<Option<SdId128>>>, read: F) -> Result<SdId128>
where
    F: FnOnce() -> Result<SdId128>,
{
    if let Some(id) = *lock_unpoisoned(id_cache(slot)) {
        return Ok(id);
    }

    let id = read()?;
    let mut cache = lock_unpoisoned(id_cache(slot));
    if cache.is_none() {
        *cache = Some(id);
    }
    Ok(id)
}

#[cfg(not(test))]
fn machine_id_path() -> PathBuf {
    PathBuf::from(MACHINE_ID_PATH)
}

#[cfg(not(test))]
fn boot_id_path() -> PathBuf {
    PathBuf::from(BOOT_ID_PATH)
}

#[cfg(test)]
fn path_override(slot: &OnceLock<Mutex<Option<PathBuf>>>, fallback: &str) -> PathBuf {
    lock_unpoisoned(slot.get_or_init(|| Mutex::new(None)))
        .clone()
        .unwrap_or_else(|| PathBuf::from(fallback))
}

#[cfg(test)]
fn machine_id_path() -> PathBuf {
    path_override(&TEST_MACHINE_ID_PATH, MACHINE_ID_PATH)
}

#[cfg(test)]
fn boot_id_path() -> PathBuf {
    path_override(&TEST_BOOT_ID_PATH, BOOT_ID_PATH)
}

#[cfg(test)]
fn set_test_machine_id_path(path: Option<PathBuf>) {
    *lock_unpoisoned(TEST_MACHINE_ID_PATH.get_or_init(|| Mutex::new(None))) = path;
}

#[cfg(test)]
fn set_test_boot_id_path(path: Option<PathBuf>) {
    *lock_unpoisoned(TEST_BOOT_ID_PATH.get_or_init(|| Mutex::new(None))) = path;
}

#[cfg(test)]
fn clear_sd_id128_caches() {
    *lock_unpoisoned(id_cache(&MACHINE_ID_CACHE)) = None;
    *lock_unpoisoned(id_cache(&BOOT_ID_CACHE)) = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestEnvironment;
    use std::sync::{Mutex, OnceLock};

    static TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        lock_unpoisoned(TEST_MUTEX.get_or_init(|| Mutex::new(())))
    }

    struct TestPathsGuard;

    impl Drop for TestPathsGuard {
        fn drop(&mut self) {
            set_test_machine_id_path(None);
            set_test_boot_id_path(None);
            clear_sd_id128_caches();
        }
    }

    #[test]
    fn randomize_sets_uuid_bits() {
        let id = sd_id128_randomize().unwrap();
        assert_eq!(id.0[6] >> 4, 0x4);
        assert_eq!(id.0[8] >> 6, 0b10);
    }

    #[test]
    fn machine_id_reads_mock_path_and_caches_value() {
        let _lock = test_lock();
        let _guard = TestPathsGuard;

        let path = std::env::temp_dir().join(format!("systemd-machine-id-{}", std::process::id()));
        fs::write(&path, "00112233445566778899aabbccddeeff\n").unwrap();
        set_test_machine_id_path(Some(path.clone()));
        clear_sd_id128_caches();

        let first = sd_id128_get_machine().unwrap();
        fs::write(&path, "ffeeddccbbaa99887766554433221100\n").unwrap();
        let second = sd_id128_get_machine().unwrap();

        assert_eq!(first, second);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn boot_id_reads_mock_uuid_path() {
        let _lock = test_lock();
        let _guard = TestPathsGuard;

        let path = std::env::temp_dir().join(format!("systemd-boot-id-{}", std::process::id()));
        fs::write(&path, "00112233-4455-6677-8899-aabbccddeeff\n").unwrap();
        set_test_boot_id_path(Some(path.clone()));
        clear_sd_id128_caches();

        let id = sd_id128_get_boot().unwrap();
        assert_eq!(
            id,
            SdId128([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
        );
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn boot_id_missing_path_maps_to_enosys() {
        let _lock = test_lock();
        let _guard = TestPathsGuard;

        set_test_boot_id_path(Some(
            std::env::temp_dir().join(format!("systemd-missing-boot-id-{}", std::process::id())),
        ));
        clear_sd_id128_caches();
        assert_eq!(sd_id128_get_boot(), Err(NEG_ENOSYS));
    }

    #[test]
    fn machine_id_missing_path_returns_enoent() {
        let _lock = test_lock();
        let _guard = TestPathsGuard;

        set_test_machine_id_path(Some(
            std::env::temp_dir().join(format!("systemd-missing-machine-id-{}", std::process::id())),
        ));
        clear_sd_id128_caches();
        assert_eq!(sd_id128_get_machine(), Err(-libc::ENOENT));
    }

    #[test]
    fn app_specific_derivation_is_stable() {
        let base = SdId128([1; 16]);
        let app = SdId128([2; 16]);
        assert_eq!(
            sd_id128_get_app_specific(base, app).unwrap(),
            sd_id128_get_app_specific(base, app).unwrap()
        );
    }

    #[test]
    fn app_specific_matches_known_vector() {
        let base = SdId128([
            0x51, 0xdf, 0x0b, 0x4b, 0xc3, 0xb0, 0x4c, 0x97, 0x80, 0xe2, 0x99, 0xb9, 0x8c, 0xa3,
            0x73, 0xb8,
        ]);
        let app = SdId128([
            0xf0, 0x3d, 0xaa, 0xeb, 0x1c, 0x33, 0x4b, 0x43, 0xa7, 0x32, 0x17, 0x29, 0x44, 0xbf,
            0x77, 0x2e,
        ]);
        let expected = SdId128([
            0x1d, 0xee, 0x59, 0x54, 0xe7, 0x5c, 0x4d, 0x6f, 0xb9, 0x6c, 0xc6, 0xc0, 0x4c, 0xa1,
            0x8a, 0x86,
        ]);

        assert_eq!(sd_id128_get_app_specific(base, app).unwrap(), expected);
    }

    #[test]
    fn app_specific_rejects_null_app_id() {
        assert_eq!(
            sd_id128_get_app_specific(SdId128([1; 16]), SdId128::null()),
            Err(NEG_ENXIO)
        );
    }

    #[test]
    fn invocation_id_reads_environment() {
        let _lock = test_lock();
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        environment.set("INVOCATION_ID", "00112233445566778899aabbccddeeff");
        let id = sd_id128_get_invocation().unwrap();
        assert_eq!(id.0[0], 0x00);
    }

    #[test]
    fn invocation_id_rejects_invalid_environment() {
        let _lock = test_lock();
        // SAFETY: this environment-dependent test target runs with
        // --test-threads=1 and does not spawn environment readers.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        environment.set("INVOCATION_ID", "not-an-id");
        assert_eq!(sd_id128_get_invocation(), Err(NEG_EUCLEAN));
    }

    #[test]
    fn sha256_matches_known_vector() {
        let hash = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn hmac_is_stable() {
        assert_eq!(hmac_sha256(b"key", b"data"), hmac_sha256(b"key", b"data"));
    }

    #[test]
    fn reads_id128_file() {
        let path = std::env::temp_dir().join(format!("systemd-id128-{}", std::process::id()));
        fs::write(&path, "00112233445566778899aabbccddeeff\n").unwrap();
        let id = read_id128_file(&path, false).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(id.0[15], 0xff);
    }

    #[test]
    fn boot_for_invalid_pid_fails() {
        assert!(sd_id128_get_boot_for_pid(999_999).is_err());
    }

    #[test]
    fn machine_for_invalid_pid_fails() {
        assert!(sd_id128_get_machine_for_pid(999_999).is_err());
    }
}
