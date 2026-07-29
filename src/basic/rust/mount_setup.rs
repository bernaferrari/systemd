// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.mount-setup; authority=src/shared/mount-setup.c,src/shared/mount-setup.h
//
// Mount point classification — pure path-component comparison against the
// mount table and ignore list in mount-setup.c.

use std::ffi::{CStr, c_char};

// These are the .where fields from mount_table in mount-setup.c. Keep entries
// which are conditional in C: their classification is part of this ABI's
// fixed compatibility contract, independent of whether a particular build
// mounts them.
const API_MOUNT_POINTS: &[&[u8]] = &[
    b"/proc",
    b"/sys",
    b"/dev",
    b"/sys/kernel/security",
    b"/sys/fs/smackfs",
    b"/dev/shm",
    b"/dev/pts",
    b"/run",
    b"/sys/fs/cgroup",
    b"/sys/fs/pstore",
    b"/sys/firmware/efi/efivars",
    b"/sys/fs/bpf",
];

const CGROUP_PREFIX: &[u8] = b"/sys/fs/cgroup/";

const IGNORE_MOUNT_POINTS: &[&[u8]] = &[
    b"/sys/fs/selinux",
    b"/dev/console",
    b"/proc/kmsg",
    b"/proc/sys",
    b"/proc/sys/kernel/random/boot_id",
];

const RUN_HOST_PREFIX: &[u8] = b"/run/host";

// ── Path helpers ──────────────────────────────────────────────────────────

const NAME_MAX: usize = 255;

/// Return the next path component, matching path_find_first_component() with
/// accept_dot_dot=true for the inputs relevant to this table.
fn next_path_component<'a>(path: &'a [u8], cursor: &mut usize) -> Result<Option<&'a [u8]>, ()> {
    loop {
        while path.get(*cursor) == Some(&b'/') {
            *cursor += 1;
        }

        if path.get(*cursor) == Some(&b'.') && path.get(*cursor + 1) == Some(&b'/') {
            *cursor += 2;
            continue;
        }

        break;
    }

    let start = *cursor;
    if start == path.len() || (path[start] == b'.' && start + 1 == path.len()) {
        return Ok(None);
    }

    while path.get(*cursor).is_some_and(|byte| *byte != b'/') {
        *cursor += 1;
    }

    if *cursor - start > NAME_MAX {
        return Err(());
    }

    Ok(Some(&path[start..*cursor]))
}

/// Component-aware equivalent of path_equal() for a non-NULL table entry.
fn path_equal(path: &[u8], candidate: &[u8]) -> bool {
    if path.starts_with(b"/") != candidate.starts_with(b"/") {
        return false;
    }

    let (mut path_cursor, mut candidate_cursor) = (0, 0);
    loop {
        match (
            next_path_component(path, &mut path_cursor),
            next_path_component(candidate, &mut candidate_cursor),
        ) {
            (Ok(None), Ok(None)) => return true,
            (Ok(Some(path_component)), Ok(Some(candidate_component)))
                if path_component == candidate_component => {}
            _ => return false,
        }
    }
}

/// Component-aware equivalent of path_startswith() for non-NULL C strings.
fn path_startswith(path: &[u8], prefix: &[u8]) -> bool {
    if path.starts_with(b"/") != prefix.starts_with(b"/") {
        return false;
    }

    let (mut path_cursor, mut prefix_cursor) = (0, 0);
    loop {
        /* path_startswith_full() parses path before prefix, so an oversized
         * path component fails even when the prefix was already exhausted. */
        let path_component = match next_path_component(path, &mut path_cursor) {
            Ok(component) => component,
            Err(()) => return false,
        };
        let prefix_component = match next_path_component(prefix, &mut prefix_cursor) {
            Ok(component) => component,
            Err(()) => return false,
        };

        match (path_component, prefix_component) {
            (_, None) => return true,
            (Some(path_component), Some(prefix_component))
                if path_component == prefix_component => {}
            _ => return false,
        }
    }
}

fn mount_point_is_api(path: &[u8]) -> bool {
    API_MOUNT_POINTS.iter().any(|entry| path_equal(path, entry))
        || path_startswith(path, CGROUP_PREFIX)
}

fn mount_point_ignore(path: &[u8]) -> bool {
    IGNORE_MOUNT_POINTS
        .iter()
        .any(|entry| path_equal(path, entry))
        || path_startswith(path, RUN_HOST_PREFIX)
}

// ── C ABI ─────────────────────────────────────────────────────────────────

/// C ABI facade for mount_point_is_api().
///
/// # Safety
///
/// A non-NULL `path` must point to a live, NUL-terminated C string for the
/// duration of this call. A NULL path returns false as a fail-closed Rust ABI
/// extension; mount-setup.c requires a non-NULL path because it calls
/// path_startswith().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_mount_point_is_api(path: *const c_char) -> bool {
    if path.is_null() {
        return false;
    }

    // SAFETY: the caller contract guarantees a live NUL-terminated C string;
    // to_bytes() deliberately preserves non-UTF-8 bytes.
    let path = unsafe { CStr::from_ptr(path) }.to_bytes();
    mount_point_is_api(path)
}

/// C ABI facade for mount_point_ignore().
///
/// # Safety
///
/// A non-NULL `path` must point to a live, NUL-terminated C string for the
/// duration of this call. A NULL path returns false as a fail-closed Rust ABI
/// extension; mount-setup.c requires a non-NULL path because it calls
/// path_startswith().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_mount_point_ignore(path: *const c_char) -> bool {
    if path.is_null() {
        return false;
    }

    // SAFETY: the caller contract guarantees a live NUL-terminated C string;
    // to_bytes() deliberately preserves non-UTF-8 bytes.
    let path = unsafe { CStr::from_ptr(path) }.to_bytes();
    mount_point_ignore(path)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_api_mount_table_entries() {
        for path in API_MOUNT_POINTS {
            assert!(mount_point_is_api(path));
        }
    }

    #[test]
    fn is_api_uses_path_components() {
        assert!(mount_point_is_api(b"//./proc/"));
        assert!(mount_point_is_api(b"/sys//fs/cgroup/./slice"));
        assert!(!mount_point_is_api(b"/procfs"));
        assert!(!mount_point_is_api(b"/sys/fs/cgroupx"));
    }

    #[test]
    fn ignores_mount_table_entries() {
        for path in IGNORE_MOUNT_POINTS {
            assert!(mount_point_ignore(path));
        }
    }

    #[test]
    fn ignores_run_host_by_path_component() {
        assert!(mount_point_ignore(b"/run//host/./incoming"));
        assert!(!mount_point_ignore(b"/run/hostess"));
        assert!(!mount_point_ignore(b"/run/hostile"));
    }

    #[test]
    fn classifications_accept_non_utf8_c_string_bytes() {
        assert!(!mount_point_is_api(b"/proc\xff"));
        assert!(mount_point_ignore(b"/run/host/\xff"));
    }

    #[test]
    fn oversized_path_component_fails() {
        let oversized_component = vec![b'x'; NAME_MAX + 1];
        let mut cursor = 0;
        assert_eq!(
            next_path_component(&oversized_component, &mut cursor),
            Err(())
        );
        assert!(!mount_point_is_api(
            &[
                b"/sys/fs/cgroup/".as_slice(),
                oversized_component.as_slice(),
            ]
            .concat()
        ));
        assert!(!mount_point_ignore(
            &[b"/run/host/".as_slice(), oversized_component.as_slice()].concat()
        ));
    }
}
