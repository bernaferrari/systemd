// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/mempool.c, src/basic/mempool.h
//
// Memory pool: fixed-size tile allocator with freelist.
// Skipped: mempool_trim (uses log_debug/FORMAT_BYTES).

use std::alloc::{Layout, alloc};
use std::ptr;

// ── Constants ─────────────────────────────────────────────────────────────

const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const POOL_ALIGN: usize = 16;

// ── Internal pool structure ───────────────────────────────────────────────

#[repr(C)]
struct Pool {
    next: *mut Pool,
    n_tiles: usize,
    n_used: usize,
}

#[repr(C)]
pub struct Mempool {
    first_pool: *mut Pool,
    freelist: *mut u8,
    tile_size: usize,
    at_least: usize,
}

// ── Internal helpers ──────────────────────────────────────────────────────

fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

unsafe fn pool_ptr(p: *mut Pool) -> *mut u8 {
    if p.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller guarantees p points to a live Pool allocation whose
    // payload begins immediately after its header.
    unsafe { p.add(1) as *mut u8 }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Faithful port of C mempool usage pattern. Zeroes all fields and sets
/// tile_size / at_least to the provided values.
pub fn mempool_init(mp: &mut Mempool, tile_size: usize, at_least: usize) {
    mp.first_pool = ptr::null_mut();
    mp.freelist = ptr::null_mut();
    mp.tile_size = tile_size;
    mp.at_least = at_least;
}

/// Faithful port of C mempool_alloc_tile().
/// Returns a raw pointer to an allocated tile on success,
/// or Err(-EINVAL) for invalid parameters, Err(-ENOMEM) on allocation failure.
pub fn mempool_alloc_tile(mp: &mut Mempool) -> Result<*mut u8, i32> {
    if mp.tile_size < std::mem::size_of::<*mut u8>() {
        return Err(-EINVAL);
    }
    if mp.at_least == 0 {
        return Err(-EINVAL);
    }

    if !mp.freelist.is_null() {
        let t = mp.freelist;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            mp.freelist = *(t as *const *mut u8);
        }
        return Ok(t);
    }

    // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
    unsafe {
        if mp.first_pool.is_null() || (*mp.first_pool).n_used >= (*mp.first_pool).n_tiles {
            let n = if mp.first_pool.is_null() {
                0
            } else {
                (*mp.first_pool).n_tiles
            };
            let n = mp.at_least.max(n * 2);
            let pool_size = align_up(std::mem::size_of::<Pool>(), POOL_ALIGN);
            let size = pool_size + n * mp.tile_size;
            let actual_n = (size - pool_size) / mp.tile_size;

            let layout = Layout::from_size_align(size, POOL_ALIGN).map_err(|_| -ENOMEM)?;
            let p = alloc(layout) as *mut Pool;
            if p.is_null() {
                return Err(-ENOMEM);
            }

            (*p).next = mp.first_pool;
            (*p).n_tiles = actual_n;
            (*p).n_used = 0;

            mp.first_pool = p;
        }

        let i = (*mp.first_pool).n_used;
        (*mp.first_pool).n_used += 1;

        Ok(pool_ptr(mp.first_pool).add(i * mp.tile_size))
    }
}

/// Faithful port of C mempool_alloc0_tile().
/// Like mempool_alloc_tile but zeroes the allocated tile.
pub fn mempool_alloc0_tile(mp: &mut Mempool) -> Result<*mut u8, i32> {
    let p = mempool_alloc_tile(mp)?;
    // SAFETY: the destination pointer is valid, properly aligned, and not aliased for this write.
    unsafe {
        ptr::write_bytes(p, 0u8, mp.tile_size);
    }
    Ok(p)
}

/// Faithful port of C mempool_free_tile().
/// Returns the tile to the freelist. Passing None/null is a no-op.
///
/// # Safety
/// A non-null `p` must be a live, uniquely owned tile previously returned by
/// this exact `Mempool`; it must be writable for at least one pointer value and
/// must not already be present in the freelist.
pub unsafe fn mempool_free_tile(mp: &mut Mempool, p: Option<*mut u8>) {
    let p = match p {
        Some(p) if !p.is_null() => p,
        _ => return,
    };
    // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
    unsafe {
        *(p as *mut *mut u8) = mp.freelist;
        mp.freelist = p;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mempool(tile_size: usize, at_least: usize) -> Mempool {
        Mempool {
            first_pool: ptr::null_mut(),
            freelist: ptr::null_mut(),
            tile_size,
            at_least,
        }
    }

    #[test]
    fn test_mempool_init_sets_fields() {
        let mut mp = make_mempool(0, 0);
        mempool_init(&mut mp, 64, 8);
        assert_eq!(mp.tile_size, 64);
        assert_eq!(mp.at_least, 8);
        assert!(mp.first_pool.is_null());
        assert!(mp.freelist.is_null());
    }

    #[test]
    fn test_mempool_init_clears_pointers() {
        let mut mp = make_mempool(0, 0);
        mempool_init(&mut mp, 32, 4);
        assert!(mp.first_pool.is_null());
        assert!(mp.freelist.is_null());
    }

    #[test]
    fn test_mempool_alloc_tile_too_small() {
        let mut mp = make_mempool(std::mem::size_of::<*mut u8>() - 1, 8);
        assert!(mempool_alloc_tile(&mut mp).is_err());
    }

    #[test]
    fn test_mempool_alloc_tile_zero_at_least() {
        let mut mp = make_mempool(64, 0);
        assert!(mempool_alloc_tile(&mut mp).is_err());
    }

    #[test]
    fn test_mempool_alloc_single_tile() {
        let mut mp = make_mempool(64, 4);
        let tile = mempool_alloc_tile(&mut mp).unwrap();
        assert!(!tile.is_null());
        assert!(!mp.first_pool.is_null());
    }

    #[test]
    fn test_mempool_alloc_multiple_tiles() {
        let mut mp = make_mempool(32, 4);
        let mut tiles = Vec::new();
        for _ in 0..4 {
            let tile = mempool_alloc_tile(&mut mp).unwrap();
            assert!(!tile.is_null());
            tiles.push(tile);
        }
        assert!(tiles.windows(2).all(|w| w[0] != w[1]));
    }

    #[test]
    fn test_mempool_alloc_triggers_pool_growth() {
        let mut mp = make_mempool(64, 2);
        let first = mempool_alloc_tile(&mut mp).unwrap();
        let second = mempool_alloc_tile(&mut mp).unwrap();
        assert!(!first.is_null());
        assert!(!second.is_null());
        let pool1 = mp.first_pool;
        let _third = mempool_alloc_tile(&mut mp).unwrap();
        let pool2 = mp.first_pool;
        assert_ne!(pool1, pool2);
    }

    #[test]
    fn test_mempool_alloc0_tile_zeros_memory() {
        let mut mp = make_mempool(16, 2);
        let tile = mempool_alloc0_tile(&mut mp).unwrap();
        // SAFETY: the pointer and length originate from validated storage and produce a temporary slice within bounds.
        let bytes = unsafe { std::slice::from_raw_parts(tile, 16) };
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_mempool_alloc0_tile_invalid_params() {
        let mut mp = make_mempool(2, 0);
        assert!(mempool_alloc0_tile(&mut mp).is_err());
    }

    #[test]
    fn test_mempool_free_tile_basic() {
        let mut mp = make_mempool(64, 4);
        let tile = mempool_alloc_tile(&mut mp).unwrap();
        // SAFETY: `tile` was just allocated from `mp` and is returned once.
        unsafe { mempool_free_tile(&mut mp, Some(tile)) };
        assert_eq!(mp.freelist, tile);
    }

    #[test]
    fn test_mempool_free_tile_none_is_noop() {
        let mut mp = make_mempool(64, 4);
        // SAFETY: `None` is explicitly a no-op.
        unsafe { mempool_free_tile(&mut mp, None) };
        assert!(mp.freelist.is_null());
    }

    #[test]
    fn test_mempool_free_tile_null_is_noop() {
        let mut mp = make_mempool(64, 4);
        // SAFETY: a null tile is explicitly a no-op.
        unsafe { mempool_free_tile(&mut mp, Some(ptr::null_mut())) };
        assert!(mp.freelist.is_null());
    }

    #[test]
    fn test_mempool_alloc_free_reuse() {
        let mut mp = make_mempool(64, 4);
        let tile1 = mempool_alloc_tile(&mut mp).unwrap();
        // SAFETY: `tile1` was allocated from `mp` and is returned once.
        unsafe { mempool_free_tile(&mut mp, Some(tile1)) };
        let tile2 = mempool_alloc_tile(&mut mp).unwrap();
        assert_eq!(tile2, tile1);
    }

    #[test]
    fn test_mempool_freelist_lifo() {
        let mut mp = make_mempool(64, 4);
        let t1 = mempool_alloc_tile(&mut mp).unwrap();
        let t2 = mempool_alloc_tile(&mut mp).unwrap();
        assert_ne!(t1, t2);
        // SAFETY: both tiles were allocated from `mp` and are each returned once.
        unsafe {
            mempool_free_tile(&mut mp, Some(t1));
            mempool_free_tile(&mut mp, Some(t2));
        }
        let r1 = mempool_alloc_tile(&mut mp).unwrap();
        let r2 = mempool_alloc_tile(&mut mp).unwrap();
        assert_eq!(r1, t2);
        assert_eq!(r2, t1);
    }

    #[test]
    fn test_mempool_tile_size_equals_pointer_size() {
        let mut mp = make_mempool(std::mem::size_of::<*mut u8>(), 4);
        let tile = mempool_alloc_tile(&mut mp).unwrap();
        assert!(!tile.is_null());
    }
}
