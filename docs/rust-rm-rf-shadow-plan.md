# `rm_rf` Rust Shadow Plan

`src/shared/rust/rm_rf.rs` is an unselected Rust-native prototype. It has no
Meson target or `rs_*` C ABI, so `src/shared/rm-rf.c` remains the only runtime
authority. This plan deliberately prevents the prototype from being described
as a completed port before a differential shadow has earned that status.

## Scope and non-goals

The C authority is `src/shared/rm-rf.c` and `src/shared/rm-rf.h`. Its public
surface is `rm_rf_at()`, `rm_rf_child()`, `rm_rf_children()`, the two
hardening helpers, and the cleanup helpers. The eventual first Rust shadow
must expose the same C-visible return, descriptor-ownership, and output
semantics; it must not replace the installed C implementation.

Do not make the current prototype Meson-built merely to increase coverage.
The following gaps make that unsafe and would turn a build success into a
false parity claim:

- `Path::to_str()` rejects valid non-UTF-8 Unix names, whereas C accepts
  NUL-terminated bytes;
- `RmRfError` is useful internally but does not preserve every negative errno
  or C's first-error/continue-cleanup behavior at a C boundary;
- its filesystem classification is broader than C's `tmpfs`/`ramfs` exemption
  plus `cgroup2`, which weakens the physical-filesystem safety rule;
- `REMOVE_SUBVOLUME` lacks the authority's `btrfs_subvol_remove_at()`
  behavior and its recoverable-error fallthrough; and
- the C interface consumes `rm_rf_children()` file descriptors and observes
  flag-specific chmod restoration and `REMOVE_SYNCFS` ordering.

## Target design

Keep the reusable tree-walking core in safe Rust. Limit `unsafe` to a small
Linux-boundary module that owns C strings, borrowed directory descriptors,
`libc` calls, and exact errno conversion. The internal core should use:

- an opaque, validated Unix-name type backed by `&CStr`/`OsStrExt` bytes, with
  interior-NUL rejection only where a new C string is constructed;
- `Result<T, Errno>`, where `Errno` stores the original positive errno and the
  ABI adapter returns its exact negative `int`; and
- RAII (`OwnedFd`, directory handles, and explicit descriptor transfer) to
  make the C close-on-all-paths contract auditable.

The public facade belongs in a dedicated `rm-rf` shadow static library, not
the broad shared Rust crate. A narrow header should first export only the
surfaces backed by differential tests, for example
`rs_rm_rf_at(int, const char *, uint32_t) -> int`; helper exports follow only
after their own ownership contracts are exercised. Each Rust export must
publish exactly the same result as its C counterpart and preserve the caller's
allocator ownership. Cleanup helpers are deferred until their `PROTECT_ERRNO`
and free semantics are tested.

## Required implementation sequence

1. **Contract and boundary.** Add a scoped map entry, a behavior contract, and
   an ABI header for the first surface. Record raw-byte input, negative-errno,
   file-descriptor ownership, root refusal, and per-flag semantics before
   exposing any symbol.
2. **Safety policy.** Port C's exact `is_physical_fs()` predicate and root
   aliases. Preserve mount-point checks, `st_dev` restrictions, no-follow
   opens, and chmod/restore behavior. A broader notion of a temporary
   filesystem is a regression, not an enhancement.
3. **Btrfs authority.** Implement `REMOVE_SUBVOLUME` through the current
   btrfs authority with the same success, recoverable-error, recursive, and
   quota semantics. Until this is complete, reject that flag at the Rust ABI
   boundary rather than silently treating subvolumes as directories.
4. **Differential fixture.** Build a C test that invokes both C and Rust on
   isolated temporary trees and compares return values, remaining layout, and
   observable modes. The fixture must cover non-UTF-8 names, dangling
   symlinks, empty and populated trees, `REMOVE_ONLY_DIRECTORIES`,
   `REMOVE_MISSING_OK`, `REMOVE_CHMOD[_RESTORE]`, physical-filesystem refusal,
   mount-point/device boundaries, and descriptor consumption. Run btrfs cases
   only on an explicitly provisioned btrfs filesystem and mark them skipped
   otherwise; never infer btrfs parity from tmpfs.
5. **Promotion.** Wire only the tested facade into a `-Drust=enabled` shadow
   target. Keep C selected in Meson. Promote metadata from `needs_review` only
   after static ABI gates and the Lima differential fixture pass against the
   recorded current-C blobs.

## Review gates

A reviewer should reject the first production-shadow change unless all of the
following are demonstrated: raw byte names round-trip; every exported failure
is the C negative errno; no safe Rust allocation crosses a C ownership
boundary; `REMOVE_PHYSICAL` is never accidentally broadened; subvolume
behavior is explicit; and the Rust target is linked only beside, never in
place of, the C implementation. This keeps the eventual port both safe and
upstream-comparable without asking C to hide unresolved Rust behavior.
