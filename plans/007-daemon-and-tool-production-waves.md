# Plan 007: Move Rust daemons and tools from shadows to measured production waves

> **Executor instructions**: Follow this plan only after Plan 006 has satisfied
> its required evidence gates. Run
> every verification command and confirm the expected result before moving on.
> If a STOP condition occurs, stop and report; do not improvise. Promote one
> binary at a time and keep its C fallback. When done, update `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 0370637b53..HEAD -- src/udev src/journal src/resolve src/network src/volatile-root src/bootctl src/creds src/measure src/random-seed tools/rust-port docs/rust-port-completeness.md`

## Status

- **Priority**: P2
- **Effort**: XL (several independently reviewable waves)
- **Risk**: HIGH — privileged daemons and persistent state
- **Depends on**: `plans/006-dbus-lifecycle-and-linux-differential-gate.md`
- **Category**: migration / correctness / security / tests
- **Planned at**: commit `0370637b53`, 2026-08-01
- **Execution status**: IN PROGRESS — production-wave ledgers for
  `systemd-creds`, `systemd-random-seed`, and `systemd-volatile-root` are
  landed. Every one remains a C-owned `shadow`.
- **Next gate**: complete the ledger-required Linux, persistence, privilege,
  recovery, and C/Rust differential evidence for one target at a time before
  considering fallback or replacement.

## Why this matters

Replacing PID1 does not replace the systemd product. Rust has meaningful code
for udev, journald, resolved, networkd, boot tools, credentials, and
volatile-root handling, but Meson still selects their C implementations. Each
target needs an explicit C/Rust contract, real IPC/persistence tests, fallback,
and upstream drift review; source-file counts and Cargo compilation are not
replacement evidence.

## Current state

- `tools/rust-port/check-rust-production-selection.py` retains nine C tools,
  including journalctl, resolved, udevd, volatile-root, bootctl, credentials,
  measure, and random-seed.
- `docs/rust-port-completeness.md:111-145` records that udev is substantial but
  unvalidated, resolved is not a daemon, and networkd/journald remain partial.
- `docs/rust-port.md:55-61` requires linked Meson comparison for C-linked crates.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Workspace check | `cargo check --locked --workspace --tests --target aarch64-unknown-linux-gnu` in Lima | Exit 0 |
| ABI/fixtures | `python3 tools/rust-port/check-registered-test-rust-ffi.py` | Exit 0 |
| Sync | `python3 tools/rust-port/sync-metadata-gate.py --upstream-ref origin/main` | Exit 0 or reviewed drift |
| Production boundary | `python3 tools/rust-port/check-rust-production-selection.py` | Only explicitly promoted target changes |
| Safety | `python3 tools/rust-port/rust-safety-lint-policy-gate.py` | Exit 0 |
| Diff hygiene | `git diff --check` | Exit 0 |

## Scope

**In scope**: one selected target wave at a time under `src/udev/`,
`src/journal/`, `src/resolve/`, `src/network/`, `src/volatile-root/`,
`src/bootctl/`, `src/creds/`, `src/measure/`, and `src/random-seed/`; matching
Meson files, tests, ABI inventories, `map.toml`, and parity documentation.

**Out of scope**: grouped privileged promotions, C deletion, PID1 ownership,
Cargo-only claims, and unrelated large refactors.

## Steps

### Step 1: Inventory one target

Record its C Meson target, Rust target, ABI, config, sockets/varlink/D-Bus,
capabilities, persistent state, lifecycle, and tests. Mark `shadow`, `fallback`,
or `replace` only with evidence.

**Verify**: a gate rejects a status without C authority, Rust owner, ABI evidence,
or an integration test.

### Step 2: Close runtime and persistence behavior

For the selected target, match CLI/config/errno, startup/shutdown/reload,
privilege, IPC, backpressure, persistent formats, malformed input, resource
exhaustion, and restart behavior in an isolated Linux environment. Use real
kernel sockets/netlink/filesystems for integration; synthetic fixtures are for
unit tests only.

**Verify**: C/Rust traces, exit statuses, files, IPC, and cleanup match; no
  leaked FD, stale socket, unbounded queue, or privilege regression appears.

### Step 3: Promote with fallback and drift gates

Wire only the selected target through Meson, retain an explicit C fallback, and
update map/ABI/sync metadata in the same change. Run `diff-report.py` against
`origin/main` before promotion.

**Verify**: both Rust and C targets build/install/run, the relevant systemd
  suite passes, and all safety/ABI/sync/architecture gates remain green.

### Step 4: Maintain a per-target ledger

Record exact tests, kernel/architecture matrix, exclusions, fallback switch,
upstream blobs, and release eligibility. A CI check must block `replace` while
any required evidence is stale, skipped, or mismatched.

**Verify**: the ledger is reproducible and source-count changes alone cannot
  promote a target.

## Test plan

- CLI/config/ABI unit tests.
- Real Linux IPC/persistence/lifecycle tests.
- Fuzz/resource-exhaustion tests.
- C/Rust differential traces.
- Meson build/install/fallback tests and upstream drift gates.

## Done criteria

- [ ] Every promoted target has a complete C/Rust contract, tests, and rollback.
- [ ] No target is production-selected without Meson, ABI, lifecycle, and
      persistence evidence.
- [ ] Sync metadata and upstream drift checks remain green.
- [ ] The ledger clearly separates shadow, fallback, and replace.

## STOP conditions

- Persistent format, privilege, IPC, or cleanup differs from C.
- A broad unsafe/C callback boundary lacks a narrow contract.
- Meson cannot build both targets reproducibly.
- A proposed change bundles several privileged daemons or flips PID1.

## Maintenance notes

- Promote one target per reviewable change.
- Keep the C authority and exact upstream blobs in every map entry.
- Review externally visible behavior and failure paths, not Rust file counts.
