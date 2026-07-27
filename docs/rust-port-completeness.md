# Rust Port Completeness Audit

Date: 2026-07-27
Scope: `systemd/src` C-vs-Rust completeness and replacement readiness for Linux distro init use.

## Method

1. Regenerated file-count coverage snapshot with:
   `python3 tools/rust-port/coverage-dashboard.py --write docs/rust-port-coverage.md`
2. Sampled representative Rust subsystems for behavioral depth (not only file count).
3. Mapped largest replacement blockers to open beads dependency chains.

## Source Inventory Snapshot

From `docs/rust-port-coverage.md`:

- All `src` C files: **1831**
- All `src` Rust files: **1424**
- Obvious metadata adapters: **28**
- Test/fuzz support files: **89**
- Crate scaffolding files: **163**
- Unverified behavior candidates: **1144**

Interpretation: raw file ratios are not a coverage metric. Even the behavior-candidate
count is only an inventory after excluding obvious non-implementations; it does not
establish C behavior, ABI, build, installation, or executable parity.

Also from beads status at audit time:

- Open or in-progress issues: **81**
- Open or in-progress P0 issues: **64**
- Open or in-progress P1 issues: **13**
- Open or in-progress P2 issues: **4**

The ABI inventories are similarly explicit: 111 Rust-owned headers currently
declare **976** unique C symbols, of which **300** have explicit Rust C exports
and **676** remain baseline debt. Separately, C tests linked to
`libsystemd_basic_rs.a` still carry **269** unique manually declared `rs_*`
symbols with no export from that artifact. These ratchets are release blockers,
not waivers or evidence that those test targets link or run.

## Current Static Architecture And Safety Checkpoint

This review also established several boundaries that were previously implicit:

- the Cargo-declared experimental Rust PID1 reaches only **8** of the **104**
  modules declared by `src/core/rust/lib.rs`; the other **96** compile-time
  modules are disconnected shadows. A CI ratchet now makes every classification
  explicit, but lexical reachability is not behavioral parity;
- release-mode Meson configuration now rejects `rust-core-pid1`. Developer mode
  keeps it available only as a non-installed porting artifact; the installed
  and public PID1 remains the C implementation;
- all 84 internal workspace packages now set `publish = false`, and the
  architecture gate rejects newly publishable packages. The four smoke jobs
  that only exercise the CI runner's host systemd are explicitly classified as
  host behavior checks rather than Rust artifact parity evidence;
- hard-coded signed Rust `i8` has been removed from the scanned C-character ABI
  surface. The checked inventory contains **173** symbolic `libc::c_char`
  signatures and zero baseline exceptions for raw `*const i8`/`*mut i8`
  spellings;
- socket listeners are now owned by `OwnedFd` instead of leaked with
  `mem::forget` and closed manually. End-to-end `LISTEN_FDS`/`Accept=` delivery
  and event-source teardown ordering remain P0 work;
- the epoll and timerfd wrappers now keep kernel descriptors under RAII
  ownership, set close-on-exec, reject source-ID collisions and mismatched
  removal, avoid raw-FD re-ownership, and propagate callback failures. They are
  still only a small subset of sd-event and do not provide source-handle,
  priority, child, or cancellation parity;
- production cgroup paths no longer fall back to `/tmp` or accept the
  test-oriented `SYSTEMD_CGROUP_ROOT` override. Tests have an explicit private
  root constructor;
- malformed unit fragment/drop-in syntax now propagates as `ENOEXEC` instead of
  disappearing as a missing unit. Unknown sections and lvalues remain accepted
  for forward compatibility, matching the C parser's warn-and-continue policy;
- encrypted credential fallbacks and Varlink credential crypto now fail closed
  instead of returning ciphertext or plaintext identity transforms. Complete
  authenticated OpenSSL/TPM2/Varlink decryption remains a P0 release blocker;
- the glibc UTMP facade now uses libc's exact target layout and serializes
  process-global cursor transactions. It is compiled only on the supported
  Linux/glibc target instead of pretending that an unavailable void API can
  fail safely.

These are static findings only. No Cargo, Meson, runtime, VM, or cross-target
test was run during this storage-constrained review.

## Representative Completeness Findings

### 1) Core manager/unit-file loading is still partial

The core parser has been separated from manager state, but it remains a
hand-maintained directive matrix and silently ignores unknown keys (`_ => {}`).
It is not yet equivalent to systemd's canonical load-fragment/gperf pipeline.

Evidence:

- strict file parse entry: `src/core/rust/runtime_manager/unit_file.rs:563`
- section/key dispatch: `src/core/rust/runtime_manager/unit_file.rs:615`
- unknown directives dropped: `src/core/rust/runtime_manager/unit_file.rs:1103`

### 2) Udev has substantial Rust code but is not release-validated

Rust udev includes substantial behavior in parser + queue + netlink receiver paths.
This audit did not build or execute those paths and therefore does not classify udev
as replacement-ready.

Evidence:

- rules parser and tokenization implementation: `src/udev/rust/udev-rules.rs`
- kernel uevent parser and ordered queue: `src/udev/rust/uevent-netlink.rs:62`
- datagram parser for ACTION/DEVPATH/etc: `src/udev/rust/uevent-netlink.rs:212`

### 3) Resolve has a real resolver slice, but not a daemon

`src/libsystemd/rust/sd_resolve.rs` now uses real libc resolver workers and
pollable completion signalling instead of fabricated DNS answers. A significant
portion of `src/resolve/rust` remains `PORT-SYNC` metadata, however, and its
manager does not implement the DNS daemon. The incomplete Rust
`systemd-resolved` binary target was removed so it cannot be mistaken for a
deployable resolver.

Evidence:

- metadata module pattern (`PortSyncModule`, symbol inventory): `src/resolve/rust/resolved-dns-stub.rs:11`
- wrapper-only module shape without daemon logic: `src/resolve/rust/resolved-dns-stub.rs:94`

### 4) Networkd and journald runtime code exists, but still far from full daemon parity

There is real Rust logic, but sampled modules are operational helpers/simplifications rather than full C-feature parity.

Evidence:

- network runtime state helper (sysfs read + state file): `src/network/rust/networkd_runtime.rs:3`
- journald storage/marker operations: `src/journal/rust/journald_runtime_storage.rs:108`
- journald daemon ingress orchestration: `src/journal/rust/journald_runtime_daemon.rs:5`

## Largest Remaining Gaps For Ubuntu-Grade Replacement

### A) PID1 + D-Bus + transaction chain

Critical beads in chain remain open and dependency-linked:

- `systemd-dgn7` (PID1 signals, D-Bus, lifecycle, sockets, and fail-closed behavior)
- `systemd-q491` / `systemd-q491.4.9` (artifact wiring and authoritative ABI gates)
- `systemd-xxf` (unit operations)
- `systemd-s4e` / `systemd-3gh` (transaction verify/scheduling)
- `systemd-yzz` / `systemd-d7b` / `systemd-af0` (D-Bus parity)

Without these, replacing systemd as init is not credible.

### B) Unit-file parser completeness

Core parser gaps still block parity for service semantics and policy controls:

- `systemd-iy9` (`[Service]` all directives)
- `systemd-5oe` (`[Unit]` all directives)
- `systemd-fh0` / `systemd-w2s` (kill/cgroup/exec contexts)
- `systemd-ial` / `systemd-t7g` / `systemd-t72` (drop-ins/tokenizer/specifiers)

### C) Daemon parity in resolved/networkd/logind/journald

P0 daemon functionality remains open and dependency-ordered:

- resolved: `systemd-onr`, `systemd-2p6`
- resolved backend/startup hardening: `systemd-o6pw`
- networkd: `systemd-uhi`, `systemd-h9z`, `systemd-lf5`
- logind: `systemd-750`, `systemd-deo`
- journald: `systemd-4hi`, `systemd-rbk`, `systemd-h97`

Journald ingress parity for `/dev/kmsg` and `NETLINK_AUDIT` was completed in `systemd-a8q`;
socket ingress closeout evidence is captured in `docs/rust-journald-socket-ingress-parity.md`;
the kmsg/audit closeout checklist is captured in `docs/rust-journald-kmsg-audit-parity.md`.
Earlier issue notes marked journald socket ingress closed. Within journal-file parity
(`systemd-rbk`), Rust contains
empty-file binary layout, typed DATA/FIELD/ENTRY append with hash-chain linkage and canonical
entry-item ordering/deduplication, checked record readback, a real `system.journal` runtime backend
for append/rotate/flush/catalog paths, keyed hashing, structural rotate suggestions, and an acyclic
`sd_journal_file/{wire,validation,index,records,graph}.rs` boundary. The current reader validates
canonical alignment/layout constants, header-pointer coherence, object structure, machine ownership,
and secure regular-file opens; unsupported sealed writes fail closed. Historical notes claim passing
Cargo tests, but
those results were not reproduced against the current rebased tree and are not current
release evidence. Remaining `systemd-rbk` gaps are compressed payload support, complete
cross-object/backlink graph proof, FSPRG/HMAC seal authentication, crash-ordering and mmap/SIGBUS
lifecycle, old-header recovery, repair tooling, and canonical traversal/open/rotate behavior across
all storage roots.
Audit-control parity is tracked outside the socket-ingress chain.

### D) End-to-end correctness and safety gates

Integration/fuzz/system tests required for production readiness are still open:

- `systemd-eta`, `systemd-dfw`, `systemd-5re`, `systemd-5rc`, `systemd-0oq`, `systemd-2u1`

## Readiness Verdict

Current state is **not ready** for swapping distro `systemd` with Rust implementation on Ubuntu or general Linux distributions.

The port has substantial progress and several strong subsystems (especially udev-related work), but the remaining open P0 dependency graph still contains core init, parser semantics, D-Bus contract, and integration correctness blockers.

The architecture is now harder to misrepresent: incomplete PID1 selection is
release-blocked, disconnected core modules and C-character ABI debt are
ratcheted, and two high-risk ownership/layout boundaries have been repaired.
That is meaningful progress, but it does not change the **NO-SHIP** verdict.

## Reproduction Commands

```sh
python3 tools/rust-port/coverage-dashboard.py --write docs/rust-port-coverage.md
bd status
bd list -n 0 --status open --json
bd list -n 0 --status in_progress --json
```
