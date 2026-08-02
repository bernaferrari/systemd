# Rust Port Completeness Audit

Date: 2026-07-29
Scope: `systemd/src` C-vs-Rust completeness and replacement readiness for Linux distro init use.

## Method

1. Regenerated file-count coverage snapshot with:
   `python3 tools/rust-port/coverage-dashboard.py --write docs/rust-port-coverage.md`
2. Sampled representative Rust subsystems for behavioral depth (not only file count).
3. In the lightweight Ubuntu 24.04/aarch64 Lima guest, compiled every Cargo
   target with `cargo check --locked --workspace --all-targets` using Rust
   1.97.1.
4. Rebuilt and ran all 141 registered `-rust` Meson C-versus-Rust shadow tests:
   141 passed, 0 failed.
5. Ran the behavior-contract, FFI ABI, registered-fixture, GPT ABI, fixture
   catalog, and synchronization-metadata gates.
6. Configured the two explicit experimental init milestones with
   `-Drust=enabled -Drust-init-milestones=enabled`, then exercised them both
   directly and through Meson: core runtime-manager **129 passed, 0 failed**;
   platform/cgroup **24 passed, 0 failed**; Meson **2 passed, 0 failed**.

## Source Inventory Snapshot

From `docs/rust-port-coverage.md`:

- All `src` C files: **1831**
- All `src` Rust files: **1464**
- Obvious metadata adapters: **30**
- Test/fuzz support files: **95**
- Unverified behavior candidates: **1339**

Interpretation: raw file ratios are not a coverage metric. Even the behavior-candidate
count is only an inventory after excluding obvious non-implementations; it does not
establish C behavior, ABI, build, installation, or executable parity.

The former Beads/Dolt issue database is not part of the current workspace, so
its historical count of 133 P2 issues is not an actionable or authoritative
measure of remaining work. The concrete replacement risks are described below
instead of being represented by a stale issue total.

The current machine-checked ABI inventory for the Rust-linked basic shadow
surface has **756** declarations, exports, and matching signatures, with zero
duplicates. The registered test inventory contains **144** Rust FFI sources;
all have a backing artifact and 23 manually declared symbols are accounted for.
This is strong ABI/linkage accounting, but it is not a claim that every C source
or daemon path has a Rust replacement.

## Current Static Architecture And Safety Checkpoint

This review also established several boundaries that were previously implicit:

- the Cargo-declared experimental Rust PID1 reaches only **15** of the **109**
  modules classified by the core reachability gate; the other **94** compile-time
  modules are disconnected shadows. A CI ratchet now makes every classification
  explicit, but lexical reachability is not behavioral parity;
- release-mode Meson configuration now rejects `rust-core-pid1`. Developer mode
  keeps it available only as a non-installed porting artifact; the installed
  and public PID1 remains the C implementation;
- all 85 internal workspace packages now set `publish = false`, and the
  architecture gate rejects newly publishable packages. The four smoke jobs
  that only exercise the CI runner's host systemd are explicitly classified as
  host behavior checks rather than Rust artifact parity evidence;
- hard-coded signed Rust `i8` has been removed from the scanned C-character ABI
  surface. The checked inventory contains **436** symbolic `libc::c_char`
  signatures and zero baseline exceptions for raw `*const i8`/`*mut i8`
  spellings;
- socket listeners are now owned by `OwnedFd` instead of leaked with
  `mem::forget` and closed manually. End-to-end `LISTEN_FDS`/`Accept=` delivery
  and event-source teardown ordering remain high-risk incomplete work;
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
  authenticated OpenSSL/TPM2/Varlink decryption remains a release blocker;
- the glibc UTMP facade now uses libc's exact target layout and serializes
  process-global cursor transactions. It is compiled only on the supported
  Linux/glibc target instead of pretending that an unavailable void API can
  fail safely.

The current Linux evidence is no longer static-only: the full Cargo workspace
target graph compiles, the 141 reviewed C/R shadow fixtures execute cleanly,
and both explicitly scoped Rust init milestones execute through Meson in Lima.
That evidence is intentionally limited to the selected, link-closed shadow
surface. It does not exercise an installed Rust PID1, privileged boot paths,
cross-target ABIs, fault injection, or full daemon integration.

## PID1 differential-evidence gate (in progress)

`test/systemd-cd4.sh` now has explicit `c`, `rust`, and `both` modes. The two
images are independent QCOW overlays from the same verified Ubuntu base image
and cloud seed. Only the Rust overlay installs `systemd-rust` and selects it
through that overlay's `/sbin/init`; the C baseline keeps the canonical
`/usr/lib/systemd/systemd` executable. Each run records the base-image hash,
architecture, selected PID1 identity, and (for Rust) the sidecar hash.

`test/test-rust-pid1-differential.sh --run <trace-directory>` runs the paired
images and compares the evidence. Its private-peer probes use the literal
`busctl --address=unix:path=/run/systemd/private` address for both root and
the unprivileged test user; they never substitute a default system-bus call.
The `--run` gate also forces the CD4 system-bus suite on; it cannot silently
turn that prerequisite into a passing identity-only run.
The collector intentionally fails if the Rust private transport is unavailable
or differs from C. Plan 002's reviewed vtable inventory and bounded wire
decoding are now available to this branch, but production private-socket
binding, the full authorization/error matrix, system-bus ownership, and state
adoption are still absent. The newly admitted no-argument lifecycle methods
therefore preserve kernel-derived sender identity and return the explicit
standard D-Bus `NotSupported` error instead of entering a partial handoff.
This is an **IN PROGRESS, blocking evidence gate**, not a claim of D-Bus,
reexec, shutdown, or boot parity. In CI (and in paired mode), missing VM
prerequisites are failures rather than passing skips.

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

The developer-only Rust PID1 is intentionally non-installed and remains
incomplete. Signal/lifecycle handling, unit operations, D-Bus contracts,
transaction verification/scheduling, socket activation, and fail-closed error
paths must be demonstrated together before replacing the C init process is
credible.

### B) Unit-file parser completeness

Core parser gaps still block parity for complete service semantics and policy
controls: the full `[Service]` and `[Unit]` directive space, kill/cgroup/exec
contexts, drop-ins, tokenizer behavior, and specifiers need systematic C/R
coverage rather than hand-maintained subsets.

### C) Daemon parity in resolved/networkd/logind/journald

Resolved, networkd, logind, and journald still need daemon startup, backend,
and integration parity. Journald ingress parity for `/dev/kmsg` and
`NETLINK_AUDIT` has a scoped shadow implementation;
socket ingress closeout evidence is captured in `docs/rust-journald-socket-ingress-parity.md`;
the kmsg/audit closeout checklist is captured in `docs/rust-journald-kmsg-audit-parity.md`.
Within journal-file parity, Rust contains
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

Production readiness still requires integration, fuzz, fault-injection, boot,
and cross-target system testing. The current 141-fixture C/R suite is a strong
baseline, not a substitute for those environments.

## Readiness Verdict

Current state is **not ready** for swapping distro `systemd` with Rust implementation on Ubuntu or general Linux distributions.

The port has substantial progress and several strong subsystems (especially udev-related work), but the remaining core replacement gaps still contain init, parser semantics, D-Bus contract, and integration correctness blockers.

The architecture is now harder to misrepresent: incomplete PID1 selection is
release-blocked, disconnected core modules and C-character ABI debt are
ratcheted, and two high-risk ownership/layout boundaries have been repaired.
That is meaningful progress, but it does not change the **NO-SHIP** verdict.

## Reproduction Commands

```sh
python3 tools/rust-port/coverage-dashboard.py --write docs/rust-port-coverage.md
python3 tools/rust-port/check-behavior-contract.py --repo-root .
python3 tools/rust-port/check-basic-rust-ffi-abi.py --root .
python3 tools/rust-port/check-registered-test-rust-ffi.py
python3 tools/rust-port/check-gpt-basic-abi.py --root .
python3 tools/rust-port/check-rust-fixture-catalog.py --repo-root .
python3 tools/rust-port/sync-metadata-gate.py --repo-root .

# In the `systemd-rust` Lima guest, with Rust 1.97.1 on PATH:
cargo check --locked --workspace --all-targets
mapfile -t rust_tests < <(meson test -C /home/bernardoferrari.guest/build-rust-reviewed --list | awk '/-rust$/')
meson test -C /home/bernardoferrari.guest/build-rust-reviewed -j1 "${rust_tests[@]}"

# Experimental Rust init scope only; this does not install or boot Rust PID1.
meson setup /tmp/systemd-rust-milestones-build . -Drust=enabled -Drust-init-milestones=enabled
meson test -C /tmp/systemd-rust-milestones-build --setup=rust_init_milestones -j1 \
  rust-init-core-runtime-manager rust-init-platform-cgroup
```
