# Plan 005: Match C PID1 startup, security, watchdog, and reexec contracts

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If a
> STOP condition occurs, stop and report; do not improvise. Touch only the
> files listed in **Scope**. Keep C selected in Meson. When done, update
> `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 0370637b53..HEAD -- src/core/main.c src/core/rust/main.rs src/core/rust/apparmor_setup.rs src/core/rust/selinux_setup.rs src/core/rust/smack_setup.rs src/core/rust/ima_setup.rs src/core/rust/ipe_setup.rs src/core/rust/kmod_setup.rs src/core/rust/clock_warp.rs src/core/rust/crash_handler.rs src/core/rust/import_creds.rs`

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH — startup runs as PID1 and controls recovery/security
- **Depends on**: `plans/004-unit-transaction-parity.md`
- **Category**: correctness / security / architecture / tests
- **Planned at**: commit `0370637b53`, 2026-08-01
- **Execution status**: IN PROGRESS — crash-policy extraction/coverage and a
  typed fail-closed refusal of unimplemented reexec handoff are landed.
- **Next gate**: establish C-compatible security composition, watchdog and
  console/core-pattern ownership, and descriptor-preserving reexec; refusal is
  a safety boundary, not reexec parity.

## Why this matters

The Rust PID1 reaches an event loop, but it does not yet reproduce the C
startup contract that establishes mounts, security policy, credentials, machine
identity, hostname, loopback, kernel modules, watchdogs, crash handling,
console ownership, cgroups, and reexec-aware skips. A simple target boot is not
enough if startup policy differs or a failure leaves PID1 in an unsafe state.

## Current state

- Rust startup is in `src/core/rust/main.rs:1252-1423`; it performs a bounded
  mount/cgroup/hostname/signal/generator/manager path and deliberately skips
  setup in test mode at lines 1295-1302.
- Focused Rust helpers exist in `apparmor_setup.rs`, `selinux_setup.rs`,
  `smack_setup.rs`, `ima_setup.rs`, `ipe_setup.rs`, `kmod_setup.rs`,
  `clock_warp.rs`, `crash_handler.rs`, and `import_creds.rs`, but they are not
  yet composed with all C ordering/fatality rules.
- C startup authority is `src/core/main.c:3614-3855`; security orchestration is
  `src/core/main.c:3172-3217`; defaults are at `src/core/main.c:2998-3017`.

Use typed phase outcomes and small audited FFI boundaries. Optional unavailable
features may warn/continue only where C does; fatal setup must stop PID1.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Format | `cargo fmt --all -- --check` | Exit 0 |
| Core tests | `cargo test --locked --manifest-path src/core/rust/Cargo.toml --bin systemd -- --test-threads=1` in Linux | All Rust PID1 binary tests pass |
| Linux typecheck | `cargo check --locked --workspace --tests --target aarch64-unknown-linux-gnu` in Lima | Exit 0 |
| Safety policy | `python3 tools/rust-port/rust-safety-lint-policy-gate.py` | Exit 0 |
| Isolated boot | `./test/test-rust-pid1-boot-harness.sh` on privileged Linux | All expected startup markers; no fatal marker |
| Production boundary | `python3 tools/rust-port/check-core-c-retention.py` | Exit 0; C remains owner |
| Diff hygiene | `git diff --check` | Exit 0 |

## Scope

**In scope**:

- `src/core/rust/main.rs`
- `src/core/rust/apparmor_setup.rs`
- `src/core/rust/selinux_setup.rs`
- `src/core/rust/smack_setup.rs`
- `src/core/rust/ima_setup.rs`
- `src/core/rust/ipe_setup.rs`
- `src/core/rust/kmod_setup.rs`
- `src/core/rust/clock_warp.rs`
- `src/core/rust/crash_handler.rs`
- `src/core/rust/import_creds.rs`
- focused startup/configuration tests;
- `plans/README.md` (status only)

**Out of scope**:

- D-Bus transport/name ownership (Plans 002 and 006);
- parser/transaction semantics (Plans 003–004);
- executor sandbox expansion, BPF programs, or C source deletion;
- Meson production selection or `/sbin/init` ownership.

## Steps

### Step 1: Record the C startup contract

Create a phase table for every C operation in `main.c:3614-3855`, including
order, inputs, outputs, fatality, initrd behavior, reexec/serialization skip,
and evidence. Include manager config/kernel-command-line options for crash
actions, watchdogs, mounts, security, and targets.

**Verify**: a test fails if a C phase lacks a Rust owner or a fatality/order
  classification changes without a test.

### Step 2: Compose typed Rust phases

Refactor `main.rs` into testable phases for process invariants, early mounts,
security, clock/epoch, credentials/machine ID, hostname/loopback/os-release,
kmod, cgroup, watchdog/crash/console, generators, manager construction, and
initial transaction. Keep production paths free of test-only root overrides and
publish generator environment at the same point as C.

**Verify**: phase tests cover success, unavailable optional feature, malformed
  input, permission failure, and fatal failure; the namespace harness reaches
  the expected marker order.

### Step 3: Close identity/security and descriptor ownership

Wire the focused security and identity helpers in C order. Preserve initrd and
feature-disabled behavior; make policy/credential failures match C. Every
temporary FD must have one owner and a tested reexec/exec disposition.

**Verify**: injected environments agree with C on skip/warn/abort, and no FD
  remains open after a failed phase or reexec preparation.

### Step 4: Close watchdog, crash, console, and reexec state

Port defaults/config parsing for runtime/reboot/kexec/pre-timeout watchdogs,
crash action/shell/VT, core pattern, console ownership, and service watchdog
environment. Transfer or close manager descriptors exactly once on reload/
reexec; skip only phases C skips.

**Verify**: tests cover defaults, overrides, invalid values, disable paths, and
  handoff; privileged Linux evidence records the same policy/result as C.

### Step 5: Integrate without changing production ownership

Feed phase results into the transaction oracle from Plan 004. Keep the Rust
sidecar and isolated harness available, but leave C selected in all normal and
release Meson configurations.

**Verify**: retention/selection gates still report `production-owner=C` and
  zero Rust replacements.

## Test plan

- Phase-order and fatality tests with injected environments.
- Security/identity/credential/watchdog/crash negative tests.
- Initrd, normal boot, reload, and reexec fixtures.
- Privileged namespace smoke and later VM trace evidence.

## Done criteria

- [ ] Every C startup operation has a Rust owner, order, fatality policy, and
      test evidence.
- [ ] Security, identity, watchdog, crash, console, and credential phases are
      composed with explicit ownership and C-compatible fallback.
- [ ] Initrd/reexec state and diagnostics are preserved.
- [ ] No test-only path override affects production startup.
- [ ] Linux tests, workspace check, safety/retention gates, formatting, and
      diff hygiene pass; C ownership remains unchanged.

## STOP conditions

- Fatal/best-effort behavior cannot be established from C or tests.
- Security, credential, watchdog, crash, or reexec behavior would be weaker or
  less deterministic than C.
- Resource ownership cannot be proven across reexec.
- A fix needs an unscoped unsafe boundary or production selection change.

## Maintenance notes

- Update the phase table whenever `src/core/main.c` startup order/configuration
  changes.
- Review ordering and failure policy, not only helper invocation.
