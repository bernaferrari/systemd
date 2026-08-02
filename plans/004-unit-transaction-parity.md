# Plan 004: Match C unit dependency, transaction, and manager-side job semantics

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If a
> STOP condition occurs, stop and report; do not improvise. Touch only the
> files listed in **Scope**. This plan consumes Plan 003 fixtures and does not
> implement D-Bus, startup/watchdog, or live VM comparison. When done, update
> `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 0370637b53..HEAD -- src/core/rust/transaction.rs src/core/rust/runtime_manager.rs src/core/rust/runtime_manager/job_runtime.rs src/core/rust/runtime_manager/service_jobs.rs src/core/rust/runtime_manager/service_runtime.rs src/core/rust/runtime_manager/service_machine.rs src/core/rust/runtime_manager/cgroup_runtime.rs src/core/rust/runtime_manager/notify_runtime.rs src/core/rust/runtime_manager/bound_liveness.rs src/core/rust/runtime_manager/unit_load.rs src/core/rust/runtime_manager/socket_runtime.rs src/core/rust/unit`

## Status

- **Priority**: P1
- **Effort**: XL (sequential graph, service, and non-service milestones)
- **Risk**: HIGH — this graph controls activation and shutdown of all units
- **Depends on**: `plans/003-unit-parser-inventory-and-diagnostics.md`
- **Category**: correctness / tests / architecture
- **Planned at**: commit `0370637b53`, 2026-08-01

## Why this matters

The parser is only safe when the manager consumes its relationships with
C-compatible ordering, conflicts, rollback, and failure propagation. The Rust
runtime has useful jobs and service states, but full dependency semantics,
resource cleanup, service lifecycle, socket activation, and non-service unit
transitions remain incomplete. This plan is explicitly sequenced and does not
claim all unit types at once.

## Current state

- `src/core/rust/transaction.rs` owns the Rust graph and has a separate test
  module beginning around line 988.
- `src/core/rust/runtime_manager.rs:468` owns live units/jobs; resource and
  lifecycle consumers are split across `job_runtime.rs`, `service_jobs.rs`,
  `service_runtime.rs`, `service_machine.rs`, `cgroup_runtime.rs`,
  `notify_runtime.rs`, `bound_liveness.rs`, `unit_load.rs`, and
  `socket_runtime.rs`.
- `service_readiness.rs:29-70` intentionally rejects incomplete readiness
  modes; `socket_runtime.rs:25-60` supports only bounded stream activation.
- C authorities are `src/core/transaction.c`, `job.c`, `unit.c`,
  `service.c`, `socket.c`, `manager.c`, and the generated parser contract from
  Plan 003.

Plan 005 owns startup/security/watchdog setup and deadlines. This plan owns
manager-side graph/job bookkeeping and resource cleanup only; it must not
silently implement watchdog kernel setup or lifecycle handoff.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Format | `cargo fmt --all -- --check` | Exit 0 |
| Transaction tests | `cargo test --locked --manifest-path src/core/rust/Cargo.toml transaction -- --test-threads=1` in Linux | All transaction tests pass |
| Runtime tests | `cargo test --locked --manifest-path src/core/rust/Cargo.toml runtime_manager -- --test-threads=1` in Linux | All runtime-manager tests pass |
| Linux typecheck | `cargo check --locked --workspace --tests --target aarch64-unknown-linux-gnu` in Lima | Exit 0 |
| Reachability | `python3 tools/rust-port/core-runtime-reachability-gate.py` | Exit 0; new modules classified |
| Diff hygiene | `git diff --check` | Exit 0 |

## Scope

**In scope**:

- `src/core/rust/transaction.rs`
- `src/core/rust/runtime_manager.rs`
- `src/core/rust/runtime_manager/job_runtime.rs`
- `src/core/rust/runtime_manager/service_jobs.rs`
- `src/core/rust/runtime_manager/service_runtime.rs`
- `src/core/rust/runtime_manager/service_machine.rs`
- `src/core/rust/runtime_manager/cgroup_runtime.rs`
- `src/core/rust/runtime_manager/notify_runtime.rs`
- `src/core/rust/runtime_manager/bound_liveness.rs`
- `src/core/rust/runtime_manager/unit_load.rs`
- `src/core/rust/runtime_manager/socket_runtime.rs`
- `src/core/rust/unit/`
- Plan 003 fixtures and matching tests
- `plans/README.md` (status only)

**Out of scope**:

- D-Bus wire/server/name ownership (Plans 002 and 006);
- startup/security/watchdog kernel setup and reexec (Plan 005);
- changing C graph/job code or Meson production ownership;
- live VM differential scripts (Plan 006).

## Steps

### Step 1: Define a deterministic manager-side trace

Create a trace format for unit loads, edges, job IDs, job modes, ordering,
state transitions, failures, retries, and resource cleanup. For every expected
trace fixture record C provenance (`transaction.c`, `job.c`, a named upstream
test, or the Plan 003 generated directive row) and the exact assertion being
mirrored. This is a deterministic Rust contract, not live C parity; Plan 006
will execute paired C/Rust traces.

**Verify**: the same fixture produces byte-identical Rust traces and each
  expected event has checked-in C provenance.

### Step 2: Close dependency graph semantics

Implement `Requires`, `Requisite`, `Wants`, `BindsTo`, `PartOf`, `Upholds`,
`After`, `Before`, `Conflicts`, `OnFailure`, `OnSuccess`, default-dependency,
isolation, cycle detection, conflict resolution, job modes, and rollback.
Ensure rollback closes or restores every manager-owned listener, cgroup,
pidfd, notify source, and service state through the scoped consumer modules.

**Verify**: graph tests cover cycles, replacement, isolation, simultaneous
  start/stop, dependency failure, rollback, and cleanup with no leaked resource.

### Step 3: Close manager-side service lifecycle

Implement only service readiness/restart behavior whose parser and executor
consumers exist: simple, oneshot, notify, start limits, restart policies,
timeouts, and failure propagation. Keep `Type=dbus`, `notify-reload`, FDSTORE,
unsupported `NotifyAccess`, and watchdog kernel/deadline setup fail-closed until
Plan 005/006 completes their contracts.

**Verify**: tests assert MainPID, active/sub states, restart counts, timeout
  results, SIGCHLD/PID reuse, and cleanup. Unsupported modes return typed errors
  without activation.

### Step 4: Close socket and non-service bookkeeping in sequence

First complete `ListenStream` association, activation, restart, stop, and FD
metadata. Then add other socket/unit types only when parser and resource
consumers are present. Finally cover mount/swap/path/timer/target/slice/scope
state transitions represented by the current typed model. Each family gets its
own promotion status and tests; do not label the whole parser complete.

**Verify**: each promoted family has positive, invalid, conflict, stop, and
  cleanup tests; failed jobs leave no listener/cgroup/pidfd/notify state.

### Step 5: Hand off the oracle

Export the trace schema, fixture provenance, and unsupported categories for Plan
006. Keep all live C/R execution and semantic normalization out of this plan.

**Verify**: Rust tests, reachability, formatting, and diff checks pass with C
  production ownership unchanged.

## Test plan

- Deterministic graph/job traces with C provenance.
- Cycle/conflict/rollback/isolation tests.
- Service readiness/restart/timeout/notify/cleanup tests.
- Socket activation and non-service unit tests by family.
- Unsupported-mode no-mutation tests.

## Done criteria

- [ ] Graph/job trace oracle is deterministic and provenance-backed.
- [ ] Dependency, conflict, ordering, rollback, retry, and failure propagation
      match the declared C semantics.
- [ ] Promoted service/socket/unit families have parser, manager/resource
      consumers, and negative tests; unsupported families fail closed.
- [ ] Watchdog kernel/deadline setup, D-Bus, and VM parity remain deferred.
- [ ] Linux tests, workspace check, reachability, formatting, and diff hygiene
      pass; C ownership remains unchanged.

## STOP conditions

- C and Rust disagree on final state, ordering, error, or cleanup and the cause
  is not an explicitly unsupported feature.
- A setting lacks a runtime/resource consumer or requires an out-of-scope
  subsystem.
- Rollback cannot prove every manager-owned resource is restored or closed once.
- The work expands into watchdog kernel setup, D-Bus, or live VM comparison.

## Maintenance notes

- Update provenance whenever `transaction.c`, `job.c`, unit-type C files, or
  Plan 003's generated matrix changes.
- Keep graph, service, socket, and non-service promotion rows separate for
  review and rollback.
