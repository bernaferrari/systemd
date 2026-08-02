# Plan 006: Integrate full PID1 D-Bus/lifecycle behavior and Linux differential boot

> **Executor instructions**: Follow this plan only after Plans 002–005 have
> satisfied their required evidence gates. Run every verification command and confirm the expected result before
> moving on. If a STOP condition occurs, stop and report; do not improvise.
> Touch only the files listed in **Scope**. Do not flip distro production
> ownership in this plan. When done, update `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 0370637b53..HEAD -- src/core/rust/main.rs src/core/rust/pid1_dbus* src/core/rust/pid1_private_bus_runtime.rs src/core/rust/pid1_api_bus_name_owner.rs src/core/rust/pid1_manager_commands.rs src/core/rust/dbus_manager test/systemd-cd4.sh test/test-rust-pid1-boot-harness.sh docs/rust-port-completeness.md`

## Status

- **Priority**: P1
- **Effort**: XL
- **Risk**: HIGH — complete privileged control plane and boot evidence
- **Depends on**: Plans 002, 004, and 005
- **Category**: correctness / security / tests / migration
- **Planned at**: commit `0370637b53`, 2026-08-01
- **Execution status**: IN PROGRESS — the differential self-test and explicit
  private-address harness are landed. They intentionally fail closed while the
  Rust production private transport is absent.
- **Next gate**: obtain passing paired C/Rust real-boot, direct-private-IPC,
  lifecycle, and recovery traces; the harness alone is not parity evidence.

## Why this matters

This is the first plan allowed to combine the transport matrix, unit/job
semantics, startup phases, lifecycle handoff, and real Linux boot evidence. The
current Rust sidecar deliberately skips the production private bus and returns
`EOPNOTSUPP` for lifecycle objectives; the existing QEMU runner checks identity
and a small system-bus suite but has no C baseline or differential trace. A
release claim requires all of those contracts to be exercised together while
the C executable remains available for rollback.

## Current state

- `src/core/rust/main.rs:929-964` uses only a non-PID1 test socket; production
  D-Bus is explicitly unavailable.
- `src/core/rust/pid1_manager_runtime.rs:101-195` keeps terminal lifecycle
  objectives unsupported until complete state adoption exists.
- `src/core/rust/pid1_api_bus_name_owner.rs` models C's system-bus name-owner
  state but does not open the production transport.
- `test/systemd-cd4.sh:164-170` installs the sidecar and changes only the
  disposable overlay's init selector; its system-bus checks are skipped unless
  explicitly enabled at lines 245-249.
- `test/test-rust-pid1-boot-harness.sh:4-6` is intentionally a synthetic
  namespace/event-loop smoke, not a full boot.

Use the C vtables from Plan 002, the graph oracle from Plan 004, and phase
contract from Plan 005. Direct `/run/systemd/private` is peer-authenticated;
system-bus name ownership is a separate contract and must use the exact C
`RequestName` semantics. Do not normalize semantic values in differential
traces.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Format | `cargo fmt --all -- --check` | Exit 0 |
| Linux typecheck | `cargo check --locked --workspace --tests --target aarch64-unknown-linux-gnu` in Lima | Exit 0 |
| Core tests | `cargo test --locked --manifest-path src/core/rust/Cargo.toml pid1 -- --test-threads=1` in Linux | All selected PID1 tests pass |
| Shell syntax | `bash -n test/systemd-cd4.sh test/test-rust-pid1-boot-harness.sh test/test-rust-pid1-differential.sh` | Exit 0 |
| Host Rust build | `cargo build --locked --manifest-path src/core/rust/Cargo.toml --bin systemd --target x86_64-unknown-linux-gnu --target-dir <host-target>` on Linux x86_64 | Host Rust artifact exists |
| VM gate | `SYSTEMD_CD4_MODE=both SYSTEMD_CD4_SYSTEM_BUS_CHECKS=1 SYSTEMD_CD4_SYSTEMD=<host-target>/x86_64-unknown-linux-gnu/debug/systemd ./test/systemd-cd4.sh` on Linux x86_64 with QEMU/cloud tools | C baseline and Rust sidecar runs pass |
| Production boundary | `python3 tools/rust-port/check-rust-production-selection.py && python3 tools/rust-port/check-core-c-retention.py` | Exit 0; no distro ownership flip |
| Diff hygiene | `git diff --check` | Exit 0 |

## Scope

**In scope**:

- `src/core/rust/main.rs`
- all `src/core/rust/pid1_dbus*.rs` transport/server/adapter files;
- `src/core/rust/pid1_private_bus_runtime.rs`
- new `src/core/rust/pid1_system_bus_transport.rs` and its event-loop
  integration;
- `src/core/rust/pid1_api_bus_name_owner.rs`
- `src/core/rust/pid1_manager_runtime.rs`
- `src/core/rust/pid1_lifecycle.rs`
- `src/core/rust/runtime_manager/handoff.rs` and related handoff owner files
- `src/core/rust/pid1_manager_commands.rs`
- `src/core/rust/dbus_manager/`
- `test/systemd-cd4.sh`
- `test/test-rust-pid1-boot-harness.sh`
- new `test/test-rust-pid1-differential.sh`
- `docs/rust-port-completeness.md` evidence sections
- focused Rust/VM tests and `plans/README.md` status only

**Out of scope**:

- replacing `/usr/lib/systemd/systemd` or `/sbin/init` in normal/release
  installs;
- deleting C fallbacks;
- changing unit parser/graph/startup semantics outside their completed plans;
- treating `busctl` on the default system bus as a direct private-socket test.

## Steps

### Step 1: Complete the promoted API families

Use Plan 002's C-vtable matrix to implement Manager, Unit, Job, Properties,
standard Peer/Introspectable, and selected signals with exact signatures,
authorization, state mutation, reply correlation, and bounded budgets. Keep the
private peer's credentials and the system bus's name ownership distinct. The
direct private-socket checks must use the explicit address, for example:

```sh
busctl --address=unix:path=/run/systemd/private --no-pager \
    introspect org.freedesktop.systemd1 /org/freedesktop/systemd1
busctl --address=unix:path=/run/systemd/private --no-pager \
    call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager GetUnit s ssh.service
```

Run those once as the authenticated root peer and once as the test user. The
expected negative results must use the matrix's exact `AccessDenied`,
`NoSuchUnit`, `InvalidArgs`, or transport error names. Default `busctl` system
bus commands are not sufficient.

**Verify**: every promoted matrix row has a wire, authorization, manager state,
reply, signal, and negative test; unsupported rows return the declared C error.

### Step 2: Complete lifecycle state adoption

Use Plan 004's graph oracle and Plan 005's startup state to implement reload,
reexecute, exit, reboot, poweroff, halt, kexec, switch-root, and soft-reboot
only when all units/jobs, environment, descriptors, subscriptions, notify
sources, credentials, watchdogs, and pending replies are transferred or closed
exactly once. Keep unsupported objectives fail-closed until their full
contract passes.

**Verify**: in-process tests prove no stale manager state after every promoted
objective; unsupported objectives preserve the live manager and return the
correct error.

### Step 3: Build paired C/Rust disposable images

Extend `test/systemd-cd4.sh` with explicit `c` and `rust` modes. Both overlays
must derive from the same verified Ubuntu image and seed; Rust changes only the
overlay `/sbin/init` selector and installs `systemd-rust`, while the canonical C
executable remains intact. Record image checksum, binary hashes, kernel,
architecture, mode, and trace paths. Never mutate the host.

**Verify**: a static gate rejects canonical C overwrite commands; both images
  boot or fail with a diagnostic serial log, and cleanup removes only the exact
  temporary directory.

### Step 4: Run required boot, IPC, lifecycle, and recovery cases

Add `test/test-rust-pid1-differential.sh` with the same fixtures for C and Rust:

- target selection, system bus/name owner, direct private-peer authentication;
- `GetUnit`, `LoadUnit`, properties, job replies/signals, unauthorized calls;
- simple/oneshot/notify services, dependencies, restart/timeout/watchdog;
- socket activation, cgroup/namespace/credential policy, journal/network;
- daemon-reload, reexec, shutdown, soft reboot, dependency failure, bus
  disconnect, full queues, malformed unit files, and cleanup.

Normalize only PIDs, serials, timestamps, temporary paths, and machine IDs.
Compare exit statuses, D-Bus signatures/errors/signals, state/job traces,
cgroups, sockets, and journal markers.

**Verify**: C passes all required cases; Rust matches every promoted case. A
  skipped prerequisite is local-only and becomes CI failure; an unsupported
  feature is recorded and blocks production claims.

### Step 5: Publish a release-evidence report

Update the completeness document with exact image/build inputs, target matrix,
pass/fail/unsupported counts, volatile normalization, traces, and exclusions.
Add a machine-readable check that prevents `replace` or production-selection
claims while required categories are skipped or mismatched.

**Verify**: rerunning the report from a clean temporary directory reproduces the
  same result and the C-owner gates remain unchanged.

## Test plan

- Unit tests for all promoted wire, manager, authorization, and lifecycle rows.
- Paired Linux VM boots from identical images.
- Direct private-peer and system-bus tests with exact addresses/credentials.
- Differential service, dependency, cgroup, journal, network, reexec,
  shutdown, and recovery traces.
- Failure-injection and resource-cleanup checks.

## Done criteria

- [ ] Promoted D-Bus/API families and lifecycle objectives have complete C/R
      evidence and exact negative behavior.
- [ ] Rust boots as PID1 in a disposable Ubuntu overlay with the C fallback
      preserved and no host mutation.
- [ ] Required traces match C after only volatile normalization.
- [ ] Skipped or unsupported required cases block production claims.
- [ ] All Rust, shell, VM, static, safety, and diff gates pass.
- [ ] Normal/release Meson ownership remains C.

## STOP conditions

- Full state adoption, authorization, or signal ordering cannot be proven.
- Direct private-peer and system-bus semantics are conflated.
- A VM comparison needs semantic normalization or overwrites the C binary.
- QEMU/cloud prerequisites are absent in CI; fail instead of claiming evidence.

## Maintenance notes

- Every promoted C vtable, lifecycle objective, unit setting, or startup phase
  requires a matrix/fixture/report update.
- This is the evidence gate before any separate human-reviewed ownership flip;
  it is not itself permission to replace C.
