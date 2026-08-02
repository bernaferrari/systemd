# Plan 002: Build the audited Rust PID1 private-bus transport and contract matrix

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If a
> STOP condition occurs, stop and report; do not improvise. Touch only the
> files listed in **Scope**. This plan builds transport and evidence; it does
> not bind the production socket or claim full D-Bus parity. When done, update
> the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 0370637b53..HEAD -- src/core/rust/pid1_dbus_auth.rs src/core/rust/pid1_dbus_command_adapter.rs src/core/rust/pid1_dbus_listener.rs src/core/rust/pid1_dbus_reply_adapter.rs src/core/rust/pid1_dbus_reply_queue.rs src/core/rust/pid1_dbus_server.rs src/core/rust/pid1_dbus_transport.rs src/core/rust/pid1_dbus_transport_types.rs src/core/rust/pid1_dbus_wire.rs src/core/rust/pid1_private_bus_runtime.rs src/core/rust/pid1_manager_commands.rs src/core/rust/dbus_manager`

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH — this is a privileged IPC boundary
- **Depends on**: `plans/001-rust-pid1-sidecar-install.md`
- **Category**: security / correctness / architecture / tests
- **Planned at**: commit `0370637b53`, 2026-08-01
- **Execution status**: IN PROGRESS — 23 of 897 C-vtable rows have been
  reviewed. A bounded ancillary-FD receive helper compiles, but is deliberately
  disconnected from the production listener.
- **Next gate**: expand the C-authoritative row review and connect the helper
  only through authenticated direct-private-peer admission, bounded ownership,
  and cleanup tests. Production `/run/systemd/private` binding and system-bus
  name ownership remain deferred.

## Why this matters

Rust already has bounded D-Bus framing, peer authentication, reply queues, and
manager-command adapters, but these are disconnected shadows. The production
PID1 deliberately does not bind `/run/systemd/private`, and the current wire
subset cannot represent the full manager contract. Before later plans integrate
the live bus, the transport and API inventory must be correct, bounded, and
traceable to C. This plan intentionally does not request a bus name or enable a
production listener.

## Current state

- `src/core/rust/pid1_dbus_wire.rs:4-15` documents a checked scalar subset that
  rejects containers and Unix FDs; it is not an `sd-bus` replacement.
- `src/core/rust/pid1_dbus_server.rs:15-21` says the server must not be
  advertised from production `main.rs` because vtables, properties, signals,
  and authentication are incomplete.
- `src/core/rust/pid1_private_bus_runtime.rs:15-18` says the runtime is not
  constructed by `main.rs`; tests use non-production paths.
- `src/core/rust/pid1_dbus_reply_adapter.rs:33-62` exposes a deliberately
  small introspection shadow and omits `Properties`.
- `src/core/rust/main.rs:929-964` enables only a non-PID1 test pathname.
- The private socket C setup is in `src/core/dbus.c:620-744` and listener
  creation is at `src/core/dbus.c:983-1042`: it authenticates peer credentials
  and uses `sd_bus_set_sender()` for direct-peer semantics. Object/vtable
  registration starts at `src/core/dbus.c:549`. The separate system API bus name request is at
  `src/core/dbus.c:807` and is not part of this private-transport milestone.
- C member authorities are `src/core/dbus-manager.c` (including the vtables
  around line 2991), `src/core/dbus-unit.c` (around line 924),
  `src/core/dbus-job.c` (around line 122), all unit-type `src/core/dbus-*.c`
  files, and the documentation cross-check in
  `man/org.freedesktop.systemd1.xml`. The man page is DocBook, not an
  introspection XML source; do not parse it as the machine authority.

Keep the existing layering from `docs/ARCHITECTURE.md`: framing owns bytes,
transport owns peer/FD lifecycle, adapters own typed mapping, and manager
dispatch owns state. Every boundary must be fail-closed and allocation-bounded.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Format | `cargo fmt --all -- --check` | Exit 0 |
| Wire tests | `cargo test --locked --manifest-path src/core/rust/Cargo.toml pid1_dbus_wire -- --test-threads=1` in Linux | All wire tests pass |
| Transport tests | `cargo test --locked --manifest-path src/core/rust/Cargo.toml pid1_dbus -- --test-threads=1` in Linux | All matching transport tests pass |
| Matrix profile | `meson setup <matrix-build> . -Dmode=developer -Dbpf-framework=disabled -Drust=enabled && meson compile -C <matrix-build> src/core/load-fragment-gperf.c` on Linux | Generated C profile exists |
| API matrix | `python3 tools/rust-port/dbus-vtable-inventory.py --root . --meson-build <matrix-build> --output <temporary-json>` | Stable C-vtable inventory and reviewed metadata |
| Linux typecheck | `cargo check --locked --workspace --tests --target aarch64-unknown-linux-gnu` in Lima | Exit 0 |
| FFI inventory | `python3 tools/rust-port/rust-ffi-inventory-gate.py` | Exit 0 |
| Production boundary | `python3 tools/rust-port/check-core-c-retention.py && python3 tools/rust-port/check-rust-production-selection.py` | Exit 0; production owner remains C |
| Diff hygiene | `git diff --check` | Exit 0 |

## Scope

**In scope**:

- `src/core/rust/pid1_dbus_auth.rs`
- `src/core/rust/pid1_dbus_command_adapter.rs`
- `src/core/rust/pid1_dbus_listener.rs`
- `src/core/rust/pid1_dbus_reply_adapter.rs`
- `src/core/rust/pid1_dbus_reply_queue.rs`
- `src/core/rust/pid1_dbus_server.rs`
- `src/core/rust/pid1_dbus_transport.rs`
- `src/core/rust/pid1_dbus_transport_types.rs`
- `src/core/rust/pid1_dbus_wire.rs`
- `src/core/rust/pid1_dbus_wire_source.rs`
- `src/core/rust/pid1_private_bus_runtime.rs`
- `src/core/rust/pid1_manager_commands.rs`
- `src/core/rust/dbus_manager/`
- matching unit/integration tests;
- new `tools/rust-port/dbus-vtable-inventory.py`, reviewed metadata, and tests
- `plans/README.md` (status only)

**Out of scope**:

- binding `/run/systemd/private` from production `main.rs`;
- requesting `org.freedesktop.systemd1` on the system bus;
- full Manager/Unit/Job/Properties parity, lifecycle state transfer, unit
  parser work, executor policy, or startup/security work (later plans);
- changing `meson_options.txt`, `src/core/meson.build`, or the C owner;
- weakening peer credentials, polkit policy, message limits, or FD ownership.

## Steps

### Step 1: Generate a C-authoritative API matrix

Write a deterministic tool under `tools/rust-port/` that extracts signatures,
flags, and vtable membership from the C `SD_BUS_*` definitions in
`dbus-manager.c`, `dbus-unit.c`,
`dbus-job.c`, and every unit-type `dbus-*.c` selected by the configured Meson
profile. Use the generated C vtables as the machine authority; use
`man/org.freedesktop.systemd1.xml` only as a documentation cross-check.

Add an explicit reviewed metadata layer for fields that vtable declarations do
not contain: object path/interface binding (from `dbus.c:437` and registration
sites), authorization class, state mutation, Rust owner, transport, and status
(`shadow`, `unsupported`, or `ready-for-integration`). Fail on duplicates,
missing C members, signature disagreement, or promotion without a test.
Feature-conditional vtables must carry their Meson feature predicate.

**Verify**: run the tool against the repository's normal Linux Meson profile;
  it produces stable output and a test rejects a deliberately removed or
  duplicated C vtable entry.

### Step 2: Extend bounded wire and FD semantics

Implement only the signatures selected for the first transport milestone:
arrays, structs, variants, object paths, and Unix FDs as needed by existing
manager-command adapters. Validate alignment, lengths, overflow, UTF-8,
message limits, and per-connection capacity before allocation. Convert every
received FD into one `OwnedFd` and test that disconnect/drop closes it exactly
once. Do not use `mem::forget` or recreate ownership from a raw integer.

**Verify**: little/big endian, truncation, malformed alignment, duplicate
  headers, oversized frames, pipelined frames, and FD-lifetime tests pass; the
  in-scope files contain no unreviewed raw-FD ownership.

### Step 3: Close direct private-peer transport behavior

Complete listener admission, `SO_PEERCRED` capture, UID/capability checks,
socket mode, connection limits, nonblocking registration, backpressure,
reply queue cleanup, and orderly disconnect. Preserve C's direct-peer
`sd_bus_set_sender()` semantics; do not add system-bus name ownership here.
Keep accept, authentication, decode, dispatch, reply, and signal work under
bounded per-turn budgets.

**Verify**: transport tests prove unauthorized peers are rejected, a full
  queue cannot starve other event sources, disconnected peers release all FDs
  and pending replies, and malformed frames kill only the offending peer.

### Step 4: Tie typed adapters to the manager seam without claiming parity

Make `pid1_dbus_command_adapter.rs`, `pid1_manager_commands.rs`, and the
`dbus_manager` protocol map each currently supported method to one typed request
and reply. For unsupported methods return the exact typed error and leave the
manager unchanged. Keep `RuntimeManager` as the only state owner; do not add a
shadow state machine in transport.

**Verify**: every `ready-for-integration` matrix row has a request, reply,
  authorization, and state-invariant test; every `unsupported` row has a
  negative test that proves no mutation.

### Step 5: Produce an integration handoff for later plans

Record the exact transport entry points, matrix status, direct-peer address
requirements, and remaining system-bus/name-owner gaps in the parity report.
Leave `main.rs` and production Meson selection unchanged. Plan 006 may consume
this matrix only after parser, transaction, startup, and lifecycle work is
complete.

**Verify**: all static, formatting, Linux, and C-owner gates pass and the
  matrix reports no unreviewed member.

## Test plan

- Wire framing and bounded-allocation unit tests.
- Peer credential, authorization, backpressure, disconnect, and FD ownership
  tests.
- Typed command/reply correlation and no-mutation negative tests.
- C-vtable extraction and matrix consistency tests.
- Existing production-selection gates remain required.

## Done criteria

- [ ] C-generated vtables, not DocBook, are the machine authority for the API
      matrix; feature predicates and transport type are recorded.
- [ ] Promoted wire signatures are fully bounds-checked with tested FD ownership.
- [ ] Direct private-peer authentication/backpressure/reply cleanup is complete.
- [ ] Typed Rust adapters have explicit tests and no hidden manager state.
- [ ] System-bus name ownership and production binding remain explicitly
      deferred to the later integration plan.
- [ ] Linux Rust tests, workspace check, gates, formatting, and diff hygiene
      pass.

## STOP conditions

- A C vtable cannot be extracted deterministically for the configured profile;
  stop and record the generator/feature mismatch.
- Implementing a signature would require unbounded allocation, unauthenticated
  peer input, duplicated FD ownership, or a new unsafe boundary without a
  written contract.
- A method's behavior depends on parser/transaction/startup work outside this
  scope; leave it `unsupported` and report it.
- Any change would bind the production socket or request the system bus name.

## Maintenance notes

- Upstream `SD_BUS_*` vtable changes must regenerate and review the matrix.
- Keep private-peer transport and system-bus name ownership as separate
  contracts; they have different C setup and authentication semantics.
- Plan 006 is responsible for production integration only after this transport
  evidence and Plans 003–005 are complete.
