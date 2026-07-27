# Core unit Rust architecture and parity audit

`src/core/rust/unit.rs` is the stable public facade. Existing callers keep using
`crate::unit::…`; implementation details live in this directory and are re-exported
by the facade.

## Ownership

- `model.rs`: core enums, records, `Unit`, rate limiting, and private shared helpers.
- `relationships.rs`: names, dependency insertion, D-Bus identity, slices, and bus/device watches.
- `lifecycle.rs`: construction, queues, loading, state transitions, PID watches, GC, and kill entry points.
- `runtime.rs`: exec/cgroup contexts, transient settings, process/resource state, freezer state, and log identity.
- `activation.rs`: activation-detail serialization, string tables, job normalization, and marker parsing.
- `dependency.rs`: higher-level dependency construction, merging, and retroactive dependency policy.
- `integration.rs`: filesystem/bus helper results, UID/GID bookkeeping, signals, and exported runtime metadata.
- `orchestration.rs`: condition/assert validation, audit/status hooks, and job dispatch.
- `inventory.rs`: the declared port inventory and status metadata.
- `tests.rs`: facade-level tests, compiled only under `cfg(test)`.

The implementation dependency graph is acyclic:

```text
model
└─ relationships
   └─ lifecycle
      ├─ activation
      └─ runtime
         ├─ dependency
         └─ integration
            └─ orchestration (also depends on activation and dependency)
```

Some branches shown above also depend directly on an earlier layer. No implementation
module imports the facade and no module uses `super::*`.

## Canonical audit

The semantic authority is `src/core/unit.c` together with `src/core/unit.h`. The
current Rust consumers are `dbus_manager`, `main`, `service`, and the
`runtime_manager` modules. The facade retains every previously declared public Rust
type, constant, and function name; `FUNCTION_INVENTORY` still has 248 unique entries.

Two behavior corrections are directly justified by the canonical C implementation:

1. `setenv_unit_path()` now sets the process `SYSTEMD_UNIT_PATH` environment variable,
   while retaining the Rust-side cached value used by the current invocation-ID model.
2. `unit_compare_priority()` now applies the C ordering: unit type descending, CPU
   weight descending, nice value ascending, then unit ID. It previously compared only IDs.

## Remaining parity gaps

The inventory is a surface inventory, not a claim of behavioral parity. Major gaps
remain:

- `Unit` and `ManagerRecord` omit the C vtable, jobs, timestamps, reference tracking,
  collect-mode state, dependency atoms/masks, and many queue/cgroup fields. Several
  public enums are also reduced models of the C enums.
- Start, stop, reload, GC, and resource release mostly mutate in-memory state. They do
  not implement vtable dispatch, job constraints, condition/assert ordering,
  frozen/deactivating behavior, cgroup emptiness, or the canonical errno distinctions.
- Dependencies store target names only. Reciprocal atoms, `add_reference`, origin and
  destination masks, merge following, notification generation, and manager-owned Unit
  identity are not modeled.
- PID watching, killing, helper forking, cgroup setup, transient setting writes,
  filesystem cleanup, state export, and audit/logging are simulations and do not
  perform the corresponding kernel, filesystem, bus, or manager operations.
- Rust `ActivationDetails` is an environment/pair container. C uses a refcounted,
  trigger-unit-specific object with per-unit-type vtables and a different serialized
  schema.
- Invocation IDs are currently deterministic hashes. C generates a fresh random
  `sd_id128_t`, updates state files, and queues D-Bus notification.
- D-Bus invocation paths and log-field helpers are simplified and do not yet match
  system/user manager formatting and ownership semantics.
- `UnitError` intentionally collapses the much wider negative-errno contract exposed
  by C. Several Rust signatures are models rather than ABI-compatible translations.

These gaps should be closed subsystem by subsystem against the canonical call paths;
they should not be hidden by adding names to `FUNCTION_INVENTORY`.

## Verification boundary

This decomposition is verified statically: formatting, whitespace, public-symbol
inventory, module line limits, facade consumers, and the import graph. Cargo, builds,
tests, and VM execution are intentionally excluded for the storage-constrained task.
