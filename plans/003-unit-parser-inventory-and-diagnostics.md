# Plan 003: Build generated unit coverage and lossless Rust parser diagnostics

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If a
> STOP condition occurs, stop and report; do not improvise. Touch only the
> files listed in **Scope**. This plan does not implement transaction or
> executor parity. When done, update the status row for this plan in
> `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 0370637b53..HEAD -- src/core/load-fragment-gperf.gperf.in src/core/meson.build src/shared/conf-parser.c src/core/rust/runtime_manager.rs src/core/rust/runtime_manager/unit_file.rs src/core/rust/runtime_manager/unit_load.rs tools/rust-port`

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED — diagnostics must preserve C's compatibility behavior
- **Depends on**: `plans/001-rust-pid1-sidecar-install.md`
- **Category**: correctness / tests / architecture
- **Planned at**: commit `0370637b53`, 2026-08-01
- **Execution status**: IN PROGRESS — the generated directive inventory and
  retained parser diagnostics are landed; this is not parser or runtime
  semantic parity.
- **Next gate**: rerun the configured-profile inventory and diagnostics gates,
  then keep recognized-but-unconsumed directives blocked until their runtime
  consumer and differential evidence exist.

## Why this matters

The Rust unit parser is a hand-maintained subset and ends in a silent catch-all.
Before implementing more semantics, the project needs a generated, feature-aware
inventory of what C accepts and a lossless way to distinguish recognized,
unknown, invalid, and unsupported settings. This plan deliberately preserves
C's warn-and-continue behavior for unknown/future lvalues; it does not invent a
new activation policy or claim unit parity.

## Current state

- `src/core/rust/runtime_manager/unit_file.rs:619-628` preserves C's warning
  policy in comments but does not retain structured diagnostics.
- `src/core/rust/runtime_manager/unit_file.rs:658-1177` is a hand-written
  directive match ending in `_ => {}` at line 1176.
- `src/core/rust/runtime_manager.rs:66-78` owns the `unit_file` and `unit_load`
  modules; there is no `runtime_manager/mod.rs`.
- `src/shared/conf-parser.c:159` shows C continuing after unknown lvalues, and
  ordinary invalid settings are generally logged non-fatally around line 1080.
- `src/core/load-fragment-gperf.gperf.in:3` is Jinja-templated and
  feature-dependent. Meson generates the concrete gperf input at
  `src/core/meson.build:121` and compiles it into the C authority. The raw
  template cannot be treated as a complete machine inventory.
- `docs/ARCHITECTURE.md` requires unit settings to be represented consistently
  in unit files, D-Bus, and client tooling.

Use a concrete configured Linux Meson profile for generation. Every row must
include its feature predicate and unit type. Keep typed Rust values and
`Result`-based errors; do not replace them with an unbounded string map.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Format | `cargo fmt --all -- --check` | Exit 0 |
| Parser tests | `cargo test --locked --manifest-path src/core/rust/Cargo.toml unit_file -- --test-threads=1` in Linux | All parser tests pass |
| Loader tests | `cargo test --locked --manifest-path src/core/rust/Cargo.toml unit_load -- --test-threads=1` in Linux | All loader tests pass |
| Linux typecheck | `cargo check --locked --workspace --tests --target aarch64-unknown-linux-gnu` in Lima | Exit 0 |
| Generate C authority | `meson compile -C <configured-build> src/core/load-fragment-gperf.c` | Generated profile artifact exists |
| Inventory | `python3 tools/rust-port/unit-directive-inventory.py --generated-gperf <configured-build>/src/core/load-fragment-gperf.c --meson-build <configured-build> --output <temporary-json>` | Exit 0; stable matrix |
| Fixture gate | `python3 tools/rust-port/check-registered-test-rust-ffi.py` | Exit 0 |
| Diff hygiene | `git diff --check` | Exit 0 |

## Scope

**In scope**:

- `src/core/rust/runtime_manager.rs`
- `src/core/rust/runtime_manager/unit_file.rs`
- `src/core/rust/runtime_manager/unit_load.rs`
- matching parser/loader tests and fixtures;
- new `tools/rust-port/unit-directive-inventory.py` and its tests;
- generated profile metadata under `tools/rust-port/`;
- `plans/README.md` (status only)

**Out of scope**:

- modifying the C parser, gperf template, or Meson production owner;
- transaction/job graph (Plan 004);
- service executor/security behavior (Plan 004 and later);
- D-Bus transport/API (Plan 002);
- changing unknown-key behavior from C's warn-and-continue policy;
- declaring any directive `replace` without a runtime consumer and differential
  test in a later plan.

## Steps

### Step 1: Generate one configured C authority

Require a configured Linux Meson build/profile and consume the generated gperf
input or compiled symbol metadata produced by that profile. Do not parse the
raw Jinja template. Capture Meson feature predicates, enabled unit types,
aliases, deprecated spellings, value parsers, and owning C callbacks. Make the
tool fail if the build directory is absent or was configured with a profile
whose feature set is not recorded.

**Verify**: the inventory tool produces stable JSON for the same build, changes
  when a feature predicate changes, and reports the profile/commit used.

### Step 2: Compare Rust coverage without overclaiming

Parse the Rust directive match into the same `(section, key, unit type)` key
space. Emit statuses: `recognized-and-stored`, `recognized-but-unconsumed`,
`unknown-future`, `invalid-path`, or `not-present`. Require a C row for every
Rust directive and a Rust status for every C row. Do not promote a directive to
parity merely because a struct field exists.

**Verify**: tests fail on duplicate keys, missing feature predicates, a C row
  without a Rust status, or a Rust field with no declared consumer.

### Step 3: Retain parser diagnostics losslessly

Replace the unobservable parser catch-all with a diagnostic record containing
section, key, line, unit type, and classification. Preserve C behavior:

1. Unknown sections/lvalues append a warning and continue.
2. Ordinary invalid values report a typed diagnostic using the C fatality class
   and do not silently turn into a default/`None` value.
3. A recognized-but-unconsumed directive is recorded as a blocker for later
   admission, but this plan does not reject it from C-compatible parsing or
   activation on its own.
4. Specifier expansion, list reset, quoting, escaping, and duplicate assignment
   diagnostics retain the source location and do not panic on malformed input.
   Every assignment records a disposition of `applied`,
   `ignored-preserving-prior-value`, or `fatal`, so repeated/drop-in
   assignments remain distinguishable from a defaulted field.

**Verify**: tests assert diagnostic class, section/key, line, and whether the
  parser continued; existing forward-compatible unknown-key tests remain green.

### Step 4: Seed representative fixtures for later semantic plans

Generate a small representative fixture set for each parser grammar/status
(scalar, boolean, duration, list/reset, path, specifier, alias, template,
drop-in, unknown, invalid, and malformed syntax) and at least one conditional
feature example. Do not attempt one fixture for every generated directive; rows
without Rust storage remain matrix evidence and belong to later semantic plans.
Store expected parser diagnostics and typed values. Do not add transaction trace
claims here; Plan 004 consumes these fixtures for graph semantics and Plan 006
runs live C/Rust comparisons.

**Verify**: fixture generation is deterministic, each matrix row has at least
  one positive or explicit unsupported case, and no fixture relies on the host
  system's unit directory.

### Step 5: Publish the handoff

Document the configured profile, generated authority path, matrix schema,
diagnostic classes, and unresolved semantic families. Keep the production C
owner unchanged and make later plans consume this artifact rather than
re-reading a stale template.

**Verify**: workspace, parser/loader, fixture, formatting, and diff gates pass.

## Test plan

- Inventory generator tests with a small synthetic generated gperf profile.
- Parser diagnostics for unknown, invalid, alias, specifier, reset, and
  malformed cases.
- Feature/unit-type conditional coverage tests.
- Deterministic fixture and stale-profile tests.

## Done criteria

- [ ] A configured Meson-generated C authority, not raw Jinja, drives the
      directive matrix.
- [ ] Every C/Rust directive row has a status, feature predicate, unit type,
      consumer, and test classification.
- [ ] Unknown/future directives remain C-compatible warnings; invalid values do
      not silently disappear into defaults; unsupported rows are visible.
- [ ] Focused fixtures are deterministic and ready for Plan 004/006.
- [ ] Linux parser/loader tests, workspace check, gates, formatting, and diff
      hygiene pass.
- [ ] No transaction, executor, D-Bus, or production-selection claim is made.

## STOP conditions

- The configured Meson profile cannot expose a deterministic generated C
  directive authority; stop and report the missing build artifact.
- C and Rust disagree on whether an unknown/invalid directive is fatal and the
  difference cannot be resolved from tests/source.
- A diagnostic change would alter external activation behavior; defer it to
  Plan 004 and report the boundary.
- The implementation requires changing the C parser or production ownership.

## Maintenance notes

- Regenerate the matrix whenever `load-fragment-gperf.gperf.in` or its Meson
  feature inputs change.
- Reviewers should check the configured feature profile and unit type, not only
  a section/key count.
- Plan 004 owns graph/job semantics; Plan 006 owns live C/Rust differential
  execution.
