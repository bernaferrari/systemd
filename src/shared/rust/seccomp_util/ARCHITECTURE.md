# Seccomp utility Rust shadow

## Build and consumer status

`src/shared/seccomp-util.c` remains the Meson-built implementation and the
semantic authority. Meson does not list `src/shared/rust/lib.rs`; the
`systemd-shared-rs` `Cargo.toml` explicitly describes itself as IDE support
only. The crate root nevertheless declares `pub mod seccomp_util`, so
`src/shared/rust/seccomp_util.rs` is the one structurally active Rust module.
There are currently no in-tree Rust callers of that public module and it has no
`no_mangle` or `export_name` C ABI exports.

The similarly named `src/basic/rust/seccomp_util.rs` is a different, small
module in Meson's `rust_staticlib`. It now backs all five `rs_seccomp_*`
declarations with explicit C exports over a safe parsing/table core and narrow,
documented pointer adapters. `tests-extra/test-seccomp-util-rust.c` compares
valid and invalid errno syntax and every available libseccomp architecture
token against C. `tools/rust-port/check-seccomp-basic-abi.py` mechanically
checks the declarations, exact Rust signatures, crate/Meson membership, and C
test call inventory. This is a repaired comparison ABI, not production seccomp
runtime wiring.

The deleted `src/shared/rust/src/seccomp_util.rs` could never be selected:
`src/shared/rust/Cargo.toml` sets the library path to the sibling `lib.rs`, and
no Meson file or Rust `mod` declaration names the nested path. Repository-wide
references were limited to the file itself and its unsafe-safety baseline
record. It was also syntactically malformed (`extern "C]`, mismatched brackets)
and referenced undeclared constants, function fields, and synchronization
types. Keeping it implied a second implementation that no build could parse.
The historical baseline entry is intentionally not edited: the safety gate
only compares extant Rust files, and this task forbids baseline changes.

## Module ownership

- `model.rs`: public constants, errors, flags, and policy value types.
- `architecture.rs`: architecture conversion, local-architecture state,
  availability probing, and architecture capability classification.
- `syscall_lists.rs`: C-table syscall groups plus source-derived `@known`.
- `filter_set.rs`: set metadata, lookup, recursive expansion, and set mutation
  planning.
- `parsing.rs`: errno/action parsing and construction of parsed policy maps.
- `tests.rs`: `cfg(test)` unit coverage with explicit imports.
- `seccomp_util.rs`: stable facade with explicit public reexports only.

Production imports are acyclic: `architecture -> model`,
`syscall_lists -> model`, `filter_set -> {model, syscall_lists}`, and
`parsing -> {architecture, filter_set, model}`.

## Proven corrections

Direct comparison with libseccomp's current `seccomp.h.in` and
`src/shared/seccomp-util.c` corrected the X32, PA-RISC, PPC, and S390
architecture tokens; filter-attribute and comparison-operator values; added
the C-supported LoongArch64 token and mappings; and fixed x32/powerpc64 native
architecture ordering. LoongArch64 is now included in the same socket and
`_sysctl` classifications as C.

Direct comparison with `errno_is_valid()`, `parse_errno()`, and
`errno_name_no_fallback()` corrected zero-errno acceptance, symbolic and
`safe_atoi()` numeric syntax, `EINVAL`/`ERANGE` classification, and nullable
errno-name conversion. `parse_syscall_and_errno()` preserves the range error
instead of flattening it to invalid-argument. Integer-minimum inputs no longer
overflow in fatal-error or negative-errno classification.

The C filter parser truth table is now reproduced for all four
invert/allow-list combinations, including the rule that a non-inverted filter
cannot carry an explicit errno override. The Rust-only `@log` group was
removed deliberately: no in-tree code uses this unbuilt API, while accepting a
group that C rejects is a policy divergence rather than useful compatibility.
The 30 remaining groups match the C source table. `@known` is no longer a
hand-maintained approximation (which was missing 132 authority entries and
contained 9 extras); both implementations now consume
`src/include/override/sys/syscall-list.txt`.

`tools/rust-port/check-seccomp-shared-policy.py` deterministically checks the
group inventory, order, direct-list contents, and `@known` provenance against
the C source/header. Unit tests cover the parser error classes, filter truth
table, generated-list identity, and integer-minimum safety. The availability
cache publishes its computed value with release/acquire ordering, both unsafe
probes have local safety contracts, and a poisoned local-architecture mutex no
longer turns a read into a panic.

The basic comparison ABI now uses the same corrected libseccomp tokens,
including the MIPS N32/endianness encodings, PPC, and LoongArch64 values. Its
numeric parser mirrors `safe_atoi()` base/prefix, whitespace, and range
semantics; invalid raw pointers fail closed. Canonical errno names are stored
once as static `CStr` values, so the C adapters publish stable pointers without
allocation or leaks. Both errno lookup directions use target `libc::E*`
constants rather than generic-architecture numbers and perform value lookup
without assuming numeric sort order; this is required for MIPS, PowerPC, and
SPARC Linux ABIs. Canonical aliases follow `errno-to-name.awk`
(`EAGAIN`/`EDEADLK`/`EOPNOTSUPP`).

## Exact remaining runtime P2 gaps

The reviewed result remains a static policy shadow. These runtime gaps are P2
follow-up work and are not evidence for selecting Rust in production:

- This is still an unbuilt, uncalled policy shadow, not a replacement for the C
  runtime. It does not dynamically load libseccomp or implement filter
  contexts, rule resolution/addition, loading, namespace/address-family/
  architecture/realtime/sysctl/syslog/hostname/personality/SUID restrictions,
  W^X enforcement, or sync suppression.
- `is_seccomp_available()` only performs kernel probes. C additionally requires
  successful libseccomp loading and honors secure `SYSTEMD_SECCOMP` parsing.
- The Rust parser returns owned vectors/maps, not C `Hashmap` mutation and
  libseccomp syscall-number resolution semantics. `PERMISSIVE`, logging,
  unknown-syscall resolution, and syscall-number collision behavior therefore
  lack runtime C parity fixtures.
- Local architecture enumeration still lacks the full C MIPS ABI/endian,
  PA-RISC, and LoongArch target matrix.
- The shared shadow recognizes LoongArch64 and RISC-V 64 unconditionally from
  their stable libseccomp token values. C exposes those names only when the
  build's `<seccomp.h>` defines the corresponding macros; systemd accepts
  libseccomp 2.4, so an older header can still make these two conversions
  differ. Exact parity requires applying the basic comparison surface's
  existing Meson header-feature cfgs to the unbuilt shared crate.
- Linux-target Cargo checks cover the library and test code, but no linked
  unit-test execution, Meson integration result, seccomp-enabled Linux runtime,
  or VM differential result exists.
