# Rust workspace layout

The Rust port uses one Cargo workspace and one lockfile. A crate belongs with
the C subsystem whose behavior it shadows:

```
src/<subsystem>/
├── C sources and Meson definitions
└── rust/
    ├── Cargo.toml
    ├── lib.rs
    └── main.rs, module files, and focused subdirectories
```

Do not create a parallel top-level Rust tree, a per-subsystem workspace, or a
nested Cargo crate below `rust/`. A new crate is added by creating
`src/<subsystem>/rust/Cargo.toml`, adding that directory to the root workspace,
and keeping every explicit Cargo target inside that same `rust/` directory.

## Language and dependency baseline

Every member uses Rust edition 2024, and the virtual workspace explicitly uses
Cargo resolver 3. The workspace architecture gate rejects an older edition or
resolver so a newly added crate cannot silently weaken the language contract.
The current dependency graph requires Rust 1.87 or newer; CI installs the
current stable toolchain.

Developer-only test crates still live in the canonical
`src/<subsystem>/rust/` layout. A crate may declare
`package.metadata.systemd-rust.dev-only = true` only when it is unpublished,
has an explicit `[[test]]` target, and declares no library or binary release
target. The architecture and safety-lint policy gates enforce those conditions;
the deterministic parser fuzz smoke harness is the fuzz subsystem's example.
When such a harness compiles source-level fixtures from another subsystem, its
manifest must list every external `#[path]` source by canonical repository path
(for example, `src/shared/rust/example.rs`). The architecture
gate permits only existing canonical `src/<subsystem>/rust/**/*.rs` fixtures,
so source-level test coverage cannot bypass crate ownership or dependency
layering by adding an unreviewed path escape.

The root `Cargo.lock` is the reproducible dependency authority. Direct
requirements may live in a member manifest when their feature/API needs are
crate-local, but they must resolve through that one lockfile. The repository's
monthly Cargo Dependabot group keeps stable releases visible; major upgrades
still require source review because Cargo metadata resolution does not prove
API compatibility.

## Dependency direction

`tools/rust-port/workspace-layers.toml` is the checked-in dependency policy.
It is intentionally a small architectural rule, not a claim of behavioral
parity or production selection:

```
substrate → foundation → library → shared → application
```

An internal crate may depend only on a strictly lower layer. The `application`
layer is the default for subsystem executables and daemons; only reusable
infrastructure belongs in the named lower layers. If a new reusable layer is
needed, add it to the policy with an explicit rank and migrate dependencies in
the same review. Do not solve a cycle by making two layers equal: extract the
small shared interface into the appropriate lower layer instead.

The workspace architecture gate verifies the physical layout, workspace
membership, local target paths, one lockfile, and this internal dependency
direction. It deliberately does not certify C compatibility, runtime
reachability, or that Cargo artifacts are selected by Meson.

## C and libc boundary

The goal is a safe Rust core, not a libc-free Linux system manager. Use the
`libc` crate where an exact C ABI, target-native type, errno, allocator, or
Linux syscall contract requires it; do not duplicate those layouts or numeric
values. Prefer `std` and safe Rust APIs everywhere else, and keep reusable raw
Linux operations in the `platform`/`substrate` layer.

An FFI leaf should convert borrowed C bytes and raw values into a safe,
owned-or-bounded Rust representation immediately. Keep each `unsafe` block
small, document its pointer and lifetime proof, preserve C allocator
provenance, and publish output pointers only at the same points and in the
same order as the C authority. libc types must not leak into unrelated domain
logic merely because the outer facade uses them.

## Module naming and transitional facades

Name modules for the behavior they own, never for the order in which they were
ported. New `shared_validatorsN`, `shared_str_tablesN`, `misc_validatorsN`, and
`misc_rustN` modules are rejected.

When one temporary Rust surface spans several exact C authorities, keep it
under a visibly transitional directory such as `shared_facades/`. Its leaf
modules and map rows must still name their responsibility and list every C/H
authority. Move behavior into the canonical authority module as its port
becomes complete; do not grow a new numbered batch.
