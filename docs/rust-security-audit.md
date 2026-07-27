# Rust Dependency Audit

The repository has one authoritative Rust dependency graph:

- workspace manifest: `Cargo.toml`
- workspace lockfile: `Cargo.lock`
- workspace members: **84**
- locked packages: **233**

Per-crate `Cargo.lock` files under `src/**/rust` are intentionally ignored.
Cargo resolves those crates as members of the repository workspace, so auditing
local per-crate lock artifacts would report graphs that are neither committed nor
used by a clean build.

## Last Recorded Advisory Result

The last audit of the root lockfile recorded:

| Lockfile | Vulnerabilities | Warnings | Status |
|---|---:|---:|---|
| `Cargo.lock` | 0 | 1 | Historical result |

The warning was:

- `RUSTSEC-2026-0097`, reached through `rand 0.8.5` and `zbus 4.x`.
  The previous review recorded a temporary waiver through 2026-10-01 because
  the known trigger requires custom-logger re-entry into `rand`, which the
  current tree does not intentionally use. The waiver must still be revalidated
  against the current advisory text and dependency graph.

This result was not reproduced after the 2026-07-27 rebase because this review
was explicitly restricted to static work. It is not release evidence.

## Required Release Gate

Before publishing, CI must run:

```sh
python3 tools/rust-port/cargo-audit-all.py \
    --waivers tools/rust-port/cargo-audit-waivers.toml \
    --write-report docs/rust-security-audit.md
```

The audit tool must see exactly the committed root `Cargo.lock`; the workspace
architecture gate rejects committed per-crate locks and Meson references to
ignored lockfiles.
