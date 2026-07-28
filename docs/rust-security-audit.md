# Rust Dependency Audit

The repository has one authoritative Rust dependency graph:

- workspace manifest: `Cargo.toml`
- workspace lockfile: `Cargo.lock`
- workspace members: **85**
- locked packages: **180**

Per-crate `Cargo.lock` files under `src/**/rust` are intentionally ignored.
Cargo resolves those crates as members of the repository workspace, so auditing
local per-crate lock artifacts would report graphs that are neither committed nor
used by a clean build.

## Last Recorded Advisory Result

The last audit of the root lockfile recorded:

| Lockfile | Vulnerabilities | Warnings | Status |
|---|---:|---:|---|
| `Cargo.lock` | 0 | 1 | Historical result |

The warning was tied to the superseded dependency graph:

- `RUSTSEC-2026-0097`, reached through `rand 0.8.5` and `zbus 4.x`.
  The workspace now resolves `zbus 5.18.0` without `rand 0.8.5`, so its
  temporary waiver was removed rather than carried into an unrelated graph.

The refreshed lockfile resolves all direct requirements to their latest stable
releases as of 2026-07-28, but the advisory audit itself was not rerun because
`cargo-audit` was not already installed and this storage-constrained review did
not install new tools. The historical result above is not current release
evidence.

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
