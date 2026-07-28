# Rust port tooling

This directory contains the static checks and metadata that keep the C-to-Rust
port reviewable. Existing script paths are stable CI interfaces; add a new
tool in place and classify it in [`tool-taxonomy.toml`](tool-taxonomy.toml).
The taxonomy gate rejects an unclassified Python, TOML, or JSON tool artifact.

| Need | Start here |
| --- | --- |
| Find a tool or its maintenance owner | [`tool-taxonomy.toml`](tool-taxonomy.toml) |
| Map C authority to Rust twins | [`map.toml`](map.toml), `stale-check.py`, `diff-report.py` |
| Describe a reviewed partial behavior slice | `contracts/`, `check-behavior-contract.py` |
| Audit C ABI/fixture parity | `basic_ffi_review_catalog.py`, `check-*-abi.py` |
| Executable Linux priority runtime set | [`PRIORITY_RUNTIME_SET.md`](PRIORITY_RUNTIME_SET.md), job `rust-meson-reviewed-shadows` |
| Enforce safe production boundaries | `truthfulness-gate.py`, `check-*-boundary.py`, `workspace-architecture-gate.py` |
| Review safety, lints, or dependencies | `unsafe-safety-gate.py`, `rust-safety-lint-policy-gate.py`, `cargo-audit-all.py` |
| Regenerate or inspect reports | `generate-gpt-table.py`, `coverage-dashboard.py`, `audit-port1.py` |

## Fast static review

```sh
python3 tools/rust-port/check-tool-taxonomy.py
python3 tools/rust-port/test-tool-taxonomy.py
python3 tools/rust-port/sync-metadata-gate.py --repo-root .
python3 tools/rust-port/check-behavior-contract.py --repo-root .
```

Run a focused gate only when its map/contract scope exists. These checks do
not replace build, differential, kernel, or boot validation; those claims
remain explicitly separate in the port map and behavior contracts.
