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

An `exact` contract surface may group symbols only when its behavior axes
apply uniformly. On a multi-symbol surface, every `[[surface.output]]` must
name the C `symbols` it describes; this prevents one function's ownership or
publication rules from being attributed to unrelated functions in the group.
Its `arg` must name a parameter in each affected C declaration, or use
`return` for the function return value.

Every contract file below `contracts/` must have one unique `map.toml`
`contract_file` owner. A `c-exact` surface pairs each C symbol positionally
with `rs_<C symbol>`. Static fixture evidence must be the exact registered
`tests-extra/` source and must contain call/reference-shaped C and Rust tokens
in code; comments and string literals are not evidence.

For a scoped port, each Rust leaf's preamble names its direct local authority
as `PORT-SYNC: scope=<scope>; authority=<path>[,<path>...]`. Those paths must
be normalized members of the map's `c_paths`. The map may additionally pin
the reviewed transitive authority closure so changes below a direct helper
also invalidate the scope's review snapshot.
