# Rust comparison fixture catalog

`tests-extra/test-*-rust.c` remains the upstream-facing C-vs-Rust ABI test
surface. It is intentionally not moved into a Rust-only tree.

Query registered Rust-linked fixtures and their legacy ownership with:

```sh
python3 tools/rust-port/check-rust-fixture-catalog.py --json
```

New fixtures must use `test-<semantic-subject>-<behavior>-rust.c`. Historical
chronological names such as `extraN` and `rustN` are retained only in
`rust-fixture-catalog.toml`; the gate rejects any new chronological target and
stale catalog entries. Add a semantic fixture beside its C authority, then register it normally in
`tests-extra/meson.build`.
