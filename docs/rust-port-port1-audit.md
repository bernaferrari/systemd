# Port 1 Basic/Shared Audit

Generated: 2026-04-16 07:52 UTC
Repository: `/Users/bernardoferrari/Downloads/systemd/systemd`

## Scope

- `src/basic/rust/*.rs` (excluding `lib.rs`)
- `src/shared/rust/*.rs` (excluding `lib.rs`)

## Classification Summary

- Total modules audited: **404**
- `genuine-rust`: **394**
- `ffi-backed-rust`: **10**
- `thin-ffi-wrapper`: **0**
- `stub-wrapper`: **0**
- `metadata`: **0**

Definitions:
- `genuine-rust`: no `extern "C"` block; implemented logic lives in Rust.
- `ffi-backed-rust`: Rust owns control flow/logic but calls external C symbols for selected operations.
- `thin-ffi-wrapper`: mostly forwarding glue with low internal logic density.
- `stub-wrapper`: explicit `*_port_stub` symbols.
- `metadata`: Port-sync inventory/spec modules rather than behavior implementations.

## Thin-Wrapper Candidates

No thin/stub/metadata modules were detected in the audited Basic/Shared scope.

## FFI-Backed Rust Modules

| Module | extern C blocks | fn defs | ffi decls | logic tokens |
|---|---:|---:|---:|---:|
| `src/shared/rust/bpf_link.rs` | 1 | 56 | 0 | 26 |
| `src/shared/rust/bpf_program.rs` | 1 | 54 | 2 | 51 |
| `src/shared/rust/ffi.rs` | 1 | 25 | 0 | 9 |
| `src/shared/rust/idn_util.rs` | 8 | 37 | 0 | 34 |
| `src/shared/rust/libcrypt_util.rs` | 6 | 45 | 0 | 35 |
| `src/shared/rust/libmount_util.rs` | 11 | 73 | 0 | 58 |
| `src/shared/rust/password_quality_util_passwdqc.rs` | 12 | 49 | 0 | 46 |
| `src/shared/rust/password_quality_util_pwquality.rs` | 16 | 50 | 0 | 46 |
| `src/shared/rust/pcre2_util.rs` | 7 | 53 | 0 | 44 |
| `src/shared/rust/qrcode_util.rs` | 2 | 41 | 0 | 41 |

## Actionable Outcome

- No deletion candidates found in Basic/Shared by this audit; modules are either genuine Rust or FFI-backed Rust implementations.
- Existing crate layout (`src/basic/rust`, `src/shared/rust`) already hosts migrated Rust logic for Port 1 scope.

## Rebuild

```sh
python3 tools/rust-port/audit-port1.py --write docs/rust-port-port1-audit.md
```
