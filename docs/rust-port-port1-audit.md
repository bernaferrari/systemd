# Port 1 Basic/Shared Audit

Generated: 2026-07-29 14:57 UTC
Repository: `/Users/bernardoferrari/Downloads/systemd/systemd`

## Scope

- `src/basic/rust/*.rs` (excluding `lib.rs`)
- `src/shared/rust/*.rs` (excluding `lib.rs`)

## Classification Summary

- Total modules audited: **274**
- `genuine-rust`: **190**
- `ffi-backed-rust`: **84**
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
| `src/basic/rust/af_list.rs` | 6 | 29 | 0 | 16 |
| `src/basic/rust/alloc_util.rs` | 6 | 41 | 0 | 25 |
| `src/basic/rust/basic_validators.rs` | 27 | 40 | 0 | 9 |
| `src/basic/rust/bitmap.rs` | 11 | 35 | 0 | 55 |
| `src/basic/rust/bus_label.rs` | 2 | 15 | 0 | 17 |
| `src/basic/rust/capability_util.rs` | 4 | 44 | 0 | 17 |
| `src/basic/rust/credential_validators.rs` | 2 | 35 | 0 | 9 |
| `src/basic/rust/device_nodes.rs` | 2 | 13 | 0 | 26 |
| `src/basic/rust/devnum_util.rs` | 7 | 36 | 1 | 63 |
| `src/basic/rust/dlfcn_util.rs` | 1 | 16 | 2 | 27 |
| `src/basic/rust/dns_domain_validators.rs` | 4 | 27 | 0 | 7 |
| `src/basic/rust/dns_label.rs` | 30 | 52 | 0 | 271 |
| `src/basic/rust/dns_type_predicates.rs` | 16 | 48 | 0 | 16 |
| `src/basic/rust/env_util.rs` | 6 | 42 | 0 | 29 |
| `src/basic/rust/errno_util.rs` | 34 | 57 | 2 | 12 |
| `src/basic/rust/ether_addr_util.rs` | 16 | 55 | 2 | 44 |
| `src/basic/rust/exec_util.rs` | 5 | 37 | 0 | 43 |
| `src/basic/rust/exit_status.rs` | 9 | 37 | 0 | 33 |
| `src/basic/rust/extract_word.rs` | 1 | 35 | 0 | 104 |
| `src/basic/rust/gpt_util.rs` | 17 | 41 | 0 | 45 |
| `src/basic/rust/gunicode.rs` | 2 | 28 | 1 | 8 |
| `src/basic/rust/header_inline_abi.rs` | 7 | 11 | 0 | 5 |
| `src/basic/rust/hexdecoct.rs` | 21 | 69 | 0 | 171 |
| `src/basic/rust/hostname_util.rs` | 10 | 79 | 0 | 93 |
| `src/basic/rust/id128_util.rs` | 10 | 38 | 0 | 43 |
| `src/basic/rust/image_policy_util.rs` | 17 | 69 | 0 | 169 |
| `src/basic/rust/import_util.rs` | 5 | 23 | 0 | 29 |
| `src/basic/rust/in_addr_util.rs` | 1 | 77 | 1 | 199 |
| `src/basic/rust/iovec_util.rs` | 12 | 41 | 0 | 34 |
| `src/basic/rust/iovec_wrapper.rs` | 8 | 36 | 0 | 34 |
| `src/basic/rust/memory_util.rs` | 9 | 28 | 0 | 35 |
| `src/basic/rust/mempool.rs` | 3 | 25 | 0 | 16 |
| `src/basic/rust/misc_validators.rs` | 11 | 64 | 0 | 38 |
| `src/basic/rust/mount_setup.rs` | 2 | 12 | 0 | 20 |
| `src/basic/rust/mountpoint_util.rs` | 4 | 57 | 0 | 17 |
| `src/basic/rust/netdev_str_tables.rs` | 16 | 18 | 0 | 61 |
| `src/basic/rust/nsflags.rs` | 4 | 33 | 0 | 30 |
| `src/basic/rust/nulstr_util.rs` | 2 | 35 | 0 | 42 |
| `src/basic/rust/parse_util.rs` | 41 | 88 | 0 | 172 |
| `src/basic/rust/path_util.rs` | 15 | 65 | 0 | 209 |
| `src/basic/rust/pe_binary.rs` | 7 | 37 | 1 | 36 |
| `src/basic/rust/percent_util.rs` | 12 | 57 | 0 | 29 |
| `src/basic/rust/prioq.rs` | 10 | 53 | 0 | 59 |
| `src/basic/rust/process_util_str_tables.rs` | 4 | 27 | 0 | 20 |
| `src/basic/rust/procfs_util.rs` | 7 | 35 | 0 | 60 |
| `src/basic/rust/ratelimit.rs` | 6 | 37 | 0 | 13 |
| `src/basic/rust/rlimit_util.rs` | 7 | 25 | 0 | 25 |
| `src/basic/rust/seccomp_util.rs` | 5 | 23 | 0 | 25 |
| `src/basic/rust/serialize.rs` | 2 | 36 | 0 | 27 |
| `src/basic/rust/sha1.rs` | 3 | 23 | 2 | 21 |
| `src/basic/rust/sha256_hmac.rs` | 3 | 44 | 6 | 22 |
| `src/basic/rust/signal_util.rs` | 7 | 33 | 3 | 72 |
| `src/basic/rust/siphash24.rs` | 6 | 34 | 0 | 24 |
| `src/basic/rust/socket_util.rs` | 19 | 61 | 0 | 114 |
| `src/basic/rust/sort_util.rs` | 8 | 19 | 0 | 32 |
| `src/basic/rust/stat_util.rs` | 6 | 56 | 0 | 4 |
| `src/basic/rust/strbuf.rs` | 4 | 25 | 0 | 31 |
| `src/basic/rust/string_table.rs` | 5 | 33 | 0 | 29 |
| `src/basic/rust/string_util.rs` | 17 | 73 | 0 | 80 |
| `src/basic/rust/string_util_ffi.rs` | 48 | 50 | 0 | 10 |
| `src/basic/rust/string_util_lines.rs` | 6 | 8 | 0 | 47 |
| `src/basic/rust/strv.rs` | 52 | 73 | 0 | 228 |
| `src/basic/rust/strverscmp.rs` | 1 | 21 | 0 | 28 |
| `src/basic/rust/strxcpyx.rs` | 4 | 26 | 0 | 16 |
| `src/basic/rust/udev_util.rs` | 2 | 12 | 0 | 32 |
| `src/basic/rust/unaligned.rs` | 12 | 51 | 0 | 2 |
| `src/basic/rust/unit_def.rs` | 8 | 38 | 2 | 55 |
| `src/basic/rust/unit_inline_abi.rs` | 2 | 2 | 0 | 0 |
| `src/basic/rust/unit_name.rs` | 20 | 91 | 0 | 157 |
| `src/basic/rust/user_util.rs` | 7 | 27 | 0 | 31 |
| `src/basic/rust/utf8.rs` | 19 | 33 | 0 | 120 |
| `src/basic/rust/virt.rs` | 5 | 25 | 1 | 7 |
| `src/basic/rust/xml_tokenizer.rs` | 1 | 34 | 0 | 73 |
| `src/shared/rust/btrfs_util.rs` | 1 | 49 | 1 | 40 |
| `src/shared/rust/daemon_util.rs` | 1 | 52 | 1 | 29 |
| `src/shared/rust/fdset.rs` | 1 | 76 | 1 | 54 |
| `src/shared/rust/ffi.rs` | 2 | 25 | 1 | 9 |
| `src/shared/rust/find_esp.rs` | 1 | 78 | 2 | 68 |
| `src/shared/rust/machine_id_setup.rs` | 1 | 75 | 8 | 93 |
| `src/shared/rust/openssl_util.rs` | 1 | 17 | 2 | 17 |
| `src/shared/rust/osc_context.rs` | 1 | 25 | 8 | 16 |
| `src/shared/rust/password_quality_util_passwdqc.rs` | 11 | 48 | 0 | 38 |
| `src/shared/rust/password_quality_util_pwquality.rs` | 16 | 48 | 0 | 44 |
| `src/shared/rust/pcre2_util.rs` | 8 | 51 | 1 | 46 |

## Actionable Outcome

- No deletion candidates found in Basic/Shared by this audit; modules are either genuine Rust or FFI-backed Rust implementations.
- Existing crate layout (`src/basic/rust`, `src/shared/rust`) already hosts migrated Rust logic for Port 1 scope.

## Rebuild

```sh
python3 tools/rust-port/audit-port1.py --write docs/rust-port-port1-audit.md
```
