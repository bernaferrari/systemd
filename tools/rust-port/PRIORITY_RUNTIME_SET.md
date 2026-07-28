# Priority executable Linux runtime set

After static gates, `rust-meson-reviewed-shadows` in
[`.github/workflows/rust-ci.yml`](../../.github/workflows/rust-ci.yml) is the
confidence bottleneck: reviewed C-versus-Rust comparison fixtures must
**compile and run** on Linux, not only parse under static review.

Authoritative target membership lives in
[`basic_ffi_review_catalog.py`](basic_ffi_review_catalog.py) and is enforced by
[`check-basic-rust-ffi-abi.py`](check-basic-rust-ffi-abi.py). Do not expand CI
lists ad hoc; update the catalog so compile and `meson test` stay identical.

Local agents should prefer `meson test -C build-rust-reviewed <name>` (Meson
rebuilds deps). CI keeps a separate `meson compile` then
`meson test --no-rebuild` pair so the ABI gate can assert both steps.

## Priority areas and CI status

| Area | Fixtures configured for Linux CI execution | Notes |
| --- | --- | --- |
| Path / pure path / non-UTF-8 | `test-path-util-rust`, `test-path-funcs-rust`, `test-path-util-extra-rust` | Includes base predicates, `\\xff` path component, and split cases |
| Pure hash | `test-murmurhash2-rust` | Native-endian block loading and zero/negative signed-length boundary |
| Pure formatting | `test-format-util-rust` | Exact SI/IEC flags, bounded output, and `UINT64_MAX` sentinel |
| Scalar codecs | `test-hexdecoct-rust` | All decoder byte values plus masked and signed-remainder encoder boundaries |
| Argv classification | `test-argv-util-rust` | Opaque bytes, secure environment override, trailing slash, and null-terminated argv semantics |
| Confidential-virt table | `test-confidential-virt-rust` | NUL-backed borrowed strings and NULL/-EINVAL reverse lookup |
| Environment validators | `test-env-util-rust` | `ARG_MAX`, opaque invalid UTF-8, C-string vectors, and duplicate handling |
| Credential validators | `test-credential-validators-rust` | Filename/fd-name composition, glob grammar, NULL, and `NAME_MAX` boundaries |
| Locale tables and validator | `test-locale-util-rust` | NUL-backed lookup strings plus `.`, `..`, and invalid UTF-8 locale rejection |
| Image-class tables | `test-image-class-rust` | NUL-backed lookup strings, invalid enums, and NULL/-EINVAL reverse lookup |
| ARPHRD name and length tables | `test-arphrd-util-rust` | Generated Linux-UAPI names, ASCII case folding, HDLC/CISCO alias, and native-width lengths |
| Filesystem predicates | `test-fstype-util-rust` | Opaque bytes, generated filesystem sets, fuse aliases, and API-VFS path boundaries |
| D-Bus error accessors | `test-bus-error-rust` | Public struct layout, NULL predicates, and opaque C-string name matching |
| Namespace scalar helpers | `test-namespace-mountpoint-rust` | Namespace-bit masking, Linux clone-flag values, and native uid_t overflow boundaries |
| Session classification | `test-file-classify-rust` | ASCII-only session IDs, NULL/empty rejection, and opaque non-UTF-8 bytes |
| Strv ownership / allocation | `test-strv-rust`, `test-strv-extra-rust` … `test-strv-extra7-rust`, `test-strv-fnmatch-rust`, `test-string-util-extra6-rust` | Includes base vector search/mutation plus registered push/consume/split/join/fnmatch surface |
| Stat | `test-stat-util-rust`, `test-stat-util-extra2-rust`, `test-stat-util-inline-rust`, `test-stat-verify-rust` | Includes non-UTF-8 inode type string |
| Shared facades | `test-shared-validators-rust`, `test-shared-validators2-rust`, `test-shared-validators3-rust` (+ related validator fixtures in the same job) | Policy/validation facades |
| Parse / time (exported slices) | `test-parse-util-extra-rust`, `test-parse-extra-rust`, `test-parse-util-inline-rust`, `test-time-util-extra2-rust` | Partial parse/time surfaces only |
| Allocator overflow | `test-alloc-util-extra2-rust` | `malloc_multiply` / `memdup_*_multiply` SIZE_MAX guards |
| Non-UTF-8 (broader) | `test-header-inline-rust`, plus string/escape/errno fixtures already in the job | Byte-oriented invalid UTF-8 |

## Blocked base fixtures (do not claim green CI yet)

These Meson targets exist under `tests-extra/` but still call Rust symbols that
lack a stable C export (`#[no_mangle]` / `#[export_name = …]` + `extern "C"`).
They are **omitted** from `rust-meson-reviewed-shadows` until the exports land.

| Fixture | Missing C exports (link blockers) |
| --- | --- |
| `test-parse-util-rust` | `rs_parse_boolean`, `rs_parse_errno`, `rs_parse_fd`, `rs_parse_ifindex`, `rs_parse_ip_port`, `rs_parse_mode`, `rs_parse_nice`, `rs_parse_pid`, `rs_parse_size`, `rs_safe_atoi`, `rs_safe_atoi16`, `rs_safe_atolli`, `rs_safe_atollu`, `rs_safe_atollu_full`, `rs_safe_atou`, `rs_safe_atou16_full`, `rs_safe_atou8_full`, `rs_safe_atou_bounded`, `rs_safe_atou_full` |
| `test-time-util-rust` | `rs_map_clock_usec_raw`, `rs_parse_sec`, `rs_parse_sec_def_infinity`, `rs_parse_sec_fix_0`, `rs_parse_time`, `rs_timespec_load`, `rs_timespec_load_nsec`, `rs_timespec_store`, `rs_timespec_store_nsec`, `rs_timeval_load`, `rs_timeval_store`, `rs_triple_timestamp_by_clock` |
| `test-time-util-extra-rust` | `rs_timestamp_style_from_string`, `rs_timestamp_style_to_string` |
| `test-utf8-rust` | Full `rs_utf8_*` / `rs_utf16_*` / `rs_unichar_*` / `rs_ascii_is_valid_n` / `rs_char16_*` surface (no C exports yet) |

## Rules

1. Prefer extending this job over new CI sprawl.
2. Never list a target that cannot link on Linux CI; track the export gap instead.
3. Do not set `map.toml` `sync_status=synced` only because CI lists a target —
   runtime evidence still requires contracts/map policy.
4. macOS hosts without full Meson/systemd deps cannot substitute for this job;
   rely on catalog/ABI gates locally, then Linux CI for execution.
