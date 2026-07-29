# Rust `journalctl` architecture and C parity

The canonical source for this module family is
`src/journal/journalctl.c`. The other canonical `journalctl-*.c` files
already have sibling Rust ports and are outside this decomposition.

## Consumers and ownership

`src/journal/rust/lib.rs` exports `journalctl` as a library module. The
`journalctl` Cargo binary does not call this module: its entry point is
`journalctl_main.rs`, which currently execs a separate `journalctl-c`
backend. Within the Rust library, `journalctl_filter.rs` is the only
production source outside this module family that directly consumes an
item here (`JournalctlArgs`). The remaining direct consumers are the
unit tests in `tests.rs`. Public items remain re-exported from
`journalctl.rs` because downstream library consumers cannot be ruled
out by an in-tree search.

Production ownership is divided as follows:

| Module | Owned responsibility |
| --- | --- |
| `model.rs` | Parsed argument state and parser result/error types |
| `argument_values.rs` | Scalar option parsing, timestamp parsing, glob expansion, and validation |
| `arguments.rs` | Command-line state machine, option interactions, defaults, and conflict checks |
| `filter.rs` | Match expansion, filter plans, and filter-backend operation ordering |
| `dispatch.rs` | Action selection, smart-relinquish decision, and top-level run plan |
| `parsing_tests.rs` | Unit tests only; compiled through `#[cfg(test)]` |

`journalctl.rs` is only the stable module facade and public re-export
surface. It contains no forwarding functions.

## Exact known gaps from `journalctl.c`

- `help_facilities`, `help`, and `vl_server` are named in the port
  inventory but have no Rust implementation in this module family.
  Help/version requests are represented as `RunOutcome` values and do
  not print anything.
- C `run()` mounts `--image` privately and invokes the concrete action
  handlers. Rust `run()` only produces a `DispatchPlan`; it invokes
  none of `action_show`, catalog, authentication, miscellaneous, or
  Varlink action implementations.
- The recording filter backend captures intended `sd_journal`
  operations for inspection. It is not an `sd_journal` backend and
  therefore does not apply matches to an acquired journal.
- C detects Varlink invocation before normal option parsing and starts
  `vl_server()`. The Rust parser has no equivalent invocation-mode or
  runtime-scope path, despite separate Varlink port files existing.
- C retains parsed realtime microseconds and a compiled PCRE2 pattern
  for action execution. Rust validates timestamps and patterns, but
  retains the original timestamp strings and drops the compiled
  pattern.
- C initializes the FSS interval to 15 minutes when OpenSSL support is
  present. Rust represents the interval as `Option<String>` with no
  equivalent default or feature-dependent setup.
- Smart relinquish in C uses `path_get_mnt_id()`. Rust first parses
  `/proc/self/mountinfo` by literal mount-point field and falls back to
  `st_dev`; escaped mountinfo paths and mount-ID lookup failures can
  therefore produce different decisions.
- `SecretString::drop` overwrites the current String allocation, but it
  is not equivalent evidence to C's `erase_and_free` hardening against
  compiler-elided erasure.

The C-exec binary shim and wiring the existing Rust Varlink/action
modules into an executable are separate features. This architecture
pass does not change either one.
