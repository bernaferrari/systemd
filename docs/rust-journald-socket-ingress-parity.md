# Rust Journald Socket Ingress Parity Checklist

Date: 2026-04-16
Scope: `src/journal` native socket, syslog `/dev/log`, stdout stream, trusted client metadata, and per-unit runtime controls versus C journald behavior.

## C Baseline

- `src/journal/journald-manager.c`
- `src/journal/journald-native.c`
- `src/journal/journald-syslog.c`
- `src/journal/journald-stream.c`
- `src/journal/journald-context.c`
- `src/journal/journald-client.c`

## Rust Implementation Surface

- `src/journal/rust/journald_runtime.rs`
- `src/journal/rust/tests/live_daemon_e2e.rs`

## Implemented Parity

- [x] Native and syslog datagram sockets are distinct receive surfaces in Rust.
- [x] Payload classification is bound to the receive surface instead of trusting payload shape.
- [x] Stdout stream protocol is implemented with separate setup-state parsing and running-state framing.
- [x] Stdout stream fdstore persistence and restore across daemon restart is implemented.
- [x] Trusted client metadata is enriched from proc/cgroup context with C-order field emission.
- [x] Unit runtime controls are honored:
  - `log-level-max`
  - `log-extra-fields`
  - `log-rate-limit-interval`
  - `log-rate-limit-burst`
- [x] Ratelimiting is keyed by resolved systemd unit context rather than peer address/identity fallback.
- [x] Linux stdout streams require peer credential capture during stream install, matching the C trust model.

## Validation

Commands executed:

```sh
cargo test --manifest-path src/journal/rust/Cargo.toml journald_runtime::tests:: -- --test-threads=1
cargo test --manifest-path src/journal/rust/Cargo.toml --test live_daemon_e2e -- --test-threads=1
```

Observed status:

- `journald_runtime` unit set: 62 passed.
- `live_daemon_e2e` integration set: 13 passed.

Coverage includes:

- native/syslog receive-surface separation
- trusted proc/cgroup metadata enrichment
- binary unit extra-fields ingestion
- unit `log-level-max` filtering
- per-unit ratelimit enforcement
- stdout stream framing (`newline`, `NUL`, `line-max`, `EOF`, `pid-change`)
- stdout stream fdstore restore after restart
- live socket-ingress behavior through the daemon binary

## Closeout Notes

- Rust datagram ingress now consumes trusted ancillary timestamp and SELinux metadata from the socket.
  - C reference: `manager_process_datagram()` in `src/journal/journald-manager.c`
  - Rust parity: `recv_datagram_with_metadata()` now consumes `SCM_CREDENTIALS`, `SCM_TIMESTAMP`, and `SCM_SECURITY`
- Rust stdout stream ingress now captures peer SELinux context at accept time and feeds it into trusted client-context enrichment.
  - C reference: `getpeersec()` in `src/journal/journald-stream.c`
  - Rust parity: `StdoutStreamConnection::new()` captures `SO_PEERSEC` and reuses it through message append

## Notes

- The live suppression-marker test is Linux-only because stdout stream ratelimit parity depends on Linux peer credentials (`SO_PEERCRED` / `SCM_CREDENTIALS`).
- This closeout means the socket-ingress status is auditable, not that journald as a whole is replacement-ready. Journal file-format parity and other daemon surfaces remain tracked separately.
