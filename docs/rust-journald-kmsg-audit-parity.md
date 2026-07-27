# Rust Journald kmsg/audit Parity Checklist

Date: 2026-04-16
Scope: `src/journal` kernel (`/dev/kmsg`) and audit (`NETLINK_AUDIT`) ingress parity against C behavior.

## C Baseline

- `src/journal/journald-kmsg.c`
- `src/journal/journald-audit.c`
- `src/journal/journald-manager.c`

## Rust Implementation Surface

- `src/journal/rust/journald_runtime.rs`
- `src/journal/rust/tests/live_daemon_e2e.rs`

## C-to-Rust Mapping

- C `manager_open_audit()` socket setup and sender trust boundary -> Rust `AuditNetlinkReceiver::open()` and `recv_message()`
- C `manager_process_audit_message()` control-type filtering -> Rust `parse_audit_netlink_datagram()`
- C `process_audit_string(m, type, data, size)` header-type-driven `_AUDIT_TYPE` mapping -> Rust `classify_audit_netlink_ingress(payload, msg_type)`
- C `/dev/kmsg` sequence tracking + missed-message behavior -> Rust `KmsgSequenceTracker` + `process_dev_kmsg_record()`
- C persistent sequence continuity across restarts -> Rust `kernel-seqnum` state file via `load_kernel_seqnum()` / `store_kernel_seqnum()`

## Parity Checklist

- [x] Socket datagram path cannot spoof `transport=kernel` by payload shape.
- [x] Socket datagram path cannot spoof `transport=audit` by payload shape.
- [x] `/dev/kmsg` path ingests real kernel records when available.
- [x] kmsg sequence gaps emit missed-count notice and do not rewind expected seqnum on stale records.
- [x] Next expected kmsg seqnum persists to disk and is reloaded at daemon start.
- [x] `NETLINK_AUDIT` path validates kernel sender identity (`SCM_CREDENTIALS` pid 0 + netlink addr pid 0).
- [x] `NETLINK_AUDIT` ignores netlink control messages (`NLMSG_NOOP`, `NLMSG_ERROR`, non-user control types).
- [x] `_AUDIT_TYPE` / `_AUDIT_TYPE_NAME` are derived from trusted netlink header type, not payload `type=` hints.
- [x] Malformed audit payloads are dropped without daemon crash.

## Test Evidence

Commands executed:

```sh
cargo test --manifest-path src/journal/rust/Cargo.toml journald_runtime::tests:: -- --test-threads=1
cargo test --manifest-path src/journal/rust/Cargo.toml --test live_daemon_e2e -- --test-threads=1
```

Observed status:

- `journald_runtime` unit set: 62 passed.
- `live_daemon_e2e` integration set: 13 passed.

Coverage includes:

- audit sender trust-boundary checks (`audit_sender_validation_accepts_only_kernel_sender`)
- netlink datagram parser acceptance/rejection matrix for control/user types
- malformed audit record drop behavior
- live daemon refusal to treat socket audit-like payloads as trusted audit transport
- live daemon kmsg ingestion and persisted `kernel-seqnum` evidence
- expanded journald ingress live coverage alongside the same command matrix

## Known Deviations / Remaining Risks

- Kernel audit enable/disable control parity (`manager_set_kernel_audit`) is not wired in Rust runtime yet.
- End-to-end kernel-originated audit event capture is not covered by a Linux CI test in this environment; current protection is strong unit coverage on sender validation and parser gates.
- This parity slice does not imply full journald replacement readiness; adjacent journald tasks remain tracked separately.
