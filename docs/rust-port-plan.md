# Rust Port Plan For Remaining C-Only Subsystems

This plan tracks the next migration targets after the core PID1/daemon parity blockers.

Snapshot source: `docs/rust-port-coverage.md` generated on 2026-04-16.

## Prioritization Rules

1. Boot and recovery criticality first (`shutdown`, `cryptsetup`, `nss-systemd`).
2. High-privilege attack surface first (`coredump`, `journal-remote`, `bootctl`).
3. Shared dependency fanout first (`libudev`, `timesync`, `timedate`).
4. Lower-risk tooling and UX surfaces last (`portable`, `vmspawn`, `xdg-autostart-generator`).

## Wave Plan

| Wave | Subsystems | Rationale | Exit Criteria |
|---|---|---|---|
| 1 (Safety-Critical) | `shutdown`, `cryptsetup`, `cryptenroll`, `nss-systemd`, `veritysetup` | Direct boot/recovery and auth path impact | Rust binaries compile in Meson; C-vs-Rust behavior tests for command flags and error paths; rollback switch retained |
| 2 (Privileged Daemons/Agents) | `coredump`, `journal-remote`, `bootctl`, `timesync`, `timedate`, `userdb` | Root-level long-running or identity-critical processes | Integration tests for daemon lifecycle and IPC; fail-closed startup checks; production shadow mode |
| 3 (System Management/Policy) | `sysupdate`, `portable`, `tmpfiles`, `oom`, `nsresourced`, `tpm2-setup`, `pcrlock` | Policy and host state management with medium blast radius | End-to-end fixture coverage for config parsing and on-disk mutations; parity checklist complete |
| 4 (Remaining Utilities) | `busctl`, `locale`, `hostname`, `sleep`, `vmspawn`, `xdg-autostart-generator`, `factory-reset`, `growfs`, `imds`, `ssh-generator`, `sbsign` | Lower risk tools and feature surfaces | CLI parity and regression tests; map entry status moved to `replace` or `fallback` |

## C-Only Inventory (Current Snapshot)

The following subsystems currently show `C > 0` and `Rust = 0` in `src`:

- `bless-boot`
- `bootctl`
- `busctl`
- `coredump`
- `cryptenroll`
- `cryptsetup`
- `factory-reset`
- `growfs`
- `hibernate-resume`
- `hostname`
- `imds`
- `integritysetup`
- `journal-remote`
- `libc`
- `libudev`
- `locale`
- `mountfsd`
- `nsresourced`
- `nss-systemd`
- `oom`
- `pcrlock`
- `portable`
- `sbsign`
- `shutdown`
- `sleep`
- `ssh-generator`
- `sysupdate`
- `timedate`
- `timesync`
- `tmpfiles`
- `tpm2-setup`
- `userdb`
- `veritysetup`
- `vmspawn`
- `xdg-autostart-generator`

## Tracking Cadence

At each milestone:

1. Regenerate coverage snapshot:
   `python3 tools/rust-port/coverage-dashboard.py --write docs/rust-port-coverage.md`
2. Update this plan if wave ordering or blockers change.
3. Update `tools/rust-port/map.toml` status for migrated modules.
