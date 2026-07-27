# Rust Port Source Inventory

Generated: 2026-07-27 09:30 UTC
Repository: repository root
Scope: `src`

> This is a source inventory, not a completion percentage. A Rust file is
> counted as a behavior candidate only after excluding obvious metadata
> adapters, test/fuzz support, and crate scaffolding. Candidates are still
> unverified until mapped behavior and executable tests pass.

## Snapshot Totals

- All `src` C files: **1831**
- All `src` Rust files: **1424**
- Rust metadata adapters: **28**
- Rust test/fuzz support files: **89**
- Rust crate scaffolding files: **163**
- Unverified Rust behavior candidates: **1144**

Excluding `src/test`:
- C files: **1569**
- Rust files: **1424**
- Rust metadata adapters: **28**
- Rust test/fuzz support files: **89**
- Rust crate scaffolding files: **163**
- Unverified Rust behavior candidates: **1144**

## Per-Subsystem Inventory

| Subsystem | C | Rust | Metadata | Test/fuzz | Scaffolding | Behavior candidates |
|---|---:|---:|---:|---:|---:|---:|
| `ac-power` | 1 | 3 | 0 | 0 | 2 | 1 |
| `analyze` | 40 | 0 | 0 | 0 | 0 | 0 |
| `ask-password` | 1 | 3 | 0 | 0 | 2 | 1 |
| `backlight` | 1 | 3 | 0 | 0 | 2 | 1 |
| `basic` | 119 | 141 | 0 | 2 | 2 | 137 |
| `battery-check` | 1 | 3 | 0 | 0 | 2 | 1 |
| `binfmt` | 1 | 3 | 0 | 0 | 2 | 1 |
| `bless-boot` | 3 | 0 | 0 | 0 | 0 | 0 |
| `boot` | 45 | 46 | 0 | 7 | 2 | 37 |
| `bootctl` | 13 | 0 | 0 | 0 | 0 | 0 |
| `bpf` | 7 | 0 | 0 | 0 | 0 | 0 |
| `busctl` | 3 | 0 | 0 | 0 | 0 | 0 |
| `cgls` | 1 | 3 | 0 | 0 | 2 | 1 |
| `cgtop` | 1 | 3 | 0 | 0 | 2 | 1 |
| `clonesetup` | 4 | 0 | 0 | 0 | 0 | 0 |
| `core` | 97 | 126 | 0 | 6 | 3 | 117 |
| `coredump` | 11 | 0 | 0 | 0 | 0 | 0 |
| `creds` | 1 | 3 | 0 | 0 | 2 | 1 |
| `cryptenroll` | 10 | 0 | 0 | 0 | 0 | 0 |
| `cryptsetup` | 11 | 0 | 0 | 0 | 0 | 0 |
| `dbus` | 0 | 7 | 0 | 0 | 1 | 6 |
| `debug-generator` | 1 | 3 | 0 | 0 | 2 | 1 |
| `delta` | 1 | 3 | 0 | 0 | 2 | 1 |
| `detect-virt` | 1 | 3 | 0 | 0 | 2 | 1 |
| `dissect` | 1 | 3 | 0 | 0 | 2 | 1 |
| `environment-d-generator` | 1 | 3 | 0 | 0 | 2 | 1 |
| `escape` | 1 | 3 | 0 | 0 | 2 | 1 |
| `event-loop` | 0 | 5 | 0 | 0 | 1 | 4 |
| `factory-reset` | 2 | 0 | 0 | 0 | 0 | 0 |
| `firstboot` | 1 | 3 | 0 | 0 | 2 | 1 |
| `fsck` | 1 | 3 | 0 | 0 | 2 | 1 |
| `fstab-generator` | 1 | 3 | 0 | 0 | 2 | 1 |
| `fundamental` | 9 | 21 | 0 | 0 | 1 | 20 |
| `fuzz` | 15 | 0 | 0 | 0 | 0 | 0 |
| `getty-generator` | 1 | 3 | 0 | 0 | 2 | 1 |
| `gpt-auto-generator` | 1 | 3 | 0 | 0 | 2 | 1 |
| `growfs` | 2 | 0 | 0 | 0 | 0 | 0 |
| `hibernate-resume` | 3 | 0 | 0 | 0 | 0 | 0 |
| `home` | 32 | 32 | 0 | 1 | 2 | 29 |
| `hostname` | 2 | 0 | 0 | 0 | 0 | 0 |
| `hwdb` | 1 | 3 | 0 | 0 | 2 | 1 |
| `id128` | 1 | 2 | 0 | 0 | 2 | 0 |
| `imds` | 5 | 0 | 0 | 0 | 0 | 0 |
| `import` | 22 | 26 | 0 | 3 | 2 | 21 |
| `integritysetup` | 3 | 0 | 0 | 0 | 0 | 0 |
| `journal` | 41 | 56 | 0 | 12 | 3 | 41 |
| `journal-remote` | 11 | 0 | 0 | 0 | 0 | 0 |
| `kernel-install` | 1 | 3 | 0 | 0 | 2 | 1 |
| `keyutil` | 1 | 3 | 0 | 0 | 2 | 1 |
| `libc` | 23 | 0 | 0 | 0 | 0 | 0 |
| `libsystemd` | 128 | 110 | 0 | 1 | 2 | 107 |
| `libsystemd-network` | 66 | 2 | 0 | 0 | 1 | 1 |
| `libudev` | 10 | 0 | 0 | 0 | 0 | 0 |
| `locale` | 5 | 0 | 0 | 0 | 0 | 0 |
| `login` | 30 | 31 | 0 | 4 | 2 | 25 |
| `machine` | 14 | 17 | 0 | 1 | 2 | 14 |
| `machine-id-setup` | 1 | 3 | 0 | 0 | 2 | 1 |
| `measure` | 1 | 3 | 0 | 0 | 2 | 1 |
| `modules-load` | 1 | 3 | 0 | 0 | 2 | 1 |
| `mount` | 1 | 3 | 0 | 0 | 2 | 1 |
| `mountfsd` | 3 | 0 | 0 | 0 | 0 | 0 |
| `mstack` | 1 | 3 | 0 | 0 | 2 | 1 |
| `mute-console` | 1 | 3 | 0 | 0 | 2 | 1 |
| `network` | 142 | 142 | 0 | 8 | 2 | 132 |
| `notify` | 1 | 3 | 0 | 0 | 2 | 1 |
| `nspawn` | 15 | 18 | 0 | 3 | 2 | 13 |
| `nsresourced` | 6 | 0 | 0 | 0 | 0 | 0 |
| `nss-myhostname` | 1 | 2 | 0 | 0 | 1 | 1 |
| `nss-mymachines` | 1 | 2 | 0 | 0 | 1 | 1 |
| `nss-resolve` | 1 | 2 | 0 | 0 | 1 | 1 |
| `nss-systemd` | 2 | 0 | 0 | 0 | 0 | 0 |
| `oom` | 7 | 0 | 0 | 0 | 0 | 0 |
| `path` | 1 | 3 | 0 | 0 | 2 | 1 |
| `pcrextend` | 1 | 3 | 0 | 0 | 2 | 1 |
| `pcrlock` | 2 | 0 | 0 | 0 | 0 | 0 |
| `platform` | 0 | 10 | 0 | 0 | 1 | 9 |
| `portable` | 7 | 0 | 0 | 0 | 0 | 0 |
| `pstore` | 1 | 3 | 0 | 0 | 2 | 1 |
| `ptyfwd` | 1 | 3 | 0 | 0 | 2 | 1 |
| `quotacheck` | 1 | 3 | 0 | 0 | 2 | 1 |
| `random-seed` | 1 | 3 | 0 | 0 | 2 | 1 |
| `remount-fs` | 1 | 3 | 0 | 0 | 2 | 1 |
| `repart` | 3 | 3 | 0 | 0 | 2 | 1 |
| `reply-password` | 1 | 3 | 0 | 0 | 2 | 1 |
| `report` | 12 | 3 | 0 | 0 | 2 | 1 |
| `resolve` | 58 | 60 | 28 | 22 | 3 | 7 |
| `rfkill` | 1 | 3 | 0 | 0 | 2 | 1 |
| `run` | 2 | 3 | 0 | 0 | 2 | 1 |
| `run-generator` | 1 | 3 | 0 | 0 | 2 | 1 |
| `sbsign` | 2 | 0 | 0 | 0 | 0 | 0 |
| `shared` | 283 | 308 | 0 | 6 | 2 | 300 |
| `shutdown` | 7 | 0 | 0 | 0 | 0 | 0 |
| `sleep` | 3 | 0 | 0 | 0 | 0 | 0 |
| `socket-activate` | 1 | 3 | 0 | 0 | 2 | 1 |
| `socket-proxy` | 1 | 4 | 0 | 0 | 2 | 2 |
| `ssh-generator` | 4 | 0 | 0 | 0 | 0 | 0 |
| `stdio-bridge` | 1 | 3 | 0 | 0 | 2 | 1 |
| `storage` | 3 | 0 | 0 | 0 | 0 | 0 |
| `storagetm` | 1 | 3 | 0 | 0 | 2 | 1 |
| `sulogin-shell` | 1 | 3 | 0 | 0 | 2 | 1 |
| `sysctl` | 1 | 3 | 0 | 0 | 2 | 1 |
| `sysext` | 1 | 3 | 0 | 0 | 2 | 1 |
| `sysinstall` | 1 | 0 | 0 | 0 | 0 | 0 |
| `system-update-generator` | 1 | 3 | 0 | 0 | 2 | 1 |
| `systemctl` | 36 | 1 | 0 | 0 | 1 | 0 |
| `sysupdate` | 17 | 0 | 0 | 0 | 0 | 0 |
| `sysusers` | 1 | 3 | 0 | 0 | 2 | 1 |
| `test` | 262 | 0 | 0 | 0 | 0 | 0 |
| `timedate` | 3 | 0 | 0 | 0 | 0 | 0 |
| `timesync` | 7 | 0 | 0 | 0 | 0 | 0 |
| `tmpfiles` | 3 | 0 | 0 | 0 | 0 | 0 |
| `tpm2-setup` | 4 | 0 | 0 | 0 | 0 | 0 |
| `tty-ask-password-agent` | 1 | 3 | 0 | 0 | 2 | 1 |
| `udev` | 68 | 76 | 0 | 13 | 3 | 60 |
| `update-done` | 1 | 3 | 0 | 0 | 2 | 1 |
| `update-utmp` | 1 | 3 | 0 | 0 | 2 | 1 |
| `user-sessions` | 1 | 3 | 0 | 0 | 2 | 1 |
| `userdb` | 4 | 0 | 0 | 0 | 0 | 0 |
| `validatefs` | 1 | 3 | 0 | 0 | 2 | 1 |
| `varlinkctl` | 1 | 3 | 0 | 0 | 2 | 1 |
| `vconsole` | 1 | 3 | 0 | 0 | 2 | 1 |
| `veritysetup` | 2 | 0 | 0 | 0 | 0 | 0 |
| `vmspawn` | 11 | 0 | 0 | 0 | 0 | 0 |
| `volatile-root` | 1 | 3 | 0 | 0 | 2 | 1 |
| `vpick` | 1 | 3 | 0 | 0 | 2 | 1 |
| `xdg-autostart-generator` | 5 | 0 | 0 | 0 | 0 | 0 |

## Rebuild

```sh
python3 tools/rust-port/coverage-dashboard.py --write docs/rust-port-coverage.md
```
