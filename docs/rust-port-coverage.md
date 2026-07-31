# Rust Port Source Inventory

Repository: repository root
Scope: `src`

> This is a source inventory, not a completion percentage. A Rust file is
> counted as a behavior candidate only after excluding obvious metadata
> adapters and test/fuzz support. Crate roots and FFI modules remain
> candidates because their filenames do not prove they lack behavior.
> Candidates are still
> unverified until mapped behavior and executable tests pass.

## Snapshot Totals

- All `src` C files: **1831**
- All `src` Rust files: **1287**
- Rust metadata adapters: **29**
- Rust test/fuzz support files: **86**
- Unverified Rust behavior candidates: **1172**

Excluding `src/test`:
- C files: **1569**
- Rust files: **1287**
- Rust metadata adapters: **29**
- Rust test/fuzz support files: **86**
- Unverified Rust behavior candidates: **1172**

## Per-Subsystem Inventory

| Subsystem | C | Rust | Metadata | Test/fuzz | Behavior candidates |
|---|---:|---:|---:|---:|---:|
| `ac-power` | 1 | 3 | 0 | 0 | 3 |
| `analyze` | 40 | 2 | 0 | 0 | 2 |
| `ask-password` | 1 | 3 | 0 | 0 | 3 |
| `backlight` | 1 | 3 | 0 | 0 | 3 |
| `basic` | 119 | 116 | 0 | 2 | 114 |
| `battery-check` | 1 | 3 | 0 | 0 | 3 |
| `binfmt` | 1 | 2 | 0 | 0 | 2 |
| `bless-boot` | 3 | 0 | 0 | 0 | 0 |
| `boot` | 45 | 45 | 0 | 6 | 39 |
| `bootctl` | 13 | 0 | 0 | 0 | 0 |
| `bpf` | 7 | 0 | 0 | 0 | 0 |
| `busctl` | 3 | 0 | 0 | 0 | 0 |
| `cgls` | 1 | 3 | 0 | 0 | 3 |
| `cgtop` | 1 | 2 | 0 | 0 | 2 |
| `clonesetup` | 4 | 0 | 0 | 0 | 0 |
| `core` | 97 | 148 | 0 | 6 | 142 |
| `coredump` | 11 | 0 | 0 | 0 | 0 |
| `creds` | 1 | 3 | 0 | 0 | 3 |
| `cryptenroll` | 10 | 0 | 0 | 0 | 0 |
| `cryptsetup` | 11 | 0 | 0 | 0 | 0 |
| `dbus` | 0 | 7 | 0 | 0 | 7 |
| `debug-generator` | 1 | 3 | 0 | 0 | 3 |
| `delta` | 1 | 3 | 0 | 0 | 3 |
| `detect-virt` | 1 | 3 | 0 | 0 | 3 |
| `dissect` | 1 | 3 | 0 | 0 | 3 |
| `environment-d-generator` | 1 | 3 | 0 | 0 | 3 |
| `escape` | 1 | 3 | 0 | 0 | 3 |
| `event-loop` | 0 | 5 | 0 | 0 | 5 |
| `factory-reset` | 2 | 0 | 0 | 0 | 0 |
| `firstboot` | 1 | 3 | 0 | 0 | 3 |
| `fsck` | 1 | 3 | 0 | 0 | 3 |
| `fstab-generator` | 1 | 3 | 0 | 0 | 3 |
| `fundamental` | 9 | 21 | 0 | 0 | 21 |
| `fuzz` | 15 | 1 | 0 | 0 | 1 |
| `getty-generator` | 1 | 3 | 0 | 0 | 3 |
| `gpt-auto-generator` | 1 | 3 | 0 | 0 | 3 |
| `growfs` | 2 | 0 | 0 | 0 | 0 |
| `hibernate-resume` | 3 | 0 | 0 | 0 | 0 |
| `home` | 32 | 32 | 0 | 1 | 31 |
| `hostname` | 2 | 0 | 0 | 0 | 0 |
| `hwdb` | 1 | 3 | 0 | 0 | 3 |
| `id128` | 1 | 2 | 0 | 0 | 2 |
| `imds` | 5 | 0 | 0 | 0 | 0 |
| `import` | 22 | 26 | 0 | 3 | 23 |
| `integritysetup` | 3 | 0 | 0 | 0 | 0 |
| `journal` | 41 | 25 | 0 | 9 | 16 |
| `journal-remote` | 11 | 0 | 0 | 0 | 0 |
| `kernel-install` | 1 | 3 | 0 | 0 | 3 |
| `keyutil` | 1 | 3 | 0 | 0 | 3 |
| `libc` | 23 | 0 | 0 | 0 | 0 |
| `libsystemd` | 128 | 111 | 0 | 6 | 105 |
| `libsystemd-network` | 66 | 2 | 0 | 0 | 2 |
| `libudev` | 10 | 0 | 0 | 0 | 0 |
| `locale` | 5 | 0 | 0 | 0 | 0 |
| `login` | 30 | 31 | 0 | 4 | 27 |
| `machine` | 14 | 17 | 0 | 1 | 16 |
| `machine-id-setup` | 1 | 3 | 0 | 0 | 3 |
| `measure` | 1 | 3 | 0 | 0 | 3 |
| `modules-load` | 1 | 3 | 0 | 0 | 3 |
| `mount` | 1 | 3 | 0 | 0 | 3 |
| `mountfsd` | 3 | 0 | 0 | 0 | 0 |
| `mstack` | 1 | 3 | 0 | 0 | 3 |
| `mute-console` | 1 | 3 | 0 | 0 | 3 |
| `network` | 142 | 142 | 0 | 8 | 134 |
| `notify` | 1 | 3 | 0 | 0 | 3 |
| `nspawn` | 15 | 18 | 0 | 3 | 15 |
| `nsresourced` | 6 | 0 | 0 | 0 | 0 |
| `nss-myhostname` | 1 | 2 | 0 | 0 | 2 |
| `nss-mymachines` | 1 | 2 | 0 | 0 | 2 |
| `nss-resolve` | 1 | 2 | 0 | 0 | 2 |
| `nss-systemd` | 2 | 0 | 0 | 0 | 0 |
| `oom` | 7 | 0 | 0 | 0 | 0 |
| `path` | 1 | 3 | 0 | 0 | 3 |
| `pcrextend` | 1 | 0 | 0 | 0 | 0 |
| `pcrlock` | 2 | 0 | 0 | 0 | 0 |
| `platform` | 0 | 15 | 0 | 0 | 15 |
| `portable` | 7 | 0 | 0 | 0 | 0 |
| `pstore` | 1 | 3 | 0 | 0 | 3 |
| `ptyfwd` | 1 | 3 | 0 | 0 | 3 |
| `quotacheck` | 1 | 3 | 0 | 0 | 3 |
| `random-seed` | 1 | 3 | 0 | 0 | 3 |
| `remount-fs` | 1 | 3 | 0 | 0 | 3 |
| `repart` | 3 | 3 | 0 | 0 | 3 |
| `reply-password` | 1 | 3 | 0 | 0 | 3 |
| `report` | 12 | 3 | 0 | 0 | 3 |
| `resolve` | 58 | 60 | 29 | 22 | 9 |
| `rfkill` | 1 | 3 | 0 | 0 | 3 |
| `run` | 2 | 2 | 0 | 0 | 2 |
| `run-generator` | 1 | 3 | 0 | 0 | 3 |
| `sbsign` | 2 | 0 | 0 | 0 | 0 |
| `shared` | 283 | 214 | 0 | 6 | 208 |
| `shutdown` | 7 | 0 | 0 | 0 | 0 |
| `sleep` | 3 | 0 | 0 | 0 | 0 |
| `socket-activate` | 1 | 3 | 0 | 0 | 3 |
| `socket-proxy` | 1 | 4 | 0 | 0 | 4 |
| `ssh-generator` | 4 | 0 | 0 | 0 | 0 |
| `stdio-bridge` | 1 | 3 | 0 | 0 | 3 |
| `storage` | 3 | 0 | 0 | 0 | 0 |
| `storagetm` | 1 | 3 | 0 | 0 | 3 |
| `sulogin-shell` | 1 | 3 | 0 | 0 | 3 |
| `sysctl` | 1 | 3 | 0 | 0 | 3 |
| `sysext` | 1 | 2 | 0 | 0 | 2 |
| `sysinstall` | 1 | 0 | 0 | 0 | 0 |
| `system-update-generator` | 1 | 3 | 0 | 0 | 3 |
| `systemctl` | 36 | 1 | 0 | 0 | 1 |
| `sysupdate` | 17 | 0 | 0 | 0 | 0 |
| `sysusers` | 1 | 3 | 0 | 0 | 3 |
| `test` | 262 | 0 | 0 | 0 | 0 |
| `timedate` | 3 | 0 | 0 | 0 | 0 |
| `timesync` | 7 | 0 | 0 | 0 | 0 |
| `tmpfiles` | 3 | 0 | 0 | 0 | 0 |
| `tpm2-setup` | 4 | 0 | 0 | 0 | 0 |
| `tty-ask-password-agent` | 1 | 3 | 0 | 0 | 3 |
| `udev` | 68 | 68 | 0 | 9 | 59 |
| `update-done` | 1 | 3 | 0 | 0 | 3 |
| `update-utmp` | 1 | 2 | 0 | 0 | 2 |
| `user-sessions` | 1 | 2 | 0 | 0 | 2 |
| `userdb` | 4 | 0 | 0 | 0 | 0 |
| `validatefs` | 1 | 3 | 0 | 0 | 3 |
| `varlinkctl` | 1 | 2 | 0 | 0 | 2 |
| `vconsole` | 1 | 3 | 0 | 0 | 3 |
| `veritysetup` | 2 | 0 | 0 | 0 | 0 |
| `vmspawn` | 11 | 0 | 0 | 0 | 0 |
| `volatile-root` | 1 | 4 | 0 | 0 | 4 |
| `vpick` | 1 | 3 | 0 | 0 | 3 |
| `xdg-autostart-generator` | 5 | 0 | 0 | 0 | 0 |

## Rebuild

```sh
python3 tools/rust-port/coverage-dashboard.py --write docs/rust-port-coverage.md
```
