# Plan 001: Install the experimental Rust PID1 as an explicitly selected sidecar

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If a STOP condition occurs, stop and report; do not improvise.
> When done, update this plan's row in `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 8e81650692..HEAD -- meson_options.txt src/core/meson.build tools/rust-port/check-core-c-retention.py tools/rust-port/check-rust-production-selection.py tools/rust-port/truthfulness-gate.py test/systemd-cd4.sh`
>
> If an in-scope file changed, compare the current-state evidence below with
> the live code. Stop if the production C selection contract has changed.

## Status

- **Priority**: P1
- **Effort**: S (hours)
- **Risk**: LOW for normal installs, MED for the opt-in VM path
- **Depends on**: none
- **Category**: DX / architecture / tests
- **Planned at**: commit `8e81650692`, 2026-07-31

## Why this matters

Meson can build the experimental Rust PID1, but cannot stage or install it.
The QEMU milestone works around that by overwriting both canonical C PID1
locations inside its disposable image. That makes the trial path needlessly
different from packaging and destroys the fallback binary that is most useful
when a boot fails.

Add an explicit developer-only sidecar install at
`libexecdir/systemd-rust`. Normal builds, release builds, the installed
`libexecdir/systemd`, `SYSTEMD_BINARY_PATH`, and `/sbin/init` must remain owned
by C. The disposable QEMU harness may select the sidecar by changing only its
overlay's `/sbin/init` symlink; it must retain the canonical C executable for
diagnosis and recovery. This is deployment plumbing, not a parity claim.

## Current state

- `meson_options.txt:595-600` declares `rust-core-pid1`, but describes it as
  forbidden for all installation and provides no distinct sidecar option.
- `src/core/meson.build:212-220` requires explicit Rust enablement, rejects
  release mode, and emits the incomplete-implementation warning.
- `src/core/meson.build:233-248` always builds and installs the canonical C
  executable as `systemd`, linked with `libcore` and `libshared`.
- `src/core/meson.build:334-348` builds Cargo's `systemd` as Meson's
  `systemd-rust` output, but hard-codes `install : false`.
- `src/core/meson.build:398-400` installs `/sbin/init` pointing to
  `../lib/systemd/systemd`, the canonical C path.
- `tools/rust-port/check-core-c-retention.py:100-132` statically proves the C
  owner and the Rust target's non-installed status.
- `tools/rust-port/check-rust-production-selection.py:89-93` reports
  `incomplete_rust_installed=0`, but does not distinguish safe sidecar staging
  from production replacement.
- `tools/rust-port/truthfulness-gate.py:31-41` pins the release guard and the
  exact developer warning.
- `test/systemd-cd4.sh:164-170` uploads the Rust binary, then overwrites both
  `/usr/lib/systemd/systemd` and `/lib/systemd/systemd`. The image is disposable,
  but this removes the canonical C fallback and bypasses the installation
  boundary under review.
- `src/core/main.c:3841-3908` still owns complete manager construction,
  startup, default transaction, and main-loop entry in production. Rust
  `src/core/rust/main.rs:1117-1249` implements a narrower eight-step path and
  intentionally leaves the production manager D-Bus unavailable.

Match the existing fail-closed Meson style at `src/core/meson.build:212-220`:
reject invalid option combinations during configure, and keep comments
explicit about production ownership.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Static C-owner gate | `python3 tools/rust-port/check-core-c-retention.py` | Exit 0; reports the C production owner and opt-in Rust sidecar |
| Selection gate | `python3 tools/rust-port/check-rust-production-selection.py` | Exit 0; reports zero Rust production replacements |
| Truthfulness gate | `python3 tools/rust-port/truthfulness-gate.py` | Exit 0 |
| Python syntax | `python3 -m py_compile tools/rust-port/check-core-c-retention.py tools/rust-port/check-rust-production-selection.py tools/rust-port/truthfulness-gate.py` | Exit 0 |
| Whitespace | `git diff --check` | Exit 0, no output |

## Scope

**In scope**:

- `meson_options.txt`
- `src/core/meson.build`
- `tools/rust-port/check-core-c-retention.py`
- `tools/rust-port/check-rust-production-selection.py`
- `tools/rust-port/truthfulness-gate.py`
- `test/systemd-cd4.sh`
- `plans/README.md` (status only)

**Out of scope**:

- Any Rust manager behavior or Cargo dependency change.
- Binding `/run/systemd/private` or enabling any production D-Bus transport.
- Replacing `SYSTEMD_BINARY_PATH`, the canonical `systemd` executable target,
  `libcore`, or the normal `/sbin/init` install symlink.
- Enabling the option by default or permitting it in release mode.
- Claiming boot, shutdown, reexecution, generator, serialization, watchdog,
  MAC/security, or API parity.
- Modifying a host installation. The QEMU script may mutate only its temporary
  copy-on-write overlay.

## Git workflow

- Work on the existing branch unless the operator instructs otherwise.
- Use a single logical commit such as
  `rust-port: add opt-in PID1 sidecar installation`.
- Do not push unless the operator explicitly owns the session workflow.

## Steps

### Step 1: Add an explicit sidecar-install option

In `meson_options.txt`, keep `rust-core-pid1` developer-only and add a boolean
option named `rust-core-pid1-sidecar-install`, defaulting to `false`. Its
description must say that it installs the incomplete developer binary as
`libexecdir/systemd-rust`, never as the production PID1.

In `src/core/meson.build`:

1. Read the new option into `install_rust_pid1_sidecar`.
2. Fail configuration when it is true but `use_rust_pid1` is false.
3. Preserve the existing release-mode prohibition. Do not add a bypass.
4. Emit one truthful warning when the target is build-only and a stronger
   warning when the sidecar is installed; both must state that C remains the
   production-selected PID1.
5. Change only the Rust `custom_target` installation fields to:
   `install : install_rust_pid1_sidecar` and `install_dir : libexecdir`.
   Its output must remain exactly `systemd-rust`.
6. Update the comment on the canonical C executable to say the Rust target may
   be sidecar-installed but is never selected as `systemd`.

Do not change the C executable's `name`, `sources`, `link_with`, or `install`
fields, and do not change the `/sbin/init` symlink declaration.

**Verify**:

```sh
rg -n "rust-core-pid1-sidecar-install|install_rust_pid1_sidecar|output : 'systemd-rust'|install_dir : libexecdir" meson_options.txt src/core/meson.build
```

Expected: all four contracts are present; the Rust output is still uniquely
named `systemd-rust`.

### Step 2: Make the static gates distinguish sidecar install from replacement

Update `tools/rust-port/check-core-c-retention.py` so it requires:

- the new option's default-off declaration and developer-only description;
- the dependency guard (`sidecar-install` requires `rust-core-pid1`);
- the unchanged release guard;
- the unchanged installed C `systemd` target;
- the unchanged `/sbin/init -> ../lib/systemd/systemd` install symlink;
- the Rust custom target output `systemd-rust`, controlled install expression,
  and `libexecdir` destination.

Change its success text from `developer-only/non-installed` to an accurate
summary such as `developer-sidecar=opt-in production-owner=C`.

Update `tools/rust-port/check-rust-production-selection.py` to inspect
`src/core/meson.build` and assert that the Cargo target's output and optional
install destination cannot collide with `systemd`. Its success text must say
`rust_production_replacements=0`, not `incomplete_rust_installed=0`, because an
explicit sidecar install is now legitimate.

Update `tools/rust-port/truthfulness-gate.py` so the warning check accepts the
new exact build-only and sidecar warning branches while retaining the exact
release guard. Do not weaken the check to a vague substring search.

**Verify**: run the three static gates and Python syntax commands from the
commands table. Expected: all exit 0.

### Step 3: Stop the QEMU milestone from overwriting canonical PID1

In `test/systemd-cd4.sh`, change the `virt-customize` sequence to:

1. Upload the Rust binary to a temporary path in the overlay.
2. Install it mode `0755` as `/usr/lib/systemd/systemd-rust`.
3. Preserve `/usr/lib/systemd/systemd` unchanged.
4. Select Rust only by changing the overlay's `/sbin/init` symlink to
   `../usr/lib/systemd/systemd-rust` (or the correct relative path verified
   against the image). Do not copy Rust to `/lib/systemd/systemd`.
5. Keep initramfs regeneration and temporary-file cleanup.

Before the existing boot assertions, add checks that:

- `/proc/1/exe --version` reports the Rust package version;
- `/usr/lib/systemd/systemd` remains executable and does not report the Rust
  package version;
- `/usr/lib/systemd/systemd-rust` is the executable selected as PID1.

Extend `check-rust-production-selection.py` to reject either old overwrite
command and require the sidecar path plus explicit overlay-only selection.

**Verify**:

```sh
bash -n test/systemd-cd4.sh
python3 tools/rust-port/check-rust-production-selection.py
```

Expected: both exit 0; `rg -n "cp .*systemd-rust .*(usr/)?lib/systemd/systemd" test/systemd-cd4.sh`
returns no matches.

### Step 4: Prove Meson's configured install manifest

On Linux with the repository's normal Meson dependencies installed, configure
a temporary developer build with:

```sh
trial_root="$(mktemp -d /tmp/systemd-rust-sidecar.XXXXXX)"
meson setup "$trial_root/build" \
  -Dmode=developer -Drust=enabled -Drust-core-pid1=enabled \
  -Drust-core-pid1-sidecar-install=true
meson introspect --installed "$trial_root/build" >"$trial_root/installed.json"
```

Parse the JSON (with Python, not a textual order-dependent assertion) and prove
that it contains distinct destinations ending in:

- `/usr/lib/systemd/systemd` (C production owner),
- `/usr/lib/systemd/systemd-rust` (opt-in sidecar), and
- `/usr/sbin/init` pointing to the canonical C path in Meson's install plan.

Then configure a second temporary build without the sidecar option and prove
the install manifest contains no `systemd-rust`. Also prove configuration
fails for both invalid combinations:

- sidecar install enabled while `rust-core-pid1` is disabled;
- `mode=release` with `rust-core-pid1` enabled.

Clean up only the exact `trial_root` created above after confirming it starts
with `/tmp/systemd-rust-sidecar.`.

**Verify**: both positive configurations have the expected manifests and both
negative configurations exit nonzero with the intended Meson error.

## Test plan

- Static regression: gates reject renaming Rust output to `systemd`, changing
  its install destination to the canonical C path, changing `/sbin/init`,
  enabling sidecar install by default, or removing the release guard.
- Meson integration: default developer manifest contains only C PID1;
  explicit sidecar manifest contains C PID1 plus `systemd-rust`.
- QEMU harness syntax and static policy: no canonical PID1 overwrite remains.
- Do not require the full QEMU boot to pass in this plan. The Rust production
  API bus is intentionally disabled, so the existing `systemctl` checks remain
  a truthful later parity milestone.

## Done criteria

- [x] New option defaults off and requires explicit `rust-core-pid1`.
- [x] Release mode still rejects the experimental Rust PID1.
- [x] Normal install manifest and `/sbin/init` remain C-owned.
- [x] Opt-in manifest adds only `libexecdir/systemd-rust`.
- [x] QEMU overlay retains canonical C `systemd` and selects the Rust sidecar
      only through its overlay init path.
- [x] All three Rust-port gates, Python syntax, shell syntax, and
      `git diff --check` pass.
- [x] The sidecar executor stayed within the in-scope list; the other bounded
      Rust path/lifecycle fixes in this working tree were reviewed separately.
- [x] `plans/README.md` marks Plan 001 DONE.

## STOP conditions

Stop and report rather than improvising if:

- The canonical C executable or `/sbin/init` selection changed since commit
  `8e81650692`.
- Meson cannot install a `custom_target` to `libexecdir` at the repository's
  declared minimum Meson version. In that case, report the minimum-version
  conflict; do not raise the project-wide Meson requirement in this plan.
- The Ubuntu image does not retain a distinct executable canonical C PID1.
- Selecting the sidecar requires overwriting `/usr/lib/systemd/systemd` or
  altering a host installation rather than the disposable overlay.
- The work appears to require enabling `/run/systemd/private` or implementing
  missing manager behavior.
- Any verification fails twice after a reasonable correction.

## Maintenance notes

- This sidecar option should remain default-off until privileged replacement
  boot, reexecution, shutdown, generators, serialization, watchdog/security,
  and production D-Bus contracts all pass against the C implementation.
- Reviewers should treat any future change from `systemd-rust` to `systemd`,
  or from `libexecdir/systemd-rust` to the canonical path, as a separate P0
  ownership transition requiring full boot evidence.
- Once Rust is genuinely production-ready, remove this sidecar option in the
  same reviewed change that flips ownership; do not leave two ambiguous PID1
  selectors indefinitely.
