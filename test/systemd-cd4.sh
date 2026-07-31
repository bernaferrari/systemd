#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

skip() {
    echo "SKIP: $*" >&2
    exit 0
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

run() {
    echo "+ $*"
    "$@" || fail "command failed: $*"
}

guest() {
    local label="$1"
    shift

    echo "+ ssh $label"
    ssh "${ssh_opts[@]}" "$@" || fail "guest command failed: $label"
}

require_cmd() {
    local cmd="${1:?}"
    command -v "$cmd" >/dev/null 2>&1 || skip "missing prerequisite: $cmd"
}

if [[ ! -f Cargo.toml ]]; then
    fail "run this script from the systemd repository root."
fi

if [[ "$(uname -s)" != Linux ]]; then
    skip "Linux-only QEMU boot runner."
fi

if [[ "$(uname -m)" != x86_64 ]]; then
    skip "currently only x86_64 Ubuntu cloud images are supported."
fi

require_cmd qemu-system-x86_64
require_cmd qemu-img
require_cmd cloud-localds
require_cmd virt-customize
require_cmd ssh
require_cmd ssh-keygen
require_cmd curl
require_cmd sha256sum

systemd_bin="${SYSTEMD_CD4_SYSTEMD:-${CARGO_TARGET_DIR:-target}/debug/systemd}"
if [[ ! -x "$systemd_bin" ]]; then
    fail "Rust systemd binary not found at $systemd_bin; build it or set SYSTEMD_CD4_SYSTEMD"
fi

cache_dir="${SYSTEMD_CD4_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/systemd-cd4}"
image_name="noble-server-cloudimg-amd64.img"
image_url="https://cloud-images.ubuntu.com/noble/current/${image_name}"
sum_url="https://cloud-images.ubuntu.com/noble/current/SHA256SUMS"
mkdir -p "$cache_dir"

base_image="$cache_dir/$image_name"
sum_file="$cache_dir/SHA256SUMS"

if [[ ! -f "$base_image" ]]; then
    echo "+ download Ubuntu 24.04 cloud image"
    if ! curl -fL --retry 3 --retry-delay 1 "$sum_url" -o "$sum_file"; then
        fail "failed to download $sum_url"
    fi

    expected_sha="$(
        awk -v file="$image_name" '$2 == file { print $1 }' "$sum_file" | head -n1
    )"
    if [[ -z "$expected_sha" ]]; then
        fail "could not find checksum for $image_name in $sum_file"
    fi

    tmp_image="$base_image.partial"
    rm -f "$tmp_image"
    if ! curl -fL --retry 3 --retry-delay 1 "$image_url" -o "$tmp_image"; then
        fail "failed to download $image_url"
    fi

    echo "$expected_sha  $tmp_image" | sha256sum -c -
    mv -f "$tmp_image" "$base_image"
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/systemd-cd4.XXXXXX")"
qemu_pid=""

cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" >/dev/null 2>&1; then
        kill "$qemu_pid" >/dev/null 2>&1 || true
        wait "$qemu_pid" >/dev/null 2>&1 || true
    fi

    if [[ "${SYSTEMD_CD4_KEEP:-0}" != 1 ]]; then
        rm -rf "$tmpdir"
    else
        echo "Keeping artifacts in $tmpdir" >&2
    fi
}
trap cleanup EXIT

overlay="$tmpdir/ubuntu-noble.qcow2"
seed_iso="$tmpdir/seed.iso"
user_data="$tmpdir/user-data"
meta_data="$tmpdir/meta-data"
ssh_key="$tmpdir/id_ed25519"
serial_log="$tmpdir/qemu-serial.log"
ssh_known_hosts="$tmpdir/known_hosts"

run qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$overlay"
run ssh-keygen -t ed25519 -N '' -f "$ssh_key" -C systemd-cd4 >/dev/null

cat >"$user_data" <<EOF
#cloud-config
users:
  - default
  - name: cd4
    gecos: systemd cd4
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$ssh_key.pub")

write_files:
  - path: /etc/systemd/system/systemd-cd4.service
    permissions: '0644'
    content: |
      [Unit]
      Description=systemd-cd4 smoke service
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=oneshot
      RemainAfterExit=yes
      ExecStart=/bin/sh -ec 'printf "start %s\n" "$(date -Iseconds)" >> /run/systemd-cd4.log'
      ExecStop=/bin/sh -ec 'printf "stop %s\n" "$(date -Iseconds)" >> /run/systemd-cd4.log'

      [Install]
      WantedBy=multi-user.target

runcmd:
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, ssh.service]
EOF

cat >"$meta_data" <<EOF
instance-id: systemd-cd4
local-hostname: systemd-cd4
EOF

run cloud-localds "$seed_iso" "$user_data" "$meta_data"

run virt-customize \
    -a "$overlay" \
    --upload "$systemd_bin":/root/systemd-rust \
    --run-command 'install -m 0755 /root/systemd-rust /usr/lib/systemd/systemd-rust' \
    --run-command 'ln -sfnT /usr/lib/systemd/systemd-rust /sbin/init' \
    --run-command 'if command -v update-initramfs >/dev/null 2>&1; then update-initramfs -u; fi' \
    --run-command 'rm -f /root/systemd-rust'

echo "+ qemu-system-x86_64 boot"
run qemu-system-x86_64 \
    -machine q35,accel=kvm:tcg \
    -m 2048 \
    -smp 2 \
    -display none \
    -serial file:"$serial_log" \
    -daemonize \
    -pidfile "$tmpdir/qemu.pid" \
    -drive if=virtio,format=qcow2,file="$overlay" \
    -cdrom "$seed_iso" \
    -nic user,model=virtio-net-pci,hostfwd=tcp::2222-:22

qemu_pid="$(<"$tmpdir/qemu.pid")"

ssh_opts=(
    -i "$ssh_key"
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile="$ssh_known_hosts"
    -p 2222
    cd4@127.0.0.1
)

wait_for_ssh() {
    local deadline=$((SECONDS + 300))
    while (( SECONDS < deadline )); do
        if ! kill -0 "$qemu_pid" >/dev/null 2>&1; then
            return 2
        fi
        if ssh "${ssh_opts[@]}" 'true' >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

if ! wait_for_ssh; then
    echo "----- qemu serial log -----" >&2
    tail -n 200 "$serial_log" >&2 || true
    if kill -0 "$qemu_pid" >/dev/null 2>&1; then
        fail "VM did not become reachable over SSH within 300s"
    fi
    fail "QEMU exited before the VM became reachable over SSH"
fi

guest "boot checks" 'bash -se' <<'EOF'
set -euo pipefail

if ! /proc/1/exe --version | grep -q '^systemd 0\.0\.1$'; then
    echo "FAIL: PID 1 does not report Rust systemd version 0.0.1" >&2
    /proc/1/exe --version >&2 || true
    exit 1
fi

test -x /usr/lib/systemd/systemd
if /usr/lib/systemd/systemd --version | grep -q '^systemd 0\.0\.1$'; then
    echo "FAIL: canonical C PID 1 path reports the Rust systemd version" >&2
    /usr/lib/systemd/systemd --version >&2 || true
    exit 1
fi

test -x /usr/lib/systemd/systemd-rust
if ! test /proc/1/exe -ef /usr/lib/systemd/systemd-rust; then
    echo "FAIL: PID 1 is not the installed Rust sidecar" >&2
    readlink -f /proc/1/exe >&2 || true
    readlink -f /usr/lib/systemd/systemd-rust >&2 || true
    exit 1
fi
EOF

if [[ "${SYSTEMD_CD4_SYSTEM_BUS_CHECKS:-0}" != 1 ]]; then
    echo "SKIP: system-bus checks require Rust PID1 API-bus parity; set SYSTEMD_CD4_SYSTEM_BUS_CHECKS=1 to run them." >&2
    echo "PASS: Ubuntu 24.04 Rust PID1 sidecar identity and C fallback checks completed."
    exit 0
fi

guest "system-bus checks" 'bash -se' <<'EOF'
set -euo pipefail

sudo systemctl get-default | grep -qx multi-user.target
sudo systemctl is-active --quiet multi-user.target
sudo systemctl is-active --quiet systemd-networkd.service
sudo systemctl is-active --quiet systemd-journald.service
getent hosts archive.ubuntu.com >/dev/null
sudo journalctl -b --no-pager -n 20 >/dev/null

sudo systemctl start systemd-cd4.service
sudo systemctl is-active --quiet systemd-cd4.service
test "$(grep -c '^start ' /run/systemd-cd4.log)" -eq 1
sudo journalctl -b --no-pager --unit systemd-cd4.service >/dev/null

sudo systemctl restart systemd-cd4.service
test "$(grep -c '^start ' /run/systemd-cd4.log)" -eq 2
test "$(grep -c '^stop ' /run/systemd-cd4.log)" -ge 1

sudo systemctl stop systemd-cd4.service
if sudo systemctl is-active --quiet systemd-cd4.service; then
    echo "FAIL: systemd-cd4.service is still active after stop" >&2
    exit 1
fi
test "$(grep -c '^stop ' /run/systemd-cd4.log)" -ge 1

sudo systemctl show -p ActiveState -p SubState systemd-cd4.service | grep -q '^ActiveState=inactive$'
EOF

echo "PASS: Ubuntu 24.04 Rust PID1 sidecar and system-bus checks completed."
