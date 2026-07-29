#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
    echo "Run this script from the systemd repository root." >&2
    exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "SKIP: Linux-only journal parity smoke check."
    exit 0
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

for cmd in journalctl logger systemd-cat systemd-run timeout python3; do
    if ! need_cmd "$cmd"; then
        echo "SKIP: required command '$cmd' is not available."
        exit 0
    fi
done

pid1_comm="$(ps -p 1 -o comm= | tr -d '[:space:]')"
if [[ "$pid1_comm" != "systemd" ]]; then
    echo "SKIP: PID 1 is '$pid1_comm', not systemd."
    exit 0
fi

as_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        sudo -n "$@"
    else
        return 125
    fi
}

if ! as_root true; then
    echo "SKIP: root (or passwordless sudo) is required for journal parity smoke checks."
    exit 0
fi

run() {
    echo "+ $*"
    "$@"
}

journal_sync() {
    as_root journalctl --sync >/dev/null 2>&1 || true
}

journal_total_size_bytes() {
    as_root bash -lc "find /run/log/journal /var/log/journal -type f -name '*.journal*' -printf '%s\n' 2>/dev/null | awk '{s+=\$1} END{print s+0}'"
}

latest_journal_file() {
    as_root bash -lc "ls -1t /var/log/journal/*/*.journal /run/log/journal/*/*.journal 2>/dev/null | head -n1"
}

tmpdir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT

id="rust-journal-parity-$(date +%s)-$$"
echo "Running journal parity smoke id: $id"

# 1) Native-ish message path with portable required metadata fields.
native_unit="$id-native.service"
native_msg="$id native message"
run as_root systemd-run --quiet --unit "$native_unit" --wait /bin/sh -c "echo '$native_msg'"
journal_sync
run as_root journalctl --no-pager --unit "$native_unit" --grep "$native_msg" -n 1 -o json >"$tmpdir/native.json"
python3 - "$tmpdir/native.json" "$native_unit" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
unit = sys.argv[2]
lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
if not lines:
    raise SystemExit("FAIL: no native unit journal entry captured")
entry = json.loads(lines[-1])
required = ["_SYSTEMD_UNIT", "MESSAGE"]
for key in required:
    if key not in entry or not str(entry[key]).strip():
        raise SystemExit(f"FAIL: missing expected field {key} in native entry")
if entry["_SYSTEMD_UNIT"] != unit:
    raise SystemExit(f"FAIL: expected _SYSTEMD_UNIT={unit}, got {entry['_SYSTEMD_UNIT']}")
for key in ["_PID", "_COMM"]:
    if key in entry and not str(entry[key]).strip():
        raise SystemExit(f"FAIL: native entry has an empty optional field {key}")
PY

# 2) Syslog ingestion path.
syslog_tag="$id-syslog"
syslog_msg="$id syslog message"
run logger -t "$syslog_tag" "$syslog_msg"
journal_sync
run as_root journalctl --no-pager -t "$syslog_tag" --grep "$syslog_msg" -n 1 -o json >"$tmpdir/syslog.json"
python3 - "$tmpdir/syslog.json" <<'PY'
import json
import pathlib
import sys

lines = [ln for ln in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines() if ln.strip()]
if not lines:
    raise SystemExit("FAIL: no syslog journal entry captured")
entry = json.loads(lines[-1])
transport = entry.get("_TRANSPORT", "")
if transport != "syslog":
    raise SystemExit(f"FAIL: expected _TRANSPORT=syslog, got {transport!r}")
PY

# 3) kmsg ingestion path.
kmsg_msg="$id kmsg message"
run as_root bash -lc "printf '<6>%s\n' '$kmsg_msg' > /dev/kmsg"
journal_sync
run as_root journalctl --no-pager -k --grep "$kmsg_msg" -n 1 >/dev/null

# 4) --unit filtering.
run as_root journalctl --no-pager --unit "$native_unit" --grep "$native_msg" -n 1 >/dev/null
if as_root journalctl --no-pager --unit "$native_unit" --grep "$id unrelated" -n 1 | grep -q .; then
    echo "FAIL: --unit filter returned unrelated entry." >&2
    exit 1
fi

# 5) --since/--until filtering.
since_tag="$id-since"
since_msg="$id since-until message"
t0="$(( $(date +%s) - 1 ))"
run logger -t "$since_tag" "$since_msg"
journal_sync
t1="$(( $(date +%s) + 1 ))"
run as_root journalctl --no-pager -t "$since_tag" --grep "$since_msg" --since "@$t0" --until "@$t1" -n 1 >/dev/null
if as_root journalctl --no-pager -t "$since_tag" --grep "$since_msg" --until "@$((t0 - 5))" -n 1 | grep -q .; then
    echo "FAIL: --until filter returned an entry earlier than expected." >&2
    exit 1
fi

# 6) -o export with --output-fields shaping.
fields_tag="$id-fields"
fields_msg="$id fields message"
run logger -p user.info -t "$fields_tag" "$fields_msg"
journal_sync
run as_root journalctl --no-pager -t "$fields_tag" --grep "$fields_msg" -n 1 -o export --output-fields=MESSAGE,PRIORITY,_TRANSPORT >"$tmpdir/fields.export"
grep -qx "MESSAGE=$fields_msg" "$tmpdir/fields.export"
grep -qx "PRIORITY=6" "$tmpdir/fields.export"
grep -qx "_TRANSPORT=syslog" "$tmpdir/fields.export"
# The export serializer keeps a small set of identity fields such as _BOOT_ID
# even when they are not requested.  Verify the documented selection includes
# the requested fields instead of treating that required serializer context as
# a leak.

# 7) --follow delivery.
follow_tag="$id-follow"
follow_msg="$id follow message"
(
    as_root timeout --signal=KILL 15s bash -lc \
        "journalctl --no-pager -n 0 --follow -t '$follow_tag' -o cat | grep -m1 -F '$follow_msg'" \
        >"$tmpdir/follow.out"
) &
follow_pid="$!"
sleep 1
run logger -t "$follow_tag" "$follow_msg"
wait "$follow_pid"
grep -F "$follow_msg" "$tmpdir/follow.out" >/dev/null

# 8) Binary journal file readability with C journalctl.
journal_file="$(latest_journal_file || true)"
if [[ -z "$journal_file" ]]; then
    echo "FAIL: could not locate a journal file under /var/log/journal or /run/log/journal." >&2
    exit 1
fi
run as_root journalctl --no-pager --file "$journal_file" -n 1 >/dev/null

# 9) Vacuum behavior (rotate + vacuum-size shrinks total on-disk journal footprint).
vac_tag="$id-vacuum"
run as_root journalctl --rotate >/dev/null
python3 - "$vac_tag" <<'PY'
import socket
import sys

tag = sys.argv[1]
paths = ["/run/systemd/journal/dev-log", "/dev/log"]
target = None
for p in paths:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(p)
        target = s
        break
    except OSError:
        continue
if target is None:
    raise SystemExit("FAIL: could not connect to syslog unix datagram socket")

payload = ("x" * 1024).encode()
for i in range(5000):
    target.send(f"<6>{tag}: ".encode() + payload + f" #{i}".encode())
PY
journal_sync
run as_root journalctl --rotate >/dev/null
size_before="$(journal_total_size_bytes)"
run as_root journalctl --rotate --vacuum-size=1M >/dev/null
size_after="$(journal_total_size_bytes)"
if (( size_after >= size_before )); then
    echo "FAIL: vacuum-size did not reduce total journal footprint (before=$size_before after=$size_after)." >&2
    exit 1
fi

# 10) Rate limiting is a policy that a host can explicitly disable in
# journald.conf. Exercise the manager's per-unit limiter instead, so this is
# deterministic and leaves the host's journal policy untouched.
rate_unit="$id-ratelimit.service"
run as_root systemd-run --quiet --unit "$rate_unit" --wait \
    --property LogRateLimitIntervalSec=10s \
    --property LogRateLimitBurst=100 \
    /bin/sh -c 'i=0; while [ "$i" -lt 1000 ]; do echo burst; i=$((i + 1)); done'
journal_sync
rate_seen="$(as_root journalctl --no-pager --unit "$rate_unit" --grep '^burst$' -o cat | wc -l | tr -d ' ')"
python3 - "$rate_seen" <<'PY'
import sys

seen = int(sys.argv[1])
if not 0 < seen < 1000:
    raise SystemExit(f"FAIL: expected per-unit rate limiting to retain some, but not all, entries; got {seen} of 1000")
PY

echo "PASS: journal parity smoke checks completed for id=$id"
