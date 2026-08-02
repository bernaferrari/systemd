#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Focused tests for the production-wave ledger gate."""

from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_gate():
    script = Path(__file__).with_name("check-production-wave-ledger.py")
    spec = importlib.util.spec_from_file_location("production_wave_ledger", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATE = load_gate()


class ProductionWaveLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.write("src/demo/demo.c", "/* authority */\n")
        self.write("src/demo/meson.build", "sources = files('demo.c')\n")
        self.write("src/demo/rust/main.rs", "// PORT-SYNC: src/demo/demo.c\n")
        self.write("src/demo/rust/lib.rs", "// PORT-SYNC: src/demo/demo.c\n")
        self.write_ledger(status="shadow", owner="c", all_passed=False)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, contents: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def oid(self, relative: str) -> str:
        content = (self.root / relative).read_bytes()
        return hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()

    def write_ledger(self, *, status: str, owner: str, all_passed: bool) -> None:
        state = "passed" if all_passed else "missing"
        self.write(
            "tools/rust-port/production-waves.toml",
            f'''schema = 1

[[target]]
id = "demo"
status = "{status}"
production_owner = "{owner}"
fallback_owner = "c"
c_source = "src/demo/demo.c"
meson_build = "src/demo/meson.build"
c_selected_source = "demo.c"
rust_paths = ["src/demo/rust/main.rs", "src/demo/rust/lib.rs"]
reviewed_c_blobs = {{ "src/demo/demo.c" = "{self.oid("src/demo/demo.c")}" }}
reviewed_rust_blobs = {{ "src/demo/rust/main.rs" = "{self.oid("src/demo/rust/main.rs")}", "src/demo/rust/lib.rs" = "{self.oid("src/demo/rust/lib.rs")}" }}

[[target.evidence]]
name = "cli"
state = "{state}"
detail = "fixture"
[[target.evidence]]
name = "persistent-state"
state = "{state}"
detail = "fixture"
[[target.evidence]]
name = "entropy-credit"
state = "{state}"
detail = "fixture"
[[target.evidence]]
name = "privilege"
state = "{state}"
detail = "fixture"
[[target.evidence]]
name = "recovery"
state = "{state}"
detail = "fixture"
[[target.evidence]]
name = "linux-integration"
state = "{state}"
detail = "fixture"
[[target.evidence]]
name = "differential"
state = "{state}"
detail = "fixture"
''',
        )

    def validate(self) -> list[str]:
        return GATE.validate(self.root, Path("tools/rust-port/production-waves.toml"))

    def test_shadow_c_fallback_passes(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_replace_requires_all_evidence_and_rust_owner(self) -> None:
        self.write_ledger(status="replace", owner="c", all_passed=False)
        errors = self.validate()
        self.assertTrue(any("replace requires production_owner" in error for error in errors))
        self.assertTrue(any("replace requires every evidence" in error for error in errors))

    def test_c_source_must_remain_selected_by_meson(self) -> None:
        self.write("src/demo/meson.build", "sources = files('other.c')\n")
        errors = self.validate()
        self.assertTrue(any("Meson no longer selects" in error for error in errors))

    def test_blob_pin_detects_drift(self) -> None:
        self.write("src/demo/rust/main.rs", "// PORT-SYNC: src/demo/demo.c\n// changed\n")
        errors = self.validate()
        self.assertTrue(any("changed since its reviewed blob pin" in error for error in errors))

    def test_malformed_status_reports_a_gate_error(self) -> None:
        ledger = self.root / "tools/rust-port/production-waves.toml"
        ledger.write_text(
            ledger.read_text(encoding="utf-8").replace('status = "shadow"', "status = []"),
            encoding="utf-8",
        )
        errors = self.validate()
        self.assertTrue(any("status must be one of" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
