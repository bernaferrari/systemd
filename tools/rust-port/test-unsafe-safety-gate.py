#!/usr/bin/env python3
"""Regression tests for the unsafe SAFETY-rationale baseline gate."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("unsafe-safety-gate.py")


class UnsafeSafetyGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "src" / "fixture.rs"
        self.source.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_gate(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SCRIPT), "--root", str(self.root), *args],
            check=False,
            capture_output=True,
            text=True,
        )

    def write_baseline(self) -> None:
        result = self.run_gate(
            "--baseline", "baseline.json", "--write-baseline"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_site_ledger_rejects_substitution_at_constant_debt_count(self) -> None:
        self.source.write_text("fn fixture() { unsafe { old(); } }\n", encoding="utf-8")
        self.write_baseline()

        # The old count-only baseline accepted this: one undocumented site was
        # replaced with another, leaving the per-file count unchanged.
        self.source.write_text("fn fixture() { unsafe { new(); } }\n", encoding="utf-8")
        result = self.run_gate("--baseline", "baseline.json")

        self.assertEqual(result.returncode, 1)
        self.assertIn("new undocumented unsafe site", result.stderr)
        self.assertIn("unsafe { new(); }", result.stderr)

    def test_multiline_unsafe_construct_is_counted(self) -> None:
        self.source.write_text(
            "fn fixture() {\n    unsafe\n    { call(); }\n}\n",
            encoding="utf-8",
        )
        self.write_baseline()

        result = self.run_gate("--baseline", "baseline.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fixture.rs,1,0,1,1,OK", result.stdout)

    def test_documented_unsafe_site_growth_is_rejected(self) -> None:
        self.source.write_text("fn fixture() {}\n", encoding="utf-8")
        self.write_baseline()

        self.source.write_text(
            "// SAFETY: fixture contract.\nfn fixture() { unsafe { call(); } }\n",
            encoding="utf-8",
        )
        result = self.run_gate("--baseline", "baseline.json")

        self.assertEqual(result.returncode, 1)
        self.assertIn("unsafe-site growth", result.stderr)
        self.assertIn("0 -> 1", result.stderr)

    def test_type_alias_to_unsafe_function_pointer_is_not_a_site(self) -> None:
        self.source.write_text(
            'pub type Callback = unsafe extern "C" fn(*mut u8);\n',
            encoding="utf-8",
        )
        self.write_baseline()

        result = self.run_gate("--baseline", "baseline.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unsafe_sites=0 abi_sites=0 missing_safety=0", result.stdout)

    def test_unsafe_extern_is_reported_separately_from_execution_surface(self) -> None:
        self.source.write_text(
            '// SAFETY: fixture ABI declaration is only called with valid pointers.\n'
            'unsafe extern "C" { fn imported(value: *mut u8); }\n',
            encoding="utf-8",
        )
        self.write_baseline()

        result = self.run_gate("--baseline", "baseline.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fixture.rs,0,1,0,0,OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
