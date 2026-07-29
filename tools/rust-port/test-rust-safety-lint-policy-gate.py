#!/usr/bin/env python3
"""Regression tests for Rust safety-lint policy inventory."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("rust-safety-lint-policy-gate.py")
SPEC = importlib.util.spec_from_file_location("rust_safety_lint_policy_gate", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


class RustSafetyLintPolicyGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.write(
            "Cargo.toml",
            '[workspace]\nmembers = ["src/demo/rust"]\nresolver = "2"\n',
        )
        self.write(
            "src/demo/rust/Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n"
            "edition = \"2024\"\nautobins = false\n\n[lib]\npath = \"lib.rs\"\n",
        )
        self.write(
            "src/demo/rust/lib.rs",
            "#![deny(unsafe_op_in_unsafe_fn)]\nmod implementation;\n",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, contents: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def test_scoped_allow_cannot_bypass_release_root_deny(self) -> None:
        self.write(
            "src/demo/rust/implementation.rs",
            "#[allow(unsafe_op_in_unsafe_fn)]\nunsafe fn legacy() {}\n",
        )

        inventory = GATE.collect_inventory(self.root)

        self.assertEqual(
            inventory.unsafe_op_weakening_errors,
            ("src/demo/rust/implementation.rs",),
        )

    def test_deny_is_not_reported_as_a_weakening(self) -> None:
        self.write(
            "src/demo/rust/implementation.rs",
            "#[deny(unsafe_op_in_unsafe_fn)]\nunsafe fn hardened() {}\n",
        )

        inventory = GATE.collect_inventory(self.root)

        self.assertEqual(inventory.unsafe_op_weakening_errors, ())

    def test_explicit_unpublished_test_member_has_no_release_target(self) -> None:
        self.write(
            "Cargo.toml",
            '[workspace]\nmembers = ["test/fuzz"]\nresolver = "2"\n',
        )
        self.write(
            "test/fuzz/Cargo.toml",
            "[package]\nname = \"fuzz\"\nversion = \"0.1.0\"\n"
            "edition = \"2024\"\npublish = false\nautobins = false\n\n"
            "[package.metadata.systemd-rust]\ndev-only = true\n\n"
            "[[test]]\nname = \"smoke\"\npath = \"smoke.rs\"\n",
        )
        self.write("test/fuzz/smoke.rs", "#[test]\nfn smoke() {}\n")

        inventory = GATE.collect_inventory(self.root)

        self.assertEqual(inventory.release_targets, ())


if __name__ == "__main__":
    unittest.main()
