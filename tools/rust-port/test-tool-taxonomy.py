#!/usr/bin/env python3
"""Static tests for the Rust-port tool taxonomy gate."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_gate():
    script = Path(__file__).with_name("check-tool-taxonomy.py")
    spec = importlib.util.spec_from_file_location("tool_taxonomy_gate", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATE = load_gate()


class ToolTaxonomyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.write("tools/rust-port/check-demo.py", "print('demo')\n")
        self.write("tools/rust-port/demo-baseline.json", "{}\n")
        self.write("tools/rust-port/contracts/basic/demo.toml", "schema = 1\n")
        self.write_taxonomy(
            """schema = 1

[[category]]
id = "demo"
purpose = "Demo tooling."
paths = [
    "tools/rust-port/check-demo.py",
    "tools/rust-port/demo-baseline.json",
    "tools/rust-port/contracts/basic/demo.toml",
]
"""
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, contents: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def write_taxonomy(self, contents: str) -> None:
        self.write("tools/rust-port/tool-taxonomy.toml", contents)

    def test_complete_taxonomy_passes(self) -> None:
        self.assertEqual(GATE.validate(self.root), [])

    def test_new_tool_must_be_classified(self) -> None:
        self.write("tools/rust-port/check-new.py", "print('new')\n")
        self.assertTrue(any("check-new.py" in error for error in GATE.validate(self.root)))

    def test_duplicate_category_membership_fails(self) -> None:
        self.write_taxonomy(
            (self.root / "tools/rust-port/tool-taxonomy.toml").read_text()
            + """
[[category]]
id = "duplicate"
purpose = "Duplicate ownership."
paths = ["tools/rust-port/check-demo.py"]
"""
        )
        self.assertTrue(any("already in category" in error for error in GATE.validate(self.root)))

    def test_stale_classification_fails(self) -> None:
        self.write_taxonomy(
            (self.root / "tools/rust-port/tool-taxonomy.toml").read_text().replace(
                '"tools/rust-port/check-demo.py",',
                '"tools/rust-port/missing.py",',
            )
        )
        errors = GATE.validate(self.root)
        self.assertTrue(any("does not exist" in error for error in errors))
        self.assertTrue(any("unclassified" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
