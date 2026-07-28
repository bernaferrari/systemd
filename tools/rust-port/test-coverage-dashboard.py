#!/usr/bin/env python3
"""Static tests for the Rust source-inventory generator."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


def load_generator():
    script = Path(__file__).with_name("coverage-dashboard.py")
    spec = importlib.util.spec_from_file_location("coverage_dashboard", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = load_generator()


class CoverageDashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def rust_file(self, relative: str, contents: str = "pub fn behavior() {}\n") -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def test_test_module_naming_conventions_are_support(self) -> None:
        for relative in (
            "src/demo/rust/test_parser.rs",
            "src/demo/rust/fuzz-parser.rs",
            "src/demo/rust/parser_test.rs",
            "src/demo/rust/parser_tests.rs",
            "src/demo/rust/parser/tests/cases.rs",
        ):
            with self.subTest(relative=relative):
                self.assertEqual(
                    GENERATOR.classify_rust(self.rust_file(relative)),
                    "test-support",
                )

    def test_behavior_names_containing_test_are_not_support(self) -> None:
        for relative in (
            "src/demo/rust/contest.rs",
            "src/demo/rust/latest.rs",
        ):
            with self.subTest(relative=relative):
                self.assertEqual(
                    GENERATOR.classify_rust(self.rust_file(relative)),
                    "behavior-candidate",
                )

    def test_crate_roots_remain_candidates_and_metadata_is_excluded(self) -> None:
        self.assertEqual(
            GENERATOR.classify_rust(self.rust_file("src/demo/rust/lib.rs")),
            "behavior-candidate",
        )
        self.assertEqual(
            GENERATOR.classify_rust(
                self.rust_file(
                    "src/demo/rust/adapter.rs",
                    "pub struct PortSyncModule;\n",
                )
            ),
            "metadata",
        )


if __name__ == "__main__":
    unittest.main()
