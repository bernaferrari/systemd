#!/usr/bin/env python3
"""Static tests for the Rust comparison-fixture catalog gate."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_gate():
    script = Path(__file__).with_name("check-rust-fixture-catalog.py")
    spec = importlib.util.spec_from_file_location("rust_fixture_catalog", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATE = load_gate()


class RustFixtureCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "tests-extra").mkdir()
        (self.root / "tools/rust-port").mkdir(parents=True)
        (self.root / "tests-extra/test-alpha-behavior-rust.c").write_text("int main(void) {}\n")
        (self.root / "tests-extra/test-old-extra2-rust.c").write_text("int main(void) {}\n")
        (self.root / "tests-extra/meson.build").write_text(
            """rust_test_exe = executable('test-alpha-behavior-rust', files('test-alpha-behavior-rust.c'), link_with : [libshared, rust_staticlib])
test('test-alpha-behavior-rust', rust_test_exe)
rust_test_exe = executable('test-old-extra2-rust', files('test-old-extra2-rust.c'), link_with : [libshared, rust_staticlib])
test('test-old-extra2-rust', rust_test_exe)
"""
        )
        self.catalog().write_text(
            """schema = 1
[policy]
new_fixture_pattern = "test-<semantic-subject>-<behavior>-rust.c"
forbid_new_numbered_extra = true
[grandfathered_chronological]
"test-old-extra2-rust.c" = "basic.old"
"""
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def catalog(self) -> Path:
        return self.root / "tools/rust-port/rust-fixture-catalog.toml"

    def test_current_catalog_passes_and_is_queryable(self) -> None:
        errors, records = GATE.audit(self.root, self.catalog())
        self.assertEqual(errors, [])
        self.assertEqual(len(records), 2)
        old = next(record for record in records if record["grandfathered_chronological"])
        self.assertEqual(old["owner"], "basic.old")

    def test_new_numbered_extra_is_rejected(self) -> None:
        meson = self.root / "tests-extra/meson.build"
        meson.write_text(
            meson.read_text()
            + "rust_test_exe = executable('test-new-extra9-rust', files('test-new-extra9-rust.c'), link_with : [libshared, rust_staticlib])\n"
            + "test('test-new-extra9-rust', rust_test_exe)\n"
        )
        (self.root / "tests-extra/test-new-extra9-rust.c").write_text("int main(void) {}\n")
        errors, _ = GATE.audit(self.root, self.catalog())
        self.assertTrue(any("new chronological fixture" in error for error in errors))

    def test_catalog_entry_must_remain_registered(self) -> None:
        meson = self.root / "tests-extra/meson.build"
        meson.write_text(meson.read_text().replace(
            "rust_test_exe = executable('test-old-extra2-rust', files('test-old-extra2-rust.c'), link_with : [libshared, rust_staticlib])\n"
            "test('test-old-extra2-rust', rust_test_exe)\n",
            "",
        ))
        errors, _ = GATE.audit(self.root, self.catalog())
        self.assertTrue(any("stale grandfathered" in error for error in errors))

    def test_target_and_source_must_match(self) -> None:
        meson = self.root / "tests-extra/meson.build"
        meson.write_text(meson.read_text().replace("test-alpha-behavior-rust.c", "test-other-rust.c"))
        (self.root / "tests-extra/test-other-rust.c").write_text("int main(void) {}\n")
        errors, _ = GATE.audit(self.root, self.catalog())
        self.assertTrue(any("fixture must be named" in error for error in errors))

    def test_rust_fixture_must_be_registered_as_a_meson_test(self) -> None:
        meson = self.root / "tests-extra/meson.build"
        meson.write_text(
            meson.read_text().replace(
                "test('test-alpha-behavior-rust', rust_test_exe)\n", ""
            )
        )
        errors, _ = GATE.audit(self.root, self.catalog())
        self.assertTrue(any("not registered by test()" in error for error in errors))

    def test_rust_fixture_is_found_when_support_libraries_are_reordered(self) -> None:
        meson = self.root / "tests-extra/meson.build"
        meson.write_text(
            meson.read_text().replace(
                "link_with : [libshared, rust_staticlib]",
                "link_with : [rust_staticlib, libshared, extra_support]",
                1,
            )
        )
        errors, records = GATE.audit(self.root, self.catalog())
        self.assertEqual(errors, [])
        self.assertTrue(
            any(record["target"] == "test-alpha-behavior-rust" for record in records)
        )

    def test_rejects_same_name_test_without_executable_binding(self) -> None:
        """Old same-name-only gate: bare executable + test(..., rust_test_exe)."""

        (self.root / "tests-extra/meson.build").write_text(
            """executable('test-alpha-behavior-rust', files('test-alpha-behavior-rust.c'), link_with : [libshared, rust_staticlib])
test('test-alpha-behavior-rust', rust_test_exe)
rust_test_exe = executable('test-old-extra2-rust', files('test-old-extra2-rust.c'), link_with : [libshared, rust_staticlib])
test('test-old-extra2-rust', rust_test_exe)
"""
        )
        errors, _ = GATE.audit(self.root, self.catalog())
        self.assertTrue(
            any(
                "test-alpha-behavior-rust" in error and "bound to its executable" in error
                for error in errors
            )
        )

    def test_rejects_stale_rust_test_exe_reassignment(self) -> None:
        """test() after rust_test_exe was reassigned to a different target."""

        (self.root / "tests-extra/meson.build").write_text(
            """rust_test_exe = executable('test-alpha-behavior-rust', files('test-alpha-behavior-rust.c'), link_with : [libshared, rust_staticlib])
rust_test_exe = executable('test-old-extra2-rust', files('test-old-extra2-rust.c'), link_with : [libshared, rust_staticlib])
test('test-alpha-behavior-rust', rust_test_exe)
test('test-old-extra2-rust', rust_test_exe)
"""
        )
        errors, _ = GATE.audit(self.root, self.catalog())
        self.assertTrue(
            any(
                "test-alpha-behavior-rust" in error and "bound to its executable" in error
                for error in errors
            )
        )

    def test_rejects_test_bound_to_different_executable(self) -> None:
        """test() name matches, but the variable points at another executable."""

        (self.root / "tests-extra/meson.build").write_text(
            """wrong_exe = executable('test-old-extra2-rust', files('test-old-extra2-rust.c'), link_with : [libshared, rust_staticlib])
rust_test_exe = executable('test-alpha-behavior-rust', files('test-alpha-behavior-rust.c'), link_with : [libshared, rust_staticlib])
test('test-alpha-behavior-rust', wrong_exe)
test('test-old-extra2-rust', rust_test_exe)
"""
        )
        errors, _ = GATE.audit(self.root, self.catalog())
        self.assertTrue(
            any(
                "test-alpha-behavior-rust" in error and "bound to its executable" in error
                for error in errors
            )
        )
        self.assertTrue(
            any(
                "test-old-extra2-rust" in error and "bound to its executable" in error
                for error in errors
            )
        )

    def test_accepts_non_default_binding_variable(self) -> None:
        """Any identifier is fine if it resolves to the matching executable target."""

        (self.root / "tests-extra/meson.build").write_text(
            """my_rust_exe = executable('test-alpha-behavior-rust', files('test-alpha-behavior-rust.c'), link_with : [libshared, rust_staticlib])
test('test-alpha-behavior-rust', my_rust_exe)
other_exe = executable('test-old-extra2-rust', files('test-old-extra2-rust.c'), link_with : [libshared, rust_staticlib])
test('test-old-extra2-rust', other_exe)
"""
        )
        errors, records = GATE.audit(self.root, self.catalog())
        self.assertEqual(errors, [])
        self.assertEqual(len(records), 2)


if __name__ == "__main__":
    unittest.main()
