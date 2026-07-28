#!/usr/bin/env python3
"""Unit tests for the generic behavior-contract gate."""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


def load_gate():
    script = Path(__file__).with_name("check-behavior-contract.py")
    spec = importlib.util.spec_from_file_location("behavior_contract_gate", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATE = load_gate()


class BehaviorContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for relative, contents in {
            "src/basic/demo.c": "int demo(const char *s, int *ret) { return 0; }\n",
            "src/basic/demo.h": "int demo(const char *s, int *ret);\nint demo_unported(void);\n",
            "src/basic/rust/demo.rs": "#[no_mangle] pub extern \"C\" fn rs_demo() {}\n",
            "src/basic/rust/demo.h": "int rs_demo(const char *s, int *ret);\n",
            "tests-extra/test-demo-rust.c": "/* RUST-CONTRACT: demo */\nint demo(void); int rs_demo(void);\n",
            "tests-extra/meson.build": "rust_test_exe = 1\nexecutable('test-demo-rust', files('test-demo-rust.c'), link_with : [libshared, rust_staticlib])\ntest('test-demo-rust', rust_test_exe)\n",
            "tools/rust-port/contracts/basic/demo.toml": self.contract(),
            "tools/rust-port/map.toml": "[demo]\nc_file = 'src/basic/demo.c'\nrust_paths = ['src/basic/rust/demo.rs', 'src/basic/rust/demo.h']\nheader_file = 'src/basic/demo.h'\ncontract_file = 'tools/rust-port/contracts/basic/demo.toml'\nsymbols = 1\n",
        }.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def contract() -> str:
        return """schema = 1
module = 'demo'
semantic_coverage = 'partial'
source_structure = 'independent'
deviation_policy = 'explicit-only'
excluded_c_symbols = ['demo_unported']

[authority]
c_headers = ['src/basic/demo.h']
c_sources = ['src/basic/demo.c']
rust_headers = ['src/basic/rust/demo.h']
rust_sources = ['src/basic/rust/demo.rs']

[[surface]]
id = 'demo'
c_symbols = ['demo']
rust_symbols = ['rs_demo']
coverage = 'exact'
abi = 'c-exact'
bytes = 'borrowed-cstr-opaque'
errors = 'negative-errno'
runtime = 'none'
verification = 'static-only'

[[surface.output]]
arg = 'ret'
ownership = 'caller-storage'
publication_success = 'write'
publication_error = 'unchanged'
optional = false

[surface.static_fixture]
file = 'tests-extra/test-demo-rust.c'
meson_target = 'test-demo-rust'
labels = ['demo']
"""

    def validate(self) -> list[str]:
        manifest = GATE.tomllib.loads((self.root / "tools/rust-port/map.toml").read_text())
        return GATE.validate_contract(
            self.root / "tools/rust-port/contracts/basic/demo.toml",
            self.root,
            manifest["demo"],
            "demo",
        )

    def test_valid_contract_passes(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_duplicate_surface_symbol_fails(self) -> None:
        contract = self.root / "tools/rust-port/contracts/basic/demo.toml"
        contract.write_text(self.contract() + "\n[[surface]]\nid = 'again'\nc_symbols = ['demo']\nrust_symbols = ['rs_demo']\ncoverage = 'unclaimed'\nabi = 'unclaimed'\nbytes = 'unclaimed'\nerrors = 'unclaimed'\nruntime = 'unclaimed'\nverification = 'static-only'\n")
        self.assertTrue(any("occur in another surface" in error for error in self.validate()))

    def test_exact_surface_requires_unique_marker(self) -> None:
        fixture = self.root / "tests-extra/test-demo-rust.c"
        fixture.write_text("int demo(void); int rs_demo(void);\n")
        self.assertTrue(any("marker" in error for error in self.validate()))

    def test_owned_libc_requires_free_release(self) -> None:
        contract = self.root / "tools/rust-port/contracts/basic/demo.toml"
        contract.write_text(self.contract().replace("ownership = 'caller-storage'", "ownership = 'owned-libc'"))
        self.assertTrue(any("release = 'free'" in error for error in self.validate()))

    def test_multi_symbol_output_requires_explicit_symbols(self) -> None:
        contract = self.root / "tools/rust-port/contracts/basic/demo.toml"
        c_source = self.root / "src/basic/demo.c"
        c_header = self.root / "src/basic/demo.h"
        rust_source = self.root / "src/basic/rust/demo.rs"
        rust_header = self.root / "src/basic/rust/demo.h"
        fixture = self.root / "tests-extra/test-demo-rust.c"

        c_source.write_text(c_source.read_text() + "int demo_two(int *ret) { return 0; }\n")
        c_header.write_text(c_header.read_text() + "int demo_two(int *ret);\n")
        rust_source.write_text(rust_source.read_text() + '#[no_mangle] pub extern "C" fn rs_demo_two() {}\n')
        rust_header.write_text(rust_header.read_text() + "int rs_demo_two(int *ret);\n")
        fixture.write_text(fixture.read_text() + "int demo_two(void); int rs_demo_two(void);\n")
        contract.write_text(
            self.contract()
            .replace("c_symbols = ['demo']", "c_symbols = ['demo', 'demo_two']")
            .replace("rust_symbols = ['rs_demo']", "rust_symbols = ['rs_demo', 'rs_demo_two']")
        )
        map_path = self.root / "tools/rust-port/map.toml"
        map_path.write_text(map_path.read_text().replace("symbols = 1", "symbols = 2"))

        self.assertTrue(
            any(
                "multi-symbol surface must declare" in error
                for error in self.validate()
            )
        )

    def test_output_symbols_must_belong_to_surface(self) -> None:
        contract = self.root / "tools/rust-port/contracts/basic/demo.toml"
        contract.write_text(
            self.contract().replace(
                "[[surface.output]]\n",
                "[[surface.output]]\nsymbols = ['not_demo']\n",
            )
        )
        self.assertTrue(
            any(
                "symbols are not members of the surface" in error
                for error in self.validate()
            )
        )

    def test_output_arg_must_name_c_parameter(self) -> None:
        contract = self.root / "tools/rust-port/contracts/basic/demo.toml"
        contract.write_text(
            self.contract().replace("arg = 'ret'", "arg = 'not_a_parameter'")
        )
        self.assertTrue(
            any(
                "has no C parameter named 'not_a_parameter'" in error
                for error in self.validate()
            )
        )

    def test_runtime_verified_requires_reproducible_evidence(self) -> None:
        contract = self.root / "tools/rust-port/contracts/basic/demo.toml"
        contract.write_text(
            self.contract().replace(
                "verification = 'static-only'",
                "verification = 'runtime-verified'",
            )
        )
        self.assertTrue(
            any(
                "requires [surface.runtime_evidence]" in error
                for error in self.validate()
            )
        )

    def test_map_symbol_count_must_match_contract(self) -> None:
        map_path = self.root / "tools/rust-port/map.toml"
        map_path.write_text(map_path.read_text().replace("symbols = 1", "symbols = 2"))
        self.assertTrue(
            any("contracts declare 1 distinct C symbols" in error for error in self.validate())
        )

    def test_excluded_symbol_must_exist_in_authority(self) -> None:
        contract = self.root / "tools/rust-port/contracts/basic/demo.toml"
        contract.write_text(
            self.contract().replace("demo_unported", "not_in_the_authority")
        )
        self.assertTrue(
            any("excluded C symbol is absent from authority" in error for error in self.validate())
        )

    def test_kebab_case_fixture_marker_is_valid(self) -> None:
        contract = self.root / "tools/rust-port/contracts/basic/demo.toml"
        fixture = self.root / "tests-extra/test-demo-rust.c"
        contract.write_text(self.contract().replace("id = 'demo'", "id = 'demo-edge'", 1).replace("labels = ['demo']", "labels = ['demo-edge']"))
        fixture.write_text("/* RUST-CONTRACT: demo-edge */\nint demo(void); int rs_demo(void);\n")
        self.assertEqual(self.validate(), [])

    def test_cli_focused_mode_uses_map_index(self) -> None:
        result = subprocess.run(
            [
                "python3", str(Path(__file__).with_name("check-behavior-contract.py")),
                "--repo-root", str(self.root),
                "--contract", "tools/rust-port/contracts/basic/demo.toml",
            ], text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("contracts=1", result.stdout)


if __name__ == "__main__":
    unittest.main()
