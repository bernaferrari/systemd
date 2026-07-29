#!/usr/bin/env python3
"""Static fixtures for Rust workspace layout and dependency-layer policy."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("workspace-architecture-gate.py")
SPEC = importlib.util.spec_from_file_location("workspace_architecture_gate", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class WorkspaceArchitectureGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manifest = self.root / "src/example/rust/Cargo.toml"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text("[package]\nname = 'example'\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_canonical_workspace_member_layout_has_no_orphan(self) -> None:
        failures: list[str] = []
        GATE.validate_member_layout(
            self.root,
            ["src/example/rust"],
            {"src/example/rust": "application"},
            failures,
        )
        self.assertEqual(failures, [])

    def test_nested_or_unlisted_crates_are_rejected(self) -> None:
        nested = self.root / "src/example/rust/helper/Cargo.toml"
        nested.parent.mkdir()
        nested.write_text("[package]\nname = 'helper'\n", encoding="utf-8")
        failures: list[str] = []
        GATE.validate_member_layout(
            self.root,
            ["src/example/rust"],
            {"src/missing/rust": "application"},
            failures,
        )
        self.assertTrue(any("Rust Cargo manifests must live" in item for item in failures))
        self.assertTrue(any("assigns non-workspace member" in item for item in failures))

    def test_target_must_remain_inside_its_rust_crate(self) -> None:
        failures: list[str] = []
        GATE.validate_target_path(
            "src/example/rust", self.manifest, "../outside.rs", failures
        )
        self.assertEqual(
            failures,
            ["src/example/rust: target path escapes its Rust crate: ../outside.rs"],
        )

    def test_dev_only_crate_uses_an_explicit_test_not_a_release_target(self) -> None:
        manifest = {
            "package": {
                "publish": False,
                "metadata": {"systemd-rust": {"dev-only": True}},
            },
            "test": [{"name": "smoke", "path": "parser_fuzz.rs"}],
        }

        self.assertTrue(GATE.is_declared_dev_only("src/fuzz/rust", manifest))
        self.assertEqual(GATE.explicit_targets(manifest), [])
        self.assertEqual(GATE.explicit_test_targets(manifest), ["parser_fuzz.rs"])

    def test_dev_only_crate_must_remain_unpublished(self) -> None:
        manifest = {"package": {"metadata": {"systemd-rust": {"dev-only": True}}}}

        with self.assertRaisesRegex(ValueError, "must set package.publish = false"):
            GATE.is_declared_dev_only("src/fuzz/rust", manifest)

    def test_dev_only_source_fixture_must_be_explicit_and_canonical(self) -> None:
        target = self.manifest.parent / "parser_fuzz.rs"
        target.write_text(
            '#[path = "../../shared/rust/fuzz.rs"]\nmod fuzz;\n', encoding="utf-8"
        )
        fixture = self.root / "src/shared/rust/fuzz.rs"
        fixture.parent.mkdir(parents=True)
        fixture.write_text("// fixture\n", encoding="utf-8")
        manifest = {
            "package": {
                "metadata": {
                    "systemd-rust": {
                        "dev-only": True,
                        "source-fixtures": ["src/shared/rust/fuzz.rs"],
                    }
                }
            }
        }
        failures: list[str] = []
        GATE.validate_dev_only_source_fixtures(
            self.root,
            "src/fuzz/rust",
            manifest,
            self.manifest,
            ["parser_fuzz.rs"],
            failures,
        )
        self.assertEqual(failures, [])

    def test_dev_only_source_fixture_rejects_an_unlisted_escape(self) -> None:
        target = self.manifest.parent / "parser_fuzz.rs"
        target.write_text(
            '#[path = "../../shared/rust/fuzz.rs"]\nmod fuzz;\n', encoding="utf-8"
        )
        manifest = {
            "package": {"metadata": {"systemd-rust": {"dev-only": True}}}
        }
        failures: list[str] = []
        GATE.validate_dev_only_source_fixtures(
            self.root,
            "src/fuzz/rust",
            manifest,
            self.manifest,
            ["parser_fuzz.rs"],
            failures,
        )
        self.assertEqual(
            failures,
            [
                "src/fuzz/rust: external #[path] source fixture is not declared: "
                "src/shared/rust/fuzz.rs"
            ],
        )

    def test_dev_only_source_fixture_recursively_rejects_nested_escape(self) -> None:
        target = self.manifest.parent / "parser_fuzz.rs"
        target.write_text(
            '#[path = "../../shared/rust/fuzz.rs"]\nmod fuzz;\n', encoding="utf-8"
        )
        fixture = self.root / "src/shared/rust/fuzz.rs"
        fixture.parent.mkdir(parents=True)
        fixture.write_text(
            '#[path = "../../core/rust/hidden.rs"]\nmod hidden;\n',
            encoding="utf-8",
        )
        hidden = self.root / "src/core/rust/hidden.rs"
        hidden.parent.mkdir(parents=True)
        hidden.write_text("// hidden\n", encoding="utf-8")
        manifest = {
            "package": {
                "metadata": {
                    "systemd-rust": {
                        "dev-only": True,
                        "source-fixtures": ["src/shared/rust/fuzz.rs"],
                    }
                }
            }
        }
        failures: list[str] = []
        GATE.validate_dev_only_source_fixtures(
            self.root,
            "src/fuzz/rust",
            manifest,
            self.manifest,
            ["parser_fuzz.rs"],
            failures,
        )
        self.assertEqual(
            failures,
            [
                "src/fuzz/rust: external #[path] source fixture is not declared: "
                "src/core/rust/hidden.rs"
            ],
        )

    def test_dev_only_source_fixture_rejects_raw_string_escape(self) -> None:
        target = self.manifest.parent / "parser_fuzz.rs"
        target.write_text(
            '#[path = r##"../../shared/rust/fuzz.rs"##]\nmod fuzz;\n',
            encoding="utf-8",
        )
        manifest = {
            "package": {"metadata": {"systemd-rust": {"dev-only": True}}}
        }
        failures: list[str] = []
        GATE.validate_dev_only_source_fixtures(
            self.root,
            "src/fuzz/rust",
            manifest,
            self.manifest,
            ["parser_fuzz.rs"],
            failures,
        )
        self.assertEqual(
            failures,
            [
                "src/fuzz/rust: external #[path] source fixture is not declared: "
                "src/shared/rust/fuzz.rs"
            ],
        )

    def test_raised_large_file_cap_needs_a_growth_reason(self) -> None:
        source = self.root / "src/example/rust/large.rs"
        source.write_text("line\n" * 2002, encoding="utf-8")
        policy = self.root / "large-files.toml"
        policy.write_text(
            """
[policy]
max_lines = 2000

[files."src/example/rust/large.rs"]
max_lines = 2003
baseline_max_lines = 2001
issue = "systemd-example"
reason = "Split the example."
""",
            encoding="utf-8",
        )
        failures: list[str] = []
        GATE.validate_large_rust_files(self.root, policy, failures)
        self.assertEqual(
            failures,
            ["src/example/rust/large.rs: raised debt cap needs an explicit growth_reason"],
        )

    def test_raised_large_file_cap_requires_an_unchanged_baseline(self) -> None:
        source = self.root / "src/example/rust/large.rs"
        source.write_text("line\n" * 2002, encoding="utf-8")
        policy = self.root / "large-files.toml"
        policy.write_text(
            """
[policy]
max_lines = 2000

[files."src/example/rust/large.rs"]
max_lines = 2003
previous_max_lines = 2001
issue = "systemd-example"
reason = "Split the example."
growth_reason = "An old rolling allowance."
""",
            encoding="utf-8",
        )
        failures: list[str] = []
        GATE.validate_large_rust_files(self.root, policy, failures)
        self.assertEqual(
            failures,
            ["src/example/rust/large.rs: growth_reason requires baseline_max_lines"],
        )

    def test_raised_large_file_cap_must_match_the_baseline_authority(self) -> None:
        source = self.root / "src/example/rust/large.rs"
        source.write_text("line\n" * 2002, encoding="utf-8")
        policy = self.root / "large-files.toml"
        policy.write_text(
            """
[policy]
max_lines = 2000

[files."src/example/rust/large.rs"]
max_lines = 2003
baseline_max_lines = 2001
issue = "systemd-example"
reason = "Split the example."
growth_reason = "The present audited source exceeds the original cap."
""",
            encoding="utf-8",
        )
        baseline = self.root / "baseline.toml"
        baseline.write_text(
            """
[files."src/example/rust/large.rs"]
max_lines = 2000
""",
            encoding="utf-8",
        )
        failures: list[str] = []
        GATE.validate_large_rust_files(self.root, policy, failures, baseline)
        self.assertEqual(
            failures,
            [
                "src/example/rust/large.rs: baseline_max_lines differs from "
                "the immutable baseline"
            ],
        )

    def test_chronological_module_name_is_rejected(self) -> None:
        chronological = self.root / "src/example/rust/shared_validators4.rs"
        chronological.write_text("// batch four\n", encoding="utf-8")
        failures: list[str] = []
        GATE.validate_module_names(self.root, failures)
        self.assertEqual(
            failures,
            [
                "src/example/rust/shared_validators4.rs: chronological Rust "
                "module name is forbidden; use a semantic owner or a focused directory"
            ],
        )

    def test_dependency_layers_allow_only_downward_internal_edges(self) -> None:
        manifests = {
            "src/foundation/rust": {"dependencies": {"substrate": "1"}},
            "src/substrate/rust": {"dependencies": {"foundation": "1"}},
            "src/application/rust": {"dependencies": {"foundation": "1"}},
        }
        members = {
            "substrate": "src/substrate/rust",
            "foundation": "src/foundation/rust",
            "application": "src/application/rust",
        }
        failures: list[str] = []
        GATE.validate_dependency_layers(
            manifests,
            members,
            "application",
            {"substrate": 0, "foundation": 1, "application": 2},
            {
                "src/substrate/rust": "substrate",
                "src/foundation/rust": "foundation",
            },
            failures,
        )
        self.assertEqual(
            failures,
            [
                "src/substrate/rust: layer substrate may not depend on "
                "src/foundation/rust in layer foundation"
            ],
        )

    def test_rust_2024_language_contract_is_required(self) -> None:
        failures: list[str] = []
        GATE.validate_language_contract(
            {"workspace": {"resolver": "2"}},
            {
                "src/old/rust": {"package": {"edition": "2021"}},
                "src/current/rust": {"package": {"edition": "2024"}},
            },
            failures,
        )
        self.assertEqual(
            failures,
            [
                "workspace.resolver must be '3' for the Rust 2024 workspace, got '2'",
                "src/old/rust: package.edition must be '2024', got '2021'",
            ],
        )

    def test_policy_rejects_duplicate_member_assignment(self) -> None:
        policy = self.root / "layers.toml"
        policy.write_text(
            """
[policy]
member_layout = "src/<subsystem>/rust"
default_layer = "application"

[layers.substrate]
rank = 0
members = ["src/example/rust"]

[layers.application]
rank = 1
members = ["src/example/rust"]
""",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "assigned to both layers"):
            GATE.load_layer_policy(policy)


if __name__ == "__main__":
    unittest.main()
