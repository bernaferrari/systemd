#!/usr/bin/env python3
"""Static tests for Rust port drift reporting and sync metadata policy."""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


def load_script(filename: str, module_name: str):
    script = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DIFF_REPORT = load_script("diff-report.py", "rust_port_diff_report")
SYNC_GATE = load_script("sync-metadata-gate.py", "rust_port_sync_metadata")
STALE_CHECK = load_script("stale-check.py", "rust_port_stale_check_fixture")


class DiffReportTests(unittest.TestCase):
    def test_many_to_many_paths_report_authority_and_twin_sides(self) -> None:
        manifest = {
            "fixture": {
                "status": "in-progress",
                "c_paths": ["c/a.c", "c/a.h"],
                "rust_paths": ["rust/a.rs", "rust/core.rs"],
            }
        }
        report = DIFF_REPORT.get_module_touched(
            {"c/a.h", "rust/core.rs"}, manifest, []
        )
        self.assertEqual(report["mapped_count"], 1)
        self.assertEqual(report["sync_review_count"], 1)
        item = report["touched_modules"][0]
        self.assertEqual(item["upstream_touched"], ["c/a.h"])
        self.assertEqual(item["rust_touched"], ["rust/core.rs"])
        self.assertTrue(item["needs_sync_review"])
        self.assertTrue(item["rust_twin_changed"])

    def test_c_only_change_is_reported_as_needing_sync_review(self) -> None:
        manifest = {
            "fixture": {
                "c_file": "c/a.c,c/a.h",
                "rust_file": "rust/a.rs;rust/core.rs",
            }
        }
        report = DIFF_REPORT.get_module_touched({"c/a.c"}, manifest, [])
        item = report["touched_modules"][0]
        self.assertTrue(item["needs_sync_review"])
        self.assertFalse(item["rust_twin_changed"])
        self.assertIn("review the Rust twin", DIFF_REPORT.format_text(report))

    def test_mapping_schema_rejects_conflicts_and_non_normalized_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, "sets both"):
            DIFF_REPORT.c_file_paths(
                {"c_file": "c/a.c", "c_paths": ["c/a.c"]}, "fixture"
            )
        with self.assertRaisesRegex(ValueError, "non-normalized"):
            DIFF_REPORT.rust_file_paths(
                {"rust_paths": ["rust/../a.rs"]}, "fixture"
            )

    def test_new_child_inside_scope_requires_inventory_update(self) -> None:
        manifest = {
            "fixture": {
                "status": "in-progress",
                "scope": "basic.fixture",
                "c_file": "c/a.c",
                "rust_scope_paths": ["rust/a.rs", "rust/a"],
                "rust_paths": ["rust/a.rs", "rust/a/core.rs"],
            }
        }
        report = DIFF_REPORT.get_module_touched(
            {"rust/a/new_child.rs"}, manifest, []
        )
        self.assertEqual(report["inventory_review_count"], 1)
        self.assertEqual(
            report["touched_modules"][0]["scoped_unowned"],
            ["rust/a/new_child.rs"],
        )
        self.assertNotIn("rust/a/new_child.rs", report["unmapped"])
        self.assertIn("update exact rust_paths", DIFF_REPORT.format_text(report))

    def test_non_rust_child_inside_scope_stays_unmapped(self) -> None:
        manifest = {
            "fixture": {
                "status": "in-progress",
                "scope": "basic.fixture",
                "c_file": "c/a.c",
                "rust_scope_paths": ["rust/a"],
                "rust_paths": ["rust/a/core.rs"],
            }
        }
        report = DIFF_REPORT.get_module_touched({"rust/a/README.md"}, manifest, [])
        self.assertEqual(report["inventory_review_count"], 0)
        self.assertEqual(report["unmapped"], ["rust/a/README.md"])


class SyncMetadataGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        for relative, contents in {
            "c/a.c": "int a;\n",
            "rust/a.rs": "// PORT-SYNC: c/a.c\npub const A: i32 = 1;\n",
            "rust/gap.rs": "// PORT-GAP: current C authority is unknown\n",
            "rust/scoped.rs": (
                "// PORT-SYNC: scope=basic.scoped; authority=c/a.c\n"
                "pub const SCOPED: i32 = 1;\n"
            ),
        }.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def audit(self, manifest):
        return SYNC_GATE.audit_manifest(self.root, manifest, STALE_CHECK)[0]

    def test_in_progress_sync_and_explicit_gap_are_truthful(self) -> None:
        failures = self.audit(
            {
                "mapped": {
                    "status": "in-progress",
                    "sync_status": "needs_review",
                    "c_file": "c/a.c",
                    "rust_file": "rust/a.rs",
                },
                "gap": {
                    "status": "todo",
                    "sync_status": "needs_review",
                    "rust_file": "rust/gap.rs",
                },
            }
        )
        self.assertEqual(failures, [])

    def test_synced_and_sticky_claims_require_reviewed_anchors(self) -> None:
        manifest = {
            "fixture": {
                "status": "shadow",
                "sync_status": "synced",
                "c_file": "c/a.c",
                "rust_file": "rust/a.rs",
            }
        }
        failures = self.audit(manifest)
        self.assertTrue(any("sync_status=synced requires" in item for item in failures))
        self.assertTrue(any("missing per-path upstream" in item for item in failures))
        self.assertTrue(any("missing per-path rust" in item for item in failures))

    def test_marker_must_be_in_the_source_preamble(self) -> None:
        source = self.root / "rust/a.rs"
        source.write_text(
            "pub const A: i32 = 1;\n" + "\n" * 16 + "// PORT-SYNC: c/a.c\n",
            encoding="utf-8",
        )
        failures = self.audit(
            {
                "fixture": {
                    "status": "in-progress",
                    "c_file": "c/a.c",
                    "rust_file": "rust/a.rs",
                }
            }
        )
        self.assertTrue(any("first 16 lines" in item for item in failures))

    def test_scoped_marker_must_match_the_manifest_owner(self) -> None:
        entry = {
            "status": "in-progress",
            "sync_status": "needs_review",
            "scope": "basic.scoped",
            "contract_file": "tools/rust-port/contracts/basic/scoped.toml",
            "c_file": "c/a.c",
            "rust_scope_paths": ["rust/scoped.rs"],
            "rust_paths": ["rust/scoped.rs"],
        }
        self.assertEqual(self.audit({"fixture": entry}), [])

        source = self.root / "rust/scoped.rs"
        source.write_text(
            "// PORT-SYNC: scope=basic.someone-else; authority=c/a.c\n",
            encoding="utf-8",
        )
        failures = self.audit({"fixture": entry})
        self.assertTrue(
            any(
                "declares scope=basic.someone-else" in item
                and "scope=basic.scoped" in item
                for item in failures
            )
        )

    def test_scoped_owner_requires_a_behavior_contract(self) -> None:
        failures = self.audit(
            {
                "fixture": {
                    "status": "in-progress",
                    "sync_status": "needs_review",
                    "scope": "basic.scoped",
                    "c_file": "c/a.c",
                    "rust_scope_paths": ["rust/scoped.rs"],
                    "rust_paths": ["rust/scoped.rs"],
                }
            }
        )
        self.assertTrue(any("requires a contract_file" in item for item in failures))

    def test_scoped_marker_authority_must_be_mapped(self) -> None:
        entry = {
            "status": "in-progress",
            "sync_status": "needs_review",
            "scope": "basic.scoped",
            "contract_file": "tools/rust-port/contracts/basic/scoped.toml",
            "c_file": "c/a.c",
            "rust_scope_paths": ["rust/scoped.rs"],
            "rust_paths": ["rust/scoped.rs"],
        }
        source = self.root / "rust/scoped.rs"
        source.write_text(
            "// PORT-SYNC: scope=basic.scoped; authority=c/not-mapped.c\n",
            encoding="utf-8",
        )
        failures = self.audit({"fixture": entry})
        self.assertTrue(
            any(
                "declares unmapped PORT-SYNC authority c/not-mapped.c" in item
                for item in failures
            )
        )

    def test_partial_sync_status_requires_scoped_review_provenance(self) -> None:
        failures = self.audit(
            {
                "fixture": {
                    "status": "in-progress",
                    "sync_status": "partial",
                    "c_file": "c/a.c",
                    "rust_file": "rust/a.rs",
                }
            }
        )
        self.assertTrue(
            any(
                "requires scoped ownership and a behavior contract" in item
                for item in failures
            )
        )


if __name__ == "__main__":
    unittest.main()
