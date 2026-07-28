#!/usr/bin/env python3
"""Static schema tests for stale-check's many-to-many source authority."""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("stale-check.py")
SPEC = importlib.util.spec_from_file_location("stale_check", SCRIPT)
assert SPEC and SPEC.loader
STALE_CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STALE_CHECK)


class StaleCheckSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        subprocess.run(
            ["git", "init", "-q", str(self.root)],
            check=True,
            text=True,
        )
        for relative, contents in {
            "c/a.c": "int a;\n",
            "c/a.h": "#define A 1\n",
            "rust/a.rs": "pub const A: i32 = 1;\n",
            "rust/lib.rs": "pub mod a;\n",
            "rust/scoped.rs": "pub mod scoped;\n",
            "rust/scoped/child.rs": "pub const CHILD: i32 = 1;\n",
            "rust/abi.h": "int rs_scoped(void);\n",
        }.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def blob(self, relative: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.root), "hash-object", "--", relative],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()

    def evaluate(self, entry: dict[str, object], *, strict: bool = True):
        return STALE_CHECK.evaluate_module(
            "fixture",
            entry,
            self.root,
            strict=strict,
            warn_missing=False,
        )

    def test_manifest_loader_rejects_non_table_and_empty_roots(self) -> None:
        manifest = self.root / "map.toml"
        for contents, expected in (
            ("", "manifest root"),
            ("schema = 1\n", "must all be TOML tables"),
        ):
            with self.subTest(contents=contents):
                manifest.write_text(contents, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, expected):
                    STALE_CHECK.load_manifest(manifest)

    def scoped_entry(self) -> dict[str, object]:
        return {
            "status": "in-progress",
            "scope": "basic.scoped",
            "c_paths": ["c/a.c", "c/a.h"],
            "rust_scope_paths": ["rust/scoped.rs", "rust/scoped"],
            "rust_interface_paths": ["rust/abi.h"],
            "rust_paths": [
                "rust/abi.h",
                "rust/scoped.rs",
                "rust/scoped/child.rs",
            ],
            "c_provenance_edges": [
                {
                    "kind": "direct",
                    "path": "c/a.c",
                    "rust_paths": [
                        "rust/abi.h",
                        "rust/scoped.rs",
                        "rust/scoped/child.rs",
                    ],
                },
                {
                    "kind": "direct",
                    "path": "c/a.h",
                    "rust_paths": [
                        "rust/abi.h",
                        "rust/scoped.rs",
                        "rust/scoped/child.rs",
                    ],
                },
            ],
        }

    def test_one_to_one_legacy_blob_fields_remain_compatible(self) -> None:
        result = self.evaluate(
            {
                "status": "done",
                "c_file": "c/a.c",
                "rust_file": "rust/a.rs",
                "last_synced_upstream_blob": self.blob("c/a.c"),
                "last_synced_rust_blob": self.blob("rust/a.rs"),
            }
        )
        self.assertFalse(result["stale"])
        self.assertTrue(result["fully_anchored"])

    def test_many_to_many_legacy_paths_require_exact_per_path_tables(self) -> None:
        result = self.evaluate(
            {
                "status": "replace",
                "c_file": "c/a.c,c/a.h",
                "rust_file": "rust/a.rs;rust/lib.rs",
                "last_synced_upstream_blobs": {
                    "c/a.c": self.blob("c/a.c"),
                    "c/a.h": self.blob("c/a.h"),
                },
                "last_synced_rust_blobs": {
                    "rust/a.rs": self.blob("rust/a.rs"),
                    "rust/lib.rs": self.blob("rust/lib.rs"),
                },
            }
        )
        self.assertFalse(result["stale"])
        self.assertTrue(result["fully_anchored"])
        self.assertEqual(result["rust_file"], ["rust/a.rs", "rust/lib.rs"])

    def test_drift_is_attributed_to_the_exact_path(self) -> None:
        entry = {
            "status": "done",
            "c_file": "c/a.c",
            "rust_file": "rust/a.rs",
            "last_synced_upstream_blob": self.blob("c/a.c"),
            "last_synced_rust_blob": self.blob("rust/a.rs"),
        }
        (self.root / "rust/a.rs").write_text("pub const A: i32 = 2;\n")
        result = self.evaluate(entry)
        self.assertTrue(result["stale"])
        self.assertTrue(
            any("rust drift in rust/a.rs" in reason for reason in result["reasons"])
        )

    def test_singular_anchor_cannot_claim_multiple_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot anchor 2 paths"):
            self.evaluate(
                {
                    "status": "done",
                    "c_file": "c/a.c,c/a.h",
                    "rust_file": "rust/a.rs",
                    "last_synced_upstream_blob": self.blob("c/a.c"),
                    "last_synced_rust_blob": self.blob("rust/a.rs"),
                }
            )

    def test_anchor_table_must_exactly_cover_mapping(self) -> None:
        for anchors, expected in (
            ({"c/a.c": self.blob("c/a.c")}, "missing c/a.h"),
            (
                {
                    "c/a.c": self.blob("c/a.c"),
                    "c/a.h": self.blob("c/a.h"),
                    "c/extra.c": "deadbeef",
                },
                "extra c/extra.c",
            ),
        ):
            with self.subTest(anchors=anchors):
                with self.assertRaisesRegex(ValueError, expected):
                    self.evaluate(
                        {
                            "status": "done",
                            "c_paths": ["c/a.c", "c/a.h"],
                            "rust_file": "rust/a.rs",
                            "last_synced_upstream_blobs": anchors,
                            "last_synced_rust_blob": self.blob("rust/a.rs"),
                        }
                    )

    def test_duplicate_paths_and_conflicting_anchor_forms_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate paths"):
            self.evaluate(
                {
                    "status": "done",
                    "c_paths": ["c/a.c", "c/a.c"],
                    "rust_file": "rust/a.rs",
                }
            )
        with self.assertRaisesRegex(ValueError, "sets both"):
            self.evaluate(
                {
                    "status": "done",
                    "c_file": "c/a.c",
                    "rust_file": "rust/a.rs",
                    "last_synced_upstream_blob": self.blob("c/a.c"),
                    "last_synced_upstream_blobs": {
                        "c/a.c": self.blob("c/a.c"),
                    },
                }
            )

    def test_conflicting_or_non_repository_source_paths_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "sets both c_file and c_paths"):
            self.evaluate(
                {
                    "status": "in-progress",
                    "c_file": "c/a.c",
                    "c_paths": ["c/a.c"],
                    "rust_file": "rust/a.rs",
                }
            )
        for invalid in ("/etc/passwd", "../outside.c", "c/./a.c", r"c\\a.c"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "non-normalized"):
                    self.evaluate(
                        {
                            "status": "in-progress",
                            "c_paths": [invalid],
                            "rust_file": "rust/a.rs",
                        }
                    )

    def test_strict_mode_requires_anchors_only_for_sticky_states(self) -> None:
        sticky = self.evaluate(
            {
                "status": "shadow",
                "c_file": "c/a.c",
                "rust_file": "rust/a.rs",
            }
        )
        self.assertTrue(sticky["stale"])
        self.assertEqual(len(sticky["reasons"]), 2)

        in_progress = self.evaluate(
            {
                "status": "in-progress",
                "c_file": "c/a.c",
                "rust_file": "rust/a.rs",
            }
        )
        self.assertFalse(in_progress["stale"])
        self.assertFalse(in_progress["fully_anchored"])

    def test_existing_path_diagnostic_can_audit_unanchored_work(self) -> None:
        entry = {
            "status": "in-progress",
            "c_file": "c/missing.c",
            "rust_file": "rust/a.rs",
        }
        self.assertFalse(self.evaluate(entry, strict=False)["stale"])
        diagnostic = STALE_CHECK.evaluate_module(
            "fixture",
            entry,
            self.root,
            strict=False,
            warn_missing=False,
            require_existing=True,
        )
        self.assertTrue(diagnostic["stale"])
        self.assertTrue(
            any("c/missing.c" in reason for reason in diagnostic["reasons"])
        )

    def test_existing_path_diagnostic_checks_every_multi_source_path(self) -> None:
        entry = {
            "status": "in-progress",
            "c_paths": ["c/a.c", "c/missing.h"],
            "rust_file": "rust/a.rs",
        }
        diagnostic = STALE_CHECK.evaluate_module(
            "fixture",
            entry,
            self.root,
            strict=False,
            warn_missing=False,
            require_existing=True,
        )
        self.assertTrue(diagnostic["stale"])
        self.assertEqual(
            [reason for reason in diagnostic["reasons"] if "missing path" in reason],
            ["missing path c/missing.h"],
        )

    def test_scoped_inventory_requires_every_rust_leaf_and_interface(self) -> None:
        entry = self.scoped_entry()
        result = self.evaluate(entry)
        self.assertFalse(result["stale"])

        entry["rust_paths"] = ["rust/scoped.rs", "rust/abi.h"]
        with self.assertRaisesRegex(
            ValueError, "must exactly match scoped Rust inventory.*rust/scoped/child.rs"
        ):
            self.evaluate(entry)

        entry = self.scoped_entry()
        entry["rust_paths"] = [
            "rust/scoped.rs",
            "rust/scoped/child.rs",
        ]
        with self.assertRaisesRegex(
            ValueError, "must exactly match scoped Rust inventory.*rust/abi.h"
        ):
            self.evaluate(entry)

    def test_scoped_provenance_must_cover_every_c_path_and_rust_leaf(self) -> None:
        entry = self.scoped_entry()
        entry["c_provenance_edges"] = entry["c_provenance_edges"][:1]
        with self.assertRaisesRegex(ValueError, "lacks C paths: c/a.h"):
            self.evaluate(entry)

        entry = self.scoped_entry()
        entry["c_provenance_edges"][0]["rust_paths"] = ["rust/scoped.rs"]
        entry["c_provenance_edges"][1]["rust_paths"] = ["rust/scoped.rs"]
        with self.assertRaisesRegex(ValueError, "lacks direct authority for Rust leaves"):
            self.evaluate(entry)

    def test_scoped_transitive_provenance_requires_direct_route_and_rationale(self) -> None:
        entry = self.scoped_entry()
        entry["c_paths"].append("c/transitive.c")
        transitive = {
            "kind": "transitive",
            "path": "c/transitive.c",
            "via": ["c/not-direct.c"],
            "rationale": "fixture closure",
        }
        entry["c_provenance_edges"].append(transitive)
        with self.assertRaisesRegex(ValueError, "does not route through a direct C path"):
            self.evaluate(entry)

        transitive["via"] = ["c/a.c"]
        del transitive["rationale"]
        with self.assertRaisesRegex(ValueError, "rationale must explain"):
            self.evaluate(entry)

    def test_scoped_inventory_rejects_overlapping_roots(self) -> None:
        entry = self.scoped_entry()
        entry["rust_scope_paths"] = ["rust/scoped", "rust/scoped/child.rs"]
        with self.assertRaisesRegex(ValueError, "rust_scope_paths overlap"):
            self.evaluate(entry)

    def test_scoped_inventory_detects_a_new_rust_child(self) -> None:
        entry = self.scoped_entry()
        added = self.root / "rust/scoped/new_child.rs"
        added.write_text("pub const NEW_CHILD: i32 = 1;\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError, "must exactly match scoped Rust inventory.*new_child.rs"
        ):
            self.evaluate(entry)

    def test_scoped_review_snapshots_are_distinct_from_synced_parity(self) -> None:
        entry = self.scoped_entry()
        entry["last_reviewed_upstream_blobs"] = {
            "c/a.c": self.blob("c/a.c"),
            "c/a.h": self.blob("c/a.h"),
        }
        entry["last_reviewed_rust_blobs"] = {
            path: self.blob(path)
            for path in entry["rust_paths"]
        }
        result = self.evaluate(entry)
        self.assertFalse(result["stale"])
        self.assertFalse(result["fully_anchored"])
        self.assertTrue(result["fully_reviewed"])

        (self.root / "rust/scoped/child.rs").write_text(
            "pub const CHILD: i32 = 2;\n", encoding="utf-8"
        )
        result = self.evaluate(entry)
        self.assertTrue(result["stale"])
        self.assertTrue(
            any(
                "reviewed rust drift in rust/scoped/child.rs" in reason
                for reason in result["reasons"]
            )
        )

    def test_reviewed_upstream_snapshot_detects_c_drift(self) -> None:
        entry = self.scoped_entry()
        entry["last_reviewed_upstream_blobs"] = {
            "c/a.c": self.blob("c/a.c"),
            "c/a.h": self.blob("c/a.h"),
        }
        (self.root / "c/a.h").write_text("#define A 2\n", encoding="utf-8")
        result = self.evaluate(entry)
        self.assertTrue(result["stale"])
        self.assertTrue(
            any(
                "reviewed upstream drift in c/a.h" in reason
                for reason in result["reasons"]
            )
        )

    def test_scope_requires_a_name_and_scope_paths(self) -> None:
        entry = self.scoped_entry()
        del entry["scope"]
        with self.assertRaisesRegex(ValueError, "without a scope name"):
            self.evaluate(entry)

        entry = self.scoped_entry()
        del entry["rust_scope_paths"]
        with self.assertRaisesRegex(ValueError, "requires rust_scope_paths"):
            self.evaluate(entry)

    def test_manifest_rejects_duplicate_scope_names(self) -> None:
        first = self.scoped_entry()
        second = self.scoped_entry()
        second["rust_scope_paths"] = "rust/a.rs"
        del second["rust_interface_paths"]
        second["rust_paths"] = ["rust/a.rs"]
        for edge in second["c_provenance_edges"]:
            edge["rust_paths"] = ["rust/a.rs"]
        with self.assertRaisesRegex(ValueError, "duplicate scope name 'basic.scoped'"):
            STALE_CHECK.validate_manifest(
                {"first": first, "second": second}, self.root
            )

    def test_manifest_rejects_duplicate_scoped_rust_ownership(self) -> None:
        first = self.scoped_entry()
        second = self.scoped_entry()
        second["scope"] = "basic.scoped-second"
        second["rust_scope_paths"] = "rust/scoped.rs"
        second["rust_interface_paths"] = ["rust/abi.h"]
        second["rust_paths"] = ["rust/scoped.rs", "rust/abi.h"]
        for edge in second["c_provenance_edges"]:
            edge["rust_paths"] = ["rust/scoped.rs", "rust/abi.h"]
        with self.assertRaisesRegex(
            ValueError, "duplicate scoped Rust ownership for rust/abi.h"
        ):
            STALE_CHECK.validate_manifest(
                {"first": first, "second": second}, self.root
            )

    def test_manifest_rejects_scoped_ownership_hidden_by_legacy_entry(self) -> None:
        scoped = self.scoped_entry()
        legacy = {
            "status": "in-progress",
            "c_file": "c/a.c",
            "rust_file": "rust/scoped/child.rs",
        }
        with self.assertRaisesRegex(
            ValueError,
            "duplicate scoped Rust ownership for rust/scoped/child.rs",
        ):
            STALE_CHECK.validate_manifest(
                {"scoped": scoped, "legacy": legacy},
                self.root,
            )

    def test_scope_name_must_be_a_normalized_identifier(self) -> None:
        for invalid in (" basic.scoped", "basic scoped", "basic/scoped"):
            entry = self.scoped_entry()
            entry["scope"] = invalid
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    ValueError,
                    "normalized scope identifier",
                ):
                    self.evaluate(entry)


if __name__ == "__main__":
    unittest.main()
