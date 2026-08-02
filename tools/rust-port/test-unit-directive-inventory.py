#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("unit-directive-inventory.py")
SPEC = importlib.util.spec_from_file_location("unit_directive_inventory", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class UnitDirectiveInventoryTest(unittest.TestCase):
    def write_profile(self, root: Path) -> tuple[Path, Path]:
        build = root / "build"
        profile = build / "meson-info" / "intro-buildoptions.json"
        profile.parent.mkdir(parents=True)
        profile.write_text(
            json.dumps([{"name": "b_lto", "value": False}, {"name": "tests", "value": True}]),
            encoding="utf-8",
        )
        generated = root / "load-fragment-gperf.c"
        generated.write_text(
            '  {"Unit.Description", config_parse_string, 0, NULL},\n'
            '  {"Service.ExecStart", config_parse_exec, 0, NULL},\n',
            encoding="utf-8",
        )
        return generated, build

    def write_metadata(
        self,
        root: Path,
        consumers: list[dict[str, str]],
        profile_fingerprint: str | None = None,
    ) -> Path:
        path = root / "parser-consumers.json"
        path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "profiles": (
                        []
                        if profile_fingerprint is None
                        else [
                            {
                                "profile_fingerprint": profile_fingerprint,
                                "consumers": consumers,
                            }
                        ]
                    ),
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_inventory_uses_generated_rows_profile_and_conservative_statuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated, build = self.write_profile(root)
            consumers = self.write_metadata(
                root,
                [
                    {
                        "section": "Unit",
                        "key": "Description",
                        "consumer": "UnitFileInfo.description",
                    }
                ],
                str(MODULE.profile(build)["fingerprint"]),
            )

            result = MODULE.inventory(generated, build, consumers)

        self.assertEqual([row["key"] for row in result["rows"]], ["ExecStart", "Description"])
        self.assertTrue(result["meson_profile"]["fingerprint"])
        self.assertEqual(result["rows"][0]["feature_predicate"].split(":", 1)[0], "enabled-in-profile")
        self.assertEqual(result["rows"][0]["rust_status"], "recognized-but-unconsumed")
        self.assertEqual(result["rows"][1]["rust_status"], "recognized-and-stored")
        self.assertEqual(result["rows"][1]["consumer"], "UnitFileInfo.description")
        self.assertTrue(
            all(row["rust_status"] in MODULE.CONSERVATIVE_STATUSES for row in result["rows"])
        )

    def test_duplicate_generated_rows_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            generated = Path(temporary) / "load-fragment-gperf.c"
            generated.write_text(
                ' {"Unit.Description", callback, 0, NULL},\n'
                ' {"Unit.Description", callback, 0, NULL},\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate C directive"):
                MODULE.parse_c_table(generated, "profile")

    def test_missing_parser_consumer_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = self.write_metadata(
                root,
                [{"section": "Unit", "key": "Description"}],
                "profile",
            )
            with self.assertRaisesRegex(ValueError, "misses consumer for Unit.Description"):
                MODULE.load_parser_consumers(metadata, "profile")

    def test_duplicate_parser_consumer_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = {
                "section": "Unit",
                "key": "Description",
                "consumer": "UnitFileInfo.description",
            }
            metadata = self.write_metadata(root, [consumer, consumer], "profile")
            with self.assertRaisesRegex(ValueError, "duplicate parser-consumer metadata"):
                MODULE.load_parser_consumers(metadata, "profile")

    def test_stale_parser_consumer_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated, build = self.write_profile(root)
            metadata = self.write_metadata(root, [], "stale-profile")
            with self.assertRaisesRegex(ValueError, "stale parser-consumer metadata profile"):
                MODULE.inventory(generated, build, metadata)

    def test_rust_only_directive_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated, build = self.write_profile(root)
            metadata = self.write_metadata(root, [])
            parser = root / "unit_file.rs"
            parser.write_text(
                '("unit", "Description" | "RustOnly") => {}\n'
                '("service", "ExecStart") => {}\n',
                encoding="utf-8",
            )
            with patch.object(MODULE, "RUST_PARSER", parser):
                result = MODULE.inventory(generated, build, metadata)

        self.assertEqual(result["unmatched_rust_directives"], ["unit.RustOnly"])


if __name__ == "__main__":
    unittest.main()
