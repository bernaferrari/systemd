#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("unit-directive-inventory.py")
SPEC = importlib.util.spec_from_file_location("unit_directive_inventory", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class UnitDirectiveInventoryTest(unittest.TestCase):
    def test_inventory_uses_generated_rows_and_profile_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            metadata = build / "meson-info"
            metadata.mkdir(parents=True)
            (metadata / "intro-buildoptions.json").write_text(
                json.dumps([{"name": "b_lto", "value": False}, {"name": "tests", "value": True}]),
                encoding="utf-8",
            )
            generated = root / "load-fragment-gperf.c"
            generated.write_text(
                '  {"Unit.Description", config_parse_string, 0, NULL},\n'
                '  {"Service.ExecStart", config_parse_exec, 0, NULL},\n',
                encoding="utf-8",
            )

            result = MODULE.inventory(generated, build)

        self.assertEqual([row["key"] for row in result["rows"]], ["ExecStart", "Description"])
        self.assertTrue(result["meson_profile"]["fingerprint"])
        self.assertEqual(result["rows"][0]["feature_predicate"].split(":", 1)[0], "enabled-in-profile")

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


if __name__ == "__main__":
    unittest.main()
