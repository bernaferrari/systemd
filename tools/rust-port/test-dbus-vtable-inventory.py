#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Tests for the C-defined PID 1 D-Bus vtable inventory."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_tool():
    script = Path(__file__).with_name("dbus-vtable-inventory.py")
    spec = importlib.util.spec_from_file_location("dbus_vtable_inventory", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL = load_tool()


class DbusVtableInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.write(
            "src/core/meson.build",
            "libcore_sources = files(\n    'dbus-manager.c',\n)\n",
        )
        self.write(
            "src/core/dbus-manager.c",
            """const sd_bus_vtable bus_manager_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD(\"GetUnit\", \"s\", \"o\", method_get_unit, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD_WITH_ARGS(\"ListUnits\", SD_BUS_NO_ARGS, SD_BUS_RESULT(\"a(ss)\", units), method_list_units, 0),
    SD_BUS_METHOD_WITH_NAMES(\"SetTarget\", \"s\", \"target\", \"o\", \"job\", method_set_target, 0),
    SD_BUS_WRITABLE_PROPERTY(\"LogLevel\", \"s\", get_level, set_level, 0, 0),
    SD_BUS_SIGNAL_WITH_ARGS(\"Reloading\", SD_BUS_ARGS(\"b\", active), 0),
    BUS_PROPERTY_DUAL_TIMESTAMP(\"FinishTimestamp\", 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_VTABLE_END,
};

static const BusObjectImplementation manager_object = {
    \"/org/freedesktop/systemd1\",
    \"org.freedesktop.systemd1.Manager\",
    .vtables = BUS_VTABLES(bus_manager_vtable),
};

static const BusObjectImplementation fallback_object = {
    \"/org/freedesktop/systemd1/unit\",
    \"org.freedesktop.systemd1.Unit\",
    .fallback_vtables = BUS_FALLBACK_VTABLES({bus_manager_vtable, find_unit}),
};
""",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, contents: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def metadata_for(self, members: list[dict[str, object]]) -> Path:
        records = []
        for member in members:
            record = {
                field: member[field]
                for field in ("source", "vtable", "kind", "member", "input", "output", "bindings")
            }
            record.update(
                {
                    "authorization": "reviewed test policy",
                    "state_mutation": "reviewed test behavior",
                    "rust_owner": "test owner",
                    "transport": "test transport",
                    "status": "unsupported",
                }
            )
            records.append(record)
        path = self.root / "metadata.json"
        path.write_text(json.dumps({"schema": 1, "members": records}), encoding="utf-8")
        return path

    def test_extracts_signatures_bindings_and_helper_expansion(self) -> None:
        members = TOOL.inventory(self.root)
        self.assertEqual(len(members), 7)
        by_name = {member["member"]: member for member in members}
        self.assertEqual(by_name["GetUnit"]["input"], "s")
        self.assertEqual(by_name["GetUnit"]["output"], "o")
        self.assertEqual(by_name["ListUnits"]["output"], "a(ss)")
        self.assertEqual(by_name["SetTarget"]["input"], "s")
        self.assertEqual(by_name["SetTarget"]["output"], "o")
        self.assertEqual(by_name["LogLevel"]["kind"], "property")
        self.assertEqual(by_name["Reloading"]["output"], "b")
        self.assertEqual(by_name["FinishTimestamp"]["output"], "t")
        self.assertIn("FinishTimestampMonotonic", by_name)
        self.assertEqual(len(by_name["GetUnit"]["bindings"]), 2)
        self.assertIn(
            {"path": "/org/freedesktop/systemd1", "interface": "org.freedesktop.systemd1.Manager"},
            by_name["GetUnit"]["bindings"],
        )
        self.assertIn(
            {"path": "/org/freedesktop/systemd1/unit", "interface": "org.freedesktop.systemd1.Unit"},
            by_name["GetUnit"]["bindings"],
        )

    def test_metadata_signature_drift_is_rejected(self) -> None:
        members = TOOL.inventory(self.root)
        path = self.metadata_for(members)
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["members"][0]["input"] = "u"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "signature disagreement"):
            TOOL.apply_metadata(members, TOOL.load_metadata(path))

    def test_duplicate_metadata_is_rejected(self) -> None:
        members = TOOL.inventory(self.root)
        path = self.metadata_for(members)
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["members"].append(payload["members"][0])
        path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate metadata"):
            TOOL.load_metadata(path)

    def test_meson_profile_requires_configured_build_metadata(self) -> None:
        build = self.root / "build"
        with self.assertRaisesRegex(ValueError, "missing configured Meson profile"):
            TOOL.meson_profile(build)
        options = build / "meson-info/intro-buildoptions.json"
        options.parent.mkdir(parents=True)
        options.write_text(
            json.dumps(
                [
                    {"name": "mode", "value": "developer"},
                    {"name": "rust", "value": "enabled"},
                    {"name": "bpf-framework", "value": "disabled"},
                ]
            ),
            encoding="utf-8",
        )
        self.assertEqual(
            TOOL.meson_profile(build),
            {"bpf-framework": "disabled", "mode": "developer", "rust": "enabled"},
        )

    def test_repository_inventory_keeps_the_existing_shadow_subset_reviewed(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        members = TOOL.inventory(repository)
        _, unreviewed = TOOL.apply_metadata(
            members,
            TOOL.load_metadata(repository / TOOL.METADATA_NAME),
        )
        reviewed = len(members) - len(unreviewed)
        self.assertGreaterEqual(reviewed, 11)
        self.assertGreater(len(unreviewed), 0)


if __name__ == "__main__":
    unittest.main()
