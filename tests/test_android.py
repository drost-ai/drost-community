from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from drost_ai.android_cli import (
    _error_detail,
    _parse_devices,
    _resolve_launcher_activity,
    build_parser,
    resolve_serial,
    state_dir,
)
from drost_ai.android_scan import (
    _attr,
    _components,
    _declared_permissions,
    _deep_links,
    _main_activity,
)
from drost_ai.catalog import CATALOG, TOOL_GROUPS


ROOT = Path(__file__).resolve().parents[1]
ANDROID_NS = "http://schemas.android.com/apk/res/android"
MANIFEST = f"""<manifest xmlns:android="{ANDROID_NS}" package="com.example.app">
  <uses-permission android:name="android.permission.INTERNET"/>
  <permission android:name="com.example.permission.SYNC" android:protectionLevel="signature"/>
  <application android:debuggable="true" android:allowBackup="false">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
        <data android:scheme="https" android:host="example.com" android:pathPrefix="/open"/>
      </intent-filter>
    </activity>
    <service android:name=".SyncService" android:permission="com.example.permission.SYNC"/>
  </application>
</manifest>"""


class AndroidCatalogTests(unittest.TestCase):
    def test_android_tool_is_cataloged_as_an_executable(self) -> None:
        specs = {spec.name: spec for spec in CATALOG}
        self.assertIn("drost_android", specs)
        spec = specs["drost_android"]
        self.assertEqual(spec.executable, "drost-android")
        self.assertEqual(spec.category, "android")
        self.assertIn("Android", spec.description)

    def test_android_group_contains_one_executable(self) -> None:
        self.assertEqual(TOOL_GROUPS["android"], (("android", "drost-android"),))

    def test_license_policy_requires_android_notices(self) -> None:
        policy = json.loads((ROOT / "compliance" / "license-policy.json").read_text(encoding="utf-8"))
        names = {entry["name"] for entry in policy["notice_required_components"]}
        self.assertTrue(
            {"apktool", "jadx", "frida", "frida-tools", "objection", "androguard"}.issubset(names)
        )


class AndroidCliTests(unittest.TestCase):
    def test_parser_uses_the_android_command_name(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.prog, "drost-android")
        args = parser.parse_args(["proxy", "start", "--port", "9090"])
        self.assertEqual(args.command, "proxy")
        self.assertEqual(args.action, "start")
        self.assertEqual(args.port, 9090)

    def test_device_parser_keeps_serial_and_properties(self) -> None:
        devices = _parse_devices(
            "List of devices attached\n"
            "emulator-5554\tdevice product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 "
            "device:emu64a transport_id:1\n"
            "192.0.2.10:5555\tunauthorized\n"
        )
        self.assertEqual(
            devices[0],
            {
                "serial": "emulator-5554",
                "state": "device",
                "product": "sdk_gphone64_arm64",
                "model": "sdk_gphone64_arm64",
                "device": "emu64a",
                "transport_id": "1",
            },
        )
        self.assertEqual(devices[1], {"serial": "192.0.2.10:5555", "state": "unauthorized"})

    def test_explicit_and_environment_serials_are_honored(self) -> None:
        self.assertEqual(resolve_serial("emulator-5554"), "emulator-5554")
        with patch.dict(os.environ, {"DROST_ANDROID_SERIAL": "192.0.2.10:5555"}, clear=False):
            self.assertEqual(resolve_serial(), "192.0.2.10:5555")

    def test_state_directory_can_be_configured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"DROST_ANDROID_STATE": directory}, clear=False):
                self.assertEqual(state_dir(), Path(directory))

    def test_error_detail_prefers_error_lines(self) -> None:
        result = subprocess.CompletedProcess(
            ["demo"],
            1,
            stdout="ok\nError: boom\n",
            stderr="warning\nERROR: bad\n",
        )
        detail = _error_detail(result)
        self.assertIn("Error: boom", detail)
        self.assertIn("ERROR: bad", detail)
        self.assertNotIn("warning", detail)

    def test_error_detail_falls_back_to_the_tail(self) -> None:
        result = subprocess.CompletedProcess(["demo"], 1, stdout="hello\n", stderr="")
        self.assertEqual(_error_detail(result), "hello")

    def test_launcher_activity_resolution_returns_the_component(self) -> None:
        result = subprocess.CompletedProcess(
            ["adb"],
            0,
            stdout=(
                "priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true\n"
                "com.example.app/.MainActivity\n"
            ),
            stderr="",
        )
        with patch("drost_ai.android_cli._adb", return_value=result):
            self.assertEqual(
                _resolve_launcher_activity("serial", "com.example.app"),
                "com.example.app/.MainActivity",
            )

    def test_launcher_activity_resolution_returns_none_without_a_component(self) -> None:
        result = subprocess.CompletedProcess(["adb"], 0, stdout="No activity found\n", stderr="")
        with patch("drost_ai.android_cli._adb", return_value=result):
            self.assertIsNone(_resolve_launcher_activity("serial", "com.example.app"))


class AndroidManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = ET.fromstring(MANIFEST)
        self.application = self.manifest.find("application")
        self.activities = _components(self.application, "activity")
        self.services = _components(self.application, "service")

    def test_components_and_intent_filters_are_parsed(self) -> None:
        activity = self.activities[0]
        self.assertEqual(activity["name"], ".MainActivity")
        self.assertEqual(activity["exported"], "true")
        self.assertTrue(activity["exported_declared"])
        self.assertTrue(activity["effectively_exported"])
        self.assertIsNone(activity["permission"])
        self.assertEqual(len(activity["intent_filters"]), 1)
        intent_filter = activity["intent_filters"][0]
        self.assertIn("android.intent.action.MAIN", intent_filter["actions"])
        self.assertIn("android.intent.category.LAUNCHER", intent_filter["categories"])
        self.assertEqual(
            intent_filter["data"],
            [{"scheme": "https", "host": "example.com", "pathPrefix": "/open"}],
        )

    def test_components_without_an_exported_flag_and_filters_are_not_exported(self) -> None:
        service = self.services[0]
        self.assertEqual(service["name"], ".SyncService")
        self.assertIsNone(service["exported"])
        self.assertFalse(service["exported_declared"])
        self.assertFalse(service["effectively_exported"])
        self.assertEqual(service["permission"], "com.example.permission.SYNC")

    def test_main_activity_and_deep_links_are_discovered(self) -> None:
        self.assertEqual(_main_activity(self.activities), ".MainActivity")
        self.assertEqual(
            _deep_links(self.activities, "activity"),
            [
                {
                    "component": ".MainActivity",
                    "kind": "activity",
                    "scheme": "https",
                    "host": "example.com",
                    "pathPrefix": "/open",
                }
            ],
        )

    def test_declared_permissions_and_missing_attributes(self) -> None:
        self.assertEqual(
            _declared_permissions(self.manifest),
            [
                {
                    "kind": "permission",
                    "name": "com.example.permission.SYNC",
                    "protection_level": "signature",
                }
            ],
        )
        self.assertIsNone(_attr(None, "name"))
        self.assertEqual(_components(None, "activity"), [])


if __name__ == "__main__":
    unittest.main()
