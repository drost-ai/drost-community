from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import drost_ai.engagements as engagements
from drost_ai.workspace import delete_workspace_path, list_workspace, read_workspace_file, write_workspace_file


class EngagementTests(unittest.TestCase):
    def test_server_generates_persistent_random_engagement_ids(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                first = engagements.create_engagement("First", ["first.example"])
                second = engagements.create_engagement("Second", ["second.example"])

                self.assertRegex(first["engagement_id"], engagements.ENGAGEMENT_ID_PATTERN)
                self.assertNotEqual(first["engagement_id"], second["engagement_id"])
                self.assertEqual(
                    engagements.get_engagement(first["engagement_id"])["targets"],
                    ["first.example"],
                )
                listed = engagements.list_engagements()["engagements"]
                self.assertEqual({item["engagement_id"] for item in listed}, {first["engagement_id"], second["engagement_id"]})

    def test_workspace_operations_are_isolated_by_engagement(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            legacy = root / "chunks" / "prior.js"
            legacy.parent.mkdir(parents=True)
            legacy.write_text("legacy", encoding="utf-8")
            with patch.object(engagements, "WORKSPACE", root):
                first = engagements.create_engagement("First", ["first.example"])
                second = engagements.create_engagement("Second", ["second.example"])
                first_id = first["engagement_id"]
                second_id = second["engagement_id"]

                write_workspace_file(first_id, "chunks/result.txt", "first")
                write_workspace_file(second_id, "chunks/result.txt", "second")

                self.assertEqual(read_workspace_file(first_id, "chunks/result.txt")["content"], "first")
                self.assertEqual(read_workspace_file(second_id, "chunks/result.txt")["content"], "second")
                first_paths = {entry["path"] for entry in list_workspace(first_id, recursive=True)["entries"]}
                self.assertNotIn("chunks/prior.js", first_paths)
                self.assertEqual(legacy.read_text(encoding="utf-8"), "legacy")

                with self.assertRaises(ValueError):
                    write_workspace_file(first_id, "engagement.json", "{}")
                with self.assertRaises(ValueError):
                    delete_workspace_path(first_id, "engagement.json")

    def test_unknown_ids_and_cross_namespace_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                first = engagements.create_engagement("First", ["first.example"])
                second = engagements.create_engagement("Second", ["second.example"])
                with self.assertRaises(ValueError):
                    engagements.get_engagement("eng_20261009_00000000000000000000000000000000")
                with self.assertRaises(ValueError):
                    engagements.resolve_engagement_path(
                        first["engagement_id"],
                        second["workspace"],
                    )
                with self.assertRaises(ValueError):
                    engagements.resolve_engagement_path(
                        first["engagement_id"],
                        "../outside",
                        must_exist=False,
                    )


if __name__ == "__main__":
    unittest.main()
