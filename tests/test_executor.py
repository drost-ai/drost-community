import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import drost_ai.executor as executor
import drost_ai.engagements as engagements


class ExecutorTests(unittest.TestCase):
    def test_arguments_are_not_shell_interpreted(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            marker = root / "injected"
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = executor.execute_tool(
                    "printf",
                    ["%s", f"$(touch {marker})"],
                    engagement_id=engagement["engagement_id"],
                    working_directory=".",
                )
            self.assertTrue(result["success"])
            self.assertIn("$(touch", result["stdout"])
            self.assertFalse(marker.exists())

    def test_working_directory_cannot_escape_workspace(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                with self.assertRaises(ValueError):
                    engagements.resolve_engagement_path(
                        engagement["engagement_id"],
                        "../outside",
                        must_exist=False,
                    )

    def test_output_is_not_truncated(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            payload = "x" * 200_000
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = executor.execute_tool(
                    "printf",
                    ["%s", payload],
                    engagement_id=engagement["engagement_id"],
                )
            self.assertEqual(result["stdout"], payload)


if __name__ == "__main__":
    unittest.main()
