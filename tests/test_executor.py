import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import drost_ai.executor as executor


class ExecutorTests(unittest.TestCase):
    def test_arguments_are_not_shell_interpreted(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            marker = root / "injected"
            with patch.object(executor, "WORKSPACE", root):
                result = executor.execute_tool(
                    "printf",
                    ["%s", f"$(touch {marker})"],
                    working_directory=".",
                )
            self.assertTrue(result["success"])
            self.assertIn("$(touch", result["stdout"])
            self.assertFalse(marker.exists())

    def test_working_directory_cannot_escape_workspace(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(executor, "WORKSPACE", root):
                with self.assertRaises(ValueError):
                    executor.resolve_workspace_path("../outside", must_exist=False)

    def test_output_is_not_truncated(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            payload = "x" * 200_000
            with patch.object(executor, "WORKSPACE", root):
                result = executor.execute_tool("printf", ["%s", payload])
            self.assertEqual(result["stdout"], payload)


if __name__ == "__main__":
    unittest.main()
