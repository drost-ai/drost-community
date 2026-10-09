import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import drost_ai.executor as executor
import drost_ai.engagements as engagements
from drost_ai.execution_tools import execute_bash, execute_python


class ExecutorTests(unittest.IsolatedAsyncioTestCase):
    async def test_arguments_are_not_shell_interpreted(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            marker = root / "injected"
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = await executor.execute_tool(
                    "printf",
                    ["%s", f"$(touch {marker})"],
                    engagement_id=engagement["engagement_id"],
                    working_directory=".",
                )
            self.assertTrue(result["success"])
            self.assertIn("$(touch", result["stdout"])
            self.assertFalse(marker.exists())

    async def test_working_directory_cannot_escape_workspace(self):
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

    async def test_output_is_not_truncated(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            payload = "x" * 200_000
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = await executor.execute_tool(
                    "python3",
                    ["-c", "print('x' * 200000, end='')"],
                    engagement_id=engagement["engagement_id"],
                )
            self.assertEqual(result["stdout"], payload)

    async def test_long_tool_does_not_block_another_call(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                engagement_id = engagement["engagement_id"]
                long_call = asyncio.create_task(
                    executor.execute_tool("sleep", ["30"], engagement_id=engagement_id)
                )
                await asyncio.sleep(0.05)
                quick = await asyncio.wait_for(
                    executor.execute_tool("printf", ["ready"], engagement_id=engagement_id),
                    timeout=1.0,
                )
                self.assertEqual(quick["stdout"], "ready")
                long_call.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await long_call

    async def test_cancellation_terminates_the_process_group(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                task = asyncio.create_task(
                    executor.execute_tool(
                        "python3",
                        [
                            "-c",
                            "import subprocess,time; subprocess.Popen(['sleep','30']); time.sleep(30)",
                        ],
                        engagement_id=engagement["engagement_id"],
                    )
                )
                await asyncio.sleep(0.1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=3.0)

    async def test_bash_supports_pipelines_stdin_and_environment(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = await execute_bash(
                    engagement["engagement_id"],
                    "read value; printf '%s:%s' \"$DROST_TEST\" \"$value\" | tr a-z A-Z",
                    stdin="input\n",
                    environment={"DROST_TEST": "ready"},
                )
                self.assertTrue(result["success"])
                self.assertEqual(result["stdout"], "READY:INPUT")

    async def test_python_supports_inline_and_workspace_files(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                engagement_id = engagement["engagement_id"]
                inline = await execute_python(
                    engagement_id,
                    source="import json,sys; print(json.dumps({'arg': sys.argv[1]}))",
                    script_arguments=["value"],
                )
                self.assertIn('"arg": "value"', inline["stdout"])
                script = Path(engagement["workspace"]) / "script.py"
                script.write_text("print('workspace-script')\n", encoding="utf-8")
                file_result = await execute_python(engagement_id, path="script.py")
                self.assertEqual(file_result["stdout"], "workspace-script\n")
                with self.assertRaises(ValueError):
                    await execute_python(engagement_id)


if __name__ == "__main__":
    unittest.main()
