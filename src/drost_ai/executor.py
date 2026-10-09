"""Safe direct executable runner for Drost MCP tools."""

from __future__ import annotations

import asyncio
import os
import signal
import shutil
from typing import Any, Sequence

from .engagements import resolve_engagement_path


def validate_arguments(arguments: Sequence[str]) -> list[str]:
    validated: list[str] = []
    for argument in arguments:
        if not isinstance(argument, str):
            raise TypeError("every argument must be a string")
        if "\x00" in argument:
            raise ValueError("arguments cannot contain NUL bytes")
        validated.append(argument)
    return validated


def executable_status(executable: str) -> dict[str, Any]:
    resolved = shutil.which(executable)
    return {
        "executable": executable,
        "available": resolved is not None,
        "path": resolved,
    }


async def _terminate_process_group(process: asyncio.subprocess.Process) -> None:
    """Terminate a cancelled tool and any descendants it started."""
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()


async def execute_tool(
    executable: str,
    arguments: Sequence[str],
    engagement_id: str,
    working_directory: str = ".",
    stdin: str | None = None,
) -> dict[str, Any]:
    """Execute one binary without a shell, server deadline, or output truncation."""
    cwd = resolve_engagement_path(engagement_id, working_directory)
    resolved = shutil.which(executable)
    if resolved is None:
        return {
            "success": False,
            "engagement_id": engagement_id,
            "executable": executable,
            "available": False,
            "cwd": str(cwd),
            "error": f"executable is not installed: {executable}",
        }

    argv = [resolved, *validate_arguments(arguments)]
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=os.environ.copy(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        return {
            "success": False,
            "engagement_id": engagement_id,
            "executable": executable,
            "available": True,
            "argv": argv,
            "cwd": str(cwd),
            "error": str(exc),
        }

    try:
        stdout, stderr = await process.communicate(
            None if stdin is None else stdin.encode("utf-8")
        )
    except asyncio.CancelledError:
        await _terminate_process_group(process)
        raise

    return {
        "success": process.returncode == 0,
        "engagement_id": engagement_id,
        "executable": executable,
        "available": True,
        "argv": argv,
        "cwd": str(cwd),
        "returncode": process.returncode,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }
