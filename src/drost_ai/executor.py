"""Safe direct executable runner for Drost MCP tools."""

from __future__ import annotations

import os
import shutil
import subprocess
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


def execute_tool(
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
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=os.environ.copy(),
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
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

    return {
        "success": completed.returncode == 0,
        "engagement_id": engagement_id,
        "executable": executable,
        "available": True,
        "argv": argv,
        "cwd": str(cwd),
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
