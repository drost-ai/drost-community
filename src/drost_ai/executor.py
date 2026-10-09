"""Safe direct executable runner for Drost MCP tools."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Sequence


WORKSPACE = Path(os.environ.get("DROST_WORKSPACE", "/workspace")).resolve()


def resolve_workspace_path(value: str = ".", *, must_exist: bool = True) -> Path:
    raw = Path(value)
    candidate = raw.resolve() if raw.is_absolute() else (WORKSPACE / raw).resolve()
    if candidate != WORKSPACE and WORKSPACE not in candidate.parents:
        raise ValueError(f"path must remain inside {WORKSPACE}")
    if must_exist and not candidate.exists():
        raise ValueError(f"workspace path does not exist: {candidate}")
    return candidate


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
    working_directory: str = ".",
    stdin: str | None = None,
) -> dict[str, Any]:
    """Execute one binary without a shell, server deadline, or output truncation."""
    resolved = shutil.which(executable)
    if resolved is None:
        return {
            "success": False,
            "executable": executable,
            "available": False,
            "error": f"executable is not installed: {executable}",
        }

    argv = [resolved, *validate_arguments(arguments)]
    cwd = resolve_workspace_path(working_directory)
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
            "executable": executable,
            "available": True,
            "argv": argv,
            "cwd": str(cwd),
            "error": str(exc),
        }

    return {
        "success": completed.returncode == 0,
        "executable": executable,
        "available": True,
        "argv": argv,
        "cwd": str(cwd),
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
