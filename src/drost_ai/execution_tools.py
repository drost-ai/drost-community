"""General-purpose engagement execution tools."""

from __future__ import annotations

from typing import Any

from .engagements import resolve_engagement_path
from .executor import execute_tool


async def execute_bash(
    engagement_id: str,
    script: str,
    working_directory: str = ".",
    stdin: str | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not script:
        raise ValueError("script must not be empty")
    result = await execute_tool(
        "bash",
        ["-c", script],
        engagement_id=engagement_id,
        working_directory=working_directory,
        stdin=stdin,
        environment=environment,
    )
    result.update({"drost_tool": "drost_bash", "category": "execution"})
    return result


async def execute_python(
    engagement_id: str,
    source: str = "",
    path: str = "",
    script_arguments: list[str] | None = None,
    working_directory: str = ".",
    stdin: str | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    if bool(source) == bool(path):
        raise ValueError("provide exactly one of source or path")
    if source:
        arguments = ["-c", source, *(script_arguments or [])]
        origin = "inline"
    else:
        script_path = resolve_engagement_path(engagement_id, path)
        if not script_path.is_file():
            raise ValueError(f"not a Python file: {script_path}")
        arguments = [str(script_path), *(script_arguments or [])]
        origin = str(script_path)
    result = await execute_tool(
        "python3",
        arguments,
        engagement_id=engagement_id,
        working_directory=working_directory,
        stdin=stdin,
        environment=environment,
    )
    result.update(
        {
            "drost_tool": "drost_python",
            "category": "execution",
            "script_origin": origin,
        }
    )
    return result
