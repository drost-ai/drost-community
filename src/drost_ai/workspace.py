"""Engagement workspace operations confined to the container workspace."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .executor import WORKSPACE, resolve_workspace_path


def list_workspace(path: str = ".", recursive: bool = False) -> dict[str, Any]:
    root = resolve_workspace_path(path)
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    iterator = root.rglob("*") if recursive else root.iterdir()
    entries = []
    for item in sorted(iterator):
        stat = item.stat()
        entries.append(
            {
                "path": str(item.relative_to(WORKSPACE)),
                "type": "directory" if item.is_dir() else "file",
                "size": stat.st_size if item.is_file() else 0,
            }
        )
    return {"workspace": str(WORKSPACE), "entries": entries}


def read_workspace_file(path: str) -> dict[str, Any]:
    target = resolve_workspace_path(path)
    if not target.is_file():
        raise ValueError(f"not a file: {target}")
    return {
        "path": str(target.relative_to(WORKSPACE)),
        "content": target.read_text(encoding="utf-8", errors="replace"),
    }


def write_workspace_file(path: str, content: str, append: bool = False) -> dict[str, Any]:
    target = resolve_workspace_path(path, must_exist=False)
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with target.open(mode, encoding="utf-8") as handle:
        handle.write(content)
    return {
        "path": str(target.relative_to(WORKSPACE)),
        "size": target.stat().st_size,
        "appended": append,
    }


def delete_workspace_path(path: str) -> dict[str, Any]:
    target = resolve_workspace_path(path)
    if target == WORKSPACE:
        raise ValueError("cannot delete the workspace root")
    if target.is_dir():
        target.rmdir()
    else:
        target.unlink()
    return {"deleted": str(target.relative_to(WORKSPACE))}


def write_finding_report(
    path: str,
    title: str,
    target: str,
    severity: str,
    summary: str,
    evidence: list[str],
    remediation: str = "",
) -> dict[str, Any]:
    evidence_lines = "\n".join(f"- {item}" for item in evidence) or "- No evidence supplied"
    content = (
        f"# {title}\n\n"
        f"- Target: `{target}`\n"
        f"- Severity: **{severity.upper()}**\n\n"
        f"## Summary\n\n{summary}\n\n"
        f"## Evidence\n\n{evidence_lines}\n\n"
        f"## Remediation\n\n{remediation or 'Not supplied'}\n"
    )
    result = write_workspace_file(path, content, append=False)
    result.update({"title": title, "target": target, "severity": severity})
    return result
