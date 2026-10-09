"""Engagement workspace operations confined to the container workspace."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .engagements import get_engagement, resolve_engagement_path


def list_workspace(engagement_id: str, path: str = ".", recursive: bool = False) -> dict[str, Any]:
    engagement_root = Path(get_engagement(engagement_id)["workspace"])
    root = resolve_engagement_path(engagement_id, path)
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    iterator = root.rglob("*") if recursive else root.iterdir()
    entries = []
    for item in sorted(iterator):
        stat = item.stat()
        entries.append(
            {
                "path": str(item.relative_to(engagement_root)),
                "type": "directory" if item.is_dir() else "file",
                "size": stat.st_size if item.is_file() else 0,
            }
        )
    return {"engagement_id": engagement_id, "workspace": str(engagement_root), "entries": entries}


def read_workspace_file(engagement_id: str, path: str) -> dict[str, Any]:
    engagement_root = Path(get_engagement(engagement_id)["workspace"])
    target = resolve_engagement_path(engagement_id, path)
    if not target.is_file():
        raise ValueError(f"not a file: {target}")
    return {
        "engagement_id": engagement_id,
        "path": str(target.relative_to(engagement_root)),
        "content": target.read_text(encoding="utf-8", errors="replace"),
    }


def write_workspace_file(engagement_id: str, path: str, content: str, append: bool = False) -> dict[str, Any]:
    engagement_root = Path(get_engagement(engagement_id)["workspace"])
    target = resolve_engagement_path(engagement_id, path, must_exist=False)
    if target == engagement_root / "engagement.json":
        raise ValueError("engagement.json is managed by the Drost server")
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with target.open(mode, encoding="utf-8") as handle:
        handle.write(content)
    return {
        "engagement_id": engagement_id,
        "path": str(target.relative_to(engagement_root)),
        "size": target.stat().st_size,
        "appended": append,
    }


def delete_workspace_path(engagement_id: str, path: str) -> dict[str, Any]:
    engagement_root = Path(get_engagement(engagement_id)["workspace"])
    target = resolve_engagement_path(engagement_id, path)
    if target == engagement_root:
        raise ValueError("cannot delete the engagement root")
    if target == engagement_root / "engagement.json":
        raise ValueError("engagement.json is managed by the Drost server")
    if target.is_dir():
        target.rmdir()
    else:
        target.unlink()
    return {"engagement_id": engagement_id, "deleted": str(target.relative_to(engagement_root))}


def write_finding_report(
    engagement_id: str,
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
    result = write_workspace_file(engagement_id, path, content, append=False)
    result.update({"title": title, "target": target, "severity": severity})
    return result
