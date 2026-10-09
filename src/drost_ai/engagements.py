"""Persistent, server-managed Drost engagement namespaces."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any
import uuid


WORKSPACE = Path(os.environ.get("DROST_WORKSPACE", "/workspace")).resolve()
ENGAGEMENT_ID_PATTERN = re.compile(r"eng_\d{8}_[0-9a-f]{32}")
ENGAGEMENT_DIRECTORY_NAMES = ("artifacts", "evidence", "findings")


def validate_engagement_id(engagement_id: str) -> str:
    if not isinstance(engagement_id, str) or not ENGAGEMENT_ID_PATTERN.fullmatch(engagement_id):
        raise ValueError(
            "engagement_id must be a server-generated identifier such as "
            "eng_20261009_9f8d4c1a6b2743f4a2c11bb8d02a91a7"
        )
    return engagement_id


def _engagements_root() -> Path:
    return WORKSPACE / "engagements"


def _engagement_root(engagement_id: str) -> Path:
    return _engagements_root() / validate_engagement_id(engagement_id)


def _load_manifest(engagement_id: str) -> dict[str, Any]:
    engagement_root = _engagement_root(engagement_id)
    root = _engagements_root().resolve()
    if engagement_root.is_symlink() or engagement_root.resolve() != root / engagement_id:
        raise ValueError(f"invalid engagement namespace: {engagement_id}")
    path = engagement_root / "engagement.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"unknown engagement_id: {engagement_id}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid engagement manifest: {engagement_id}") from exc
    if not isinstance(manifest, dict) or manifest.get("engagement_id") != engagement_id:
        raise ValueError(f"invalid engagement manifest: {engagement_id}")
    return manifest


def _public_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    engagement_id = str(manifest["engagement_id"])
    return {
        **manifest,
        "workspace": str(_engagement_root(engagement_id).resolve()),
    }


def create_engagement(name: str, targets: list[str], objective: str = "") -> dict[str, Any]:
    if not isinstance(name, str):
        raise ValueError("name must be a string")
    normalized_name = name.strip()
    if not normalized_name:
        raise ValueError("name must not be empty")
    if len(normalized_name) > 200:
        raise ValueError("name must be 200 characters or fewer")
    if not isinstance(targets, list) or not targets:
        raise ValueError("targets must contain at least one authorized target")
    normalized_targets = []
    for target in targets:
        if not isinstance(target, str) or not target.strip():
            raise ValueError("every target must be a non-empty string")
        normalized_targets.append(target.strip())
    if not isinstance(objective, str):
        raise ValueError("objective must be a string")

    root = _engagements_root()
    root.mkdir(parents=True, exist_ok=True)
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    while True:
        engagement_id = f"eng_{date}_{uuid.uuid4().hex}"
        engagement_root = root / engagement_id
        temporary_root = root / f".{engagement_id}.tmp"
        if engagement_root.exists():
            continue
        try:
            temporary_root.mkdir()
        except FileExistsError:
            continue
        break

    for directory_name in ENGAGEMENT_DIRECTORY_NAMES:
        (temporary_root / directory_name).mkdir()
    manifest = {
        "schema_version": 1,
        "engagement_id": engagement_id,
        "name": normalized_name,
        "targets": normalized_targets,
        "objective": objective.strip(),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    manifest_path = temporary_root / "engagement.json"
    temporary_path = temporary_root / ".engagement.json.tmp"
    temporary_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary_path.replace(manifest_path)
    temporary_root.replace(engagement_root)
    return _public_manifest(manifest)


def list_engagements() -> dict[str, Any]:
    root = _engagements_root()
    if not root.is_dir():
        return {"workspace": str(WORKSPACE), "engagements": [], "invalid_engagements": []}
    engagements = []
    invalid_engagements = []
    for item in sorted(root.iterdir()):
        if not item.is_dir() or not ENGAGEMENT_ID_PATTERN.fullmatch(item.name):
            continue
        try:
            engagements.append(_public_manifest(_load_manifest(item.name)))
        except ValueError as exc:
            invalid_engagements.append({"engagement_id": item.name, "error": str(exc)})
    engagements.sort(key=lambda item: item["created_at"], reverse=True)
    return {
        "workspace": str(WORKSPACE),
        "engagements": engagements,
        "invalid_engagements": invalid_engagements,
    }


def get_engagement(engagement_id: str) -> dict[str, Any]:
    return _public_manifest(_load_manifest(engagement_id))


def resolve_engagement_path(
    engagement_id: str,
    value: str = ".",
    *,
    must_exist: bool = True,
) -> Path:
    engagement_root = Path(get_engagement(engagement_id)["workspace"]).resolve()
    raw = Path(value)
    candidate = raw.resolve() if raw.is_absolute() else (engagement_root / raw).resolve()
    if candidate != engagement_root and engagement_root not in candidate.parents:
        raise ValueError(f"path must remain inside engagement {engagement_id}")
    if must_exist and not candidate.exists():
        raise ValueError(f"engagement path does not exist: {candidate}")
    return candidate
