#!/usr/bin/env python3
"""Check a CycloneDX JSON SBOM against Drost's release license policy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from urllib.parse import unquote


def component_names(sbom: dict) -> set[str]:
    names: set[str] = set()
    for component in sbom.get("components", []):
        name = component.get("name")
        if isinstance(name, str):
            names.add(name.casefold())
            names.add(name.rsplit("/", 1)[-1].casefold())
        purl = component.get("purl")
        if isinstance(purl, str) and purl.startswith("pkg:"):
            package_part = purl.split("?", 1)[0].rsplit("/", 1)[-1]
            package_name = package_part.split("@", 1)[0]
            names.add(unquote(package_name).casefold())
    metadata_component = sbom.get("metadata", {}).get("component", {})
    name = metadata_component.get("name")
    if isinstance(name, str):
        names.add(name.casefold())
    return names


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sbom", type=Path, help="CycloneDX JSON SBOM")
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("compliance/license-policy.json"),
        help="license policy JSON",
    )
    args = parser.parse_args()

    with args.sbom.open(encoding="utf-8") as handle:
        sbom = json.load(handle)
    with args.policy.open(encoding="utf-8") as handle:
        policy = json.load(handle)

    names = component_names(sbom)
    blocked = [
        entry
        for entry in policy.get("blocked_components", [])
        if entry["name"].casefold() in names
    ]
    review = [
        entry
        for entry in policy.get("review_required_components", [])
        if entry["name"].casefold() in names
    ]
    notices = [
        entry
        for entry in policy.get("notice_required_components", [])
        if entry["name"].casefold() in names
    ]

    print(f"SBOM components: {len(sbom.get('components', []))}")
    for entry in review:
        print(f"REVIEW: {entry['name']}: {entry['reason']}")
    for entry in notices:
        print(f"NOTICE: {entry['name']}: {entry['reason']}")
    for entry in blocked:
        print(f"BLOCKED: {entry['name']}: {entry['reason']}", file=sys.stderr)

    if blocked:
        print(
            f"Release blocked by {len(blocked)} component(s).",
            file=sys.stderr,
        )
        return 1
    print("No blocked components detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
