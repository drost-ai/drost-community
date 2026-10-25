"""Static Android APK triage for Drost Android engagements."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _attr(element: Any, name: str) -> str | None:
    if element is None:
        return None
    return element.get(ANDROID_NS + name)


def _intent_filters(element: Any) -> list[dict[str, Any]]:
    filters: list[dict[str, Any]] = []
    for intent_filter in element.findall("intent-filter"):
        actions = [value for value in (item.get(ANDROID_NS + "name") for item in intent_filter.findall("action")) if value]
        categories = [value for value in (item.get(ANDROID_NS + "name") for item in intent_filter.findall("category")) if value]
        data: list[dict[str, str]] = []
        for item in intent_filter.findall("data"):
            entry = {
                key: value
                for key in ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType")
                if (value := item.get(ANDROID_NS + key))
            }
            if entry:
                data.append(entry)
        filters.append({"actions": actions, "categories": categories, "data": data})
    return filters


def _component(element: Any) -> dict[str, Any]:
    filters = _intent_filters(element)
    exported = _attr(element, "exported")
    effectively_exported = bool(filters) if exported is None else exported.lower() == "true"
    return {
        "name": _attr(element, "name"),
        "exported": exported,
        "exported_declared": exported is not None,
        "effectively_exported": effectively_exported,
        "permission": _attr(element, "permission"),
        "enabled": _attr(element, "enabled"),
        "process": _attr(element, "process"),
        "intent_filters": filters,
    }


def _components(application: Any, tag: str) -> list[dict[str, Any]]:
    if application is None:
        return []
    return [_component(element) for element in application.findall(tag)]


def _certificate_name(name: Any) -> str:
    try:
        return str(name.human_friendly)
    except Exception:
        return str(name.native)


def _certificate(certificate: Any) -> dict[str, Any]:
    return {
        "sha256": certificate.sha256.hex(),
        "subject": _certificate_name(certificate.subject),
        "issuer": _certificate_name(certificate.issuer),
        "serial_number": str(certificate.serial_number),
        "not_valid_before": certificate.not_valid_before.isoformat(),
        "not_valid_after": certificate.not_valid_after.isoformat(),
    }


def _deep_links(components: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = []
    for component in components:
        for intent_filter in component["intent_filters"]:
            for data in intent_filter["data"]:
                if "scheme" in data or "host" in data:
                    links.append({"component": component["name"], "kind": kind, **data})
    return links


def _declared_permissions(manifest: Any) -> list[dict[str, Any]]:
    permissions: list[dict[str, Any]] = []
    for tag in ("permission", "permission-group", "permission-tree"):
        for element in manifest.findall(tag):
            permissions.append(
                {
                    "kind": tag,
                    "name": _attr(element, "name"),
                    "protection_level": _attr(element, "protectionLevel"),
                }
            )
    return permissions


def _main_activity(activities: list[dict[str, Any]]) -> str | None:
    for activity in activities:
        for intent_filter in activity["intent_filters"]:
            if "android.intent.action.MAIN" in intent_filter["actions"] and "android.intent.category.LAUNCHER" in intent_filter["categories"]:
                return activity["name"]
    return None


def scan_apk(path: Path) -> dict[str, Any]:
    """Return a JSON-serializable triage report for one APK."""
    try:
        from loguru import logger

        logger.remove()
    except Exception:
        pass

    from androguard.core.apk import APK

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    apk = APK(str(path))
    manifest = apk.get_android_manifest_xml()
    application = manifest.find("application")

    activities = _components(application, "activity")
    services = _components(application, "service")
    receivers = _components(application, "receiver")
    providers = _components(application, "provider")

    files = apk.get_files()
    native_libs: dict[str, list[str]] = {}
    for name in files:
        parts = name.split("/")
        if len(parts) == 3 and parts[0] == "lib":
            native_libs.setdefault(parts[1], []).append(parts[2])

    return {
        "apk": str(path),
        "sha256": digest,
        "size": path.stat().st_size,
        "package": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "max_sdk": apk.get_max_sdk_version(),
        "debuggable": _attr(application, "debuggable"),
        "allow_backup": _attr(application, "allowBackup"),
        "uses_cleartext_traffic": _attr(application, "usesCleartextTraffic"),
        "network_security_config": _attr(application, "networkSecurityConfig"),
        "extract_native_libs": _attr(application, "extractNativeLibs"),
        "request_legacy_external_storage": _attr(application, "requestLegacyExternalStorage"),
        "test_only": _attr(application, "testOnly"),
        "permissions": apk.get_permissions(),
        "declared_permissions": _declared_permissions(manifest),
        "main_activity": _main_activity(activities),
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
        "exported_components": [
            {"kind": kind, "name": component["name"], "permission": component["permission"]}
            for kind, components in (
                ("activity", activities),
                ("service", services),
                ("receiver", receivers),
                ("provider", providers),
            )
            for component in components
            if component["effectively_exported"]
        ],
        "deep_links": _deep_links(activities, "activity")
        + _deep_links(services, "service")
        + _deep_links(receivers, "receiver")
        + _deep_links(providers, "provider"),
        "native_libs": {abi: sorted(names) for abi, names in sorted(native_libs.items())},
        "certificates": [_certificate(certificate) for certificate in apk.get_certificates()],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Static Android APK triage")
    parser.add_argument("apk", type=Path, help="APK file to inspect")
    parser.add_argument("--output", type=Path, help="write the JSON report to this file")
    args = parser.parse_args()

    report = scan_apk(args.apk)
    payload = json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
