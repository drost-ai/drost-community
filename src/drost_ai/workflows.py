"""Deterministic Drost engagement planning helpers."""

from __future__ import annotations

from typing import Any


WORKFLOW_STEPS: dict[str, tuple[dict[str, Any], ...]] = {
    "recon": (
        {"tool": "drost_subfinder", "purpose": "Enumerate subdomains"},
        {"tool": "drost_amass", "purpose": "Expand passive and active asset discovery"},
        {"tool": "drost_httpx", "purpose": "Identify responsive HTTP services"},
        {"tool": "drost_nmap", "purpose": "Map exposed services"},
        {"tool": "drost_nuclei", "purpose": "Run template-based checks"},
    ),
    "web": (
        {"tool": "drost_httpx", "purpose": "Probe the application and collect metadata"},
        {"tool": "drost_katana", "purpose": "Crawl reachable content"},
        {"tool": "drost_ffuf", "purpose": "Discover routes and resources"},
        {"tool": "drost_arjun", "purpose": "Discover request parameters"},
        {"tool": "drost_nuclei", "purpose": "Run web-focused checks"},
        {"tool": "drost_sqlmap", "purpose": "Validate suspected SQL injection"},
    ),
    "api": (
        {"tool": "drost_openapi_inspect", "purpose": "Inventory the documented API operations"},
        {"tool": "drost_http_request", "purpose": "Exercise requests and inspect complete responses"},
        {"tool": "drost_graphql_request", "purpose": "Exercise GraphQL operations when present"},
        {"tool": "drost_jwt_decode", "purpose": "Inspect token claims without claiming verification"},
        {"tool": "drost_arjun", "purpose": "Discover undocumented parameters"},
        {"tool": "drost_nuclei", "purpose": "Run API-relevant templates"},
    ),
    "vulnerability_assessment": (
        {"tool": "drost_nmap", "purpose": "Inventory exposed services"},
        {"tool": "drost_nuclei", "purpose": "Run reproducible vulnerability checks"},
        {"tool": "drost_nikto", "purpose": "Assess web-server configuration"},
        {"tool": "drost_trivy", "purpose": "Assess filesystems, images, and configuration"},
        {"tool": "drost_scan_summary", "purpose": "Preserve and summarize complete tool results"},
    ),
    "bug_bounty": (
        {"tool": "drost_subfinder", "purpose": "Discover in-scope subdomains"},
        {"tool": "drost_httpx", "purpose": "Identify responsive properties"},
        {"tool": "drost_katana", "purpose": "Crawl reachable application content"},
        {"tool": "drost_gau", "purpose": "Collect historical URLs"},
        {"tool": "drost_arjun", "purpose": "Discover parameters"},
        {"tool": "drost_dalfox", "purpose": "Test XSS candidates"},
        {"tool": "drost_nuclei", "purpose": "Run scoped templates"},
        {"tool": "drost_finding_report", "purpose": "Persist validated findings"},
    ),
    "cloud": (
        {"tool": "drost_prowler", "purpose": "Assess configured cloud accounts"},
        {"tool": "drost_scout_suite", "purpose": "Build a cloud security inventory"},
        {"tool": "drost_trivy", "purpose": "Scan images, filesystems, and configuration"},
        {"tool": "drost_checkov", "purpose": "Scan infrastructure as code"},
        {"tool": "drost_kube_bench", "purpose": "Check Kubernetes CIS controls"},
    ),
    "binary": (
        {"tool": "drost_file", "purpose": "Identify the artifact"},
        {"tool": "drost_checksec", "purpose": "Inspect binary protections"},
        {"tool": "drost_strings", "purpose": "Extract printable content"},
        {"tool": "drost_binwalk", "purpose": "Identify embedded data"},
        {"tool": "drost_radare2", "purpose": "Perform static and dynamic analysis"},
        {"tool": "drost_gdb", "purpose": "Debug runtime behavior"},
    ),
    "forensics": (
        {"tool": "drost_file", "purpose": "Classify input artifacts"},
        {"tool": "drost_exiftool", "purpose": "Extract metadata"},
        {"tool": "drost_bulk_extractor", "purpose": "Extract forensic features"},
        {"tool": "drost_foremost", "purpose": "Carve files"},
        {"tool": "drost_volatility", "purpose": "Analyze memory images"},
    ),
    "ctf": (
        {"tool": "drost_file", "purpose": "Classify challenge artifacts"},
        {"tool": "drost_strings", "purpose": "Extract initial clues"},
        {"tool": "drost_exiftool", "purpose": "Inspect metadata"},
        {"tool": "drost_binwalk", "purpose": "Find embedded content"},
        {"tool": "drost_checksec", "purpose": "Inspect binary protections when applicable"},
    ),
    "credentials": (
        {"tool": "drost_hash_identifier", "purpose": "Classify supplied hashes"},
        {"tool": "drost_john", "purpose": "Run wordlist and rule-based cracking"},
        {"tool": "drost_hashcat", "purpose": "Run accelerated hash recovery"},
        {"tool": "drost_hydra", "purpose": "Test explicitly authorized network authentication"},
    ),
    "wireless": (
        {"tool": "drost_airmon", "purpose": "Prepare a compatible wireless interface"},
        {"tool": "drost_airodump", "purpose": "Capture authorized wireless traffic"},
        {"tool": "drost_aircrack", "purpose": "Analyze captured handshakes"},
        {"tool": "drost_kismet", "purpose": "Perform wireless discovery and monitoring"},
    ),
}


def engagement_plan(kind: str, target: str, objective: str = "") -> dict[str, Any]:
    normalized = kind.strip().lower()
    if normalized not in WORKFLOW_STEPS:
        raise ValueError(f"unknown workflow kind: {kind}; choose from {sorted(WORKFLOW_STEPS)}")
    return {
        "kind": normalized,
        "target": target,
        "objective": objective,
        "steps": list(WORKFLOW_STEPS[normalized]),
        "note": "This is a deterministic plan. Each step requires an explicit MCP tool call.",
    }


def recommend_tools(objective: str, target_type: str = "web") -> dict[str, Any]:
    text = objective.lower()
    scores: dict[str, int] = {kind: 0 for kind in WORKFLOW_STEPS}
    keywords = {
        "recon": ("recon", "asset", "domain", "subdomain", "network", "port"),
        "web": ("web", "http", "api", "url", "application", "xss", "sqli"),
        "api": ("api", "graphql", "openapi", "swagger", "jwt"),
        "vulnerability_assessment": ("vulnerability", "assessment", "scan", "cve"),
        "bug_bounty": ("bug bounty", "bounty", "scope", "program"),
        "cloud": ("cloud", "aws", "azure", "gcp", "kubernetes", "container", "iac"),
        "binary": ("binary", "reverse", "pwn", "elf", "executable"),
        "forensics": ("forensic", "memory", "disk", "image", "artifact"),
        "ctf": ("ctf", "challenge", "flag", "puzzle"),
        "credentials": ("password", "credential", "hash", "authentication"),
        "wireless": ("wireless", "wifi", "802.11", "wpa"),
    }
    for kind, needles in keywords.items():
        scores[kind] = sum(needle in text for needle in needles)
    if max(scores.values()) == 0 and target_type.lower() in scores:
        scores[target_type.lower()] = 1
    selected = max(scores, key=scores.get)
    return {
        "selected_workflow": selected,
        "scores": scores,
        "tools": list(WORKFLOW_STEPS[selected]),
        "basis": "deterministic keyword matching over the supplied objective and target type",
    }


def attack_chain(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered = sorted(
        findings,
        key=lambda finding: severity_order.get(str(finding.get("severity", "info")).lower(), 5),
    )
    steps = [
        {
            "order": index,
            "finding": finding,
            "reason": "ordered by supplied severity; validate reachability and prerequisites before execution",
        }
        for index, finding in enumerate(ordered, start=1)
    ]
    return {"steps": steps, "generated": False, "basis": "caller-supplied findings"}


def scan_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    succeeded = [result for result in results if result.get("success") is True]
    failed = [result for result in results if result.get("success") is False]
    return {
        "total": len(results),
        "succeeded": len(succeeded),
        "failed": len(failed),
        "return_codes": [result.get("returncode") for result in results],
        "tools": [result.get("drost_tool") or result.get("tool") for result in results],
        "results": results,
    }
