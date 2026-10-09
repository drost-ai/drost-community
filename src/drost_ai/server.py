"""Direct stdio MCP server for Drost AI."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from . import __version__
from .api_audit import audit_graphql, audit_jwt, audit_openapi, fuzz_api_parameter
from .browser import BROWSER_MANAGER
from .catalog import CATALOG, ToolSpec, category_counts
from .engagements import WORKSPACE, create_engagement, get_engagement, list_engagements
from .execution_tools import execute_bash, execute_python
from .http_workbench import create_http_session, get_http_session, intrude_http_parameter, list_http_sessions, read_http_history, repeat_http_request, update_http_session
from .executor import execute_tool
from .native_tools import analyze_binary_with_angr, decode_jwt, encode_payload, extract_indicators, graphql_request, hash_workspace_file, hibp_password_range, http_request, inspect_openapi, lookup_cve, process_snapshot, technology_hints
from .workspace import delete_workspace_path, list_workspace, read_workspace_file, write_finding_report, write_workspace_file
from .workflows import WORKFLOW_STEPS, attack_chain, engagement_plan, recommend_tools, scan_summary


mcp = FastMCP(
    "Drost AI",
    instructions=(
        "Drost AI is a container-native offensive security toolkit. Use tools only for "
        "authorized targets. Executable-backed tools accept explicit argv tokens and never "
        "invoke a shell unless the caller explicitly selects drost_bash. Before using an "
        "executable or workspace-backed tool, create an "
        "engagement with drost_engagement_create or select an existing ID returned by "
        "drost_engagement_list. Supply that engagement_id on every relevant tool call. In "
        "full mode prefer direct named Drost tools. Use drost_execute only with an exact "
        "drost_* name returned by a filtered drost_catalog query. Prefer drost_jq or "
        "drost_python over grep for structured JSON, and prefer specialized API/browser "
        "tools over ad-hoc parsing when they match the task."
    ),
)


def _registered_catalog() -> tuple[ToolSpec, ...]:
    mode = os.environ.get("DROST_MCP_MODE", "full").strip().lower()
    if mode == "compact":
        return ()
    raw_categories = os.environ.get("DROST_TOOL_CATEGORIES", "").strip()
    if not raw_categories:
        return CATALOG
    selected = {category.strip() for category in raw_categories.split(",") if category.strip()}
    unknown = selected - set(category_counts())
    if unknown:
        raise ValueError(f"unknown DROST_TOOL_CATEGORIES: {sorted(unknown)}")
    return tuple(spec for spec in CATALOG if spec.category in selected)


REGISTERED_CATALOG = _registered_catalog()
LEGACY_NATIVE_AND_WORKSPACE_TOOL_COUNT = 23
ENGAGEMENT_MANAGEMENT_TOOL_COUNT = 3
GENERAL_EXECUTION_TOOL_COUNT = 2
API_AUDIT_TOOL_COUNT = 4
HTTP_WORKBENCH_TOOL_COUNT = 7
BROWSER_TOOL_COUNT = 13
FIXED_MCP_TOOL_COUNT = (
    LEGACY_NATIVE_AND_WORKSPACE_TOOL_COUNT
    + ENGAGEMENT_MANAGEMENT_TOOL_COUNT
    + GENERAL_EXECUTION_TOOL_COUNT
    + API_AUDIT_TOOL_COUNT
    + HTTP_WORKBENCH_TOOL_COUNT
    + BROWSER_TOOL_COUNT
)


def _native_category(name: str) -> str:
    if name.startswith("drost_browser_"):
        return "browser"
    if name.startswith("drost_http_session_") or name in {"drost_http_repeater", "drost_http_intruder", "drost_http_history"}:
        return "http_workbench"
    if name in {"drost_openapi_audit", "drost_graphql_audit", "drost_jwt_audit", "drost_api_fuzz"}:
        return "api_audit"
    if name in {"drost_bash", "drost_python"}:
        return "execution"
    if name.startswith("drost_engagement_"):
        return "engagement"
    if name.startswith("drost_workspace_") or name == "drost_finding_report":
        return "workspace"
    return "native"


def _external_tool(spec: ToolSpec) -> Callable[..., dict[str, Any]]:
    async def run(
        engagement_id: str,
        arguments: list[str],
        working_directory: str = ".",
        stdin: str | None = None,
    ) -> dict[str, Any]:
        """Run a Drost container executable with explicit argv tokens."""
        result = await execute_tool(
            spec.executable,
            arguments,
            engagement_id=engagement_id,
            working_directory=working_directory,
            stdin=stdin,
        )
        result["drost_tool"] = spec.name
        result["category"] = spec.category
        return result

    run.__name__ = spec.name
    run.__qualname__ = spec.name
    run.__doc__ = spec.description
    return run


for _spec in REGISTERED_CATALOG:
    mcp.tool(
        name=_spec.name,
        description=(
            f"{_spec.description} Runs from the selected engagement namespace; "
            "use relative paths for engagement artifacts."
        ),
        structured_output=True,
    )(
        _external_tool(_spec)
    )


@mcp.tool(name="drost_catalog", description="Search every Drost executable and native MCP tool by exact `drost_*` name, substring query, or category. An unfiltered call returns only counts; set include_all=true only when the complete catalog is genuinely required.", structured_output=True)
def drost_catalog(name: str | None = None, query: str | None = None, category: str | None = None, missing_only: bool = False, registered_only: bool = False, include_all: bool = False, include_contracts: bool = False) -> dict[str, Any]:
    if name and query:
        raise ValueError("choose either exact name or substring query, not both")
    registered_names = {spec.name for spec in REGISTERED_CATALOG}
    managed_tools = mcp._tool_manager._tools
    external_names = {spec.name for spec in CATALOG}
    candidates: list[dict[str, Any]] = []
    for spec in CATALOG:
        managed = managed_tools.get(spec.name)
        entry: dict[str, Any] = {
            **spec.as_dict(),
            "available": shutil.which(spec.executable) is not None,
            "path": shutil.which(spec.executable),
            "registered_individually": spec.name in registered_names,
            "kind": "executable",
        }
        if include_contracts:
            entry["input_schema"] = managed.parameters if managed else {
                "required": ["tool", "engagement_id", "arguments"],
                "properties": {
                    "tool": {"const": spec.name},
                    "engagement_id": {"type": "string"},
                    "arguments": {"type": "array", "items": {"type": "string"}},
                    "working_directory": {"type": "string", "default": "."},
                    "stdin": {"type": ["string", "null"], "default": None},
                },
            }
        candidates.append(entry)
    for tool_name, managed in managed_tools.items():
        if tool_name in external_names:
            continue
        entry = {
            "name": tool_name,
            "executable": None,
            "category": _native_category(tool_name),
            "description": managed.description or "",
            "available": True,
            "path": None,
            "registered_individually": True,
            "kind": "native",
        }
        if include_contracts:
            entry["input_schema"] = managed.parameters
        candidates.append(entry)
    exact_exists = name is None or any(entry["name"] == name for entry in candidates)
    if not exact_exists:
        raise ValueError(f"unknown Drost catalog tool: {name}")
    tools = []
    for entry in candidates:
        if name and entry["name"] != name:
            continue
        if query:
            haystack = " ".join(
                str(entry.get(field) or "")
                for field in ("name", "executable", "category", "description", "kind")
            ).lower()
            if query.strip().lower() not in haystack:
                continue
        if category and entry["category"] != category:
            continue
        if registered_only and not entry["registered_individually"]:
            continue
        if missing_only and entry["available"]:
            continue
        if include_all or name or query or category or missing_only or registered_only:
            tools.append(entry)
    native_counts: dict[str, int] = {}
    for entry in candidates:
        if entry["kind"] == "native":
            native_counts[entry["category"]] = native_counts.get(entry["category"], 0) + 1
    return {
        "version": __version__,
        "workspace": str(WORKSPACE),
        "engagements_root": str(WORKSPACE / "engagements"),
        "external_tool_count": len(CATALOG),
        "registered_external_tool_count": len(REGISTERED_CATALOG),
        "native_and_workspace_tool_count": LEGACY_NATIVE_AND_WORKSPACE_TOOL_COUNT,
        "engagement_management_tool_count": ENGAGEMENT_MANAGEMENT_TOOL_COUNT,
        "general_execution_tool_count": GENERAL_EXECUTION_TOOL_COUNT,
        "api_audit_tool_count": API_AUDIT_TOOL_COUNT,
        "http_workbench_tool_count": HTTP_WORKBENCH_TOOL_COUNT,
        "browser_tool_count": BROWSER_TOOL_COUNT,
        "advertised_mcp_tool_count": len(REGISTERED_CATALOG) + FIXED_MCP_TOOL_COUNT,
        "mcp_mode": os.environ.get("DROST_MCP_MODE", "full"),
        "workflow_kinds": sorted(WORKFLOW_STEPS),
        "category_counts": category_counts(),
        "native_category_counts": dict(sorted(native_counts.items())),
        "complete_catalog_count": len(candidates),
        "matched_tool_count": len(tools),
        "hint": (
            "Use name for one exact drost_* contract, query for substring discovery, "
            "category for a tool family, or include_all=true for every entry."
        ),
        "tools": tools,
    }


@mcp.tool(name="drost_execute", description="Dispatch one executable-backed catalog entry by its exact `drost_*` name returned by drost_catalog. This is primarily a compact-mode fallback; in full mode prefer the direct named tool. Use relative paths for engagement artifacts.", structured_output=True)
async def drost_execute(tool: str, engagement_id: str, arguments: list[str], working_directory: str = ".", stdin: str | None = None) -> dict[str, Any]:
    spec = next((entry for entry in CATALOG if entry.name == tool), None)
    if spec is None:
        raise ValueError(f"unknown Drost catalog tool: {tool}")
    result = await execute_tool(spec.executable, arguments, engagement_id=engagement_id, working_directory=working_directory, stdin=stdin)
    result["drost_tool"] = spec.name
    result["category"] = spec.category
    return result


@mcp.tool(name="drost_bash", description="Run an arbitrary Bash script inside the Drost container from the selected engagement directory. Supports pipelines and redirection; the container is the trust boundary. Execution is asynchronous and client-cancellable.", structured_output=True)
async def drost_bash(engagement_id: str, script: str, working_directory: str = ".", stdin: str | None = None, environment: dict[str, str] | None = None) -> dict[str, Any]:
    return await execute_bash(engagement_id, script, working_directory, stdin, environment)


@mcp.tool(name="drost_python", description="Run inline Python source or an engagement-relative Python file inside the Drost container. Provide exactly one of source or path. Execution uses the Drost Python environment and is asynchronous and client-cancellable.", structured_output=True)
async def drost_python(engagement_id: str, source: str = "", path: str = "", script_arguments: list[str] | None = None, working_directory: str = ".", stdin: str | None = None, environment: dict[str, str] | None = None) -> dict[str, Any]:
    return await execute_python(engagement_id, source, path, script_arguments, working_directory, stdin, environment)


@mcp.tool(name="drost_engagement_create", description="Create a persistent engagement namespace and return its server-generated ID.", structured_output=True)
async def drost_engagement_create(name: str, targets: list[str], objective: str = "") -> dict[str, Any]:
    return await asyncio.to_thread(create_engagement, name, targets, objective)


@mcp.tool(name="drost_engagement_list", description="List persistent Drost engagements available for client-side selection.", structured_output=True)
async def drost_engagement_list() -> dict[str, Any]:
    return await asyncio.to_thread(list_engagements)


@mcp.tool(name="drost_engagement_get", description="Return metadata for one server-generated Drost engagement ID.", structured_output=True)
async def drost_engagement_get(engagement_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(get_engagement, engagement_id)


@mcp.tool(name="drost_workspace_list", description="List files within the Drost engagement workspace.", structured_output=True)
async def drost_workspace_list(engagement_id: str, path: str = ".", recursive: bool = False) -> dict[str, Any]:
    return await asyncio.to_thread(list_workspace, engagement_id, path, recursive)


@mcp.tool(name="drost_workspace_read", description="Read a UTF-8 text file from the Drost engagement workspace.", structured_output=True)
async def drost_workspace_read(engagement_id: str, path: str) -> dict[str, Any]:
    return await asyncio.to_thread(read_workspace_file, engagement_id, path)


@mcp.tool(name="drost_workspace_write", description="Write or append a UTF-8 text file inside the Drost engagement workspace.", structured_output=True)
async def drost_workspace_write(engagement_id: str, path: str, content: str, append: bool = False) -> dict[str, Any]:
    return await asyncio.to_thread(write_workspace_file, engagement_id, path, content, append)


@mcp.tool(name="drost_workspace_delete", description="Delete one file or empty directory inside the Drost engagement workspace.", structured_output=True)
async def drost_workspace_delete(engagement_id: str, path: str) -> dict[str, Any]:
    return await asyncio.to_thread(delete_workspace_path, engagement_id, path)


@mcp.tool(name="drost_finding_report", description="Write a structured Markdown security finding inside the engagement workspace.", structured_output=True)
async def drost_finding_report(engagement_id: str, path: str, title: str, target: str, severity: str, summary: str, evidence: list[str], remediation: str = "") -> dict[str, Any]:
    return await asyncio.to_thread(write_finding_report, engagement_id, path, title, target, severity, summary, evidence, remediation)


@mcp.tool(name="drost_http_request", description="Send a complete HTTP request and return the full response without truncation.", structured_output=True)
async def drost_http_request(method: str, url: str, headers: dict[str, str] | None = None, body: str | None = None, follow_redirects: bool = True) -> dict[str, Any]:
    return await asyncio.to_thread(http_request, method, url, headers, body, follow_redirects)


@mcp.tool(name="drost_graphql_request", description="Send a GraphQL query and return the full server response.", structured_output=True)
async def drost_graphql_request(url: str, query: str, variables: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(graphql_request, url, query, variables, headers)


@mcp.tool(name="drost_jwt_decode", description="Decode JWT header and payload fields without claiming signature verification.", structured_output=True)
def drost_jwt_decode(token: str) -> dict[str, Any]:
    return decode_jwt(token)


@mcp.tool(name="drost_openapi_inspect", description="Extract operations from a JSON OpenAPI document at a URL or engagement-relative path. Prefer this over grep, jq, or Python when the task is OpenAPI operation inventory.", structured_output=True)
async def drost_openapi_inspect(engagement_id: str, source: str) -> dict[str, Any]:
    return await asyncio.to_thread(inspect_openapi, engagement_id, source)


@mcp.tool(name="drost_hibp_password_check", description="Check a password against HIBP using its k-anonymity range API.", structured_output=True)
async def drost_hibp_password_check(password: str) -> dict[str, Any]:
    return await asyncio.to_thread(hibp_password_range, password)


@mcp.tool(name="drost_process_snapshot", description="Return the container process table and active network connections.", structured_output=True)
async def drost_process_snapshot(include_connections: bool = True) -> dict[str, Any]:
    return await asyncio.to_thread(process_snapshot, include_connections)


@mcp.tool(name="drost_angr_analyze", description="Analyze a workspace binary with the angr Python library.", structured_output=True)
async def drost_angr_analyze(engagement_id: str, path: str, auto_load_libs: bool = False) -> dict[str, Any]:
    return await asyncio.to_thread(analyze_binary_with_angr, engagement_id, path, auto_load_libs)


@mcp.tool(name="drost_cve_lookup", description="Retrieve a CVE record from NVD without inventing intelligence.", structured_output=True)
async def drost_cve_lookup(cve_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(lookup_cve, cve_id)


@mcp.tool(name="drost_file_hashes", description="Calculate complete cryptographic hashes for a workspace file.", structured_output=True)
async def drost_file_hashes(engagement_id: str, path: str, algorithms: list[str] | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(hash_workspace_file, engagement_id, path, algorithms)


@mcp.tool(name="drost_openapi_audit", description="Audit an OpenAPI JSON document from a URL or engagement-relative path for operation inventory, declared authentication coverage, path-parameter consistency, sensitive fields, and transport review items. Results are evidence-backed leads and are persisted in the engagement.", structured_output=True)
async def drost_openapi_audit(engagement_id: str, source: str) -> dict[str, Any]:
    return await asyncio.to_thread(audit_openapi, engagement_id, source)


@mcp.tool(name="drost_graphql_audit", description="Assess a GraphQL endpoint using introspection evidence and enumerate query/mutation fields. Results are persisted and do not claim vulnerabilities without response evidence.", structured_output=True)
async def drost_graphql_audit(engagement_id: str, url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(audit_graphql, engagement_id, url, headers)


@mcp.tool(name="drost_jwt_audit", description="Audit JWT structure and claims for evidence-backed review items such as alg=none, missing expiry, issuer mismatch, and audience mismatch. Signature verification is never implied.", structured_output=True)
async def drost_jwt_audit(engagement_id: str, token: str, expected_issuer: str = "", expected_audience: str = "") -> dict[str, Any]:
    return await asyncio.to_thread(audit_jwt, engagement_id, token, expected_issuer, expected_audience)


@mcp.tool(name="drost_api_fuzz", description="Run a caller-bounded, single-parameter API fuzz matrix against an authorized target and preserve complete response evidence. The caller selects payloads and max_requests.", structured_output=True)
async def drost_api_fuzz(engagement_id: str, base_url: str, path: str, method: str, location: str, parameter: str, payloads: list[str], max_requests: int, headers: dict[str, str] | None = None, base_body: str = "", follow_redirects: bool = True) -> dict[str, Any]:
    return await asyncio.to_thread(fuzz_api_parameter, engagement_id, base_url, path, method, location, parameter, payloads, max_requests, headers, base_body, follow_redirects)


@mcp.tool(name="drost_http_session_create", description="Create a persistent engagement-scoped HTTP workbench session with declared target scope, default headers, cookies, TLS, and redirect behavior.", structured_output=True)
async def drost_http_session_create(engagement_id: str, name: str, base_url: str, scope_hosts: list[str] | None = None, include_subdomains: bool = False, default_headers: dict[str, str] | None = None, verify_tls: bool = True, follow_redirects: bool = True) -> dict[str, Any]:
    return await asyncio.to_thread(create_http_session, engagement_id, name, base_url, scope_hosts, include_subdomains, default_headers, verify_tls, follow_redirects)


@mcp.tool(name="drost_http_session_list", description="List persistent HTTP workbench sessions in one engagement.", structured_output=True)
async def drost_http_session_list(engagement_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(list_http_sessions, engagement_id)


@mcp.tool(name="drost_http_session_get", description="Inspect one engagement-scoped HTTP workbench session and its history count.", structured_output=True)
async def drost_http_session_get(engagement_id: str, session_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(get_http_session, engagement_id, session_id)


@mcp.tool(name="drost_http_session_update", description="Update an HTTP workbench session's scope, headers, cookies, match/replace rules, TLS verification, or redirect behavior.", structured_output=True)
async def drost_http_session_update(engagement_id: str, session_id: str, scope_hosts: list[str] | None = None, include_subdomains: bool | None = None, default_headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None, rules: list[dict[str, str]] | None = None, verify_tls: bool | None = None, follow_redirects: bool | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(update_http_session, engagement_id, session_id, scope_hosts, include_subdomains, default_headers, cookies, rules, verify_tls, follow_redirects)


@mcp.tool(name="drost_http_repeater", description="Replay one crafted HTTP request through an engagement workbench session, enforcing scope and applying persisted headers, cookies, and match/replace rules. Complete evidence is retained.", structured_output=True)
async def drost_http_repeater(engagement_id: str, session_id: str, method: str, url: str, headers: dict[str, str] | None = None, body: str | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(repeat_http_request, engagement_id, session_id, method, url, headers, body)


@mcp.tool(name="drost_http_intruder", description="Run caller-bounded sniper-style payload iteration through an HTTP workbench session against one query, header, body, or path location.", structured_output=True)
async def drost_http_intruder(engagement_id: str, session_id: str, method: str, url: str, location: str, parameter: str, payloads: list[str], max_requests: int, headers: dict[str, str] | None = None, body: str = "") -> dict[str, Any]:
    return await asyncio.to_thread(intrude_http_parameter, engagement_id, session_id, method, url, location, parameter, payloads, max_requests, headers, body)


@mcp.tool(name="drost_http_history", description="Read the complete persisted request/response history for one engagement HTTP workbench session.", structured_output=True)
async def drost_http_history(engagement_id: str, session_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(read_http_history, engagement_id, session_id)


@mcp.tool(name="drost_browser_create", description="Launch an isolated headless Chromium context inside the Drost container and return a server-generated browser session ID bound to the engagement.", structured_output=True)
async def drost_browser_create(engagement_id: str, name: str, viewport_width: int = 1440, viewport_height: int = 900, user_agent: str = "", extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    return await BROWSER_MANAGER.create(engagement_id, name, viewport_width, viewport_height, user_agent, extra_headers)


@mcp.tool(name="drost_browser_list", description="List live browser sessions owned by this MCP process for one engagement.", structured_output=True)
async def drost_browser_list(engagement_id: str) -> dict[str, Any]:
    return await BROWSER_MANAGER.list(engagement_id)


@mcp.tool(name="drost_browser_get", description="Inspect one live Drost browser session, including URL, title, network event count, and interception rules.", structured_output=True)
async def drost_browser_get(engagement_id: str, session_id: str) -> dict[str, Any]:
    return await BROWSER_MANAGER.get(engagement_id, session_id)


@mcp.tool(name="drost_browser_close", description="Close a live browser context and release its Chromium resources. Unlike engagement close, this has real process lifecycle semantics.", structured_output=True)
async def drost_browser_close(engagement_id: str, session_id: str) -> dict[str, Any]:
    return await BROWSER_MANAGER.close(engagement_id, session_id)


@mcp.tool(name="drost_browser_navigate", description="Navigate a live Drost browser session to a URL and return the resulting status, headers, URL, and title.", structured_output=True)
async def drost_browser_navigate(engagement_id: str, session_id: str, url: str, wait_until: str = "load") -> dict[str, Any]:
    return await BROWSER_MANAGER.navigate(engagement_id, session_id, url, wait_until)


@mcp.tool(name="drost_browser_snapshot", description="Return the current page text and accessibility-oriented ARIA snapshot, with optional complete HTML.", structured_output=True)
async def drost_browser_snapshot(engagement_id: str, session_id: str, include_html: bool = False) -> dict[str, Any]:
    return await BROWSER_MANAGER.snapshot(engagement_id, session_id, include_html)


@mcp.tool(name="drost_browser_action", description="Perform a selector-based browser action: click, fill, type, clear, press, check, uncheck, select, or hover.", structured_output=True)
async def drost_browser_action(engagement_id: str, session_id: str, action: str, selector: str, value: str = "") -> dict[str, Any]:
    return await BROWSER_MANAGER.action(engagement_id, session_id, action, selector, value)


@mcp.tool(name="drost_browser_screenshot", description="Capture a browser screenshot into the selected engagement and return its relative artifact path.", structured_output=True)
async def drost_browser_screenshot(engagement_id: str, session_id: str, path: str = "", full_page: bool = True) -> dict[str, Any]:
    return await BROWSER_MANAGER.screenshot(engagement_id, session_id, path, full_page)


@mcp.tool(name="drost_browser_evaluate", description="Evaluate JavaScript in the active page and return its serializable result.", structured_output=True)
async def drost_browser_evaluate(engagement_id: str, session_id: str, expression: str, argument: Any = None) -> dict[str, Any]:
    return await BROWSER_MANAGER.evaluate(engagement_id, session_id, expression, argument)


@mcp.tool(name="drost_browser_state", description="Read cookies, localStorage, and sessionStorage from a live browser session.", structured_output=True)
async def drost_browser_state(engagement_id: str, session_id: str) -> dict[str, Any]:
    return await BROWSER_MANAGER.state(engagement_id, session_id)


@mcp.tool(name="drost_browser_set_state", description="Set cookies, localStorage, and sessionStorage in a live browser session.", structured_output=True)
async def drost_browser_set_state(engagement_id: str, session_id: str, cookies: list[dict[str, Any]] | None = None, local_storage: dict[str, str] | None = None, session_storage: dict[str, str] | None = None) -> dict[str, Any]:
    return await BROWSER_MANAGER.set_state(engagement_id, session_id, cookies, local_storage, session_storage)


@mcp.tool(name="drost_browser_network_rules", description="Configure browser request interception with blocked URL patterns, URL replacements, and extra request headers.", structured_output=True)
async def drost_browser_network_rules(engagement_id: str, session_id: str, blocked_patterns: list[str] | None = None, url_replacements: list[dict[str, str]] | None = None, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    return await BROWSER_MANAGER.network_rules(engagement_id, session_id, blocked_patterns, url_replacements, extra_headers)


@mcp.tool(name="drost_browser_network_log", description="Return complete request/response metadata captured by a live browser session, optionally clearing the in-memory log afterward.", structured_output=True)
async def drost_browser_network_log(engagement_id: str, session_id: str, clear: bool = False) -> dict[str, Any]:
    return await BROWSER_MANAGER.network_log(engagement_id, session_id, clear)


@mcp.tool(name="drost_payload_encode", description="Encode text as base64, base64url, hex, URL, or form data.", structured_output=True)
def drost_payload_encode(data: str, encoding: str) -> dict[str, str]:
    return encode_payload(data, encoding)


@mcp.tool(name="drost_extract_indicators", description="Extract URLs, IPv4 addresses, CVEs, and common hashes from supplied text.", structured_output=True)
def drost_extract_indicators(text: str) -> dict[str, list[str]]:
    return extract_indicators(text)


@mcp.tool(name="drost_technology_hints", description="Detect deterministic technology hints in supplied HTTP headers and body text.", structured_output=True)
def drost_technology_hints(headers: dict[str, str] | None = None, body: str = "") -> dict[str, Any]:
    return technology_hints(headers, body)


@mcp.tool(name="drost_engagement_plan", description="Create a deterministic Drost engagement plan using catalog tool names.", structured_output=True)
def drost_engagement_plan(kind: str, target: str, objective: str = "") -> dict[str, Any]:
    return engagement_plan(kind, target, objective)


@mcp.tool(name="drost_recommend_tools", description="Recommend Drost tools using deterministic objective matching.", structured_output=True)
def drost_recommend_tools(objective: str, target_type: str = "web") -> dict[str, Any]:
    return recommend_tools(objective, target_type)


@mcp.tool(name="drost_attack_chain", description="Order caller-supplied findings into a reviewable severity-based attack chain.", structured_output=True)
def drost_attack_chain(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return attack_chain(findings)


@mcp.tool(name="drost_scan_summary", description="Summarize complete Drost tool results without discarding their output.", structured_output=True)
def drost_scan_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    return scan_summary(results)


def self_test() -> dict[str, Any]:
    missing = [spec.name for spec in CATALOG if shutil.which(spec.executable) is None]
    return {
        "status": "healthy",
        "version": __version__,
        "external_tools": len(CATALOG),
        "native_and_workspace_tools": LEGACY_NATIVE_AND_WORKSPACE_TOOL_COUNT,
        "engagement_management_tools": ENGAGEMENT_MANAGEMENT_TOOL_COUNT,
        "general_execution_tools": GENERAL_EXECUTION_TOOL_COUNT,
        "api_audit_tools": API_AUDIT_TOOL_COUNT,
        "http_workbench_tools": HTTP_WORKBENCH_TOOL_COUNT,
        "browser_tools": BROWSER_TOOL_COUNT,
        "total_mcp_tools": len(REGISTERED_CATALOG) + FIXED_MCP_TOOL_COUNT,
        "registered_external_tools": len(REGISTERED_CATALOG),
        "mcp_mode": os.environ.get("DROST_MCP_MODE", "full"),
        "available_external_tools": len(CATALOG) - len(missing),
        "missing_external_tools": missing,
        "workspace": str(WORKSPACE),
        "engagements_root": str(WORKSPACE / "engagements"),
        "browser_runtime": {
            "playwright": __import__("importlib.util").util.find_spec("playwright") is not None,
            "chromium": shutil.which("chromium") or shutil.which("chromium-browser"),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(prog="drost-mcp")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--catalog-json", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
        print(json.dumps(result, indent=2, sort_keys=True))
        if result["missing_external_tools"]:
            raise SystemExit(1)
        return
    if args.catalog_json:
        print(json.dumps([spec.as_dict() for spec in CATALOG], indent=2, sort_keys=True))
        return
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
