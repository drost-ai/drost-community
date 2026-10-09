"""Direct stdio MCP server for Drost AI."""

from __future__ import annotations

import argparse
import json
import os
import shutil
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from . import __version__
from .catalog import CATALOG, ToolSpec, category_counts
from .executor import WORKSPACE, execute_tool
from .native_tools import analyze_binary_with_angr, decode_jwt, encode_payload, extract_indicators, graphql_request, hash_workspace_file, hibp_password_range, http_request, inspect_openapi, lookup_cve, process_snapshot, technology_hints
from .workspace import delete_workspace_path, list_workspace, read_workspace_file, write_finding_report, write_workspace_file
from .workflows import WORKFLOW_STEPS, attack_chain, engagement_plan, recommend_tools, scan_summary


mcp = FastMCP(
    "Drost AI",
    instructions=(
        "Drost AI is a container-native offensive security toolkit. Use tools only for "
        "authorized targets. Executable-backed tools accept explicit argv tokens and never "
        "invoke a shell."
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


def _external_tool(spec: ToolSpec) -> Callable[..., dict[str, Any]]:
    def run(
        arguments: list[str],
        working_directory: str = ".",
        stdin: str | None = None,
    ) -> dict[str, Any]:
        """Run a Drost container executable with explicit argv tokens."""
        result = execute_tool(
            spec.executable,
            arguments,
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
    mcp.tool(name=_spec.name, description=_spec.description, structured_output=True)(
        _external_tool(_spec)
    )


@mcp.tool(name="drost_catalog", description="List the complete Drost tool catalog and executable availability.", structured_output=True)
def drost_catalog(category: str | None = None, missing_only: bool = False, registered_only: bool = False) -> dict[str, Any]:
    registered_names = {spec.name for spec in REGISTERED_CATALOG}
    tools = []
    for spec in CATALOG:
        if category and spec.category != category:
            continue
        if registered_only and spec.name not in registered_names:
            continue
        path = shutil.which(spec.executable)
        if missing_only and path is not None:
            continue
        tools.append(
            {
                **spec.as_dict(),
                "available": path is not None,
                "path": path,
                "registered_individually": spec.name in registered_names,
            }
        )
    return {
        "version": __version__,
        "workspace": str(WORKSPACE),
        "external_tool_count": len(CATALOG),
        "registered_external_tool_count": len(REGISTERED_CATALOG),
        "mcp_mode": os.environ.get("DROST_MCP_MODE", "full"),
        "workflow_kinds": sorted(WORKFLOW_STEPS),
        "category_counts": category_counts(),
        "tools": tools,
    }


@mcp.tool(name="drost_execute", description="Execute any executable-backed Drost catalog entry by its Drost tool name.", structured_output=True)
def drost_execute(tool: str, arguments: list[str], working_directory: str = ".", stdin: str | None = None) -> dict[str, Any]:
    spec = next((entry for entry in CATALOG if entry.name == tool), None)
    if spec is None:
        raise ValueError(f"unknown Drost catalog tool: {tool}")
    result = execute_tool(spec.executable, arguments, working_directory=working_directory, stdin=stdin)
    result["drost_tool"] = spec.name
    result["category"] = spec.category
    return result


@mcp.tool(name="drost_workspace_list", description="List files within the Drost engagement workspace.", structured_output=True)
def drost_workspace_list(path: str = ".", recursive: bool = False) -> dict[str, Any]:
    return list_workspace(path, recursive)


@mcp.tool(name="drost_workspace_read", description="Read a UTF-8 text file from the Drost engagement workspace.", structured_output=True)
def drost_workspace_read(path: str) -> dict[str, Any]:
    return read_workspace_file(path)


@mcp.tool(name="drost_workspace_write", description="Write or append a UTF-8 text file inside the Drost engagement workspace.", structured_output=True)
def drost_workspace_write(path: str, content: str, append: bool = False) -> dict[str, Any]:
    return write_workspace_file(path, content, append)


@mcp.tool(name="drost_workspace_delete", description="Delete one file or empty directory inside the Drost engagement workspace.", structured_output=True)
def drost_workspace_delete(path: str) -> dict[str, Any]:
    return delete_workspace_path(path)


@mcp.tool(name="drost_finding_report", description="Write a structured Markdown security finding inside the engagement workspace.", structured_output=True)
def drost_finding_report(path: str, title: str, target: str, severity: str, summary: str, evidence: list[str], remediation: str = "") -> dict[str, Any]:
    return write_finding_report(path, title, target, severity, summary, evidence, remediation)


@mcp.tool(name="drost_http_request", description="Send a complete HTTP request and return the full response without truncation.", structured_output=True)
def drost_http_request(method: str, url: str, headers: dict[str, str] | None = None, body: str | None = None, follow_redirects: bool = True) -> dict[str, Any]:
    return http_request(method, url, headers, body, follow_redirects)


@mcp.tool(name="drost_graphql_request", description="Send a GraphQL query and return the full server response.", structured_output=True)
def drost_graphql_request(url: str, query: str, variables: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    return graphql_request(url, query, variables, headers)


@mcp.tool(name="drost_jwt_decode", description="Decode JWT header and payload fields without claiming signature verification.", structured_output=True)
def drost_jwt_decode(token: str) -> dict[str, Any]:
    return decode_jwt(token)


@mcp.tool(name="drost_openapi_inspect", description="Inspect a JSON OpenAPI document from a URL or workspace file.", structured_output=True)
def drost_openapi_inspect(source: str) -> dict[str, Any]:
    return inspect_openapi(source)


@mcp.tool(name="drost_hibp_password_check", description="Check a password against HIBP using its k-anonymity range API.", structured_output=True)
def drost_hibp_password_check(password: str) -> dict[str, Any]:
    return hibp_password_range(password)


@mcp.tool(name="drost_process_snapshot", description="Return the container process table and active network connections.", structured_output=True)
def drost_process_snapshot(include_connections: bool = True) -> dict[str, Any]:
    return process_snapshot(include_connections)


@mcp.tool(name="drost_angr_analyze", description="Analyze a workspace binary with the angr Python library.", structured_output=True)
def drost_angr_analyze(path: str, auto_load_libs: bool = False) -> dict[str, Any]:
    return analyze_binary_with_angr(path, auto_load_libs)


@mcp.tool(name="drost_cve_lookup", description="Retrieve a CVE record from NVD without inventing intelligence.", structured_output=True)
def drost_cve_lookup(cve_id: str) -> dict[str, Any]:
    return lookup_cve(cve_id)


@mcp.tool(name="drost_file_hashes", description="Calculate complete cryptographic hashes for a workspace file.", structured_output=True)
def drost_file_hashes(path: str, algorithms: list[str] | None = None) -> dict[str, Any]:
    return hash_workspace_file(path, algorithms)


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
        "native_and_workspace_tools": 23,
        "registered_external_tools": len(REGISTERED_CATALOG),
        "mcp_mode": os.environ.get("DROST_MCP_MODE", "full"),
        "available_external_tools": len(CATALOG) - len(missing),
        "missing_external_tools": missing,
        "workspace": str(WORKSPACE),
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
