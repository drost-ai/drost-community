#!/usr/bin/env python3
"""Small MCP stdio client used to verify Drost without an MCP SDK."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import sys
import time


def send(process: subprocess.Popen[str], payload: dict) -> None:
    assert process.stdin is not None
    process.stdin.write(json.dumps(payload) + "\n")
    process.stdin.flush()


def receive(process: subprocess.Popen[str], request_id: int, timeout: float = 30.0) -> dict:
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    while selector.select(timeout):
        line = process.stdout.readline()
        if not line:
            break
        payload = json.loads(line)
        if payload.get("id") == request_id:
            return payload
    raise RuntimeError(f"no MCP response for request {request_id}")


def structured_result(response: dict) -> dict:
    result = response.get("result", {})
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured
    for item in result.get("content", []):
        if item.get("type") == "text":
            try:
                payload = json.loads(item["text"])
            except (KeyError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                return payload
    raise RuntimeError(f"MCP response has no structured object: {response}")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: mcp_smoke.py COMMAND [ARG ...]")
    process = subprocess.Popen(
        sys.argv[1:],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    compact = os.environ.get("DROST_SMOKE_COMPACT") == "1"
    try:
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "drost-smoke", "version": "1"},
                },
            },
        )
        initialized = receive(process, 1)
        if "error" in initialized:
            raise RuntimeError(initialized["error"])
        send(process, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        send(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listed = receive(process, 2)
        tools = listed["result"]["tools"]
        names = [tool["name"] for tool in tools]
        expected_tool_count = 26 if compact else 132
        if len(names) != expected_tool_count:
            raise RuntimeError(f"expected {expected_tool_count} MCP tools; found {len(names)}")
        if len(names) != len(set(names)):
            raise RuntimeError("duplicate MCP tool names")
        if not all(name.startswith("drost_") for name in names):
            raise RuntimeError("non-Drost tool name found")
        engagement_tools = {"drost_engagement_create", "drost_engagement_list", "drost_engagement_get"}
        if not engagement_tools.issubset(names):
            raise RuntimeError(f"missing engagement tools: {sorted(engagement_tools - set(names))}")
        executable_name = "drost_execute" if compact else "drost_nmap"
        executable_definition = next(tool for tool in tools if tool["name"] == executable_name)
        executable_schema = executable_definition["inputSchema"]
        expected_properties = {"tool", "engagement_id", "arguments", "working_directory", "stdin"} if compact else {"engagement_id", "arguments", "working_directory", "stdin"}
        if set(executable_schema.get("properties", {})) != expected_properties:
            raise RuntimeError(f"unexpected Drost executable schema: {executable_schema}")
        expected_required = {"tool", "engagement_id", "arguments"} if compact else {"engagement_id", "arguments"}
        if set(executable_schema.get("required", [])) != expected_required:
            raise RuntimeError(f"unexpected required fields: {executable_schema}")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "drost_catalog", "arguments": {}},
            },
        )
        called = receive(process, 3)
        if "error" in called:
            raise RuntimeError(called["error"])
        catalog_payload = structured_result(called)
        if "drost_grep" not in {tool["name"] for tool in catalog_payload["tools"]}:
            raise RuntimeError("drost_grep is missing from the complete catalog")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "drost_engagement_create",
                    "arguments": {
                        "name": "Drost MCP smoke test",
                        "targets": ["127.0.0.1"],
                        "objective": "Validate engagement isolation",
                    },
                },
            },
        )
        engagement_called = receive(process, 4)
        if "error" in engagement_called or engagement_called["result"].get("isError", False):
            raise RuntimeError(engagement_called.get("error") or engagement_called["result"])
        engagement = structured_result(engagement_called)
        engagement_id = engagement["engagement_id"]
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": executable_name,
                    "arguments": (
                        {"tool": "drost_nmap", "engagement_id": engagement_id, "arguments": ["--version"]}
                        if compact
                        else {"engagement_id": engagement_id, "arguments": ["--version"]}
                    ),
                },
            },
        )
        nmap_called = receive(process, 5)
        if "error" in nmap_called or nmap_called["result"].get("isError", False):
            raise RuntimeError(nmap_called.get("error") or nmap_called["result"])
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "drost_engagement_plan",
                    "arguments": {"kind": "recon", "target": "127.0.0.1"},
                },
            },
        )
        plan_called = receive(process, 6)
        if "error" in plan_called or plan_called["result"].get("isError", False):
            raise RuntimeError(plan_called.get("error") or plan_called["result"])
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "drost_workspace_write",
                    "arguments": {"engagement_id": engagement_id, "path": "smoke/mcp.txt", "content": "first-engagement\n"},
                },
            },
        )
        write_called = receive(process, 7)
        if "error" in write_called or write_called["result"].get("isError", False):
            raise RuntimeError(write_called.get("error") or write_called["result"])
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "drost_workspace_read", "arguments": {"engagement_id": engagement_id, "path": "smoke/mcp.txt"}},
            },
        )
        read_called = receive(process, 8)
        if "error" in read_called or read_called["result"].get("isError", False):
            raise RuntimeError(read_called.get("error") or read_called["result"])
        if structured_result(read_called)["content"] != "first-engagement\n":
            raise RuntimeError("first engagement returned unexpected workspace content")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "drost_engagement_create",
                    "arguments": {"name": "Second smoke engagement", "targets": ["localhost"]},
                },
            },
        )
        second_called = receive(process, 9)
        if "error" in second_called or second_called["result"].get("isError", False):
            raise RuntimeError(second_called.get("error") or second_called["result"])
        second_id = structured_result(second_called)["engagement_id"]
        if second_id == engagement_id:
            raise RuntimeError("server generated duplicate engagement IDs")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "drost_workspace_write",
                    "arguments": {"engagement_id": second_id, "path": "smoke/mcp.txt", "content": "second-engagement\n"},
                },
            },
        )
        second_write = receive(process, 10)
        if "error" in second_write or second_write["result"].get("isError", False):
            raise RuntimeError(second_write.get("error") or second_write["result"])
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": "drost_workspace_read", "arguments": {"engagement_id": engagement_id, "path": "smoke/mcp.txt"}},
            },
        )
        isolated_read = receive(process, 11)
        if structured_result(isolated_read)["content"] != "first-engagement\n":
            raise RuntimeError("engagement workspace isolation failed")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "drost_execute" if compact else "drost_grep",
                    "arguments": (
                        {
                            "tool": "drost_grep",
                            "engagement_id": engagement_id,
                            "arguments": ["-n", "first-engagement", "smoke/mcp.txt"],
                        }
                        if compact
                        else {
                            "engagement_id": engagement_id,
                            "arguments": ["-n", "first-engagement", "smoke/mcp.txt"],
                        }
                    ),
                },
            },
        )
        grep_called = receive(process, 12)
        if "first-engagement" not in structured_result(grep_called)["stdout"]:
            raise RuntimeError("drost_grep did not search the engagement workspace")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": executable_name,
                    "arguments": (
                        {
                            "tool": "drost_nmap",
                            "engagement_id": engagement_id,
                            "arguments": ["-Pn", "--scan-delay", "1s", "-p", "1-100", "127.0.0.1"],
                        }
                        if compact
                        else {
                            "engagement_id": engagement_id,
                            "arguments": ["-Pn", "--scan-delay", "1s", "-p", "1-100", "127.0.0.1"],
                        }
                    ),
                },
            },
        )
        time.sleep(0.3)
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 14,
                "method": "tools/call",
                "params": {"name": "drost_engagement_list", "arguments": {}},
            },
        )
        concurrent_called = receive(process, 14, timeout=5.0)
        if "error" in concurrent_called or concurrent_called["result"].get("isError", False):
            raise RuntimeError("long executable blocked a concurrent MCP call")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 13, "reason": "Drost cancellation smoke test"},
            },
        )
        time.sleep(0.3)
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 15,
                "method": "tools/call",
                "params": {
                    "name": "drost_process_snapshot",
                    "arguments": {"include_connections": False},
                },
            },
        )
        snapshot_called = receive(process, 15, timeout=5.0)
        processes = structured_result(snapshot_called)["processes"]
        if any("--scan-delay" in " ".join(item.get("cmdline") or []) for item in processes):
            raise RuntimeError("cancelled executable remained alive in the container")
        print(
            json.dumps(
                {
                    "server": initialized["result"]["serverInfo"],
                    "tool_count": len(names),
                    "first_tools": names[:5],
                    "executable_schema": executable_schema,
                    "compact_mode": compact,
                    "catalog_call_ok": not called["result"].get("isError", False),
                    "nmap_call_ok": True,
                    "engagement_plan_ok": True,
                    "workspace_roundtrip_ok": True,
                    "engagement_isolation_ok": True,
                    "grep_call_ok": True,
                    "concurrent_call_ok": True,
                    "cancellation_cleanup_ok": True,
                    "engagement_id": engagement_id,
                    "second_engagement_id": second_id,
                },
                indent=2,
            )
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    main()
