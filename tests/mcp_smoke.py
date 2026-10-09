#!/usr/bin/env python3
"""Small MCP stdio client used to verify Drost without an MCP SDK."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import sys


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
        minimum_tools = 20 if compact else 110
        if len(names) < minimum_tools:
            raise RuntimeError(f"catalog unexpectedly small: {len(names)}")
        if len(names) != len(set(names)):
            raise RuntimeError("duplicate MCP tool names")
        if not all(name.startswith("drost_") for name in names):
            raise RuntimeError("non-Drost tool name found")
        executable_name = "drost_execute" if compact else "drost_nmap"
        executable_definition = next(tool for tool in tools if tool["name"] == executable_name)
        executable_schema = executable_definition["inputSchema"]
        expected_properties = {"tool", "arguments", "working_directory", "stdin"} if compact else {"arguments", "working_directory", "stdin"}
        if set(executable_schema.get("properties", {})) != expected_properties:
            raise RuntimeError(f"unexpected Drost executable schema: {executable_schema}")
        expected_required = ["tool", "arguments"] if compact else ["arguments"]
        if executable_schema.get("required") != expected_required:
            raise RuntimeError(f"unexpected required fields: {executable_schema}")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "drost_catalog", "arguments": {"missing_only": True}},
            },
        )
        called = receive(process, 3)
        if "error" in called:
            raise RuntimeError(called["error"])
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": executable_name,
                    "arguments": (
                        {"tool": "drost_nmap", "arguments": ["--version"]}
                        if compact
                        else {"arguments": ["--version"]}
                    ),
                },
            },
        )
        nmap_called = receive(process, 4)
        if "error" in nmap_called or nmap_called["result"].get("isError", False):
            raise RuntimeError(nmap_called.get("error") or nmap_called["result"])
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "drost_engagement_plan",
                    "arguments": {"kind": "recon", "target": "127.0.0.1"},
                },
            },
        )
        plan_called = receive(process, 5)
        if "error" in plan_called or plan_called["result"].get("isError", False):
            raise RuntimeError(plan_called.get("error") or plan_called["result"])
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "drost_workspace_write",
                    "arguments": {"path": "smoke/mcp.txt", "content": "drost-mcp-smoke\n"},
                },
            },
        )
        write_called = receive(process, 6)
        if "error" in write_called or write_called["result"].get("isError", False):
            raise RuntimeError(write_called.get("error") or write_called["result"])
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "drost_workspace_read", "arguments": {"path": "smoke/mcp.txt"}},
            },
        )
        read_called = receive(process, 7)
        if "error" in read_called or read_called["result"].get("isError", False):
            raise RuntimeError(read_called.get("error") or read_called["result"])
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
