#!/usr/bin/env python3
"""End-to-end stdio MCP smoke test for the Drost capability epic."""

from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import selectors
import subprocess
import sys
import threading


class FixtureHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("set-cookie", "fixture=1; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            body = b"""<!doctype html><html><body>
            <label>Name <input id='name'></label>
            <button id='go' onclick=\"document.querySelector('#output').textContent='clicked:'+document.querySelector('#name').value; fetch('/api/ping')\">Go</button>
            <div id='output'>ready</div></body></html>"""
            self.send_response(200)
            self.send_header("content-type", "text/html")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/openapi.json":
            self._send_json(
                200,
                {
                    "openapi": "3.1.0",
                    "info": {"title": "Epic Fixture", "version": "1"},
                    "paths": {
                        "/api/ping": {
                            "get": {"responses": {"200": {"description": "ok"}}}
                        }
                    },
                },
            )
            return
        self._send_json(200, {"path": self.path, "browser_header": self.headers.get("x-browser", "")})

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length).decode()
        if self.path == "/graphql":
            self._send_json(
                200,
                {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": {"name": "Mutation"},
                            "types": [
                                {"name": "Query", "kind": "OBJECT", "fields": [{"name": "viewer", "args": []}]},
                                {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "updateUser", "args": []}]},
                            ],
                        }
                    }
                },
            )
            return
        self._send_json(200, {"body": raw, "header": self.headers.get("x-test", "")})

    def log_message(self, format, *args):
        return


def send(process, payload):
    process.stdin.write(json.dumps(payload) + "\n")
    process.stdin.flush()


def receive(process, request_id, timeout=30.0):
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


def structured(response):
    if "error" in response:
        raise RuntimeError(response["error"])
    result = response["result"]
    if result.get("isError"):
        raise RuntimeError(result)
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"]
    for item in result.get("content", []):
        if item.get("type") == "text":
            try:
                value = json.loads(item["text"])
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
    raise RuntimeError(f"no structured result: {response}")


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: mcp_epic_smoke.py COMMAND [ARG ...]")
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    fixture_thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    fixture_thread.start()
    base_url = f"http://127.0.0.1:{fixture.server_port}"
    process = subprocess.Popen(
        sys.argv[1:],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    request_id = 0

    def request(name, arguments, timeout=30.0):
        nonlocal request_id
        request_id += 1
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
        )
        return structured(receive(process, request_id, timeout))

    try:
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 1000,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "drost-epic-smoke", "version": "1"},
                },
            },
        )
        initialized = receive(process, 1000)
        if "error" in initialized:
            raise RuntimeError(initialized["error"])
        send(process, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

        engagement = request(
            "drost_engagement_create",
            {"name": "Capability epic smoke", "targets": ["127.0.0.1"]},
        )
        engagement_id = engagement["engagement_id"]

        bash = request(
            "drost_bash",
            {
                "engagement_id": engagement_id,
                "script": "printf '%s' \"$EPIC_VALUE\" | tr a-z A-Z",
                "environment": {"EPIC_VALUE": "bash-ready"},
            },
        )
        assert bash["stdout"] == "BASH-READY"

        python = request(
            "drost_python",
            {
                "engagement_id": engagement_id,
                "source": "import json; print(json.dumps({'python': 'ready'}))",
            },
        )
        assert json.loads(python["stdout"])["python"] == "ready"

        request(
            "drost_workspace_write",
            {"engagement_id": engagement_id, "path": "data.json", "content": '{"items":[1,2,3]}'},
        )
        jq = request(
            "drost_jq",
            {"engagement_id": engagement_id, "arguments": [".items | length", "data.json"]},
        )
        assert jq["stdout"].strip() == "3"

        catalog_summary = request("drost_catalog", {})
        assert catalog_summary["tools"] == []
        catalog_python = request("drost_catalog", {"name": "drost_python", "include_contracts": True})
        assert catalog_python["tools"][0]["category"] == "execution"
        assert "source" in catalog_python["tools"][0]["input_schema"]["properties"]

        openapi = request(
            "drost_openapi_audit",
            {"engagement_id": engagement_id, "source": base_url + "/openapi.json"},
        )
        assert openapi["operation_count"] == 1
        graphql = request(
            "drost_graphql_audit",
            {"engagement_id": engagement_id, "url": base_url + "/graphql"},
        )
        assert graphql["introspection_available"] is True
        encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
        token = f"{encode({'alg': 'none'})}.{encode({'sub': 'test'})}.signature"
        jwt = request("drost_jwt_audit", {"engagement_id": engagement_id, "token": token})
        assert {item["code"] for item in jwt["review_items"]} == {"jwt_alg_none", "jwt_missing_exp"}
        fuzz = request(
            "drost_api_fuzz",
            {
                "engagement_id": engagement_id,
                "base_url": base_url,
                "path": "/api/ping",
                "method": "GET",
                "location": "query",
                "parameter": "probe",
                "payloads": ["one", "two"],
                "max_requests": 2,
            },
        )
        assert fuzz["request_count"] == 2

        http_session = request(
            "drost_http_session_create",
            {"engagement_id": engagement_id, "name": "Fixture", "base_url": base_url},
        )
        http_id = http_session["session_id"]
        request(
            "drost_http_session_update",
            {
                "engagement_id": engagement_id,
                "session_id": http_id,
                "default_headers": {"x-test": "before"},
                "rules": [{"location": "header", "match": "before", "replace": "after"}],
            },
        )
        repeated = request(
            "drost_http_repeater",
            {"engagement_id": engagement_id, "session_id": http_id, "method": "GET", "url": "/api/ping"},
        )
        assert json.loads(repeated["response"]["body"])["browser_header"] == ""
        intruder = request(
            "drost_http_intruder",
            {
                "engagement_id": engagement_id,
                "session_id": http_id,
                "method": "GET",
                "url": "/api/ping",
                "location": "query",
                "parameter": "probe",
                "payloads": ["a", "b"],
                "max_requests": 2,
            },
        )
        assert intruder["request_count"] == 2
        history = request("drost_http_history", {"engagement_id": engagement_id, "session_id": http_id})
        assert len(history["entries"]) == 3

        browser = request("drost_browser_create", {"engagement_id": engagement_id, "name": "Fixture browser"}, timeout=60)
        browser_id = browser["session_id"]
        request(
            "drost_browser_network_rules",
            {"engagement_id": engagement_id, "session_id": browser_id, "extra_headers": {"x-browser": "drost"}},
        )
        navigated = request(
            "drost_browser_navigate",
            {"engagement_id": engagement_id, "session_id": browser_id, "url": base_url + "/"},
            timeout=60,
        )
        assert navigated["status"] == 200
        request(
            "drost_browser_action",
            {"engagement_id": engagement_id, "session_id": browser_id, "action": "fill", "selector": "#name", "value": "Drost"},
        )
        request(
            "drost_browser_action",
            {"engagement_id": engagement_id, "session_id": browser_id, "action": "click", "selector": "#go"},
        )
        snapshot = request(
            "drost_browser_snapshot",
            {"engagement_id": engagement_id, "session_id": browser_id},
        )
        assert "clicked:Drost" in snapshot["text"]
        evaluated = request(
            "drost_browser_evaluate",
            {"engagement_id": engagement_id, "session_id": browser_id, "expression": "() => document.querySelector('#output').textContent"},
        )
        assert evaluated["value"] == "clicked:Drost"
        request(
            "drost_browser_set_state",
            {"engagement_id": engagement_id, "session_id": browser_id, "local_storage": {"token": "fixture"}},
        )
        state = request("drost_browser_state", {"engagement_id": engagement_id, "session_id": browser_id})
        assert state["localStorage"]["token"] == "fixture"
        screenshot = request(
            "drost_browser_screenshot",
            {"engagement_id": engagement_id, "session_id": browser_id},
            timeout=60,
        )
        assert screenshot["size"] > 0
        network = request("drost_browser_network_log", {"engagement_id": engagement_id, "session_id": browser_id})
        assert any(event["type"] == "request" for event in network["events"])
        closed = request("drost_browser_close", {"engagement_id": engagement_id, "session_id": browser_id})
        assert closed["closed"] is True

        print(
            json.dumps(
                {
                    "engagement_id": engagement_id,
                    "bash_ok": True,
                    "python_ok": True,
                    "jq_ok": True,
                    "catalog_search_ok": True,
                    "api_audit_ok": True,
                    "http_workbench_ok": True,
                    "browser_ok": True,
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
        fixture.shutdown()
        fixture.server_close()
        fixture_thread.join(timeout=2)


if __name__ == "__main__":
    main()
