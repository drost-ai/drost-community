import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import drost_ai.engagements as engagements
from drost_ai.api_audit import audit_graphql, audit_jwt, audit_openapi, fuzz_api_parameter
from drost_ai.http_workbench import (
    create_http_session,
    get_http_session,
    intrude_http_parameter,
    read_http_history,
    repeat_http_request,
    update_http_session,
)


class FixtureHandler(BaseHTTPRequestHandler):
    def _send(self, status, payload, headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/redirect-out":
            self.send_response(302)
            self.send_header("location", "https://example.com/")
            self.end_headers()
            return
        self._send(
            200,
            {
                "path": parsed.path,
                "query": parse_qs(parsed.query),
                "header": self.headers.get("x-test", ""),
            },
            {"set-cookie": "fixture=1; Path=/"},
        )

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length).decode()
        if self.path == "/graphql":
            self._send(
                200,
                {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": {"name": "Mutation"},
                            "types": [
                                {"name": "Query", "kind": "OBJECT", "fields": [{"name": "viewer", "args": []}]},
                                {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "updateUser", "args": [{"name": "role"}]}]},
                            ],
                        }
                    }
                },
            )
            return
        self._send(200, {"body": raw, "header": self.headers.get("x-test", "")})

    def log_message(self, format, *args):
        return


class CapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if importlib.util.find_spec("requests") is None:
            raise unittest.SkipTest("requests is installed in the Drost image, not this host interpreter")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.patch = patch.object(engagements, "WORKSPACE", self.root)
        self.patch.start()
        self.engagement = engagements.create_engagement("Test", ["127.0.0.1"])
        self.engagement_id = self.engagement["engagement_id"]

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def test_openapi_graphql_and_jwt_audits_preserve_evidence(self):
        document = {
            "openapi": "3.1.0",
            "info": {"title": "Fixture", "version": "1"},
            "servers": [{"url": self.base_url}],
            "paths": {
                "/users/{user_id}": {
                    "get": {
                        "parameters": [{"name": "token", "in": "query"}],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }
        source = Path(self.engagement["workspace"]) / "openapi.json"
        source.write_text(json.dumps(document), encoding="utf-8")
        openapi = audit_openapi(self.engagement_id, "openapi.json")
        self.assertEqual(openapi["operation_count"], 1)
        self.assertTrue(openapi["review_items"])
        self.assertTrue((Path(self.engagement["workspace"]) / openapi["artifact_path"]).is_file())

        graphql = audit_graphql(self.engagement_id, self.base_url + "/graphql")
        self.assertTrue(graphql["introspection_available"])
        self.assertEqual(graphql["mutation_fields"][0]["name"], "updateUser")

        encode = lambda payload: base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        token = f"{encode({'alg': 'none'})}.{encode({'sub': 'test'})}.signature"
        jwt = audit_jwt(self.engagement_id, token)
        self.assertEqual({item["code"] for item in jwt["review_items"]}, {"jwt_alg_none", "jwt_missing_exp"})
        self.assertFalse(jwt["verified"])

    def test_api_fuzzing_is_caller_bounded(self):
        result = fuzz_api_parameter(
            self.engagement_id,
            self.base_url,
            "/echo",
            "GET",
            "query",
            "value",
            ["one", "two"],
            2,
        )
        self.assertEqual(result["request_count"], 2)
        with self.assertRaises(ValueError):
            fuzz_api_parameter(
                self.engagement_id,
                self.base_url,
                "/echo",
                "GET",
                "query",
                "value",
                ["one", "two"],
                1,
            )

    def test_http_workbench_scope_rules_cookies_intruder_and_history(self):
        state = create_http_session(
            self.engagement_id,
            "Fixture",
            self.base_url,
            default_headers={"x-test": "before"},
        )
        session_id = state["session_id"]
        update_http_session(
            self.engagement_id,
            session_id,
            rules=[{"location": "header", "match": "before", "replace": "after"}],
        )
        repeated = repeat_http_request(self.engagement_id, session_id, "GET", "/echo?base=1")
        parsed = json.loads(repeated["response"]["body"])
        self.assertEqual(parsed["header"], "after")
        self.assertEqual(get_http_session(self.engagement_id, session_id)["cookies"], {"fixture": "1"})

        intruder = intrude_http_parameter(
            self.engagement_id,
            session_id,
            "GET",
            "/echo",
            "query",
            "probe",
            ["a", "b"],
            2,
        )
        self.assertEqual(intruder["request_count"], 2)
        self.assertEqual(len(read_http_history(self.engagement_id, session_id)["entries"]), 3)
        with self.assertRaises(ValueError):
            repeat_http_request(self.engagement_id, session_id, "GET", "https://example.com/")
        with self.assertRaises(ValueError):
            repeat_http_request(self.engagement_id, session_id, "GET", "/redirect-out")


if __name__ == "__main__":
    unittest.main()
