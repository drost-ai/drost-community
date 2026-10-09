import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import drost_ai.engagements as engagements
import drost_ai.workspace as workspace
from drost_ai.native_tools import decode_jwt, encode_payload, extract_indicators, technology_hints
from drost_ai.workflows import attack_chain, engagement_plan, recommend_tools, scan_summary


def b64url(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class NativeToolTests(unittest.TestCase):
    def test_jwt_decode_is_explicitly_unverified(self):
        token = f"{b64url({'alg': 'none'})}.{b64url({'sub': 'test'})}.signature"
        result = decode_jwt(token)
        self.assertEqual(result["payload"]["sub"], "test")
        self.assertFalse(result["verified"])

    def test_payload_encoding_and_indicator_extraction(self):
        self.assertEqual(encode_payload("drost", "base64")["encoded"], "ZHJvc3Q=")
        result = extract_indicators("See CVE-2026-12345 at https://example.test and 127.0.0.1")
        self.assertEqual(result["cves"], ["CVE-2026-12345"])
        self.assertEqual(result["ipv4"], ["127.0.0.1"])

    def test_technology_hints_only_use_supplied_evidence(self):
        result = technology_hints({"server": "nginx", "cf-ray": "abc"}, "")
        self.assertEqual(result["detected"], ["cloudflare", "nginx"])

    def test_deterministic_workflows(self):
        self.assertEqual(engagement_plan("recon", "example.test")["kind"], "recon")
        self.assertEqual(recommend_tools("audit an AWS account")["selected_workflow"], "cloud")
        chain = attack_chain([{"severity": "low"}, {"severity": "critical"}])
        self.assertEqual(chain["steps"][0]["finding"]["severity"], "critical")
        summary = scan_summary([{"success": True}, {"success": False}])
        self.assertEqual((summary["succeeded"], summary["failed"]), (1, 1))

    def test_finding_report_stays_in_workspace(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = workspace.write_finding_report(
                    engagement["engagement_id"],
                    "findings/test.md",
                    "Test finding",
                    "example.test",
                    "high",
                    "Summary",
                    ["Evidence"],
                    "Fix it",
                )
            self.assertEqual(result["path"], "findings/test.md")
            report = Path(engagement["workspace"]) / "findings/test.md"
            self.assertIn("Test finding", report.read_text())


if __name__ == "__main__":
    unittest.main()
