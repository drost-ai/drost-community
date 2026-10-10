from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-license-policy.py"


class LicensePolicyTests(unittest.TestCase):
    def run_checker(self, component_names: list[str], policy: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sbom_path = root / "sbom.json"
            policy_path = root / "policy.json"
            sbom_path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "components": [
                            {"type": "application", "name": name}
                            for name in component_names
                        ],
                    }
                ),
                encoding="utf-8",
            )
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    str(CHECKER),
                    str(sbom_path),
                    "--policy",
                    str(policy_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

    def test_blocked_component_fails_release(self) -> None:
        result = self.run_checker(
            ["burpsuite"],
            {
                "blocked_components": [
                    {"name": "burpsuite", "reason": "redistribution unresolved"}
                ],
                "review_required_components": [],
            },
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("BLOCKED: burpsuite", result.stderr)

    def test_go_module_path_matches_component_basename(self) -> None:
        result = self.run_checker(
            ["github.com/tomnomnom/waybackurls"],
            {
                "blocked_components": [
                    {"name": "waybackurls", "reason": "no upstream license"}
                ],
                "review_required_components": [],
            },
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("BLOCKED: waybackurls", result.stderr)

    def test_wpscan_is_blocked(self) -> None:
        result = self.run_checker(
            ["wpscan"],
            {
                "blocked_components": [
                    {
                        "name": "wpscan",
                        "reason": "distribution terms are incompatible",
                    }
                ],
                "review_required_components": [],
            },
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("BLOCKED: wpscan", result.stderr)

    def test_review_item_does_not_fail_release(self) -> None:
        result = self.run_checker(
            ["nmap"],
            {
                "blocked_components": [],
                "review_required_components": [
                    {"name": "nmap", "reason": "review NPSL terms"}
                ],
            },
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("REVIEW: nmap", result.stdout)


if __name__ == "__main__":
    unittest.main()
