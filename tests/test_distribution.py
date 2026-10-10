from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
PUBLISH_WORKFLOW = (ROOT / ".github/workflows/publish-container.yml").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


class DistributionComplianceTests(unittest.TestCase):
    def test_base_images_are_digest_pinned(self) -> None:
        from_lines = [line for line in DOCKERFILE.splitlines() if line.startswith("FROM ")]
        self.assertGreaterEqual(len(from_lines), 4)
        self.assertTrue(all("@sha256:" in line for line in from_lines))

    def test_mutable_download_selectors_are_not_used(self) -> None:
        self.assertNotRegex(DOCKERFILE, re.compile(r"go install .*@latest"))
        self.assertNotIn("/releases/latest/", DOCKERFILE)

    def test_restricted_packages_are_not_installed(self) -> None:
        install_block = DOCKERFILE.split("apt-get install -y --no-install-recommends", 1)[1]
        install_block = install_block.split("&& apt-get clean", 1)[0]
        packages = {
            line.strip().removesuffix("\\").strip()
            for line in install_block.splitlines()
            if line.strip()
        }
        self.assertTrue({"burpsuite", "maltego", "wpscan"}.isdisjoint(packages))
        self.assertIn("whatweb", packages)
        self.assertNotIn("github.com/tomnomnom/waybackurls", DOCKERFILE)

    def test_kali_package_set_uses_the_stable_release_snapshot(self) -> None:
        self.assertIn("kalilinux/kali-last-release:latest@sha256:", DOCKERFILE)

    def test_notices_and_source_offer_are_embedded(self) -> None:
        self.assertIn("THIRD_PARTY_NOTICES.md SOURCE_OFFER.md", DOCKERFILE)
        self.assertIn("/usr/share/drost/licenses", DOCKERFILE)

    def test_release_workflow_signs_provenance_and_sbom_attestations(self) -> None:
        self.assertGreaterEqual(PUBLISH_WORKFLOW.count("uses: actions/attest@v4"), 3)
        self.assertIn("sbom-path:", PUBLISH_WORKFLOW)
        self.assertIn("push-to-registry: true", PUBLISH_WORKFLOW)
        self.assertIn("LicenseRef-Drost-Third-Party", PUBLISH_WORKFLOW)

    def test_readme_advertises_current_full_tool_count(self) -> None:
        self.assertIn("159 offensive-security MCP tools", README)
        self.assertNotIn("128 offensive-security tools", README)


if __name__ == "__main__":
    unittest.main()
