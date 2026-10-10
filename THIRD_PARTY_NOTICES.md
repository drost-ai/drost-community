# Drost Community Edition third-party notices

Drost Community Edition source code authored by Drost is licensed under the
Apache License 2.0. The container image is a collection of independently
licensed software. The repository's Apache-2.0 license does not replace or
override any third-party license.

## Release evidence

The official v1.0.0 multi-platform image is published at:

```text
ghcr.io/drost-ai/drost-community:1.0.0
```

Resolve the current immutable index and platform digests directly from the
registry with `docker buildx imagetools inspect`. The release is built from the
Git revision recorded in its OCI metadata and carries BuildKit provenance and
SBOM attestations. Digests are registry-generated publication evidence and are
therefore not embedded recursively inside the image whose digest they identify.

Generate release-specific SPDX and CycloneDX inventories with
[`scripts/generate-sbom.sh`](scripts/generate-sbom.sh). The SBOM, the installed
license files, and this document must be considered together; this document is
not a substitute for the complete package-level inventory.

## License material retained in the image

Kali and Debian packages retain their package copyright files at
`/usr/share/doc/<package>/copyright` and common license texts at
`/usr/share/common-licenses`. Python distributions generally retain license
and metadata files in their `.dist-info` directories, and Ruby gems retain
license metadata in their gem specifications or installed source trees.

The remediated Dockerfile additionally copies license and notice files found in
the Go and Rust module caches and the direct source builds into
`/usr/share/drost/licenses`. Release verification checks that this material and
Drost's corresponding-source offer are present.

## Direct non-Kali additions

The following components are installed directly by the Dockerfile rather than
solely through Kali's package manager. Versions are from the audited ARM64
build where they could be recovered; unpinned inputs must be pinned before the
next release.

| Component | Audited version | Upstream | Declared license | Current status |
| --- | --- | --- | --- | --- |
| Drost Community Edition | 1.0.0 | <https://github.com/drost-ai/drost-community> | Apache-2.0 | Drost-owned source |
| MCP Python SDK | 1.22.0 | <https://github.com/modelcontextprotocol/python-sdk> | MIT | Notice required |
| Playwright for Python | 1.55.0 | <https://github.com/microsoft/playwright-python> | Apache-2.0 | Notice required |
| Requests | 2.34.2 | <https://github.com/psf/requests> | Apache-2.0 | Notice required |
| angr | 10.0.0 | <https://github.com/angr/angr> | BSD-2-Clause | Notice required |
| Volatility 3 | 2.28.0 | <https://github.com/volatilityfoundation/volatility3> | Volatility Software License 1.0 | Include full custom license |
| Checkov | 3.3.20 | <https://github.com/bridgecrewio/checkov> | Apache-2.0 | Notice required |
| kube-hunter | 0.6.8 | <https://github.com/aquasecurity/kube-hunter> | Apache-2.0 | Notice required |
| ScoutSuite | 5.14.0 | <https://github.com/nccgroup/ScoutSuite> | GPL-2.0-only | Source obligations apply |
| Prowler | 3.11.3 | <https://github.com/prowler-cloud/prowler> | Apache-2.0 | Notice required |
| zsteg | 0.2.14 | <https://github.com/zed-0xff/zsteg> | MIT | Notice required |
| one_gadget | 2.1.1 | <https://github.com/david942j/one_gadget> | MIT | Notice required |
| anew | 0.1.1 | <https://github.com/tomnomnom/anew> | MIT | Pinned module; module licenses copied |
| URLFinder | 0.0.3 | <https://github.com/projectdiscovery/urlfinder> | MIT | Replaces unlicensed waybackurls; copy module licenses |
| subzy | 1.2.1 | <https://github.com/PentestPad/subzy> | GPL | Replaces WPScan; source obligations apply |
| Jaeles | commit `d40305ffe42a` | <https://github.com/jaeles-project/jaeles> | MIT | Copy module licenses |
| kube-bench | 0.16.0 | <https://github.com/aquasecurity/kube-bench> | Apache-2.0 | Copy module licenses and NOTICE |
| Terrascan | 1.19.9 | <https://github.com/tenable/terrascan> | Apache-2.0 | Copy license/NOTICE |
| x8 | 4.3.2 | <https://github.com/Sh1Yo/x8> | GPL-3.0-or-later | Source obligations apply; crate licenses copied |
| pwninit | 3.3.3 | <https://github.com/io12/pwninit> | MIT | Built from pinned crate; crate licenses copied |
| HashPump-partialhash | commit `b822764fa71209858c91378736d43d082c674e96` | <https://github.com/mheistermann/HashPump-partialhash> | MIT | License copied |
| Docker Bench for Security | commit `154869da6418089decf7e1ab0cfca0e1cdfc5c49` | <https://github.com/docker/docker-bench-security> | Apache-2.0 | Pinned commit; license retained in cloned tree |

Each component also has transitive dependencies. Their package URLs, versions,
checksums, and detected license expressions belong in the release SBOM.

## Components deliberately excluded

The remediated image deliberately excludes these components. The license policy
fails a release if any of them reappear, including as a transitive package.

| Component | Evidence | Required resolution |
| --- | --- | --- |
| Burp Suite Community Edition | No clean public-container redistribution grant was established. | Replaced at the catalog level by the existing ZAP, mitmproxy, HTTP workbench, and browser tooling; `subzy` occupies the released executable slot. |
| waybackurls | No upstream license or affirmative redistribution grant was found. | Replaced by MIT-licensed URLFinder; GAU also remains available. |
| Maltego | Redistribution rights were not established and it was not exposed as a distinct MCP tool. | Removed; SpiderFoot remains the graph/OSINT-oriented alternative. |
| WPScan | Its public-source terms restrict commercialization and value-added products. | Removed; GPL-licensed WhatWeb provides CMS and web-technology fingerprinting. |

## Components with special obligations

| Component | Reason |
| --- | --- |
| Nmap | Nmap 7.99 remains a separately executed program under NPSL-0.94. Preserve `/usr/share/doc/nmap/copyright`, identify the exact Kali source package, honor the corresponding-source offer, and do not describe Nmap itself as Apache-2.0. Organizations requiring a proprietary integration should obtain their own Nmap OEM advice or license. |
| Volatility 3 | Preserve the complete Volatility Software License 1.0 text and corresponding source information. |
| GPL/AGPL/CPL components | The image contains GPL, AGPL, LGPL, CPL, and other reciprocal licenses. Preserve notices and provide complete corresponding source or the published source offer for the exact binaries distributed. |
| Nikto databases | The database files are all-rights-reserved and may be distributed and used only with the full Nikto package. Keep the package intact and preserve its license text. |

## Release requirements

A public image is ready for promotion only when all of the following are true:

1. Every direct non-package-manager build input is pinned to a version, commit,
   or digest as appropriate; the Kali package set is tied to the
   `kali-last-snapshot` repository and recorded in the release SBOM/source
   manifest.
2. The excluded components above are absent from both platform images.
3. SPDX and CycloneDX SBOMs are generated for both published platform digests.
4. License and notice texts for source-built and downloaded binaries are copied
   into the final image.
5. Exact corresponding-source locations are published for reciprocal-license
   components.
6. The OCI license label describes the mixed-license image accurately rather
   than implying that every image component is Apache-2.0.
7. The SBOMs, notice bundle, image digests, and provenance attestations are
   attached to the release and verified after publication.

This inventory is an engineering compliance aid, not legal advice. Questions
about custom licenses or whether a particular combination is a derivative work
should be resolved by qualified counsel or the relevant copyright holder.
