# Corresponding source offer

Drost Community Edition images contain independently licensed programs,
including software distributed under the GPL, AGPL, LGPL, CPL, Nmap Public
Source License, Volatility Software License, and other licenses that require
source availability or preservation of specific terms.

For each official Drost Community Edition container image distributed by Drost,
Drost will provide the complete corresponding source code that it is required
to provide under those licenses. This offer is valid for at least three years
from the date Drost last distributes the applicable image version.

To request source, open an issue at
<https://github.com/drost-ai/drost-community/issues> with:

- the title `Corresponding source request`;
- the image reference and immutable digest;
- the requested component or source package;
- whether electronic delivery is sufficient.

Electronic delivery is provided without charge. If physical media is
requested and legally required, Drost may charge no more than the reasonable
cost of performing that distribution.

## Source locations

- Drost-authored source and build scripts are published in this repository.
- Kali package source identifiers and versions are exported for each release
  by `scripts/generate-license-bundle.sh`.
- Go and Rust modules are identified by version in the release SBOM; their
  license texts are copied into `/usr/share/drost/licenses` in the image.
- Direct source builds and their immutable versions or commits are recorded in
  `THIRD_PARTY_NOTICES.md` and the Dockerfile.

The source manifest, SPDX SBOM, CycloneDX SBOM, license bundle, checksums, and
image provenance must be published together for each release.
