#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 IMAGE [OUTPUT_DIRECTORY] [PLATFORM]" >&2
  echo "example: $0 registry:ghcr.io/drost-ai/drost-community@sha256:... sbom linux/amd64" >&2
  exit 2
fi

image=$1
output_directory=${2:-sbom}
platform=${3:-}

if ! command -v syft >/dev/null 2>&1; then
  echo "error: syft is required: https://github.com/anchore/syft" >&2
  exit 1
fi

mkdir -p "$output_directory"

suffix=${platform//\//-}
if [[ -z "$suffix" ]]; then
  suffix=default
fi

cyclonedx="$output_directory/drost-community-$suffix.cdx.json"
spdx="$output_directory/drost-community-$suffix.spdx.json"

arguments=(
  scan
  "$image"
  --override-default-catalogers package
  --select-catalogers=-file
  --output "cyclonedx-json=$cyclonedx"
  --output "spdx-json=$spdx"
)

if [[ -n "$platform" ]]; then
  arguments+=(--platform "$platform")
fi

SYFT_CHECK_FOR_APP_UPDATE=false \
SYFT_FILE_METADATA_SELECTION=none \
SYFT_PACKAGE_EXCLUDE_BINARY_OVERLAP_BY_OWNERSHIP=false \
SYFT_RELATIONSHIPS_PACKAGE_FILE_OWNERSHIP=false \
SYFT_RELATIONSHIPS_PACKAGE_FILE_OWNERSHIP_OVERLAP=false \
  syft "${arguments[@]}"

cyclonedx_name=$(basename "$cyclonedx")
spdx_name=$(basename "$spdx")
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output_directory" && sha256sum "$cyclonedx_name" "$spdx_name" >"SHA256SUMS-$suffix")
else
  (cd "$output_directory" && shasum -a 256 "$cyclonedx_name" "$spdx_name" >"SHA256SUMS-$suffix")
fi

python3 scripts/check-license-policy.py "$cyclonedx"

echo "wrote $cyclonedx"
echo "wrote $spdx"
