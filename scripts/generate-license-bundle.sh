#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 IMAGE [OUTPUT_DIRECTORY] [PLATFORM]" >&2
  exit 2
fi

image=$1
output_directory=${2:-licenses}
platform=${3:-}
mkdir -p "$output_directory"

docker_arguments=(run --rm)
if [[ -n "$platform" ]]; then
  docker_arguments+=(--platform "$platform")
fi
docker_arguments+=(--entrypoint sh "$image")

docker "${docker_arguments[@]}" -c \
  'dpkg-query -W -f="\${source:Package}\t\${source:Version}\t\${binary:Package}\t\${Version}\n" | sort -u' \
  >"$output_directory/debian-source-packages.tsv"

docker "${docker_arguments[@]}" -c '
  {
    find /usr/share/drost/licenses -type f -print0 2>/dev/null
    find \
      /usr/share/doc \
      /usr/share/common-licenses \
      /opt/drost-analysis \
      /opt/drost-checkov \
      /opt/drost-kube-hunter \
      /opt/drost-scout \
      /opt/drost-prowler \
      /opt/drost-ai-venv \
      /var/lib/gems \
      -type f \
      \( -iname copyright -o -iname "LICENSE*" -o -iname "COPYING*" -o -iname "NOTICE*" \) \
      -print0 2>/dev/null
  } \
  | sort -z \
  | tar --null --files-from=- --create --gzip --file=-
' >"$output_directory/third-party-license-texts.tar.gz"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output_directory" && sha256sum \
    debian-source-packages.tsv \
    third-party-license-texts.tar.gz \
    >LICENSE-SHA256SUMS)
else
  (cd "$output_directory" && shasum -a 256 \
    debian-source-packages.tsv \
    third-party-license-texts.tar.gz \
    >LICENSE-SHA256SUMS)
fi

echo "wrote $output_directory/debian-source-packages.tsv"
echo "wrote $output_directory/third-party-license-texts.tar.gz"
