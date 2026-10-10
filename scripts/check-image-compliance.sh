#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 IMAGE [PLATFORM]" >&2
  exit 2
fi

image=$1
platform=${2:-}
docker_arguments=(run --rm)
if [[ -n "$platform" ]]; then
  docker_arguments+=(--platform "$platform")
fi
docker_arguments+=(--entrypoint sh "$image" -c)

docker "${docker_arguments[@]}" '
  set -eu
  for forbidden in burpsuite maltego wpscan waybackurls; do
    if command -v "$forbidden" >/dev/null 2>&1; then
      echo "forbidden executable present: $forbidden" >&2
      exit 1
    fi
  done
  for required in whatweb urlfinder subzy nmap vol; do
    command -v "$required" >/dev/null 2>&1 || {
      echo "required executable missing: $required" >&2
      exit 1
    }
  done
  test -f /usr/share/drost/licenses/drost-ai/THIRD_PARTY_NOTICES.md
  test -f /usr/share/drost/licenses/drost-ai/SOURCE_OFFER.md
  test -d /usr/share/drost/licenses/go
  test -d /usr/share/drost/licenses/rust
  test -f /usr/share/doc/nmap/copyright
  echo "image compliance smoke check passed"
'
