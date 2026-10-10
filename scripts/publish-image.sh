#!/usr/bin/env bash
set -euo pipefail

image_repository=${1:-ghcr.io/drost-ai/drost-community}
version=${2:-1.0.0}

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: refusing to publish from a dirty worktree" >&2
  exit 1
fi

if [[ "$image_repository" != "ghcr.io/drost-ai/drost-community" ]]; then
  echo "error: the signed release workflow publishes ghcr.io/drost-ai/drost-community" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: the GitHub CLI is required to dispatch the signed release workflow" >&2
  exit 1
fi

ref=$(git symbolic-ref --quiet --short HEAD || git rev-parse HEAD)
gh workflow run publish-container.yml \
  --repo drost-ai/drost-community \
  --ref "$ref" \
  --field "version=$version"

echo "dispatched signed multi-platform release for $image_repository:$version"
echo "watch it with: gh run list --repo drost-ai/drost-community --workflow publish-container.yml"
