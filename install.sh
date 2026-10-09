#!/usr/bin/env bash

set -Eeuo pipefail

readonly DEFAULT_VERSION="1.0.0"
readonly DEFAULT_IMAGE="ghcr.io/drost-ai/drost-community"
readonly DEFAULT_CONTAINER="drost-ai"
readonly DEFAULT_VOLUME="drost-ai-workspace"
readonly MANAGED_LABEL="com.drost.community.managed"

version="${DROST_VERSION:-$DEFAULT_VERSION}"
image_repository="${DROST_IMAGE:-$DEFAULT_IMAGE}"
container_name="${DROST_CONTAINER_NAME:-$DEFAULT_CONTAINER}"
volume_name="${DROST_VOLUME_NAME:-$DEFAULT_VOLUME}"
mode="install"
purge_workspace=false
backup_container=""

usage() {
  cat <<'EOF'
Drost Community Edition installer

Usage:
  install.sh [--version VERSION]
  install.sh --uninstall [--purge-workspace]

Options:
  --version VERSION     Install a specific release (default: 1.0.0).
  --uninstall           Remove the installer-managed Drost container.
  --purge-workspace     Also remove its Docker volume during uninstall.
  -h, --help            Show this help.

Environment overrides:
  DROST_VERSION, DROST_IMAGE, DROST_CONTAINER_NAME, DROST_VOLUME_NAME
EOF
}

die() {
  printf 'drost: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'drost: %s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but was not found."
}

is_managed_container() {
  local candidate="$1"
  [[ "$(docker inspect --format "{{ index .Config.Labels \"${MANAGED_LABEL}\" }}" "$candidate" 2>/dev/null || true)" == "true" ]]
}

is_managed_volume() {
  local candidate="$1"
  [[ "$(docker volume inspect --format "{{ index .Labels \"${MANAGED_LABEL}\" }}" "$candidate" 2>/dev/null || true)" == "true" ]]
}

restore_backup() {
  if [[ -z "$backup_container" ]]; then
    return
  fi

  log "installation failed; restoring the previous managed container"
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  docker rename "$backup_container" "$container_name" >/dev/null 2>&1 || true
  docker start "$container_name" >/dev/null 2>&1 || true
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || die "--version requires a value."
      version="$2"
      shift 2
      ;;
    --uninstall)
      mode="uninstall"
      shift
      ;;
    --purge-workspace)
      purge_workspace=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must look like 1.0.0."
if [[ "$purge_workspace" == true && "$mode" != "uninstall" ]]; then
  die "--purge-workspace may only be used with --uninstall."
fi
require_command docker

docker info >/dev/null 2>&1 || die "Docker is installed but its daemon is not available."

if [[ "$mode" == "uninstall" ]]; then
  if docker container inspect "$container_name" >/dev/null 2>&1; then
    is_managed_container "$container_name" || die "container '$container_name' exists but is not managed by this installer."
    log "removing managed container '$container_name'"
    docker rm -f "$container_name" >/dev/null
  else
    log "managed container '$container_name' is already absent"
  fi

  if [[ "$purge_workspace" == true ]]; then
    if docker volume inspect "$volume_name" >/dev/null 2>&1; then
      is_managed_volume "$volume_name" || die "volume '$volume_name' exists but is not managed by this installer."
      log "removing workspace volume '$volume_name'"
      docker volume rm "$volume_name" >/dev/null
    fi
  else
    log "preserved workspace volume '$volume_name'"
  fi

  log "uninstall complete"
  exit 0
fi

architecture="$(docker info --format '{{.Architecture}}' 2>/dev/null || true)"
case "$architecture" in
  x86_64|amd64|aarch64|arm64) ;;
  *) die "unsupported Docker architecture '$architecture'; use linux/amd64 or linux/arm64." ;;
esac

image="${image_repository}:${version}"
log "pulling ${image}"
docker pull "$image"

docker volume inspect "$volume_name" >/dev/null 2>&1 || \
  docker volume create --label "${MANAGED_LABEL}=true" "$volume_name" >/dev/null

if docker container inspect "$container_name" >/dev/null 2>&1; then
  is_managed_container "$container_name" || die "container '$container_name' already exists and is not managed by this installer. Rename or remove it, then run the installer again."
  backup_container="${container_name}-rollback-$(date +%s)"
  log "preserving the current managed container as '$backup_container' during the upgrade"
  docker stop "$container_name" >/dev/null 2>&1 || true
  docker rename "$container_name" "$backup_container"
  trap restore_backup ERR INT TERM
fi

log "starting '$container_name'"
docker run -d \
  --name "$container_name" \
  --restart unless-stopped \
  --label "${MANAGED_LABEL}=true" \
  --label "com.drost.community.version=${version}" \
  -v "${volume_name}:/workspace" \
  "$image" >/dev/null

log "verifying the MCP server"
docker exec "$container_name" drost-mcp --self-test >/dev/null

if [[ -n "$backup_container" ]]; then
  docker rm "$backup_container" >/dev/null
  backup_container=""
fi
trap - ERR INT TERM

log "Drost Community Edition ${version} is ready"
printf '\nMCP command:\n  docker exec -i %s drost-mcp\n' "$container_name"
