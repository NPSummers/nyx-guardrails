#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="${ROOT_DIR}/openclaw-plugin-ngr"

log() {
  printf "\n==> %s\n" "$1"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

need_cmd cargo
need_cmd npm
need_cmd openclaw

if [[ ! -d "$PLUGIN_DIR" ]]; then
  echo "Plugin directory not found: $PLUGIN_DIR" >&2
  exit 1
fi

log "Building nyx-guardrails (release)"
cd "$ROOT_DIR"
cargo build --release

log "Removing previously installed nyx plugin versions (if present)"
openclaw plugins uninstall nyx-guardrails-plugin >/dev/null 2>&1 || true
openclaw plugins uninstall @nyx/openclaw-ngr >/dev/null 2>&1 || true

log "Packing plugin"
cd "$PLUGIN_DIR"
rm -f ./*.tgz
PLUGIN_TGZ="$(npm pack --silent)"
PLUGIN_TGZ_PATH="${PLUGIN_DIR}/${PLUGIN_TGZ}"

log "Installing plugin package"
if openclaw plugins install "$PLUGIN_TGZ_PATH"; then
  :
elif openclaw plugins install "file:${PLUGIN_TGZ_PATH}"; then
  :
else
  echo "Failed to install plugin from ${PLUGIN_TGZ_PATH}" >&2
  exit 1
fi

log "Installed plugin. Current plugin list:"
openclaw plugins list || true

log "Done"
echo "Use /ngr_sanitize on|off|none and /ngr_dashboard in OpenClaw."
