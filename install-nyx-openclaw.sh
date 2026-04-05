#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="${ROOT_DIR}/openguardrails/moltguard"
BASHRC="${HOME}/.bashrc"
NYX_CONFIG_PATH="${HOME}/.config/nyx-guardrails/nyx-guardrails.yaml"
OPENCLAW_EXT_DIR="${HOME}/.openclaw/extensions"
PLUGIN_ID="nyx-guardrails"
PATH_MARKER_START="# >>> nyx-guardrails-path >>>"
PATH_MARKER_END="# <<< nyx-guardrails-path <<<"
ENV_MARKER_START="# >>> nyx-guardrails-openclaw >>>"
ENV_MARKER_END="# <<< nyx-guardrails-openclaw <<<"

log() {
  printf "\n==> %s\n" "$1"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

set_openclaw_allowlist() {
  local current allow_json updated_json
  current="$(openclaw config get plugins.allow 2>/dev/null || echo '[]')"
  updated_json="$(python3 - "$current" <<'PY'
import json
import sys

raw = sys.argv[1].strip()
plugin_id = "nyx-guardrails"

try:
    data = json.loads(raw)
except Exception:
    data = []

if not isinstance(data, list):
    data = []

if plugin_id not in data:
    data.append(plugin_id)

print(json.dumps(data))
PY
)"
  openclaw config set plugins.allow --json "$updated_json"
}

manual_install_plugin() {
  log "Using manual plugin install fallback"
  mkdir -p "$OPENCLAW_EXT_DIR"
  rm -rf "${OPENCLAW_EXT_DIR}/${PLUGIN_ID}"
  cp -R "$PLUGIN_DIR" "${OPENCLAW_EXT_DIR}/${PLUGIN_ID}"
  set_openclaw_allowlist
}

append_or_replace_block() {
  local file="$1"
  local start="$2"
  local end="$3"
  local content="$4"
  touch "$file"
  local tmp
  tmp="$(mktemp)"
  awk -v s="$start" -v e="$end" '
    BEGIN { in_block = 0 }
    $0 == s { in_block = 1; next }
    $0 == e { in_block = 0; next }
    in_block == 0 { print }
  ' "$file" > "$tmp"
  mv "$tmp" "$file"
  {
    echo ""
    echo "$start"
    printf "%s\n" "$content"
    echo "$end"
  } >> "$file"
}

need_cmd cargo
need_cmd npm
need_cmd openclaw

if [[ ! -d "$PLUGIN_DIR" ]]; then
  echo "Plugin directory not found: $PLUGIN_DIR" >&2
  exit 1
fi

log "Configuring HF token for backend"
read -r -p "Enter HF_TOKEN (leave empty to skip): " HF_TOKEN_INPUT
HF_TOKEN_VALUE="${HF_TOKEN_INPUT:-${HF_TOKEN:-}}"

log "Ensuring Nyx config exists at ${NYX_CONFIG_PATH}"
mkdir -p "$(dirname "$NYX_CONFIG_PATH")"
if [[ ! -f "$NYX_CONFIG_PATH" ]]; then
  cp "${ROOT_DIR}/nyx-guardrails.default.yaml" "$NYX_CONFIG_PATH"
fi

log "Installing nyx-guardrails binary globally via cargo"
cargo install --path "$ROOT_DIR" --force

log "Ensuring ~/.cargo/bin is available in bash"
if [[ ":${PATH}:" != *":${HOME}/.cargo/bin:"* ]]; then
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi
append_or_replace_block "$BASHRC" "$PATH_MARKER_START" "$PATH_MARKER_END" 'export PATH="$HOME/.cargo/bin:$PATH"'

log "Configuring OpenClaw/Nyx environment in bash"
append_or_replace_block "$BASHRC" "$ENV_MARKER_START" "$ENV_MARKER_END" "$(cat <<EOF
export NYX_BACKEND_START_CMD="nyx-guardrails --config ${NYX_CONFIG_PATH}"
export NYX_BACKEND_CWD="${ROOT_DIR}"
export NYX_BASE_URL="http://127.0.0.1:8686"
export HF_TOKEN="${HF_TOKEN_VALUE}"
EOF
)"

log "Stopping any running nyx-guardrails backend"
pkill -f nyx-guardrails >/dev/null 2>&1 || true
pkill -f "cargo run --release" >/dev/null 2>&1 || true

log "Building and reinstalling OpenClaw plugin"
cd "$PLUGIN_DIR"
npm install
npm run build
openclaw plugins uninstall "$PLUGIN_ID" >/dev/null 2>&1 || true
openclaw plugins uninstall @nyx/nyx-guardrails >/dev/null 2>&1 || true
openclaw plugins uninstall moltguard >/dev/null 2>&1 || true
openclaw plugins uninstall @openguardrails/moltguard >/dev/null 2>&1 || true

if openclaw plugins install -l . --dangerously-force-unsafe-install; then
  log "Plugin installed via openclaw plugins install"
else
  manual_install_plugin
fi

log "Restarting OpenClaw gateway to load plugin"
openclaw gateway restart || true

log "Starting nyx-guardrails backend"
mkdir -p "${HOME}/.nyx-guardrails"
nohup nyx-guardrails > "${HOME}/.nyx-guardrails/nyx-backend.log" 2>&1 &
sleep 1

log "Install complete"
echo "nyx-guardrails is now globally available."
echo "Run 'source ~/.bashrc' in existing shells to load updated env/path."
echo "Nyx config: ${NYX_CONFIG_PATH}"
echo "Backend log: ${HOME}/.nyx-guardrails/nyx-backend.log"
