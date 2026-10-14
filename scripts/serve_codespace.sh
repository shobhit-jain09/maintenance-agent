#!/usr/bin/env bash
# Start the agent web UI inside a GitHub Codespace (free personal quota) or any Linux box with Docker.
# The port is forwarded privately by Codespaces AND protected by a random access token printed below.
set -euo pipefail
cd "$(dirname "$0")/.."
export AGENT_UI_TOKEN="${AGENT_UI_TOKEN:-$(openssl rand -hex 16)}"
echo "----------------------------------------------------------------"
echo " Access token for the UI (paste it when the page asks):"
echo "   $AGENT_UI_TOKEN"
echo " Optional, for private repos / PRs:  export AGENT_READ_TOKEN=...  AGENT_WRITE_TOKEN=..."
echo "----------------------------------------------------------------"
exec python -m agent serve --host 0.0.0.0 --port 8080 --sandbox docker "$@"
