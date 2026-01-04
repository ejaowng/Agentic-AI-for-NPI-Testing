
#!/usr/bin/env bash
set -euo pipefail

# Load env
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/moshell_env.sh"

if ! command -v sshpass >/dev/null 2>&1; then
  echo "[ERR] sshpass not found. Install it (e.g., sudo apt-get install -y sshpass)" >&2
  exit 1
fi

: "${MOSHELL_USER:?MOSHELL_USER not set}"
: "${MOSHELL_HOST:?MOSHELL_HOST not set}"
: "${MOSHELL_PASS:?MOSHELL_PASS not set}"
MOSHELL_REMOTE_DIR="${MOSHELL_REMOTE_DIR:-~/moshell_jobs}"

# Allow passing the local path; default to ./example.mos
LOCAL_MOS="${1:-example.mos}"
if [[ ! -f "$LOCAL_MOS" ]]; then
  echo "[ERR] local file not found: $LOCAL_MOS" >&2
  exit 1
fi

REMOTE_INBOX="${MOSHELL_REMOTE_DIR}/inbox"
REMOTE_DEST="${REMOTE_INBOX}/example.mos"

echo "[INFO] Uploading $LOCAL_MOS -> ${MOSHELL_USER}@${MOSHELL_HOST}:${REMOTE_DEST}"
sshpass -p "$MOSHELL_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "$LOCAL_MOS" "${MOSHELL_USER}@${MOSHELL_HOST}:${REMOTE_DEST}"

# Quick sanity check
echo "[INFO] Verifying on remote..."
sshpass -p "$MOSHELL_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "${MOSHELL_USER}@${MOSHELL_HOST}" "ls -l ${REMOTE_DEST} && echo OK_STEP3"

echo "[OK] Step 3 successful."
