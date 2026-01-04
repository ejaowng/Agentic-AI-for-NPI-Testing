
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

if [[ -z "${MOSHELL_PASS:-}" || -z "${MOSHELL_USER:-}" || -z "${MOSHELL_HOST:-}" ]]; then
  echo "[ERR] MOSHELL_USER/HOST/PASS must be set in scripts/moshell_env.sh" >&2
  exit 1
fi

REMOTE_INBOX="${MOSHELL_REMOTE_DIR}/inbox"
REMOTE_OUT="${MOSHELL_REMOTE_DIR}/out"

CMD="mkdir -p \"$REMOTE_INBOX\" \"$REMOTE_OUT\" && echo OK_STEP2"

echo "[INFO] Connecting to ${MOSHELL_USER}@${MOSHELL_HOST} and preparing ${MOSHELL_REMOTE_DIR}/{inbox,out} ..."
sshpass -p "$MOSHELL_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "${MOSHELL_USER}@${MOSHELL_HOST}" "$CMD"

echo "[OK] Step 2 successful."
