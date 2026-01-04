#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/moshell_env.sh"

: "${MOSHELL_USER:?}"
: "${MOSHELL_HOST:?}"
: "${MOSHELL_PASS:?}"
: "${MOSHELL_REMOTE_DIR:?}"

REMOTE_OUT="${MOSHELL_REMOTE_DIR}/out"
REMOTE_FILE="${REMOTE_OUT}/example0.txt"

# Destination on the VM (default: ./example0.txt where you run this script)
LOCAL_FILE="${1:-example0.txt}"

echo "[INFO] Waiting for ${REMOTE_FILE} to become available..."
# Wait up to 120s for a non-empty file
for i in $(seq 1 120); do
  size=$(sshpass -p "$MOSHELL_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${MOSHELL_USER}@${MOSHELL_HOST}" "test -s ${REMOTE_FILE} && stat -c %s ${REMOTE_FILE} || true")
  if [[ -n "${size:-}" ]]; then
    echo "[INFO] Remote file ready (${size} bytes). Attempting download to ${LOCAL_FILE}..."
    break
  fi
  sleep 1
done

# Try up to 3 attempts (handles quick rewrites/rotations)
attempt=1
while (( attempt <= 3 )); do
  echo "[INFO] Download attempt ${attempt} via scp..."
  if sshpass -p "$MOSHELL_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      ${MOSHELL_USER}@${MOSHELL_HOST}:${REMOTE_FILE} "${LOCAL_FILE}"; then
    if [[ -s "${LOCAL_FILE}" ]]; then
      echo "[OK] Step 6: downloaded ${LOCAL_FILE} (${attempt} attempt(s))"
      exit 0
    fi
  fi

  echo "[WARN] scp failed or empty file. Fallback via ssh+cat..."
  # Fallback path: no scp, just stream the bytes over ssh into the local file
  if sshpass -p "$MOSHELL_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "${MOSHELL_USER}@${MOSHELL_HOST}" "test -f ${REMOTE_FILE} && cat ${REMOTE_FILE}" > "${LOCAL_FILE}"; then
    if [[ -s "${LOCAL_FILE}" ]]; then
      echo "[OK] Step 6: downloaded via ssh+cat to ${LOCAL_FILE}"
      exit 0
    fi
  fi

  ((attempt++))
  sleep 1
done

echo "[ERR] Failed to fetch a non-empty ${LOCAL_FILE}. Remote path checked: ${REMOTE_FILE}"
# Helpful diagnostics:
sshpass -p "$MOSHELL_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "${MOSHELL_USER}@${MOSHELL_HOST}" "ls -l ${REMOTE_OUT} || true; ls -l ${REMOTE_FILE} || true"
exit 1
