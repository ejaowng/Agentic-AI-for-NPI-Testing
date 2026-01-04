#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/moshell_env.sh"

: "${MOSHELL_USER:?}"
: "${MOSHELL_HOST:?}"
: "${MOSHELL_PASS:?}"
: "${MOSHELL_REMOTE_DIR:?}"

# CRGNB IP/host to connect to (pass raw IPv6 or IPv4). Example call:
#   bash ~/swipl/scripts/moshell_step4_run_once.sh '2001:1b70:4294:fd0a::31'
CRGNB_IP="${1:-${CRGNB_IP:-}}"
if [[ -z "$CRGNB_IP" ]]; then
  echo "[ERR] CRGNB_IP not provided (usage: $0 <CRGNB_IP>)" >&2
  exit 1
fi

REMOTE_BASE="${MOSHELL_REMOTE_DIR}"
REMOTE_INBOX="${REMOTE_BASE}/inbox"
REMOTE_OUT="${REMOTE_BASE}/out"
REMOTE_LOG="${REMOTE_BASE}/watch.log"
REMOTE_MOSF="${REMOTE_INBOX}/example.mos"
REMOTE_OUTF="${REMOTE_OUT}/example0.txt"

# Single SSH call, no remote file creation; pass CRGNB via env to avoid IPv6 quoting issues
sshpass -p "$MOSHELL_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "${MOSHELL_USER}@${MOSHELL_HOST}" \
  "CRGNB='$CRGNB_IP' bash -lc '
    set -euo pipefail

    LOG=${REMOTE_LOG}
    INBOX=${REMOTE_INBOX}
    OUT=${REMOTE_OUT}
    MOSF=${REMOTE_MOSF}
    OUTF=${REMOTE_OUTF}

    # Log & trace
    exec > >(tee -a \"\$LOG\") 2>&1
    set -x

    mkdir -p \"\$INBOX\" \"\$OUT\"
    if [[ ! -f \"\$MOSF\" ]]; then
      echo \"[step4] no example.mos at \$MOSF\"
      exit 1
    fi

    # Find moshell (login PATH)
    MOSHELL_BIN=\$(bash -lc \"command -v moshell || true\")
    if [[ -z \"\$MOSHELL_BIN\" ]]; then
      echo \"[step4][ERR] moshell not found\"
      exit 127
    fi
    echo \"[step4] MOSHELL_BIN=\$MOSHELL_BIN\"
    echo \"[step4] TARGET=\$CRGNB\"  # use raw IPv6, no brackets (as you prefer)

    # Always write output to \$OUTF by wrapping your uploaded script with l+/l-
    rm -f \"\$OUTF\" || true
    cd \"\$OUT\"

    COMBINED=\"\$OUT/_run_example.mos\"
    {
      echo \"l+ \$OUTF\"
      cat \"\$MOSF\"
      echo \"l-\"
    } > \"\$COMBINED\"

    # Run moshell with -f; still tee to \$OUTF so errors end up in the file
    \"\$MOSHELL_BIN\" \"\$CRGNB\" \"\$COMBINED\" 2>&1 | tee \"\$OUTF\" || true

    # Fallback: pipe stdin if -f produced nothing
    if [[ ! -s \"\$OUTF\" ]]; then
      echo \"[step4] fallback: piping MOS via stdin\"
      \"\$MOSHELL_BIN\" \"\$CRGNB\" < \"\$COMBINED\" 2>&1 | tee -a \"\$OUTF\" || true
    fi

    echo \"[step4] done; OUTF exists? \$(test -f \"\$OUTF\" && echo yes || echo no); size=\$(test -f \"\$OUTF\" && stat -c%s \"\$OUTF\" || echo 0)\"
    exit 0
  '" || true

echo "[OK] Step 4 run-once finished."
