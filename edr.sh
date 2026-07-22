#!/usr/bin/env bash
set -euo pipefail

VERSION="2.0.0"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

usage() {
    cat <<EOF
RansomWatch EDR v$VERSION — Behavioral Ransomware Detection

Usage: $0 <command> [options]

Commands:
  monitor              Start EDR monitoring (default)
  dashboard            Show recent alerts
  sim-benign           Simulate normal file activity
  sim-attack           Simulate ransomware encryption
  sim-all              Simulate both benign and attack
  analyze <file>       Calculate entropy of a specific file

Options:
  -c, --config FILE    Config file (default: config/edr.yml)
  -p, --path DIR       Honeypot directory (default: ./honeypot)
  -t, --threshold NUM  Entropy alert threshold (default: 7.5)
  --size KB            Simulated ransomware file size in KB
  --json               JSON output where applicable

Examples:
  $0 monitor
  $0 sim-attack --size 4096
  $0 dashboard
  $0 analyze suspicious_file.bin
EOF
    exit 0
}

log_info()  { echo -e "${CYAN}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()   { echo -e "${RED}[-]${NC} $1" >&2; }

CMD="${1:-help}"; shift || true

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--config) CONFIG="$2"; shift 2 ;;
        -p|--path) MONITOR_PATH="$2"; shift 2 ;;
        -t|--threshold) THRESHOLD="$2"; shift 2 ;;
        --size) SIZE="$2"; shift 2 ;;
        --json) JSON="--json"; shift ;;
        *) break ;;
    esac
done

ARGS=""
[ -n "${CONFIG:-}" ]  && ARGS="$ARGS -c $CONFIG"
[ -n "${MONITOR_PATH:-}" ] && ARGS="$ARGS -p $MONITOR_PATH"
[ -n "${THRESHOLD:-}" ] && ARGS="$ARGS --threshold $THRESHOLD"
[ -n "${SIZE:-}" ] && ARGS="$ARGS --size $SIZE"
[ -n "${JSON:-}" ] && ARGS="$ARGS --json"

mkdir -p honeypot logs 2>/dev/null || true

case "$CMD" in
    monitor|sim-benign|sim-attack|sim-all|dashboard)
        log_info "RansomWatch EDR — $CMD"
        python3 edr.py "$CMD" $ARGS
        ;;
    analyze)
        FILE="${1:-}"
        [ -z "$FILE" ] && { log_err "Usage: $0 analyze <file>"; exit 1; }
        log_info "Analyzing: $FILE"
        python3 -c "
import sys; sys.path.insert(0, '.')
from edr import EntropyEngine
e = EntropyEngine.file_entropy('$FILE')
print(f'Entropy: {e}')
" 2>/dev/null || {
        python3 -c "
import math, collections
with open('$FILE','rb') as f:
    d = f.read(1048576)
freq = collections.Counter(d)
e = -sum((c/len(d))*math.log2(c/len(d)) for c in freq.values())
print(f'Entropy: {e:.4f}')
"
        }
        ;;
    help|*) usage ;;
esac
