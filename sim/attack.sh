#!/usr/bin/env bash
set -euo pipefail

HONEYPOT="${1:-./honeypot}"
SIZE_KB="${SIZE:-2048}"

echo "[*] Ransomware Attack Simulation"
echo "[*] Target: $HONEYPOT"
mkdir -p "$HONEYPOT"

echo "[+] Creating benign document..."
for i in 1 2 3; do
    python3 -c "
with open('$HONEYPOT/doc_$i.txt', 'w') as f:
    f.write('Normal business document content line $i\n' * 200)
" 2>/dev/null || printf "Normal document content\n%.0s" $(seq 1 200) > "$HONEYPOT/doc_$i.txt"
done

sleep 2
echo "[!] Simulating ransomware encryption..."
python3 -c "
import os
with open('$HONEYPOT/accounts_encrypted.bin', 'wb') as f:
    f.write(os.urandom($SIZE_KB * 1024))
with open('$HONEYPOT/sales_encrypted.bin', 'wb') as f:
    f.write(os.urandom($SIZE_KB * 1024))
" 2>/dev/null || dd if=/dev/urandom bs=1024 count="$SIZE_KB" of="$HONEYPOT/encrypted.bin" 2>/dev/null

echo "[!] Dropping ransom note..."
cat > "$HONEYPOT/README_TO_DECRYPT.txt" << 'RANSOM'
=== YOUR FILES HAVE BEEN ENCRYPTED ===
All your documents, databases, and important files have been encrypted with AES-256.
To recover your data, send 1 BTC to the following address:
  bc1qransomwareaddressxxxxxxxxxxxxxxxxxx
After payment, contact decrypt@ransomware.xyz with your personal ID.
Do not attempt to recover files yourself — you will lose them permanently.
RANSOM

echo "[+] Attack simulation complete. Check the EDR monitor for alerts."
