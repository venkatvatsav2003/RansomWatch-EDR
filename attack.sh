#!/usr/bin/env bash

HONEYPOT_DIR="./honeypot"
mkdir -p "$HONEYPOT_DIR"

echo "Simulating normal file write..."
echo "This is a normal document with regular, predictable text content." > "$HONEYPOT_DIR/normal_doc.txt"
sleep 2

echo "Simulating ransomware encryption (high-entropy data)..."
dd if=/dev/urandom bs=2048 count=1 of="$HONEYPOT_DIR/important_data.enc" 2>/dev/null
echo "Ransomware simulation complete. Check the EDR console for alerts."
