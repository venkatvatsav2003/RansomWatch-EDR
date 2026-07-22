#!/usr/bin/env bash
set -euo pipefail

HONEYPOT="${1:-./honeypot}"

mkdir -p "$HONEYPOT"

echo "[*] Simulating normal user activity..."

python3 -c "
import time
import os

base = '$HONEYPOT'
os.makedirs(base, exist_ok=True)

# Normal text documents
for name, content in [
    ('notes.txt', 'Meeting notes: Discussed Q2 roadmap and resource allocation.\n' * 50),
    ('todo.txt', 'Tasks:\n1. Review PR #42\n2. Deploy to staging\n3. Update dependencies\n' * 30),
    ('readme.md', '# Project Documentation\n\nThis is a normal project with no encrypted files.\n' * 40),
    ('config.json', '{\"host\": \"localhost\", \"port\": 8080, \"debug\": false}\n' * 20),
]:
    with open(os.path.join(base, name), 'w') as f:
        f.write(content)
    print(f'  Created: {name} ({len(content)} bytes)')
    time.sleep(0.5)
" 2>/dev/null

echo "[+] Normal activity simulation complete."
