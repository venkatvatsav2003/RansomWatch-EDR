# RansomWatch EDR

A behavioral-based ransomware detector that monitors file entropy changes to identify encryption activity in real time.

## Ideology
Ransomware leaves a detectable signature: it transforms structured, low-entropy data into high-entropy encrypted output. By monitoring file entropy (Shannon entropy), RansomWatch can detect ransomware behavior without relying on signatures — catching both known and novel variants.

## How It Works
1. Watches a designated folder (`./honeypot`)
2. Detects file creation or modification via timestamp changes
3. Computes Shannon entropy from byte frequency distribution
4. Alerts if entropy exceeds 7.5 (near-maximum randomness)

## Usage

**Terminal 1 — Start the monitor:**
```bash
chmod +x ransomwatch.sh attack.sh
./ransomwatch.sh
```

**Terminal 2 — Simulate an attack:**
```bash
./attack.sh
```

## Example
```
RansomWatch EDR
Monitoring: ./honeypot
Entropy threshold: 7.5

[OK] ./honeypot/normal_doc.txt (entropy: 4.12)
[ALERT] ./honeypot/important_data.enc (entropy: 7.95)
                   - Possible ransomware encryption!
```

## Architecture
```
filesystem changes
    |
    v
[Timestamp Tracker] --> detect new/modified files
    |
    v
[Entropy Engine] --> od + awk (byte frequency analysis)
    |
    v
[Alert System] --> threshold comparison (>7.5)
```

## Dependencies
`bash`, `od`, `awk`, `bc` (standard Unix utilities)
