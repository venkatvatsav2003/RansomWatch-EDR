# RansomWatch EDR — Design Document

## Problem Statement
Signature-based antivirus fails against novel ransomware. Behavioral detection — identifying the act of encryption itself — catches both known and unknown variants.

## Core Ideology
Encrypted data is indistinguishable from random data. Ransomware, regardless of family, transforms structured files into high-entropy output. By monitoring entropy, we detect the behavior, not the signature.

## Detection Algorithm
1. **File Change Detection** — Track modification timestamps per file
2. **Byte Sampling** — Read up to 1MB of file content
3. **Frequency Analysis** — Count occurrences of each byte value (0-255)
4. **Shannon Entropy** — `H = -Σ(p(i) × log₂(p(i)))` where p(i) is byte frequency
5. **Threshold Comparison** — Alert if entropy > 7.5 (max is 8.0)

## Architecture

```
┌───────────────┐
│ Honeypot Dir  │  ./honeypot/
└───────┬───────┘
        │ file changes
        ▼
┌───────────────┐
│ State Tracker │  .edr_state.json
│ (mtime)       │
└───────┬───────┘
        ▼
┌───────────────┐
│ Entropy       │  od + awk / Python byte analysis
│ Engine        │
└───────┬───────┘
        ▼
┌───────────────┐
│ Alert System  │  logs/alerts.json + console
└───────────────┘
```

## Attack Simulation
The simulator creates two file types:
- **Benign**: Repeated ASCII text — low entropy (~4.0)
- **Ransomware**: `os.urandom()` data — high entropy (~7.9)

This allows testing the detection pipeline without actual malware.

## Limitations
- Polling-based (not inotify) — 1-second delay in detection
- Only monitors designated honeypot directory
- High-entropy legitimate files (archives, encrypted backups) may trigger false positives
