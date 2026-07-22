# RansomWatch EDR

![CI](https://github.com/venkatvatsav2003/RansomWatch-EDR/actions/workflows/ci.yml/badge.svg)
![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Language](https://img.shields.io/badge/language-Bash%20%2B%20Python-blue)

A behavioral ransomware detection engine that monitors file system entropy in real time. Instead of relying on signatures (which miss novel variants), RansomWatch detects the cryptographic behavior common to all ransomware: transforming low-entropy data into high-entropy encrypted output.

## Features

- **Behavioral Detection** — No signatures needed. Detects known and unknown ransomware
- **Shannon Entropy Analysis** — Byte-level randomness measurement
- **Real-Time Monitoring** — Polls file system for changes every second
- **Attack Simulation Suite** — Built-in benign and ransomware simulators
- **Alert Dashboard** — Review historical alerts from log
- **JSON Alert Logging** — Structured logging for SIEM integration
- **Configurable Thresholds** — Adjust sensitivity via YAML config
- **File Signature Tracking** — Hex signature and size metadata in alerts

## Quick Start

```bash
# Terminal 1: Start monitoring
./edr.sh monitor

# Terminal 2: Simulate an attack
./edr.sh sim-attack
./sim/attack.sh

# View alerts
./edr.sh dashboard

# Analyze a specific file
./edr.sh analyze suspicious.bin
```

## Architecture

```
┌─────────────────────────────────────┐
│        edr.sh (Bash Orchestrator)    │
│  - Command routing                    │
│  - Simulation launcher               │
│  - Dashboard viewer                  │
└────────────┬────────────────────────┘
             │
    ┌────────┴────────┐
    ▼                 ▼
┌────────────┐  ┌──────────┐
│ edr.py     │  │ sim/     │
│ Monitor    │  │ attack   │
│ Engine     │  │ .sh      │
│            │  │ benign   │
│ - Entropy  │  │ .sh      │
│ - Tracking │  └──────────┘
│ - Alerting │
└────────────┘
```

## Detection Logic

| Entropy Range | Classification | Action |
|--------------|----------------|--------|
| < 6.5 | Normal | Logged as OK |
| 6.5 - 7.5 | Suspicious | Warning alert |
| > 7.5 | Ransomware | Critical alert |

## Project Structure

```
RansomWatch-EDR/
├── edr.py                # Python detection engine
├── edr.sh                # Bash orchestrator
├── config/edr.yml        # Detection config
├── sim/
│   ├── attack.sh         # Ransomware simulation
│   └── benign.sh         # Normal file simulation
├── tests/                # Pytest suite
├── logs/                 # Alert output
├── honeypot/             # Monitored directory
├── Dockerfile
├── Makefile
└── .github/workflows/
```

## Dependencies

- Python 3.8+ (with `pyyaml`)
- Bash, `od`, `awk`, `bc` (standard Unix utilities)
