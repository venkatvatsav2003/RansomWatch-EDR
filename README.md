# RansomWatch EDR

![CI](https://github.com/venkatvatsav2003/RansomWatch-EDR/actions/workflows/ci.yml/badge.svg)
![Version](https://img.shields.io/badge/version-3.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

**Behavioral ransomware detection via real-time file entropy monitoring.**

## Install & Run

```bash
# One-liner
pip install ransomwatch && ransomwatch monitor

# Or clone and run
git clone https://github.com/venkatvatsav2003/RansomWatch-EDR.git
cd RansomWatch-EDR && pip install -r requirements.txt
./edr.sh monitor                    # Start monitoring
./edr.sh sim-attack                 # Simulate ransomware
./edr.sh dashboard                  # View alerts

# Docker
docker-compose up edr               # Start monitoring
docker-compose run --rm simulator   # Simulate attack
```

## Features

- **Behavioral Detection** — no signatures needed, catches unknown variants
- **Shannon Entropy** — byte-level randomness analysis
- **Real-Time Monitoring** — 1-second polling interval
- **Attack Simulator** — built-in benign and ransomware simulation
- **Alert Dashboard** — structured JSON alerts with SIEM-ready format
- **Webhook Alerts** — forward alerts to Slack, Teams, Discord, or custom endpoints
- **Prometheus Metrics** — optional /metrics endpoint for observability
- **Systemd Service** — production daemon mode

## Quick Start

```bash
# Terminal 1: Start the monitor
./edr.sh monitor

# Terminal 2: Simulate an attack
./edr.sh sim-attack

# View dashboard
./edr.sh dashboard

# Analyze a single file
./edr.sh analyze suspicious.bin
```

## Detection Logic

| Entropy | Classification | Action |
|---------|----------------|--------|
| < 6.5 | Normal | Logged |
| 6.5 - 7.5 | Suspicious | Warning |
| > 7.5 | Ransomware | Critical alert |

## Project Structure

```
RansomWatch-EDR/
├── edr.py                 # Python engine
├── edr.sh                 # Bash launcher
├── pyproject.toml         # pip install
├── docker-compose.yml     # Docker one-command
├── .env.example           # Config template
├── config/edr.yml         # Detection config
├── sim/attack.sh          # Attack simulation
├── tests/
├── Dockerfile
└── Makefile
```
