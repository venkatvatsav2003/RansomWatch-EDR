# RansomWatch EDR

An Endpoint Detection and Response (EDR) mock agent designed to detect and respond to ransomware behavior in real-time.

## Overview

Unlike traditional signature-based Anti-Virus (AV), modern security solutions rely on behavioral heuristics. RansomWatch operates by monitoring critical file paths or "honeypot" directories for malicious behavior typical of ransomware:
1. **High-Speed File Modifications:** Ransomware quickly iterates over directories to encrypt files.
2. **High Shannon Entropy:** The mathematical randomness of a file. Normal text files have low entropy, while encrypted files have an entropy close to 8.0.

## Features

- **Real-Time Monitoring:** Utilizes Python's `watchdog` to hook into filesystem events.
- **Entropy Analysis:** Calculates Shannon entropy of modified files on the fly.
- **Rate Limiting/Thresholding:** Triggers an alert when modification velocity exceeds normal user behavior.
- **Automated Response Protocol:** Simulates process termination when a threat is identified.

## Installation & Setup

1. Ensure Python 3.8+ is installed.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the agent:
   ```bash
   python agent.py
   ```
   The agent will create a `honeypot_dir` and start monitoring it.

## Simulation

To test the agent, you can simulate a ransomware attack by rapidly copying files into the `honeypot_dir` or by generating highly random data in a loop:

```bash
# In another terminal, generate files with high entropy (random bytes)
for i in {1..10}; do dd if=/dev/urandom of=./honeypot_dir/test_$i.bin bs=1024 count=1; done
```

Watch the agent logs for `HIGH ENTROPY DETECTED` and `RAPID FILE MODIFICATION DETECTED` alerts.
