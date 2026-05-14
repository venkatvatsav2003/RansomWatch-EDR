# RansomWatch EDR

A simple Python script to detect ransomware behavior by monitoring file entropy.

## How it works
Ransomware encrypts files, which turns normal data into highly random data. This script watches a specific folder (`./honeypot`). Whenever a file is created or modified, it calculates the file's "Shannon Entropy". If the entropy is very high (close to 8.0), it triggers an alert indicating possible ransomware activity.

## Setup

No external libraries are required! It uses pure Python.

1. Run the monitor script in your terminal:
```bash
python ransomwatch.py
```

2. Open a second terminal and run the attack simulation to see it in action:
```bash
python attack.py
```

## Example Output
```text
--- RansomWatch EDR Started ---
Monitoring folder: ./honeypot
[*] Detected change in normal_doc.txt (Entropy: 4.12)
[*] Detected change in important_data.enc (Entropy: 7.95)
🚨 ALERT! HIGH ENTROPY DETECTED!
🚨 Possible Ransomware encryption on file: important_data.enc
```
