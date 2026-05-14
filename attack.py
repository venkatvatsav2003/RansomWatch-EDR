import os
import time

print("--- Simulating Ransomware Attack ---")

HONEYPOT = "./honeypot"
if not os.path.exists(HONEYPOT):
    os.makedirs(HONEYPOT)

# 1. Simulate normal user behavior
print("Creating a normal text file...")
with open(f"{HONEYPOT}/normal_doc.txt", "w") as f:
    f.write("Hello, this is just a regular text file. It has low entropy.")

time.sleep(3)

# 2. Simulate ransomware behavior (encrypting files)
print("Creating a highly random file (simulating encryption)...")
with open(f"{HONEYPOT}/important_data.enc", "wb") as f:
    # Random bytes simulate the high entropy of encrypted data
    f.write(os.urandom(2048))

print("Attack simulation finished! Check your RansomWatch terminal.")
