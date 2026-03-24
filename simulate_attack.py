import os
import time
import random

HONEYPOT_DIR = "./honeypot_dir"

def simulate_normal():
    print("Simulating normal activity...")
    for i in range(3):
        with open(f"{HONEYPOT_DIR}/file_{i}.txt", "w") as f:
            f.write("This is a normal text file.")
        print(f"  - Created {HONEYPOT_DIR}/file_{i}.txt")
        time.sleep(1)

def simulate_ransomware():
    print("\n--- INITIATING RANSOMWARE SIMULATION ---")
    for i in range(10):
        # Generate random high-entropy data
        data = os.urandom(1024)
        with open(f"{HONEYPOT_DIR}/encrypted_{i}.enc", "wb") as f:
            f.write(data)
        print(f"  - Encrypted file_{i}.txt -> encrypted_{i}.enc (Velocity: {i+1} files/s)")
        # No sleep to simulate rapid modification
        
if __name__ == "__main__":
    if not os.path.exists(HONEYPOT_DIR):
        os.makedirs(HONEYPOT_DIR)
        
    simulate_normal()
    time.sleep(2)
    simulate_ransomware()
    print("\nCheck the EDR agent logs for alerts!")
