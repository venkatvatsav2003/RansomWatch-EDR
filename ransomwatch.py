import os
import time
import math

DIRECTORY_TO_WATCH = "./honeypot"
ENTROPY_THRESHOLD = 7.5

def calculate_entropy(filepath):
    # Calculates the randomness of a file. Ransomware produces high entropy.
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            
        if not data:
            return 0.0
            
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy
    except Exception:
        return 0.0

if __name__ == "__main__":
    print("--- RansomWatch EDR Started ---")
    print(f"Monitoring folder: {DIRECTORY_TO_WATCH}")

    if not os.path.exists(DIRECTORY_TO_WATCH):
        os.makedirs(DIRECTORY_TO_WATCH)

    # Keep track of file modification times
    last_modified = {}

    try:
        while True:
            # Get all files in the directory
            files = os.listdir(DIRECTORY_TO_WATCH)
            
            for file in files:
                filepath = os.path.join(DIRECTORY_TO_WATCH, file)
                
                # Skip directories
                if os.path.isdir(filepath):
                    continue
                    
                mod_time = os.path.getmtime(filepath)
                
                # Check if file is new or recently modified
                if filepath not in last_modified or last_modified[filepath] != mod_time:
                    last_modified[filepath] = mod_time
                    
                    # Check the entropy of the file
                    ent = calculate_entropy(filepath)
                    print(f"[*] Detected change in {file} (Entropy: {ent:.2f})")
                    
                    if ent > ENTROPY_THRESHOLD:
                        print("🚨 ALERT! HIGH ENTROPY DETECTED!")
                        print(f"🚨 Possible Ransomware encryption on file: {file}\n")
            
            # Pause for a second before checking again
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping RansomWatch...")
