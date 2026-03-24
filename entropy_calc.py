import math
import os

def calculate_entropy(filepath, chunk_size=8192):
    """
    Calculates the Shannon entropy of a file to determine its randomness.
    Encrypted files (like those modified by ransomware) typically have 
    an entropy very close to 8.0.
    """
    if not os.path.isfile(filepath):
        return 0.0

    # Read a chunk of the file to determine entropy (faster than whole file for large files)
    with open(filepath, 'rb') as f:
        data = f.read(chunk_size)
        
    if not data:
        return 0.0

    entropy = 0
    # 256 possible byte values
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
            
    return entropy
