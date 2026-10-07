"""
Shannon Entropy Calculator for Ransomware & Encryption Detection
"""
import math
import os
from typing import Dict

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    
    byte_counts: Dict[int, int] = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
    length = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
        
    return round(entropy, 4)

def calculate_file_entropy(filepath: str, max_bytes: int = 1048576) -> float:
    """Read file content (up to max_bytes) and compute Shannon entropy."""
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return 0.0
        
    try:
        with open(filepath, "rb") as f:
            data = f.read(max_bytes)
        return calculate_shannon_entropy(data)
    except (PermissionError, OSError):
        return 0.0
