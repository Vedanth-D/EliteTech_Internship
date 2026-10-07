"""
File Integrity Scanner - Hashes files and extracts security metadata
"""
import hashlib
import os
import stat
from typing import Dict, Any, Optional
from config import HASH_CHUNK_SIZE, is_path_ignored
from analytics.entropy import calculate_file_entropy

def calculate_sha256(filepath: str) -> Optional[str]:
    """Calculate SHA-256 hash of a file using 64KB chunks."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, OSError):
        return None

def get_file_metadata(filepath: str, root_dir: str) -> Optional[Dict[str, Any]]:
    """Extract metadata, SHA-256 hash, and entropy for a given file."""
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return None

    try:
        file_stat = os.stat(filepath)
        sha256 = calculate_sha256(filepath)
        if sha256 is None:
            return None
            
        entropy = calculate_file_entropy(filepath)
        rel_path = os.path.relpath(filepath, root_dir).replace("\\", "/")
        
        # Determine if text file and count lines if feasible
        line_count = None
        if file_stat.st_size < 2 * 1024 * 1024:  # Under 2MB
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    line_count = sum(1 for _ in f)
            except Exception:
                line_count = None

        return {
            "rel_path": rel_path,
            "abs_path": os.path.abspath(filepath),
            "sha256": sha256,
            "size": file_stat.st_size,
            "mtime": file_stat.st_mtime,
            "mode": stat.filemode(file_stat.st_mode),
            "permissions": oct(file_stat.st_mode & 0o777),
            "entropy": entropy,
            "line_count": line_count,
            "extension": os.path.splitext(filepath)[1].lower()
        }
    except Exception as e:
        return None

def scan_directory(target_dir: str) -> Dict[str, Dict[str, Any]]:
    """
    Walk directory and generate metadata map for all non-ignored files.
    Returns dict mapping relative_path -> metadata dictionary.
    """
    results: Dict[str, Dict[str, Any]] = {}
    target_dir = os.path.abspath(target_dir)

    for root, dirs, files in os.walk(target_dir):
        # Prune ignored directories in-place for speed
        dirs[:] = [d for d in dirs if not is_path_ignored(os.path.join(root, d), target_dir)]

        for filename in files:
            filepath = os.path.join(root, filename)
            if is_path_ignored(filepath, target_dir):
                continue
                
            meta = get_file_metadata(filepath, target_dir)
            if meta:
                results[meta["rel_path"]] = meta

    return results
