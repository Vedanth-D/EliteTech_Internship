"""
HMAC-Protected Baseline Manager & Comparison Engine
"""
import hmac
import hashlib
import json
import os
import secrets
from typing import Dict, Any, Tuple, List, Optional
from config import BASELINE_FILE, HMAC_FILE, KEY_FILE


def get_storage_dir(target_dir: str) -> str:
    """Return target_dir if writeable, else fallback to local .fim_storage/<hash> directory."""
    target_dir = os.path.abspath(target_dir)
    test_file = os.path.join(target_dir, ".fim_write_test")
    try:
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        return target_dir
    except (PermissionError, OSError):
        path_hash = hashlib.md5(target_dir.encode("utf-8")).hexdigest()[:10]
        local_dir = os.path.abspath(os.path.join(".fim_storage", path_hash))
        os.makedirs(local_dir, exist_ok=True)
        return local_dir

def get_or_create_hmac_key(target_dir: str) -> bytes:
    """Retrieve secret key from environment or local key file, or generate a new 256-bit key."""
    env_key = os.environ.get("FIM_HMAC_KEY")
    if env_key:
        return env_key.encode("utf-8")

    storage_dir = get_storage_dir(target_dir)
    key_path = os.path.join(storage_dir, KEY_FILE)
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()

    secret_key = secrets.token_bytes(32)
    try:
        with open(key_path, "wb") as f:
            f.write(secret_key)
        if hasattr(os, "chmod"):
            os.chmod(key_path, 0o600)
    except Exception:
        pass

    return secret_key

def compute_json_hmac(json_bytes: bytes, secret_key: bytes) -> str:
    """Compute HMAC-SHA256 signature of byte content."""
    return hmac.new(secret_key, json_bytes, hashlib.sha256).hexdigest()

def save_baseline(target_dir: str, metadata_map: Dict[str, Dict[str, Any]]) -> Tuple[str, str]:
    """
    Save scanned metadata to baseline file and create HMAC signature.
    Returns (baseline_path, hmac_path).
    """
    storage_dir = get_storage_dir(target_dir)
    baseline_path = os.path.join(storage_dir, BASELINE_FILE)
    hmac_path = os.path.join(storage_dir, HMAC_FILE)
    secret_key = get_or_create_hmac_key(target_dir)

    json_str = json.dumps(metadata_map, indent=2, sort_keys=True)
    json_bytes = json_str.encode("utf-8")

    with open(baseline_path, "wb") as f:
        f.write(json_bytes)

    sig = compute_json_hmac(json_bytes, secret_key)
    with open(hmac_path, "w", encoding="utf-8") as f:
        f.write(sig)

    return baseline_path, hmac_path

def verify_baseline_integrity(target_dir: str) -> Tuple[bool, str]:
    """
    Verify that baseline JSON matches its HMAC-SHA256 signature.
    Returns (is_valid, error_or_success_message).
    """
    storage_dir = get_storage_dir(target_dir)
    baseline_path = os.path.join(storage_dir, BASELINE_FILE)
    hmac_path = os.path.join(storage_dir, HMAC_FILE)

    if not os.path.exists(baseline_path):
        return False, "Baseline file does not exist."
    if not os.path.exists(hmac_path):
        return False, "HMAC signature file missing. Baseline integrity cannot be verified."

    secret_key = get_or_create_hmac_key(target_dir)

    try:
        with open(baseline_path, "rb") as f:
            json_bytes = f.read()

        with open(hmac_path, "r", encoding="utf-8") as f:
            stored_sig = f.read().strip()

        computed_sig = compute_json_hmac(json_bytes, secret_key)

        if hmac.compare_digest(stored_sig, computed_sig):
            return True, "Baseline integrity verified (HMAC-SHA256 valid)."
        else:
            return False, "CRITICAL ALERT: Baseline file has been tampered with! HMAC signature mismatch!"
    except Exception as e:
        return False, f"Failed to verify baseline: {str(e)}"

def load_baseline(target_dir: str) -> Tuple[Optional[Dict[str, Dict[str, Any]]], str]:
    """Load baseline after verifying HMAC integrity."""
    valid, msg = verify_baseline_integrity(target_dir)
    if not valid:
        return None, msg

    storage_dir = get_storage_dir(target_dir)
    baseline_path = os.path.join(storage_dir, BASELINE_FILE)
    with open(baseline_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data, msg

def compare_scans(
    old_baseline: Dict[str, Dict[str, Any]], 
    current_scan: Dict[str, Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare current scan against baseline.
    Detects: NEW, MODIFIED, DELETED, MOVED, UNCHANGED files.
    """
    results: Dict[str, List[Dict[str, Any]]] = {
        "new": [],
        "modified": [],
        "deleted": [],
        "moved": [],
        "unchanged": []
    }

    old_hashes: Dict[str, str] = {path: meta["sha256"] for path, meta in old_baseline.items()}
    current_hashes: Dict[str, str] = {path: meta["sha256"] for path, meta in current_scan.items()}

    deleted_candidate_paths = set(old_baseline.keys()) - set(current_scan.keys())
    new_candidate_paths = set(current_scan.keys()) - set(old_baseline.keys())

    matched_deleted = set()
    matched_new = set()

    for del_path in deleted_candidate_paths:
        del_hash = old_hashes[del_path]
        for new_path in new_candidate_paths:
            if new_path in matched_new:
                continue
            if current_hashes[new_path] == del_hash:
                results["moved"].append({
                    "old_path": del_path,
                    "new_path": new_path,
                    "sha256": del_hash,
                    "old_meta": old_baseline[del_path],
                    "new_meta": current_scan[new_path]
                })
                matched_deleted.add(del_path)
                matched_new.add(new_path)
                break

    for del_path in deleted_candidate_paths - matched_deleted:
        results["deleted"].append({
            "rel_path": del_path,
            "old_meta": old_baseline[del_path]
        })

    for new_path in new_candidate_paths - matched_new:
        results["new"].append({
            "rel_path": new_path,
            "new_meta": current_scan[new_path]
        })

    common_paths = set(old_baseline.keys()) & set(current_scan.keys())
    for path in common_paths:
        old_meta = old_baseline[path]
        new_meta = current_scan[path]

        if old_meta["sha256"] != new_meta["sha256"]:
            entropy_delta = round(new_meta["entropy"] - old_meta["entropy"], 4)
            size_delta = new_meta["size"] - old_meta["size"]
            
            results["modified"].append({
                "rel_path": path,
                "old_meta": old_meta,
                "new_meta": new_meta,
                "entropy_delta": entropy_delta,
                "size_delta": size_delta
            })
        else:
            results["unchanged"].append({
                "rel_path": path,
                "meta": new_meta
            })

    return results
