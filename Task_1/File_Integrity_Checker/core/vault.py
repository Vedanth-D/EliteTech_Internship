"""
Secure Backup Vault & Quarantine Engine
"""
import os
import shutil
import stat
from typing import Tuple
from config import VAULT_DIR
from core.baseline import get_storage_dir

def get_vault_path(target_dir: str) -> str:
    """Get absolute path to vault directory using get_storage_dir fallback."""
    storage_dir = get_storage_dir(target_dir)
    vault_path = os.path.join(storage_dir, VAULT_DIR)
    os.makedirs(vault_path, exist_ok=True)
    os.makedirs(os.path.join(vault_path, "backups"), exist_ok=True)
    os.makedirs(os.path.join(vault_path, "quarantine"), exist_ok=True)
    return vault_path

def backup_file_to_vault(target_dir: str, rel_path: str) -> bool:
    """Save a copy of a file to the vault backups directory."""
    abs_src = os.path.join(os.path.abspath(target_dir), rel_path)
    if not os.path.exists(abs_src):
        return False
        
    vault = get_vault_path(target_dir)
    safe_name = rel_path.replace("/", "_").replace("\\", "_")
    dest = os.path.join(vault, "backups", safe_name)
    
    try:
        shutil.copy2(abs_src, dest)
        return True
    except Exception:
        return False

def backup_all_baseline_files(target_dir: str, metadata_map: dict) -> int:
    """Backup all current baseline files to vault."""
    count = 0
    for rel_path in metadata_map.keys():
        if backup_file_to_vault(target_dir, rel_path):
            count += 1
    return count

def restore_file_from_vault(target_dir: str, rel_path: str) -> Tuple[bool, str]:
    """Restore a file from its vault backup copy."""
    target_dir = os.path.abspath(target_dir)
    vault = get_vault_path(target_dir)
    safe_name = rel_path.replace("/", "_").replace("\\", "_")
    backup_path = os.path.join(vault, "backups", safe_name)
    dest_path = os.path.join(target_dir, rel_path)

    if not os.path.exists(backup_path):
        return False, f"No vault backup found for file: {rel_path}"

    try:
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(backup_path, dest_path)
        return True, f"Successfully restored {rel_path} from vault backup."
    except Exception as e:
        return False, f"Failed to restore file {rel_path}: {str(e)}"

def quarantine_file(target_dir: str, rel_path: str) -> Tuple[bool, str]:
    """Move a file to the vault quarantine folder and remove execution permissions."""
    target_dir = os.path.abspath(target_dir)
    abs_path = os.path.join(target_dir, rel_path)
    
    if not os.path.exists(abs_path):
        return False, f"File does not exist: {rel_path}"

    vault = get_vault_path(target_dir)
    safe_name = rel_path.replace("/", "_").replace("\\", "_")
    quarantine_dest = os.path.join(vault, "quarantine", safe_name)

    try:
        shutil.move(abs_path, quarantine_dest)
        if hasattr(os, "chmod"):
            os.chmod(quarantine_dest, stat.S_IRUSR | stat.S_IWUSR)
        return True, f"File {rel_path} moved to quarantine ({quarantine_dest})."
    except Exception as e:
        return False, f"Failed to quarantine file {rel_path}: {str(e)}"
