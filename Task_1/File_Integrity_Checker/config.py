"""
Configuration settings for File Integrity Checker (FIM)
"""
import os
import sys
import json
import platform

# Baseline & Vault Storage Settings
BASELINE_FILE = ".fim_baseline.json"
HMAC_FILE = ".fim_hmac.sig"
VAULT_DIR = ".fim_vault"
KEY_FILE = ".fim_secret.key"

CONFIG_JSON_PATH = os.path.join(os.path.dirname(__file__), "config.json")

def load_config_json():
    """Load config.json or return fallback defaults."""
    if os.path.exists(CONFIG_JSON_PATH):
        try:
            with open(CONFIG_JSON_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_config_json(config_data: dict):
    """Save configuration dictionary to config.json."""
    try:
        with open(CONFIG_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
    except Exception as e:
        print(f"[Config] Error saving config.json: {e}")

_cfg = load_config_json()

DEFAULT_IGNORE_DIRS = set(_cfg.get("ignore_dirs", [
    ".git", "__pycache__", ".pytest_cache", ".venv", "venv", ".fim_vault", "node_modules"
]))

DEFAULT_IGNORE_FILES = set(_cfg.get("ignore_files", [
    ".fim_baseline.json", ".fim_hmac.sig", ".fim_secret.key", "events.log", "fim_security_alerts.log", "fim_incident_report.html", "fim_incident_report.pdf", ".DS_Store"
]))

DEFAULT_IGNORE_EXTENSIONS = set(_cfg.get("ignore_extensions", [
    ".pyc", ".log", ".tmp", ".swp"
]))

SHANNON_ENTROPY_RANSOMWARE_THRESHOLD = float(_cfg.get("shannon_entropy_threshold", 7.2))
BURST_TIME_WINDOW_SECONDS = int(_cfg.get("burst_time_window_seconds", 10))
BURST_FILE_COUNT_THRESHOLD = int(_cfg.get("burst_file_count_threshold", 5))
AUTO_LEARNING_PERIOD_HOURS = int(_cfg.get("auto_learning_period_hours", 24))
DESKTOP_NOTIFICATIONS_ENABLED = bool(_cfg.get("desktop_notifications_enabled", True))
AUTO_EXPORT_PDF_REPORTS = bool(_cfg.get("auto_export_pdf_reports", True))

HASH_CHUNK_SIZE = 65536

def get_approved_folders() -> list:
    """Return user-consented approved folders stored in config.json."""
    cfg = load_config_json()
    folders = cfg.get("approved_folders", [])
    valid = []
    for f in folders:
        abs_p = os.path.abspath(f)
        if os.path.exists(abs_p) and abs_p not in valid:
            valid.append(abs_p)
    return valid

def add_approved_folder(folder_path: str) -> list:
    """Add a new folder to user-consented approved_folders in config.json."""
    cfg = load_config_json()
    folders = cfg.get("approved_folders", [])
    abs_p = os.path.abspath(folder_path)
    if abs_p not in folders:
        folders.append(abs_p)
        cfg["approved_folders"] = folders
        save_config_json(cfg)
    return get_approved_folders()

def remove_approved_folder(folder_path: str) -> list:
    """Remove a folder from approved_folders in config.json."""
    cfg = load_config_json()
    folders = cfg.get("approved_folders", [])
    abs_p = os.path.abspath(folder_path)
    if abs_p in folders:
        folders.remove(abs_p)
        cfg["approved_folders"] = folders
        save_config_json(cfg)
    return get_approved_folders()

def get_auto_target_paths() -> list:
    """Return approved folders if available, otherwise OS default paths."""
    approved = get_approved_folders()
    if approved:
        return approved

    system_os = platform.system().lower()
    if system_os == "windows":
        paths = _cfg.get("default_paths_windows", ["C:\\Windows\\System32\\drivers\\etc", "demo/demo_target"])
    else:
        paths = _cfg.get("default_paths_linux", ["/etc", "/usr/bin", "~/Documents", "~/.ssh"])

    valid_paths = []
    for p in paths:
        expanded = os.path.expanduser(p)
        if os.path.exists(expanded):
            valid_paths.append(expanded)
            
    if not valid_paths:
        fallback = os.path.abspath("demo/demo_target")
        os.makedirs(fallback, exist_ok=True)
        valid_paths.append(fallback)

    return valid_paths

def is_path_ignored(filepath: str, root_dir: str) -> bool:
    """Check if a given path should be ignored by scanner."""
    try:
        rel_path = os.path.relpath(filepath, root_dir)
    except ValueError:
        rel_path = filepath
        
    parts = rel_path.split(os.sep)
    
    for part in parts[:-1]:
        if part in DEFAULT_IGNORE_DIRS or part.startswith(".fim"):
            return True
            
    filename = parts[-1]
    if filename in DEFAULT_IGNORE_FILES or filename.startswith(".fim"):
        return True
        
    _, ext = os.path.splitext(filename)
    if ext in DEFAULT_IGNORE_EXTENSIONS:
        return True
        
    return False
