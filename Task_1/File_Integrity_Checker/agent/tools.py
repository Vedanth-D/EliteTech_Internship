"""
Read-Only Investigation Tools for the AI SOC Analyst Agent
"""
import difflib
import os
import psutil
from typing import Dict, Any, List, Optional
from core.vault import get_vault_path

def get_diff(target_dir: str, rel_path: str) -> str:
    """Generate text diff between backup vault copy and current file content."""
    target_dir = os.path.abspath(target_dir)
    current_file = os.path.join(target_dir, rel_path)
    
    vault = get_vault_path(target_dir)
    safe_name = rel_path.replace("/", "_").replace("\\", "_")
    backup_file = os.path.join(vault, "backups", safe_name)

    if not os.path.exists(current_file):
        return f"[File {rel_path} was DELETED]"
    if not os.path.exists(backup_file):
        # Read current content snippet
        try:
            with open(current_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[:50]
            return "[NEW FILE CREATED]\nFirst 50 lines:\n" + "".join(lines)
        except Exception as e:
            return f"[Binary or unreadable file: {str(e)}]"

    try:
        with open(backup_file, "r", encoding="utf-8", errors="ignore") as f:
            old_lines = f.readlines()
        with open(current_file, "r", encoding="utf-8", errors="ignore") as f:
            new_lines = f.readlines()

        diff = list(difflib.unified_diff(
            old_lines, new_lines,
            fromfile=f"baseline/{rel_path}",
            tofile=f"current/{rel_path}",
            lineterm=""
        ))
        if not diff:
            return "[No textual difference detected]"
        return "\n".join(diff[:100])  # Truncate large diffs for security/safety
    except Exception as e:
        return f"[Error computing diff: {str(e)}]"

def get_file_metadata_tool(target_dir: str, rel_path: str) -> Dict[str, Any]:
    """Get metadata statistics for a file."""
    abs_path = os.path.join(os.path.abspath(target_dir), rel_path)
    if not os.path.exists(abs_path):
        return {"error": f"File {rel_path} does not exist."}
        
    from core.scanner import get_file_metadata
    meta = get_file_metadata(abs_path, target_dir)
    return meta or {"error": "Failed to extract metadata."}

def get_process_info_tool() -> List[Dict[str, Any]]:
    """Retrieve snapshot of running system processes for correlation."""
    processes = []
    try:
        for p in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
            try:
                info = p.info
                # Filter system background processes to keep list relevant
                name = (info.get('name') or '').lower()
                if name in ('python.exe', 'cmd.exe', 'powershell.exe', 'bash', 'sh', 'cron', 'wscript.exe', 'cscript.exe'):
                    processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return processes[:15]

def get_related_changes_tool(recent_events: List[Dict[str, Any]]) -> List[str]:
    """Return list of files modified within the same recent session."""
    paths = []
    for ev in recent_events:
        meta = ev.get("new_meta") or ev.get("old_meta") or {}
        p = meta.get("rel_path") or ev.get("rel_path")
        if p and p not in paths:
            paths.append(p)
    return paths
