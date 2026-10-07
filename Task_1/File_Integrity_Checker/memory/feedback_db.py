"""
SQLite Storage for Historical Verdicts & False Positive Learning
"""
import sqlite3
import os
import time
from typing import List, Dict, Any

DB_FILE = ".fim_memory.db"

def get_db_connection(target_dir: str = ".") -> sqlite3.Connection:
    """Connect to or create local FIM SQLite database."""
    db_path = os.path.join(os.path.abspath(target_dir), DB_FILE)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn

def _init_schema(conn: sqlite3.Connection):
    """Initialize database tables."""
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                rel_path TEXT,
                event_type TEXT,
                sha256 TEXT,
                entropy REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyst_verdicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                rel_path TEXT,
                verdict TEXT,
                confidence TEXT,
                mitre_tactic TEXT,
                reasoning TEXT,
                action_taken TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS feedback_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                rel_path TEXT,
                original_verdict TEXT,
                is_false_positive INTEGER
            )
        """)

def log_scan_event(target_dir: str, rel_path: str, event_type: str, sha256: str, entropy: float):
    """Log file change scan event."""
    try:
        conn = get_db_connection(target_dir)
        with conn:
            conn.execute(
                "INSERT INTO scan_history (timestamp, rel_path, event_type, sha256, entropy) VALUES (?, ?, ?, ?, ?)",
                (time.time(), rel_path, event_type, sha256, entropy)
            )
    except Exception:
        pass

def log_analyst_verdict(target_dir: str, verdict_data: Dict[str, Any], action_taken: str):
    """Store analyst verdict and action taken."""
    try:
        conn = get_db_connection(target_dir)
        with conn:
            conn.execute(
                """INSERT INTO analyst_verdicts 
                   (timestamp, rel_path, verdict, confidence, mitre_tactic, reasoning, action_taken) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    time.time(),
                    verdict_data.get("target_file", ""),
                    verdict_data.get("verdict", ""),
                    verdict_data.get("confidence", ""),
                    verdict_data.get("mitre_tactic", ""),
                    verdict_data.get("reasoning", ""),
                    action_taken
                )
            )
    except Exception:
        pass

def record_user_feedback(target_dir: str, rel_path: str, original_verdict: str, is_false_positive: bool = True):
    """Store operator feedback when an alert is marked as false positive."""
    try:
        conn = get_db_connection(target_dir)
        with conn:
            conn.execute(
                "INSERT INTO feedback_memory (timestamp, rel_path, original_verdict, is_false_positive) VALUES (?, ?, ?, ?)",
                (time.time(), rel_path, original_verdict, 1 if is_false_positive else 0)
            )
        print(f"[Memory] Recorded False Positive feedback for {rel_path}. Future alerts will be downgraded.")
    except Exception as e:
        print(f"[Memory Error] {e}")

def is_known_false_positive(target_dir: str, rel_path: str) -> bool:
    """Check if this file path has been previously flagged by user as false positive."""
    try:
        conn = get_db_connection(target_dir)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM feedback_memory WHERE rel_path = ? AND is_false_positive = 1",
            (rel_path,)
        )
        count = cursor.fetchone()[0]
        return count > 0
    except Exception:
        return False
