"""
Ransomware Burst & Entropy Spike Detector
"""
import time
from typing import List, Dict, Any, Tuple
from config import SHANNON_ENTROPY_RANSOMWARE_THRESHOLD, BURST_TIME_WINDOW_SECONDS, BURST_FILE_COUNT_THRESHOLD

class BurstDetector:
    def __init__(self):
        self.recent_events: List[Dict[str, Any]] = []

    def add_event(self, change_event: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Record a file change event and check for ransomware burst signatures.
        Returns: (is_ransomware_burst, alert_message)
        """
        now = time.time()
        # Add timestamp to event
        event_record = {
            "timestamp": now,
            "event": change_event
        }
        self.recent_events.append(event_record)

        # Prune events outside time window
        self.recent_events = [
            e for e in self.recent_events 
            if (now - e["timestamp"]) <= BURST_TIME_WINDOW_SECONDS
        ]

        # Count high-entropy modifications in current window
        high_entropy_count = 0
        affected_files = []

        for e in self.recent_events:
            ev = e["event"]
            meta = ev.get("new_meta") or ev.get("old_meta") or {}
            entropy = meta.get("entropy", 0.0)
            
            if entropy >= SHANNON_ENTROPY_RANSOMWARE_THRESHOLD:
                high_entropy_count += 1
                rel_path = meta.get("rel_path", "unknown")
                if rel_path not in affected_files:
                    affected_files.append(rel_path)

        if high_entropy_count >= BURST_FILE_COUNT_THRESHOLD:
            msg = (
                f"🚨 RANSOMWARE BURST DETECTED! {high_entropy_count} files encrypted/modified "
                f"with high entropy (>{SHANNON_ENTROPY_RANSOMWARE_THRESHOLD}) within {BURST_TIME_WINDOW_SECONDS} seconds! "
                f"Affected: {', '.join(affected_files[:3])}..."
            )
            return True, msg

        return False, "Normal event rate."
